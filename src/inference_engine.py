import time
import queue
import threading
import torch
import numpy as np
from pathlib import Path

from config import cfg
from dataset_generator import ProcessBufferManager
from model import LSTMAutoencoder, CNNAutoencoder
from response_agent import ResponseAgent

class InferenceEngine:
    """
    Real-Time Streaming Inference Engine.
    Drains telemetry queues, maintains per-process rolling buffers, runs PyTorch 
    forward passes, and triggers response mitigation on anomaly detection.
    """
    def __init__(self, model_path=None):
        self.model_path = Path(model_path) if model_path else cfg.paths.BEST_MODEL_PATH
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        self.buffer_manager = ProcessBufferManager()
        self.response_agent = ResponseAgent(cool_off_seconds=30)
        
        self.model = None
        self.theta = None
        self.is_running = False

        self._load_model_checkpoint()

    def _load_model_checkpoint(self):
        """Loads trained PyTorch model and calibrated threshold theta."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"[!] Checkpoint not found at: {self.model_path}")

        print(f"[*] Inference Engine loading checkpoint: {self.model_path.name}")
        checkpoint = torch.load(self.model_path, map_location=self.device, weights_only=False)

        self.theta = checkpoint.get('threshold', 0.05)
        model_config = checkpoint.get('config', {})
        arch_type = checkpoint.get('arch', 'LSTM').upper()

        if 'CNN' in arch_type:
            self.model = CNNAutoencoder(
                input_dim=model_config.get('input_dim', cfg.model.INPUT_DIM),
                seq_len=model_config.get('seq_len', cfg.model.SEQ_LEN),
                latent_dim=model_config.get('latent_dim', cfg.model.LATENT_DIM)
            )
        else:
            self.model = LSTMAutoencoder(
                input_dim=model_config.get('input_dim', cfg.model.INPUT_DIM),
                seq_len=model_config.get('seq_len', cfg.model.SEQ_LEN),
                hidden_dim=model_config.get('hidden_dim', cfg.model.HIDDEN_DIM),
                latent_dim=model_config.get('latent_dim', cfg.model.LATENT_DIM),
                num_layers=model_config.get('num_layers', cfg.model.NUM_LAYERS)
            )

        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()  # Set PyTorch evaluation mode
        print(f"[+] Model loaded successfully. Active threshold (theta): {self.theta:.6f}")

    def process_event(self, raw_event):
        """
        Ingests a single raw ETW event dictionary, updates process ring buffers,
        and runs model inference if a [30, 10] matrix is emitted.
        """
        if not isinstance(raw_event, dict):
            return

        pid = raw_event.get('pid')
        ppid = raw_event.get('ppid')
        proc_name = raw_event.get('process_name', 'unknown')
        op = raw_event.get('operation', '')

        # Handle process exit events immediately to clean up RAM
        if op == 'PROCESS_EXIT':
            self.buffer_manager.handle_process_exit(pid)
            return

        # Push event to ProcessBufferManager (Extracts features + updates deque)
        matrix = self.buffer_manager.push_event(raw_event)

        # If a complete [30, 10] matrix was emitted by the stride generator:
        if matrix is not None:
            self._evaluate_matrix(pid, ppid, proc_name, matrix)

    def _evaluate_matrix(self, pid, ppid, proc_name, matrix_np):
        """Converts NumPy matrix to PyTorch tensor and computes reconstruction MSE."""
        # Matrix shape: [30, 10] -> Tensor shape: [1, 30, 10]
        tensor_x = torch.from_numpy(matrix_np).unsqueeze(0).float().to(self.device)

        start_t = time.perf_counter()
        with torch.no_grad():
            reconstructed = self.model(tensor_x)
            # Compute Mean Squared Error across all matrix elements
            mse_loss = torch.mean((tensor_x - reconstructed) ** 2).item()
        eval_time_ms = (time.perf_counter() - start_t) * 1000.0

        # Anomaly Check
        if mse_loss > self.theta:
            print(f"[*] Inference evaluated in {eval_time_ms:.2f} ms | MSE: {mse_loss:.6f} > {self.theta:.6f}")
            self.response_agent.mitigate_threat(
                pid=pid,
                ppid=ppid,
                process_name=proc_name,
                mse=mse_loss,
                theta=self.theta,
                feature_matrix=matrix_np
            )

    def run_streaming_consumer(self, telemetry_queue):
        """
        Background worker daemon loop.
        Continuously drains telemetry_queue and processes events in real time.
        """
        self.is_running = True
        print("[*] Inference Engine worker loop started. Waiting for telemetry events...")

        event_count = 0
        start_time = time.time()

        while self.is_running:
            try:
                # Non-blocking pop with 1 second timeout
                raw_event = telemetry_queue.get(timeout=1.0)
                self.process_event(raw_event)
                telemetry_queue.task_done()
                event_count += 1
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Error in inference event loop: {e}")

        elapsed = time.time() - start_time
        print(f"[*] Inference Engine loop stopped. Processed {event_count:,} events in {elapsed:.2f}s.")

    def stop(self):
        self.is_running = False