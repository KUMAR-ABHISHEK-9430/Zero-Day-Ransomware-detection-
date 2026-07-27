import os
import sys
import time
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

# Import centralized project configuration and modules
from config import cfg
from dataset import ShardedTelemetryDataset
from model import LSTMAutoencoder, CNNAutoencoder

# Try importing sklearn metrics with fallback if not installed
try:
    from sklearn.metrics import roc_auc_score, precision_recall_fscore_support, confusion_matrix
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class Evaluator:
    """
    Offline Evaluation and Threshold Analysis Suite for Autoencoder Anomaly Models.
    """
    def __init__(self, checkpoint_path=None, data_dir=None, device_override=None):
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else cfg.paths.BEST_MODEL_PATH
        self.data_dir = Path(data_dir) if data_dir else cfg.paths.PROCESSED_DATA_DIR
        
        self.device = torch.device(
            device_override if device_override else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        print(f"[*] Evaluator initialized on device: {self.device}")
        
        self.model = None
        self.calibrated_theta = None
        self.model_config = {}
        
        self._load_checkpoint()

    def _load_checkpoint(self):
        """Loads model weights, architecture configuration, and threshold from checkpoint."""
        if not self.checkpoint_path.exists():
            raise FileNotFoundError(f"[!] Checkpoint file not found at: {self.checkpoint_path}")

        print(f"[*] Loading checkpoint: {self.checkpoint_path.name}")
        checkpoint = torch.load(self.checkpoint_path, map_location=self.device, weights_only=False)

        self.model_config = checkpoint.get('config', {})
        self.calibrated_theta = checkpoint.get('threshold', None)

        # Instantiate appropriate model architecture
        arch_type = checkpoint.get('arch', 'LSTM').upper()
        if 'CNN' in arch_type:
            self.model = CNNAutoencoder(
                input_dim=self.model_config.get('input_dim', cfg.model.INPUT_DIM),
                seq_len=self.model_config.get('seq_len', cfg.model.SEQ_LEN),
                latent_dim=self.model_config.get('latent_dim', cfg.model.LATENT_DIM)
            )
            print("  └── Loaded Architecture: 1D-CNN Autoencoder")
        else:
            self.model = LSTMAutoencoder(
                input_dim=self.model_config.get('input_dim', cfg.model.INPUT_DIM),
                seq_len=self.model_config.get('seq_len', cfg.model.SEQ_LEN),
                hidden_dim=self.model_config.get('hidden_dim', cfg.model.HIDDEN_DIM),
                latent_dim=self.model_config.get('latent_dim', cfg.model.LATENT_DIM),
                num_layers=self.model_config.get('num_layers', cfg.model.NUM_LAYERS)
            )
            print("  └── Loaded Architecture: LSTM Autoencoder")

        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()

        if self.calibrated_theta:
            print(f"   └── Calibrated Baseline Threshold (theta): {self.calibrated_theta:.6f}")

    def compute_reconstruction_errors(self, dataset, batch_size=cfg.train.BATCH_SIZE):
        """
        Passes dataset samples through the model in full FP32 precision 
        and computes per-sample Mean Squared Error (MSE).
        """
        loader = DataLoader(
            dataset, 
            batch_size=batch_size, 
            shuffle=False, 
            num_workers=cfg.train.NUM_WORKERS,
            pin_memory=True
        )

        errors = []
        start_time = time.time()

        with torch.no_grad():
            for batch_x in loader:
                batch_x = batch_x.to(self.device)
                
                # Full FP32 forward pass for maximum reconstruction precision
                reconstructed = self.model(batch_x)
                
                # Compute MSE per window sample: shape [batch_size]
                sample_mse = torch.mean((batch_x - reconstructed) ** 2, dim=(1, 2))
                errors.extend(sample_mse.cpu().numpy())

        total_time = time.time() - start_time
        errors = np.array(errors, dtype=np.float32)
        
        return errors, total_time

    def run_full_evaluation(self):
        """Executes peacetime analysis, adversarial detection, and threshold sensitivity sweep."""
        print("\n==================================================")
        print("          AEGIS MODEL EVALUATION SUITE            ")
        print("==================================================")

        # 1. Evaluate Peacetime Baseline Shards (Label = 0)
        try:
            peace_dataset = ShardedTelemetryDataset(data_dir=self.data_dir, prefix="X_system_telemetry")
        except FileNotFoundError:
            print(f"[!] Error: Peacetime shards not found in {self.data_dir}")
            return

        print(f"[*] Ingesting Peacetime Dataset ({len(peace_dataset):,} samples)...")
        peace_errors, peace_time = self.compute_reconstruction_errors(peace_dataset)
        print(f"  └── Computed in {peace_time:.2f}s (Avg: {(peace_time/len(peace_dataset))*1000:.3f} ms/sample)")

        # 2. Evaluate Adversarial Threat Shards (Label = 1)
        adv_dataset = None
        adv_errors = None
        try:
            adv_dataset = ShardedTelemetryDataset(data_dir=self.data_dir, prefix="X_simulated_attack")
            print(f"[*] Ingesting Adversarial Dataset ({len(adv_dataset):,} samples)...")
            adv_errors, adv_time = self.compute_reconstruction_errors(adv_dataset)
            print(f"  └── Computed in {adv_time:.2f}s (Avg: {(adv_time/len(adv_dataset))*1000:.3f} ms/sample)")
        except FileNotFoundError:
            print("[!] Note: Adversarial threat dataset not found. Running peacetime stats only.")

        # 3. Print Statistical Distribution Breakdown
        self._print_error_distributions(peace_errors, adv_errors)

        # 4. Threshold Sensitivity Sweep & Classification Metrics
        if adv_errors is not None:
            self._evaluate_threshold_sweep(peace_errors, adv_errors)

    def _print_error_distributions(self, peace_errors, adv_errors=None):
        """Prints percentile breakdowns of reconstruction errors."""
        print("\n--- Reconstruction Loss Distributions (MSE) ---")
        
        percentiles = [50, 90, 95, 98, 99, 99.5, 99.9]
        peace_pcts = np.percentile(peace_errors, percentiles)

        print(f"{'Metric / Percentile':<25} | {'Peacetime (Clean)':<20} | {'Adversarial (Attack)':<20}")
        print("-" * 72)
        print(f"{'Mean ± Std':<25} | {np.mean(peace_errors):.6f} ± {np.std(peace_errors):.6f} | " + 
              (f"{np.mean(adv_errors):.6f} ± {np.std(adv_errors):.6f}" if adv_errors is not None else "N/A"))
        print(f"{'Min / Max':<25} | {np.min(peace_errors):.6f} / {np.max(peace_errors):.6f} | " + 
              (f"{np.min(adv_errors):.6f} / {np.max(adv_errors):.6f}" if adv_errors is not None else "N/A"))
        
        for p, val in zip(percentiles, peace_pcts):
            adv_val = f"{np.percentile(adv_errors, p):.6f}" if adv_errors is not None else "N/A"
            print(f"{f'{p}th Percentile':<25} | {val:.6f}{' (theta)' if self.calibrated_theta and abs(val-self.calibrated_theta)<1e-5 else ''}{' ':<8} | {adv_val}")

    def _evaluate_threshold_sweep(self, peace_errors, adv_errors):
        """Sweeps multiple candidate thresholds and computes FPR, TPR (Recall), Precision, and F1."""
        print("\n--- Threshold Sensitivity Analysis Sweep ---")
        
        # Candidate thresholds based on peacetime percentiles
        percentile_candidates = [95.0, 98.0, 99.0, 99.5, 99.9]
        candidate_thetas = {f"{p}%ile": float(np.percentile(peace_errors, p)) for p in percentile_candidates}
        
        if self.calibrated_theta and self.calibrated_theta not in candidate_thetas.values():
            candidate_thetas["Calibrated"] = self.calibrated_theta

        # Combine ground truth and predictions for ROC-AUC
        y_true = np.concatenate([np.zeros(len(peace_errors)), np.ones(len(adv_errors))])
        y_scores = np.concatenate([peace_errors, adv_errors])

        print(f"{'Threshold (theta)':<20} | {'FPR (%)':<10} | {'TPR/Recall (%)':<15} | {'Precision (%)':<15} | {'F1-Score':<10}")
        print("-" * 82)

        for label, theta in candidate_thetas.items():
            # Predictions: 1 if error > theta, else 0
            y_pred_peace = (peace_errors > theta).astype(int)
            y_pred_adv = (adv_errors > theta).astype(int)

            fp = np.sum(y_pred_peace)
            tn = len(peace_errors) - fp
            tp = np.sum(y_pred_adv)
            fn = len(adv_errors) - tp

            fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
            tpr = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
            precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
            f1 = (2 * precision * tpr / (precision + tpr)) / 100.0 if (precision + tpr) > 0 else 0.0

            marker = " <= CALIBRATED" if self.calibrated_theta and abs(theta - self.calibrated_theta) < 1e-6 else ""
            print(f"{f'{theta:.6f} ({label})':<20} | {fpr:<10.2f} | {tpr:<15.2f} | {precision:<15.2f} | {f1:<10.4f}{marker}")

        # Global ROC-AUC Calculation
        if HAS_SKLEARN:
            auc_score = roc_auc_score(y_true, y_scores)
            print(f"\n[+] Area Under ROC Curve (ROC-AUC): {auc_score:.6f}")
        else:
            print("\n[!] Install scikit-learn (`pip install scikit-learn`) for exact ROC-AUC computation.")


if __name__ == "__main__":
    # Custom checkpoint path can be passed via command line argument: python evaluate.py <checkpoint.pt>
    ckpt_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    evaluator = Evaluator(checkpoint_path=ckpt_path)
    evaluator.run_full_evaluation()