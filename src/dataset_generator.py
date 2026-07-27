import os
import json
import math
import time
from collections import deque, defaultdict
from pathlib import Path
import numpy as np
from config import cfg

# =====================================================================
# PIPELINE CONFIGURATION
# =====================================================================
WINDOW_SIZE = cfg.features.WINDOW_SIZE
STRIDE = cfg.features.STRIDE
TTL_SECONDS = cfg.features.TTL_SECONDS
SCRIPT_HOSTS = cfg.features.SCRIPT_HOSTS
USER_DATA_DIRS = cfg.features.USER_DATA_DIRS



# =====================================================================
# FEATURE EXTRACTOR (F = 10)
# =====================================================================
class TelemetryVectorizer:
    """Converts a raw JSON log event into a 1D numerical feature vector [10]."""

    @staticmethod
    def extract_features(event, prev_event_time, prev_entropy):
        current_ts = float(event.get('timestamp', 0))
        
        # 1. Time Delta (log-scaled)
        time_delta = current_ts - prev_event_time if prev_event_time > 0 else 0.0
        time_delta_feat = math.log10(max(time_delta, 1e-6) + 1e-6)

        # 2-5. Operation Type One-Hot
        op = str(event.get('operation', '')).upper()
        op_create = 1.0 if op == 'CREATE' else 0.0
        op_read   = 1.0 if op == 'READ' else 0.0
        op_write  = 1.0 if op == 'WRITE' else 0.0
        op_close  = 1.0 if op == 'CLOSE' else 0.0

        # 6. Bytes Delta (log-scaled)
        bytes_raw = event.get('bytes_delta', 0)
        bytes_delta_feat = math.log10(max(float(bytes_raw), 0.0) + 1.0)

        # 7. Normalized Shannon Entropy (0.0 to 1.0)
        entropy_raw = float(event.get('entropy', 0.0))
        entropy_feat = min(max(entropy_raw / 8.0, 0.0), 1.0)

        # 8. Entropy Delta
        entropy_delta_feat = entropy_feat - prev_entropy

        # 9. User Data Path Flag
        file_path = str(event.get('file_path', '')).lower()
        is_user_data = 1.0 if any(u_dir in file_path for u_dir in USER_DATA_DIRS) else 0.0

        # Note: Feature 10 (dir_diversity) is dynamically computed at window-assembly level
        return [
            time_delta_feat, op_create, op_read, op_write, op_close,
            bytes_delta_feat, entropy_feat, entropy_delta_feat, is_user_data
        ], file_path, current_ts, entropy_feat


# =====================================================================
# PROCESS BUFFER & TTL MANAGER
# =====================================================================
class ProcessBufferManager:
    """Manages per-PID/PPID rolling deques, directory context, and TTL eviction."""

    def __init__(self, window_size=WINDOW_SIZE, stride=STRIDE, ttl=TTL_SECONDS):
        self.window_size = window_size
        self.stride = stride
        self.ttl = ttl
        
        # State Tracking: { routing_key: deque(maxlen=W) }
        self.buffers = defaultdict(lambda: deque(maxlen=self.window_size))
        self.path_history = defaultdict(lambda: deque(maxlen=self.window_size))
        
        # Metadata per routing key
        self.last_seen = {}
        self.events_since_sample = defaultdict(int)
        self.prev_timestamps = defaultdict(float)
        self.prev_file_entropy = defaultdict(dict)
        self.process_name_cache = {}

    def get_routing_key(self, pid, ppid, process_name):
        """Routes worker/script child processes into the PPID family buffer."""
        self.process_name_cache[pid] = process_name
        parent_name = self.process_name_cache.get(ppid, '').lower()

        # PPID Family Routing
        if parent_name in SCRIPT_HOSTS:
            return f"ppid_{ppid}"
        return f"pid_{pid}"

    def push_event(self, event):
        pid = event.get('pid')
        ppid = event.get('ppid')
        proc_name = event.get('process_name', '')
        
        if not pid:
            return None

        key = self.get_routing_key(pid, ppid, proc_name)
        
        # Extract features
        prev_ts = self.prev_timestamps[key]
        file_path = str(event.get('file_path', ''))
        prev_ent = self.prev_file_entropy[key].get(file_path, 0.0)

        base_feats, path, current_ts, current_ent = TelemetryVectorizer.extract_features(
            event, prev_ts, prev_ent
        )

        # Update process state
        self.prev_timestamps[key] = current_ts
        self.prev_file_entropy[key][file_path] = current_ent
        self.last_seen[key] = current_ts

        # Store vector and path context
        self.buffers[key].append(base_feats)
        self.path_history[key].append(Path(path).parent)
        self.events_since_sample[key] += 1

        # Check if window is full and hits stride criteria
        if len(self.buffers[key]) == self.window_size:
            if self.events_since_sample[key] >= self.stride:
                self.events_since_sample[key] = 0
                return self._assemble_matrix(key)

        return None

    def _assemble_matrix(self, key):
        """Combines raw feature deque and dir_diversity into a complete [30, 10] matrix."""
        raw_buffer = list(self.buffers[key])
        paths = list(self.path_history[key])

        # Feature 9: Calculate Directory Diversity Ratio across window
        unique_dirs = len(set(paths))
        dir_diversity = unique_dirs / float(self.window_size)

        # Insert dir_diversity into index 8 of each row
        matrix = []
        for row in raw_buffer:
            row_copy = list(row)
            row_copy.insert(8, dir_diversity) # Keeps [30, 10] shape
            matrix.append(row_copy)

        return np.array(matrix, dtype=np.float32)

    def evict_stale_buffers(self, current_time):
        """Scans and removes inactive process buffers to protect RAM."""
        stale_keys = [
            k for k, last_t in self.last_seen.items() 
            if (current_time - last_t) > self.ttl
        ]
        for k in stale_keys:
            del self.buffers[k]
            del self.path_history[k]
            del self.last_seen[k]
            del self.events_since_sample[k]
            del self.prev_timestamps[k]
            del self.prev_file_entropy[k]

    def handle_process_exit(self, pid):
        """Instantly releases RAM when a process exit opcode is logged."""
        key = f"pid_{pid}"
        if key in self.buffers:
            del self.buffers[key]
            del self.path_history[key]
            del self.last_seen[key]


# =====================================================================
# DATASET GENERATOR & SHARD EXPORTER
# =====================================================================
class DatasetGenerator:
    def __init__(self, output_dir="../data/processed"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.buffer_manager = ProcessBufferManager()

    def process_telemetry_file(self, jsonl_path, label_flag=0, shard_size=10000):
        """
        Parses a .jsonl telemetry file line-by-line and dumps [30, 10] 
        matrices into memory-mapped .npy shards.
        """
        jsonl_path = Path(jsonl_path)
        print(f"[*] Ingesting: {jsonl_path.name} | Label: {label_flag}")

        collected_samples = []
        shard_count = 0
        total_lines = 0

        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                total_lines += 1
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[!] JSON Decode Error at line {total_lines}: {line.strip()}")
                    continue    

                # Handle Process Exits immediately
                if event.get('operation') == 'PROCESS_EXIT':
                    self.buffer_manager.handle_process_exit(event.get('pid'))
                    continue

                # Push event to manager
                matrix = self.buffer_manager.push_event(event)
                if matrix is not None:
                    collected_samples.append(matrix)

                # Periodically trigger TTL sweep
                if total_lines % CLEANUP_INTERVAL == 0:
                    current_ts = float(event.get('timestamp', time.time()))
                    self.buffer_manager.evict_stale_buffers(current_ts)

                # Export Shard when buffer hits size limit
                if len(collected_samples) >= shard_size:
                    self._save_shard(collected_samples, jsonl_path.stem, shard_count, label_flag)
                    shard_count += 1
                    collected_samples.clear()

        # Flush remaining matrices
        if collected_samples:
            self._save_shard(collected_samples, jsonl_path.stem, shard_count, label_flag)

        print(f"[+] Completed {jsonl_path.name}: {total_lines} lines processed.")

    def _save_shard(self, sample_list, prefix, shard_idx, label):
        """Saves a batch of samples to disk as a binary .npy file."""
        X_data = np.array(sample_list, dtype=np.float32)  # Shape: [N, 30, 10]
        y_data = np.full((len(X_data),), label, dtype=np.int64)

        x_filename = self.output_dir / f"X_{prefix}_shard_{shard_idx:03d}.npy"
        y_filename = self.output_dir / f"y_{prefix}_shard_{shard_idx:03d}.npy"

        np.save(x_filename, X_data)
        np.save(y_filename, y_data)
        print(f"    └── Exported Shard {shard_idx:03d}: Shape {X_data.shape} -> {x_filename.name}")


# =====================================================================
# ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    generator = DatasetGenerator(output_dir="../data/processed")

    # 1. Process Peacetime Telemetry Trace (Label = 0)
    peacetime_file = "../data/raw_telemetry/system_telemetry.jsonl"
    if os.path.exists(peacetime_file):
        generator.process_telemetry_file(peacetime_file, label_flag=0)
    else:
        print(f"[!] Warning: Peacetime log file not found at {peacetime_file}")

    # 2. Process Adversarial Threat Trace (Label = 1)
    adversarial_file = "../data/raw_telemetry/simulated_attack_telemetry.jsonl"
    if os.path.exists(adversarial_file):
        generator.process_telemetry_file(adversarial_file, label_flag=1)
    else:
        print(f"[!] Note: Adversarial log file not found at {adversarial_file} (Ready for when generated).")