import os
import sys
import time
import json
import subprocess
from pathlib import Path
import numpy as np

# Try importing psutil for cross-platform process management with fallback
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from config import cfg

class ResponseAgent:
    """
    Active Threat Response Agent.
    Handles process tree termination, alert debouncing, and forensic snapshot logging.
    """
    def __init__(self, cool_off_seconds=30):
        self.cool_off_seconds = cool_off_seconds
        self.alert_dir = cfg.paths.ALERT_LOGS_DIR
        
        # Debounce state: { pid_or_key: last_action_timestamp }
        self.cool_off_cache = {}

    def is_in_cool_off(self, pid, ppid):
        """Checks if a process or its parent has already been mitigated recently."""
        current_time = time.time()
        
        # Purge expired entries from cache
        expired_keys = [k for k, v in self.cool_off_cache.items() if (current_time - v) > self.cool_off_seconds]
        for k in expired_keys:
            del self.cool_off_cache[k]

        return (pid in self.cool_off_cache) or (ppid in self.cool_off_cache)

    def mark_cool_off(self, pid, ppid):
        """Marks PID and PPID as actively mitigated."""
        now = time.time()
        self.cool_off_cache[pid] = now
        if ppid:
            self.cool_off_cache[ppid] = now

    def kill_process_tree(self, pid, ppid):
        """
        Terminates the target process and its parent process tree root.
        Supports native Windows taskkill and psutil fallback.
        """
        pids_to_kill = [p for p in [pid, ppid] if p and p > 4] # Exclude system PIDs (0-4)
        success_status = {}

        for target_pid in pids_to_kill:
            if HAS_PSUTIL:
                try:
                    parent = psutil.Process(target_pid)
                    # Kill child processes first
                    children = parent.children(recursive=True)
                    for child in children:
                        child.kill()
                    parent.kill()
                    success_status[target_pid] = True
                    print(f"[+] [RESPONSE] Successfully terminated PID {target_pid} (and children) via psutil.")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    success_status[target_pid] = False
                    print(f"[!] [RESPONSE] psutil failed for PID {target_pid}: {e}")
            else:
                # Native OS Fallback (Windows / Linux)
                try:
                    if sys.platform == "win32":
                        # /F = Force, /T = Tree (includes children)
                        cmd = f"taskkill /F /T /PID {target_pid}"
                        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        os.kill(target_pid, 9)
                    success_status[target_pid] = True
                    print(f"[+] [RESPONSE] Successfully terminated PID {target_pid} via OS command.")
                except Exception as e:
                    success_status[target_pid] = False
                    print(f"[!] [RESPONSE] Taskkill failed for PID {target_pid}: {e}")

        return success_status

    def dump_forensic_snapshot(self, pid, ppid, process_name, mse, theta, feature_matrix):
        """Dumps a structured JSON forensic snapshot of the anomaly window to logs/alerts/."""
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        snapshot_file = self.alert_dir / f"alert_pid{pid}_{timestamp_str}.json"

        # Convert numpy matrix [30, 10] to nested list for JSON serialization
        matrix_list = feature_matrix.tolist() if isinstance(feature_matrix, np.ndarray) else feature_matrix

        alert_payload = {
            "alert_metadata": {
                "timestamp": time.time(),
                "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S IST"),
                "reconstruction_mse": float(mse),
                "threshold_theta": float(theta),
                "anomaly_ratio": float(mse / theta) if theta > 0 else 0.0
            },
            "process_context": {
                "pid": pid,
                "ppid": ppid,
                "process_name": process_name
            },
            "sequence_window": {
                "window_size": len(matrix_list),
                "feature_dim": len(matrix_list[0]) if matrix_list else 0,
                "matrix_data": matrix_list
            }
        }

        try:
            with open(snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(alert_payload, f, indent=2)
            print(f"[+] [FORENSICS] Alert snapshot dumped -> {snapshot_file.name}")
        except Exception as e:
            print(f"[!] [FORENSICS] Failed to write forensic snapshot: {e}")

    def mitigate_threat(self, pid, ppid, process_name, mse, theta, feature_matrix):
        """Main execution entry point triggered by the Inference Engine upon anomaly detection."""
        if self.is_in_cool_off(pid, ppid):
            print(f"[*] [RESPONSE] PID {pid} (Parent: {ppid}) is in cool-off guard. Skipping duplicate kill action.")
            return

        print(f"\n==================================================")
        print(f"🚨 [THREAT ALERT] ANOMALY DETECTED!")
        print(f"   PID: {pid} | PPID: {ppid} | Process: {process_name}")
        print(f"   Reconstruction MSE: {mse:.6f} > Threshold (theta): {theta:.6f}")
        print(f"==================================================")

        # 1. Mark cool-off immediately to prevent alert storming
        self.mark_cool_off(pid, ppid)

        # 2. Dump forensic snapshot to disk
        self.dump_forensic_snapshot(pid, ppid, process_name, mse, theta, feature_matrix)

        # 3. Terminate offending process tree
        self.kill_process_tree(pid, ppid)