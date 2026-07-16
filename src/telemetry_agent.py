import time
import json
import math
import queue
import threading
import os
import ctypes
from collections import OrderedDict

# Native Windows ETW Dependencies
import etw
from etw import evntrace, ProviderInfo, GUID, ETW

# ==========================================
# PART 1: NT DEVICE PATH RESOLUTION
# ==========================================

def get_dos_drive_map():
    """Maps kernel paths like \\Device\\HarddiskVolume3 to logical drives (C:)."""
    drive_map = {}
    buffer = ctypes.create_unicode_buffer(1024)
    for drive_letter in [f"{chr(x)}:" for x in range(65, 91)]:
        if ctypes.windll.kernel32.QueryDosDeviceW(drive_letter, buffer, 1024) != 0:
            device_path = buffer.value.lower()
            drive_map[device_path] = drive_letter
    return drive_map

DRIVE_MAP = get_dos_drive_map()

def nt_to_dos_path(nt_path):
    if not nt_path:
        return ""
    nt_path_lower = nt_path.lower()
    for device_path, drive_letter in DRIVE_MAP.items():
        if nt_path_lower.startswith(device_path):
            return drive_letter + nt_path[len(device_path):]
    return nt_path




# ==========================================
# PART 2: LRU POINTER CACHE
# ==========================================

# LRU cache is being used to store file pointers and their path.
# AS we get both file pointer and path only in file create event after that we only get
#  pointer



class LRUCache:
    def __init__(self, capacity=20000):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = threading.Lock()

    def set(self, key, value):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def get(self, key):
        with self.lock:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]

    def remove(self, key):
        with self.lock:
            if key in self.cache:
                del self.cache[key]



# TODO: Test the optimal capacity of telemetry queue and LRU cache.
# 
#  

# Shared Global Buffers
telemetry_queue = queue.Queue(maxsize=100000) 
process_metadata_cache = {} 
file_pointer_cache = LRUCache(capacity=20000)
cache_lock = threading.Lock() 

# ==========================================
# PART 3: FEATURE EXTRACTION
# ==========================================

class TelemetryNormalizer:
    @staticmethod
    def filetime_to_unix(filetime_int):
        try:
            return (float(filetime_int) - 116444736000000000) / 10000000.0
        except Exception:
            return time.time()

    # TODO: Consider expanding this to check digital signatures of binaries for more robust detection.
    @staticmethod
    def is_microsoft_signed(process_name):
        trusted_binaries = ['explorer.exe', 'svchost.exe', 'cmd.exe', 'powershell.exe']
        return 1 if process_name.lower() in trusted_binaries else 0

    @staticmethod
    def calculate_entropy(file_path):
        resolved_path = nt_to_dos_path(file_path)
        if not os.path.exists(resolved_path):
            return 0.0
        try:
            with open(resolved_path, 'rb') as f:
                chunk = f.read(1024)
            if not chunk:
                return 0.0
            
            length = len(chunk)
            byte_counts = [0] * 256
            for byte in chunk:
                byte_counts[byte] += 1
                
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)
            return round(entropy, 4)
        except PermissionError:
            return -1.0 
        except Exception:
            return 0.0



            

# ==========================================
# PART 4: COHERENT CONSUMER
# ==========================================

# Consumer thread takes data from shared queue and processes it to extract features
#  and write to disk. It also maintains process metadata cache and file pointer cache.

class StreamConsumer(threading.Thread):
    def __init__(self, output_path, event_queue):
        super().__init__(daemon=True)
        self.output_path = output_path
        self.queue = event_queue
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

    def run(self):
        print(f"[Consumer Thread] Active. Writing telemetry to: {self.output_path}")
        with open(self.output_path, 'a', encoding='utf-8') as log_file:
            while True:
                try:
                    # Consumer strictly processes the enqueued dictionary
                    raw_event = self.queue.get() 
                    self._process_event(raw_event, log_file)
                except Exception as e:
                    print(f"[!] Parsing Error Dropped Event: {str(e)}") 
                finally:
                    self.queue.task_done()

    def _process_event(self, event, log_file):
        task_name = event.get('Task Name')
        header = event.get('EventHeader', {})
        
        if task_name == 'PROCESS':
            self._handle_process_lifecycle(event, header)
        elif task_name == 'FILEIO':
            pid = header.get('ProcessId')
            if pid:
                self._handle_file_mutation(event, header, pid, log_file)
                

    def _handle_process_lifecycle(self, event, header):
        opcode = header.get('EventDescriptor', {}).get('Opcode')
        raw_pid = event.get('ProcessId')
        
        if not raw_pid:
            return
            
        try:
            target_pid = int(raw_pid, 16) if isinstance(raw_pid, str) and raw_pid.startswith('0x') else int(raw_pid)
        except ValueError:
            return

        with cache_lock:
            # Opcode 1, 3, 4 represent starting / DCStart states
            if opcode in [1, 3, 4]: 
                raw_ppid = event.get('ParentId')
                ppid = 0
                if raw_ppid:
                    try:
                        ppid = int(raw_ppid, 16) if isinstance(raw_ppid, str) and raw_ppid.startswith('0x') else int(raw_ppid)
                    except ValueError:
                        pass
                
                image_name = event.get('ImageFileName', 'unknown_binary')
                clean_name = image_name.split('\\')[-1] if '\\' in image_name else image_name
                
                process_metadata_cache[target_pid] = {
                    "process_name": clean_name,
                    "ppid": ppid,
                    "is_signed": TelemetryNormalizer.is_microsoft_signed(clean_name)
                }
            # Opcode 2, 39 represent Process Exit / End states
            elif opcode in [2, 39]: 
                process_metadata_cache.pop(target_pid, None)

    def _handle_file_mutation(self, event, header, pid, log_file):
        opcode = header.get('EventDescriptor', {}).get('Opcode')
        pointer_key = event.get('FileObject') or event.get('IrpPtr') or event.get('FileKey')
        file_string = event.get('OpenPath') or event.get('FileName')

        if not pointer_key:
            return

        if opcode == 64 and file_string:
            with cache_lock:
                if event.get('IrpPtr'):
                    file_pointer_cache.set(event['IrpPtr'], file_string)
                if event.get('FileObject'):
                    file_pointer_cache.set(event['FileObject'], file_string)
                
            # Opcode 65/66/70: File Close / Eviction
        if opcode == 64:
            op_type = "CREATE"
        elif opcode == 67:
            op_type = "READ"
        elif opcode == 68:
            op_type = "WRITE"
        elif opcode in [65, 66, 70]:
            op_type = "CLOSE"
        else:
            op_type = f"UNKNOWN_OP_{opcode}"

        # 3. Resolve the Path from Cache
        with cache_lock:
            file_path = file_pointer_cache.get(pointer_key) or file_string
        
        # If we have absolutely no path context from event or cache, drop it
        if not file_path:
            return

        # Prevent our logging thread from writing about its own log files (Infinite Loop)
        if file_path.endswith('.jsonl') or 'raw_telemetry' in file_path:
            return

        # 4. Gather Process Context
        with cache_lock:
            proc_context = process_metadata_cache.get(pid, {
                "process_name": "unknown_process", 
                "ppid": 0, 
                "is_signed": 0
            })

        # Calculate live features
        entropy = TelemetryNormalizer.calculate_entropy(file_path) if op_type in ["WRITE", "CREATE"] else 0.0
        dos_path = nt_to_dos_path(file_path)

        bytes_delta_raw = event.get('IoSize') or event.get('Length') or '0x0'
        try:
            bytes_delta = int(bytes_delta_raw, 16) if isinstance(bytes_delta_raw, str) and bytes_delta_raw.startswith('0x') else int(bytes_delta_raw)
        except ValueError:
            bytes_delta = 0

        # 5. Flush the complete vector straight to disk
        atomic_record = {
            "timestamp": TelemetryNormalizer.filetime_to_unix(header.get('TimeStamp', 0)),
            "pid": pid,
            "ppid": proc_context["ppid"],
            "process_name": proc_context["process_name"],
            "is_signed": proc_context["is_signed"],
            "operation": op_type,
            "file_path": dos_path,
            "bytes_delta": bytes_delta,
            "entropy": entropy
        }

        log_file.write(json.dumps(atomic_record) + '\n')
        log_file.flush()

        # Clean handle memory *after* logging the close event
        if opcode in [65, 66, 70]:
            with cache_lock:
                file_pointer_cache.remove(pointer_key)


                
# ==========================================
# PART 5: THE PRODUCER (ETW Pipeline)
# ==========================================


# Etw producer will put raw event data of "Process " and "File IO " in queue which is shared
# Between producer and consumer 
# I have deliberately kept callback function simple so that it will be fast.


class ETWProducer:
    def __init__(self, target_queue):
        self.queue = target_queue
        self.provider = [ProviderInfo(
            name="NT Kernel Logger",
            guid=GUID("{9E814AAD-3204-11D2-9A82-006008A86939}"),
            any_keywords=(
                evntrace.EVENT_TRACE_FLAG_PROCESS |    
                evntrace.EVENT_TRACE_FLAG_FILE_IO |    
                evntrace.EVENT_TRACE_FLAG_FILE_IO_INIT 
            )
        )]

    def _etw_callback(self, event_tuple):
        """Ultra-fast callback. Strips the tuple and enqueues just the dictionary."""
        
        try:
            if isinstance(event_tuple, tuple) and len(event_tuple) > 1:
                self.queue.put_nowait(event_tuple[1])
        except queue.Full:
            pass
        

    def start_trace(self):
        print("[Producer Thread] Initializing Native ETW Kernel Listener...")
        try:
            self.job = ETW(
                session_name="NT Kernel Logger",
                providers=self.provider, 
                event_callback=self._etw_callback
            )
            print("[Producer Thread] Trace active. Capturing system streams...")
            self.job.start()
            
            while True:
                time.sleep(1)
                
        except PermissionError:
            print("[!] FATAL: ETW Tracing requires SYSTEM/Admin privileges.")
        except Exception as e:
            print(f"[-] ETW Trace Error: {str(e)}")
        finally:
            if hasattr(self, 'job'):
                try:
                    self.job.stop()
                except AttributeError:
                    pass

# ==========================================
# PART 6: ORCHESTRATOR
# ==========================================

def main():
    print("==================================================")
    print(" AegisStream Telemetry Agent (Production Ingress) ")
    print("==================================================\n")
    
    OUTPUT_LOG_PATH = "./data/raw_telemetry/system_telemetry.jsonl"
    
    consumer = StreamConsumer(output_path=OUTPUT_LOG_PATH, event_queue=telemetry_queue)
    consumer.start()
    
    producer = ETWProducer(target_queue=telemetry_queue)
    
    try:
        producer.start_trace()
    except KeyboardInterrupt:
        print("\n[-] Agent termination requested by user.")
    finally:
        print("[*] Shutting down trace components...")





if __name__ == "__main__":
    main()