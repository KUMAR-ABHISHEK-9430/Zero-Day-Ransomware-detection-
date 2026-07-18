import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def stream_encrypt_chacha20(secret_key: bytes, nonce: bytes, plaintext_chunks: list[bytes]) -> bytes:
    """Encrypts a stream of data chunks using ChaCha20."""
    # 1. Initialize the ChaCha20 cipher object (No mode parameter is needed for ChaCha20)
    cipher = Cipher(algorithms.ChaCha20(secret_key, nonce), mode=None)
    encryptor = cipher.encryptor()
    
    ciphertext = b""
    
    # 2. Process chunks dynamically as they stream in
    for chunk in plaintext_chunks:
        ciphertext += encryptor.update(chunk)
        
    # 3. Finalize the stream (Note: stream ciphers don't produce trailing bytes on finalize)
    ciphertext += encryptor.finalize()
    return ciphertext

def stream_decrypt_chacha20(secret_key: bytes, nonce: bytes, ciphertext_chunks: list[bytes]) -> bytes:
    """Decrypts a stream of data chunks using ChaCha20."""
    cipher = Cipher(algorithms.ChaCha20(secret_key, nonce), mode=None)
    decryptor = cipher.decryptor()
    
    decrypted_text = b""
    
    for chunk in ciphertext_chunks:
        decrypted_text += decryptor.update(chunk)
        
    decrypted_text += decryptor.finalize()
    return decrypted_text

# --- Execution Example ---
if __name__ == "__main__":
    # ChaCha20 requires a 256-bit (32-byte) key and a 128-bit (16-byte) nonce
    key = os.urandom(32)
    nonce = os.urandom(16)
    
    # Simulating data arriving in a stream
    streamed_input = [b"Streaming data ", b"chunk by chunk ", b"using ChaCha20."]
    print(f"Original Text: {b''.join(streamed_input).decode()}")
    
    # Encrypt the stream
    encrypted_data = stream_encrypt_chacha20(key, nonce, streamed_input)
    print(f"Ciphertext (Hex): {encrypted_data.hex()}")
    
    # Decrypt the stream (simulated in chunks)
    chunk_size = 10
    ciphertext_chunks = [encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
    
    decrypted_data = stream_decrypt_chacha20(key, nonce, ciphertext_chunks)
    print(f"Decrypted Text: {decrypted_data.decode()}")
