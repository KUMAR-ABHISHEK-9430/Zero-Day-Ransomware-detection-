# What this script does:

# Phase 1: It will create a directory with multiple folders and files in it.

# sleep for 10 sec 

# phase 2: It will simulate a ransomware attack by encrypting the files in the created folders using ChaCha20Poly1305 symmetric encryption.

# TODO: maybe add more encryption algorithms to simulate different ransomware attacks.


# In the specified directory, it will first create multiple folders and in each folder it will create some files. 
# Then simulated ransomware will open -> read -> encrypt -> close the files in each folder.

# TODO: Try to make 2 simulations. One for fast attack and 2nd for slow attack.


# Critical: It should not touch files and folders of other directory.


import os   # for generating random nos. which will be used to create keys for encryption

# using cryptography library will do symmetric (AES) encryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

