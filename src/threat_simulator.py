# What this script does:
# In the specified directory, it will first create multiple folders and in each folder it will create some files. 
# Then simulated ransomware will open -> read -> encrypt -> close the files in each folder.
# TODO: Try to make 2 simulations. One for fast attack and 2nd for slow attack.


# Critical: It should not touch files and folders of other directory.


import os
# using cryptography library will do symmetric (AES) encryption
import 