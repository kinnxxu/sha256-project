#!/usr/bin/env python3
"""
encrypt_decrypt.py

Usage:
  python encrypt_decrypt.py encrypt <password> <input.docx> <output.enc>
  python encrypt_decrypt.py decrypt <password> <input.enc>  <output.docx>
"""

import sys
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def derive_key(password: str) -> bytes:
    """
    Derive a 32-byte AES key from the given password using SHA-256.
    """
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_file(password: str, in_file: str, out_file: str) -> None:
    key = derive_key(password)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(in_file, 'rb') as f_in:
        plaintext = f_in.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Store IV + ciphertext
    with open(out_file, 'wb') as f_out:
        f_out.write(iv + ciphertext)

    print(f"Encrypted '{in_file}' → '{out_file}'")

def decrypt_file(password: str, in_file: str, out_file: str) -> None:
    key = derive_key(password)

    with open(in_file, 'rb') as f_in:
        iv = f_in.read(16)
        ciphertext = f_in.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(out_file, 'wb') as f_out:
        f_out.write(plaintext)

    print(f"Decrypted '{in_file}' → '{out_file}'")

def main():
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)

    mode, password, inp, outp = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    if mode == 'encrypt':
        encrypt_file(password, inp, outp)
    elif mode == 'decrypt':
        decrypt_file(password, inp, outp)
    else:
        print("Mode must be 'encrypt' or 'decrypt'")
        sys.exit(1)

if __name__ == '__main__':
    main()
