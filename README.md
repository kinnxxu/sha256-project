File Encryption & Decryption with AES-CBC and SHA-256

This repository provides a Python script to securely encrypt and decrypt any binary file (e.g., Microsoft Word documents) using AES-256 in CBC mode. The script derives a strong 256-bit key from a user-supplied password via SHA-256.

Contents

encrypt_decrypt.py: Main Python script implementing key derivation, encryption, and decryption.

README.md: This file.

Prerequisites

Python 3.6 or newer

pycryptodome library for cryptographic primitives

Installation

Clone this repository:

git clone https://github.com/yourusername/encrypt-decrypt-aes.git
cd encrypt-decrypt-aes

Install dependencies:

pip install pycryptodome

Usage

Encrypt a file

python encrypt_decrypt.py encrypt <password> <input_file> <output_file>

<password>: Your chosen passphrase.

<input_file>: Path to the file you want to encrypt (e.g., document.docx).

<output_file>: Path for the resulting encrypted file (e.g., document.enc).

Example:

python encrypt_decrypt.py encrypt MyStrongPass document.docx document.enc

Decrypt a file

python encrypt_decrypt.py decrypt <password> <input_file> <output_file>

<password>: Same passphrase used for encryption.

<input_file>: Encrypted file (e.g., document.enc).

<output_file>: Path for the decrypted output (e.g., document_decrypted.docx).

Example:

python encrypt_decrypt.py decrypt MyStrongPass document.enc document_decrypted.docx

How It Works

Key Derivation: The script hashes the password with SHA-256 to produce a fixed, high-entropy 256-bit key for AES.

AES-CBC Mode: Uses a random 16-byte Initialization Vector (IV), prepended to the ciphertext file.

Padding: Applies PKCS7 padding so plaintexts of any length are supported.

Output: The encrypted file contains IV || ciphertext.

Security Considerations

Use a strong, unique password to prevent brute-force attacks.

Store your password securely; without it, decryption is impossible.

Do not use ECB mode; this script uses CBC with an IV for security.

For additional security, consider integrating a key-stretching function (e.g., PBKDF2).

License

This project is released under the MIT License. See LICENSE for details.
