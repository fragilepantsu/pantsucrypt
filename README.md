# pantsucrypt.py

## Overview

**pantsucrypt.py** is a robust command-line utility designed for secure file encryption and decryption using the AES-256-GCM algorithm. This tool provides a straightforward approach to protecting sensitive data by transforming files into encrypted formats and subsequently restoring them when required. 

### Features

- **File Encryption**: Safeguard your files by converting them into a secure encrypted format, which protects against unauthorized access.
- **File Decryption**: Retrieve the original file from its encrypted state, provided the correct password is used.

### Usage

1. **Encrypt a File**:
   - To encrypt a file, use the command: 
     ```bash
     python pantsucrypt.py.py -f <file_path> -p <password> -e
     ```
   - Example: 
     ```bash
     python pantsucrypt.py.py -f example.txt -p securepassword -e
     ```

2. **Decrypt a File**:
   - To decrypt an encrypted file, use the command:
     ```bash
     python pantsucrypt.py.py -f <encrypted_file_path> -p <password> -d
     ```
   - Example:
     ```bash
     python pantsucrypt.py.py -f example.txt.enc -p securepassword -d
     ```

### Requirements

- Python 3.6 or higher
- `cryptography` library

To install the necessary libraries, run:

```bash
pip install cryptography
```

### Technical Details

**PantsuCrypt** employs AES-256-GCM encryption to ensure high levels of data security. The encryption and decryption processes are as follows:

1. **Key Derivation**:
   - A key is derived from the provided password and a randomly generated salt using PBKDF2-HMAC-SHA256. This method ensures that each key is unique and secure.

2. **Encryption Process**:
   - A random salt and nonce (IV) are generated.
   - The derived key is used to initialize a `Cipher` object in AES-GCM mode.
   - The contents of the file are encrypted. The encrypted file contains the following components:
     - **Salt**: 16 bytes of random data used for key derivation.
     - **Nonce (IV)**: 12 bytes of random data used for encryption.
     - **Authentication Tag**: 16 bytes used to verify the integrity of the encrypted data.
     - **Ciphertext**: The actual encrypted data.

3. **Decryption Process**:
   - The encrypted file is read to extract the salt, nonce, authentication tag, and ciphertext.
   - The key is regenerated from the password and salt using the same derivation method as in encryption.
   - A `Cipher` object is initialized with AES-GCM mode using the extracted nonce and tag.
   - The ciphertext is decrypted, and the resulting plaintext is saved as a new file.

The following Python libraries are used:

- `cryptography`: Provides the cryptographic primitives necessary for AES-256-GCM encryption and decryption.
