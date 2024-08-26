import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + nonce + encryptor.tag + ciphertext)
    
    print(f"File encrypted and saved as {file_path}.enc")

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    nonce = data[16:28]
    tag = data[28:44]
    ciphertext = data[44:]
    
    key = derive_key(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        with open(file_path.replace('.enc', ''), 'wb') as f:
            f.write(plaintext)
        print(f"File decrypted and saved as {file_path.replace('.enc', '')}")
    except Exception as e:
        print(f"Decryption failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file.")
    parser.add_argument('-f', '--file', required=True, help="Path to the file")
    parser.add_argument('-p', '--password', required=True, help="Password for encryption/decryption")
    parser.add_argument('-e', '--encrypt', action='store_true', help="Encrypt the file")
    parser.add_argument('-d', '--decrypt', action='store_true', help="Decrypt the file")
    
    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print("Cannot specify both encrypt and decrypt options.")
        return
    
    if not args.encrypt and not args.decrypt:
        print("Must specify either encrypt or decrypt option.")
        return
    
    if args.encrypt:
        encrypt_file(args.file, args.password)
    elif args.decrypt:
        if not args.file.endswith('.enc'):
            print("Decryption requires a file with '.enc' extension.")
            return
        decrypt_file(args.file, args.password)

if __name__ == "__main__":
    main()
