import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(data, password="default_password"):
    if isinstance(data, dict):
        plaintext = json.dumps(data)
    else:
        plaintext = str(data)
    
    plaintext_bytes = plaintext.encode('utf-8')
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    
    encrypted_data = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
        "salt": base64.b64encode(salt).decode(),
        "algorithm": "AES-256-GCM",
        "iterations": 100000
    }
    
    # Convert to JSON without spaces and encode to base64
    json_str = json.dumps(encrypted_data, separators=(',', ':'))
    return base64.b64encode(json_str.encode()).decode()

def decrypt_data(encrypted_payload, password="default_password"):
    """
    Decrypt data that was encrypted with encrypt_data function
    
    Args:
        encrypted_payload (str): Base64 encoded encrypted data
        password (str): Password used for encryption
        
    Returns:
        str: Decrypted plaintext
    """
    try:
        # Decode base64 and parse JSON
        json_str = base64.b64decode(encrypted_payload).decode('utf-8')
        encrypted_data = json.loads(json_str)
        
        # Extract components
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        salt = base64.b64decode(encrypted_data['salt'])
        
        # Derive key using same parameters
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=encrypted_data.get('iterations', 100000),
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Convert back to string
        plaintext = plaintext_bytes.decode('utf-8')
        
        # Try to parse as JSON, otherwise return as string
        try:
            return json.loads(plaintext)
        except:
            return plaintext
            
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# Interactive input loop
if __name__ == "__main__":
    print("🔐 Encrypt/Decrypt Tool")
    print("Commands: 'encrypt', 'decrypt', 'exit'")
    print("=" * 40)
    
    while True:
        # Get command
        command = input("\nEnter command (encrypt/decrypt/exit): ").strip().lower()
        
        if command == 'exit':
            print("Goodbye!")
            break
        
        elif command == 'encrypt':
            # Get data to encrypt
            user_input = input("Enter data to encrypt: ").strip()
            
            # Try to parse as JSON, otherwise treat as text
            try:
                data = json.loads(user_input)
                print(f"Parsed as JSON: {data}")
            except:
                data = user_input
                print(f"Using as text: {data}")
            
            # Get password (optional)
            password = input("Enter password (press Enter for default): ").strip()
            if not password:
                password = "default_password"
            
            # Encrypt
            encrypted = encrypt_data(data, password)
            print(f"\n✅ Encrypted: {encrypted}")
            
        elif command == 'decrypt':
            # Get encrypted data
            encrypted_input = input("Enter encrypted data: ").strip()
            
            # Get password (optional)
            password = input("Enter password (press Enter for default): ").strip()
            if not password:
                password = "default_password"
            
            # Decrypt
            decrypted = decrypt_data(encrypted_input, password)
            print(f"\n🔓 Decrypted: {decrypted}")
            
        else:
            print("Invalid command. Use 'encrypt', 'decrypt', or 'exit'")

# Test function to verify encrypt/decrypt works
def test_encrypt_decrypt():
    print("\n🧪 Testing Encrypt/Decrypt")
    print("-" * 30)
    
    # Test data
    test_cases = [
        "test@example.com",
        {"email": "user@example.com"},
        {"from": "sender@test.com", "to": "recipient@test.com", "subject": "Test", "body": "Hello"},
        "Hello World!"
    ]
    
    for i, test_data in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_data}")
        
        # Encrypt
        encrypted = encrypt_data(test_data)
        print(f"Encrypted: {encrypted[:50]}...")
        
        # Decrypt
        decrypted = decrypt_data(encrypted)
        print(f"Decrypted: {decrypted}")
        
        # Verify
        if test_data == decrypted:
            print("✅ Success - Data matches!")
        else:
            print("❌ Failed - Data doesn't match!")
    
    print("\n" + "=" * 50)

# Uncomment to run test
# test_encrypt_decrypt()