# utils/encryption.py - Enhanced version
import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import KEY_FILE
import secrets

class EnhancedEncryption:
    """
    Enhanced encryption class that supports multiple encryption methods
    for Mail-as-a-Service API
    """
    
    _instance = None
    _fernet_cipher = None
    _master_key = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EnhancedEncryption, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize encryption with master key"""
        # Generate master key if it doesn't exist
        if not os.path.exists(KEY_FILE):
            master_key = Fernet.generate_key()
            with open(KEY_FILE, 'wb') as f:
                f.write(master_key)
        
        # Load the master key
        with open(KEY_FILE, 'rb') as f:
            self._master_key = f.read()
        
        self._fernet_cipher = Fernet(self._master_key)
    
    # ========== FERNET ENCRYPTION (Current Implementation) ==========
    def encrypt(self, data):
        """Legacy Fernet encryption for backward compatibility"""
        if isinstance(data, str):
            data = data.encode()
        return self._fernet_cipher.encrypt(data).decode()
    
    def decrypt(self, data):
        """Legacy Fernet decryption for backward compatibility"""
        if isinstance(data, str):
            data = data.encode()
        try:
            return self._fernet_cipher.decrypt(data).decode()
        except Exception:
            return "[Failed to decrypt]"
    
    # ========== AES-256-GCM ENCRYPTION (Recommended for API) ==========
    def encrypt_aes_gcm(self, plaintext, password=None):
        """
        Encrypt data using AES-256-GCM with password-based key derivation
        
        Args:
            plaintext (str): Data to encrypt
            password (str, optional): Password for encryption. If None, uses master key
            
        Returns:
            dict: Contains encrypted data, nonce, salt, and tag
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        # Generate random salt and nonce
        salt = os.urandom(16)  # 128-bit salt
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Derive key from password or use master key
        if password:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        else:
            # Use master key directly (ensure it's 32 bytes)
            key = self._master_key[:32] if len(self._master_key) >= 32 else self._master_key.ljust(32, b'0')
        
        # Encrypt with AES-256-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Return encrypted data with metadata
        result = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(encryptor.tag).decode(),
            'salt': base64.b64encode(salt).decode() if password else None,
            'algorithm': 'AES-256-GCM',
            'iterations': 100000 if password else None
        }
        
        return result
    
    def decrypt_aes_gcm(self, encrypted_data, password=None):
        """
        Decrypt data using AES-256-GCM
        
        Args:
            encrypted_data (dict): Encrypted data with metadata
            password (str, optional): Password for decryption
            
        Returns:
            str: Decrypted plaintext
        """
        try:
            # Extract components
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            # Derive key
            if password and encrypted_data.get('salt'):
                salt = base64.b64decode(encrypted_data['salt'])
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=encrypted_data.get('iterations', 100000),
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
            else:
                # Use master key
                key = self._master_key[:32] if len(self._master_key) >= 32 else self._master_key.ljust(32, b'0')
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode()
            
        except Exception as e:
            return f"[Decryption failed: {str(e)}]"
    
    # ========== API ENCRYPTION METHODS ==========
    def encrypt_for_api(self, data, client_password=None):
        """
        Encrypt data for API transmission
        
        Args:
            data (str): Data to encrypt
            client_password (str, optional): Client-specific password
            
        Returns:
            str: Base64 encoded JSON string containing encrypted data
        """
        encrypted = self.encrypt_aes_gcm(data, client_password)
        json_str = json.dumps(encrypted)
        return base64.b64encode(json_str.encode()).decode()
    
    def decrypt_from_api(self, encrypted_payload, client_password=None):
        """
        Decrypt data received from API
        
        Args:
            encrypted_payload (str): Base64 encoded JSON string
            client_password (str, optional): Client-specific password
            
        Returns:
            str: Decrypted data
        """
        try:
            # Decode base64 and parse JSON
            json_str = base64.b64decode(encrypted_payload).decode()
            encrypted_data = json.loads(json_str)
            
            # Decrypt
            return self.decrypt_aes_gcm(encrypted_data, client_password)
            
        except Exception as e:
            return f"[API decryption failed: {str(e)}]"
    
    # ========== UTILITY METHODS ==========
    def generate_client_key(self, client_id):
        """Generate a unique key for a client"""
        combined = f"{client_id}:{self._master_key.decode('latin-1')}"
        return base64.b64encode(combined.encode()).decode()
    
    def validate_encrypted_format(self, encrypted_data):
        """Validate if encrypted data has correct format"""
        required_fields = ['ciphertext', 'nonce', 'tag', 'algorithm']
        
        if isinstance(encrypted_data, str):
            try:
                encrypted_data = json.loads(base64.b64decode(encrypted_data).decode())
            except:
                return False
        
        return all(field in encrypted_data for field in required_fields)


# ========== ENCRYPTION SERVICE FOR API ROUTES ==========
class EncryptionService:
    """Service class for handling encryption in API routes"""
    
    def __init__(self):
        self.encryption = EnhancedEncryption()
    
    def encrypt_email_content(self, content, client_password=None):
        """Encrypt email content for storage"""
        if isinstance(content, dict):
            # Encrypt each field that needs encryption
            encrypted_content = {}
            for key, value in content.items():
                if key in ['subject', 'body'] and value:
                    encrypted_content[key] = self.encryption.encrypt_aes_gcm(str(value), client_password)
                else:
                    encrypted_content[key] = value
            return encrypted_content
        else:
            # Single string encryption
            return self.encryption.encrypt_aes_gcm(str(content), client_password)
    
    def decrypt_email_content(self, encrypted_content, client_password=None):
        """Decrypt email content for retrieval"""
        if isinstance(encrypted_content, dict):
            # Decrypt each encrypted field
            decrypted_content = {}
            for key, value in encrypted_content.items():
                if key in ['subject', 'body'] and isinstance(value, dict) and 'ciphertext' in value:
                    decrypted_content[key] = self.encryption.decrypt_aes_gcm(value, client_password)
                else:
                    decrypted_content[key] = value
            return decrypted_content
        else:
            # Single encrypted data
            return self.encryption.decrypt_aes_gcm(encrypted_content, client_password)
    
    def process_api_request(self, encrypted_payload, client_password=None):
        """Process encrypted API request"""
        try:
            # Decrypt the incoming payload
            decrypted_data = self.encryption.decrypt_from_api(encrypted_payload, client_password)
            
            # Parse the decrypted JSON
            if isinstance(decrypted_data, str):
                return json.loads(decrypted_data)
            
            return decrypted_data
            
        except Exception as e:
            raise ValueError(f"Failed to process encrypted API request: {str(e)}")
    
    def prepare_api_response(self, response_data, client_password=None):
        """Prepare encrypted API response"""
        try:
            # Convert response to JSON string
            json_data = json.dumps(response_data)
            
            # Encrypt for API transmission
            return self.encryption.encrypt_for_api(json_data, client_password)
            
        except Exception as e:
            raise ValueError(f"Failed to prepare encrypted API response: {str(e)}")


# ========== BACKWARD COMPATIBILITY ==========
class Encryption(EnhancedEncryption):
    """Backward compatibility class"""
    pass