import os
import json
import hashlib
import hmac
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import tpm2_pytss as tpm
import logging
import secrets

logging.basicConfig(level=logging.INFO)

class QuantumResistantKeyManager:
    def __init__(self, tpm_support=False):
        self.tpm_support = tpm_support
        self.keys = {}
        self.master_key = self._initialize_master_key()

    def _initialize_master_key(self):
        if self.tpm_support:
            try:
                return self._get_tpm_key()
            except Exception as e:
                logging.warning(f"TPM unavailable: {e}")
        
        # Fallback to password-based derivation
        return self._derive_key_from_password()

    def _get_tpm_key(self):
        with tpm.TctiLdr() as tcti:
            with tpm.TPM(tcti) as tpm_instance:
                # Create primary key in TPM
                primary_handle = tpm_instance.create_primary(
                    tpm.ESYS_TR.RH_OWNER,
                    tpm.TPM2B_PUBLIC(
                        publicArea=tpm.TPMT_PUBLIC(
                            type=tpm.TPM2_ALG.ECC,
                            nameAlg=tpm.TPM2_ALG.SHA256,
                            objectAttributes=(
                                tpm.TPMA_OBJECT.FIXEDTPM |
                                tpm.TPMA_OBJECT.FIXEDPARENT |
                                tpm.TPMA_OBJECT.SENSITIVEDATAORIGIN |
                                tpm.TPMA_OBJECT.USERWITHAUTH
                            ),
                            parameters=tpm.TPMS_ECC_PARMS(
                                scheme=tpm.TPMT_ECC_SCHEME(
                                    scheme=tpm.TPM2_ALG.ECDH
                                ),
                                curveID=tpm.TPM2_ECC.NIST_P256,
                                kdf=tpm.TPMT_KDF_SCHEME(
                                    scheme=tpm.TPM2_ALG.KDF1_SP800_108
                                )
                            )
                        )
                    )
                )
                
                # Derive session key
                session_key = tpm_instance.ECDH_KeyGen(primary_handle)
                return session_key

    def _derive_key_from_password(self):
        password = getpass("Enter master password: ")
        salt = b"BIC_Key_Derivation_Salt"
        kdf = HKDF(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            info=b'BIC Key Manager',
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def generate_hybrid_keypair(self, key_id="default"):
        # Generate traditional RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Generate post-quantum key pair
        pq_private_key = os.urandom(64)
        pq_public_key = self._generate_pq_public_key(pq_private_key)

        # Encrypt private keys with master key
        enc_rsa_private = self._encrypt_key(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        
        enc_pq_private = self._encrypt_key(pq_private_key)

        # Store keys
        self.keys[key_id] = {
            "rsa_public": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "pq_public": pq_public_key.hex(),
            "rsa_private": enc_rsa_private.hex(),
            "pq_private": enc_pq_private.hex()
        }
        return self.keys[key_id]

    def _generate_pq_public_key(self, private_key):
        # Using a simplified version of Kyber for demonstration
        # In real implementation, use a proper post-quantum algorithm
        seed = hashlib.shake_128(private_key).digest(32)
        public_key = hashlib.blake2b(seed).digest()
        return public_key

    def _encrypt_key(self, key_data):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.master_key[:32]),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key_data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def _decrypt_key(self, encrypted_data):
        if len(encrypted_data) < 16 + 16:
            raise ValueError("Invalid encrypted data length")
            
        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = Cipher(
            algorithms.AES(self.master_key[:32]),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def save_keyring(self, filename="keyring.enc"):
        encrypted_data = self._encrypt_key(
            json.dumps(self.keys).encode()
        )
        with open(filename, "wb") as f:
            f.write(encrypted_data)

    def load_keyring(self, filename="keyring.enc"):
        with open(filename, "rb") as f:
            encrypted_data = f.read()
        decrypted = self._decrypt_key(encrypted_data)
        self.keys = json.loads(decrypted.decode())

if __name__ == "__main__":
    manager = QuantumResistantKeyManager(tpm_support=True)
    manager.generate_hybrid_keypair()
    manager.save_keyring()