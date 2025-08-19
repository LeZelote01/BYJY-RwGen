#!/usr/bin/env python3
"""
Advanced Fast-Flux DNS Infrastructure
Dynamic DNS management for resilient C&C communication
For defensive cybersecurity research purposes only
"""

import os
import sys
import json
import time
import random
import hashlib
import threading
import socket
import struct
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import dns.resolver
import dns.zone
import dns.update
import dns.query
import dns.tsigkeyring
import requests
from concurrent.futures import ThreadPoolExecutor


class FastFluxDNSManager:
    def __init__(self, config_file: str = "fast_flux_config.json"):
        self.config = self.load_config(config_file)
        self.active_nodes = []
        self.backup_nodes = []
        self.dns_records = {}
        self.rotation_interval = self.config.get('rotation_interval', 300)  # 5 minutes
        self.is_running = False
        
        # Initialize node pools
        self.initialize_node_pools()
        
        print("[+] Fast-Flux DNS Manager initialized")
        print(f"[+] Managing {len(self.active_nodes)} active nodes")
        print(f"[+] Backup pool: {len(self.backup_nodes)} nodes")
    
    def load_config(self, config_file: str) -> Dict:
        """Load fast-flux configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default configuration for research
            default_config = {
                "domains": [
                    "research-c2-primary.local",
                    "backup-control-server.local",
                    "update-security-check.com"
                ],
                "node_pools": {
                    "active_nodes": [
                        {"ip": "192.168.1.10", "location": "US-East", "provider": "ResearchCloud1"},
                        {"ip": "192.168.1.11", "location": "US-West", "provider": "ResearchCloud2"},
                        {"ip": "192.168.1.12", "location": "EU-West", "provider": "ResearchCloud3"},
                        {"ip": "192.168.1.13", "location": "Asia-Pacific", "provider": "ResearchCloud4"}
                    ],
                    "backup_nodes": [
                        {"ip": "10.0.1.20", "location": "US-Central", "provider": "BackupCloud1"},
                        {"ip": "10.0.1.21", "location": "EU-Central", "provider": "BackupCloud2"},
                        {"ip": "10.0.1.22", "location": "Asia-East", "provider": "BackupCloud3"}
                    ]
                },
                "rotation_interval": 300,
                "ttl_values": [60, 120, 180, 300],
                "dns_servers": [
                    {"server": "ns1.research-dns.local", "key": "research_tsig_key"},
                    {"server": "ns2.research-dns.local", "key": "research_tsig_key"}
                ],
                "algorithm_settings": {
                    "node_selection": "weighted_round_robin",
                    "health_check_interval": 60,
                    "failure_threshold": 3,
                    "recovery_timeout": 600
                }
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"[+] Created default fast-flux config: {config_file}")
            return default_config
    
    def initialize_node_pools(self):
        """Initialize active and backup node pools"""
        self.active_nodes = []
        self.backup_nodes = []
        
        # Load nodes from config
        node_pools = self.config.get('node_pools', {})
        
        for node_data in node_pools.get('active_nodes', []):
            node = FastFluxNode(
                ip_address=node_data['ip'],
                location=node_data['location'],
                provider=node_data['provider'],
                node_type='active'
            )
            self.active_nodes.append(node)
        
        for node_data in node_pools.get('backup_nodes', []):
            node = FastFluxNode(
                ip_address=node_data['ip'],
                location=node_data['location'],
                provider=node_data['provider'],
                node_type='backup'
            )
            self.backup_nodes.append(node)
        
        print(f"[+] Initialized {len(self.active_nodes)} active nodes")
        print(f"[+] Initialized {len(self.backup_nodes)} backup nodes")
    
    def start_fast_flux(self):
        """Start fast-flux DNS rotation system"""
        print("[+] Starting Fast-Flux DNS system...")
        self.is_running = True
        
        # Start background threads
        threads = [
            threading.Thread(target=self.dns_rotation_loop, daemon=True),
            threading.Thread(target=self.health_monitor_loop, daemon=True),
            threading.Thread(target=self.metrics_collector_loop, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("[+] Fast-Flux DNS system active")
        return True
    
    def stop_fast_flux(self):
        """Stop fast-flux DNS system"""
        print("[+] Stopping Fast-Flux DNS system...")
        self.is_running = False
        time.sleep(2)  # Allow threads to finish
        print("[+] Fast-Flux DNS system stopped")
    
    def dns_rotation_loop(self):
        """Main DNS rotation loop"""
        while self.is_running:
            try:
                # Perform DNS rotation
                self.rotate_dns_records()
                
                # Wait for next rotation
                time.sleep(self.rotation_interval)
                
            except Exception as e:
                print(f"[!] DNS rotation error: {e}")
                time.sleep(30)  # Shorter retry interval on error
    
    def rotate_dns_records(self):
        """Rotate DNS records across available nodes"""
        domains = self.config.get('domains', [])
        
        for domain in domains:
            # Select nodes for this rotation
            selected_nodes = self.select_rotation_nodes()
            
            if not selected_nodes:
                print(f"[!] No healthy nodes available for {domain}")
                continue
            
            # Update DNS records
            success = self.update_dns_records(domain, selected_nodes)
            
            if success:
                print(f"[+] Rotated DNS for {domain}: {[n.ip_address for n in selected_nodes]}")
                self.dns_records[domain] = {
                    'nodes': selected_nodes,
                    'updated_at': datetime.now(),
                    'ttl': random.choice(self.config.get('ttl_values', [300]))
                }
            else:
                print(f"[-] Failed to rotate DNS for {domain}")
    
    def select_rotation_nodes(self) -> List['FastFluxNode']:
        """Select nodes for DNS rotation using configured algorithm"""
        algorithm = self.config.get('algorithm_settings', {}).get('node_selection', 'round_robin')
        
        # Filter healthy active nodes
        healthy_nodes = [node for node in self.active_nodes if node.is_healthy()]
        
        if len(healthy_nodes) < 2:
            # Use backup nodes if not enough active nodes
            healthy_backups = [node for node in self.backup_nodes if node.is_healthy()]
            healthy_nodes.extend(healthy_backups[:2])
        
        if len(healthy_nodes) == 0:
            return []
        
        # Apply selection algorithm
        if algorithm == 'round_robin':
            return self.round_robin_selection(healthy_nodes)
        elif algorithm == 'weighted_round_robin':
            return self.weighted_round_robin_selection(healthy_nodes)
        elif algorithm == 'geographic_distribution':
            return self.geographic_distribution_selection(healthy_nodes)
        elif algorithm == 'random':
            return self.random_selection(healthy_nodes)
        else:
            return healthy_nodes[:2]  # Default to first 2 nodes
    
    def round_robin_selection(self, nodes: List['FastFluxNode']) -> List['FastFluxNode']:
        """Simple round-robin node selection"""
        current_time = int(time.time())
        rotation_cycle = current_time // self.rotation_interval
        
        # Select 2-4 nodes in round-robin fashion
        num_nodes = min(4, len(nodes))
        start_idx = rotation_cycle % len(nodes)
        
        selected = []
        for i in range(num_nodes):
            idx = (start_idx + i) % len(nodes)
            selected.append(nodes[idx])
        
        return selected
    
    def weighted_round_robin_selection(self, nodes: List['FastFluxNode']) -> List['FastFluxNode']:
        """Weighted round-robin selection based on node performance"""
        # Calculate weights based on node health and performance
        weighted_nodes = []
        for node in nodes:
            weight = self.calculate_node_weight(node)
            weighted_nodes.append((node, weight))
        
        # Sort by weight (descending)
        weighted_nodes.sort(key=lambda x: x[1], reverse=True)
        
        # Select top 2-3 nodes with some randomization
        num_nodes = min(3, len(weighted_nodes))
        selected = []
        
        for i in range(num_nodes):
            # Add some randomness to prevent predictable patterns
            if random.random() < 0.8 or i == 0:  # Always include top node
                selected.append(weighted_nodes[i][0])
        
        # Ensure at least 2 nodes
        if len(selected) < 2 and len(weighted_nodes) >= 2:
            for node, _ in weighted_nodes:
                if node not in selected:
                    selected.append(node)
                    if len(selected) >= 2:
                        break
        
        return selected
    
    def geographic_distribution_selection(self, nodes: List['FastFluxNode']) -> List['FastFluxNode']:
        """Select nodes with geographic distribution"""
        # Group nodes by location
        location_groups = {}
        for node in nodes:
            location = node.location.split('-')[0]  # Get region (e.g., "US" from "US-East")
            if location not in location_groups:
                location_groups[location] = []
            location_groups[location].append(node)
        
        # Select one node from each region
        selected = []
        for location, location_nodes in location_groups.items():
            # Pick best node from this location
            best_node = max(location_nodes, key=lambda n: self.calculate_node_weight(n))
            selected.append(best_node)
            
            if len(selected) >= 3:  # Limit to 3 geographic regions
                break
        
        # Fill remaining slots if needed
        remaining_nodes = [n for n in nodes if n not in selected]
        while len(selected) < 2 and remaining_nodes:
            selected.append(remaining_nodes.pop(0))
        
        return selected
    
    def random_selection(self, nodes: List['FastFluxNode']) -> List['FastFluxNode']:
        """Random node selection with health weighting"""
        if len(nodes) <= 3:
            return nodes
        
        # Weight by health score
        weights = [self.calculate_node_weight(node) for node in nodes]
        
        # Weighted random selection
        selected = []
        available_nodes = list(nodes)
        available_weights = list(weights)
        
        for _ in range(min(3, len(nodes))):
            if not available_nodes:
                break
            
            # Weighted random choice
            total_weight = sum(available_weights)
            if total_weight == 0:
                # All nodes have zero weight, use uniform random
                chosen_idx = random.randint(0, len(available_nodes) - 1)
            else:
                r = random.uniform(0, total_weight)
                cumulative = 0
                chosen_idx = 0
                for i, weight in enumerate(available_weights):
                    cumulative += weight
                    if r <= cumulative:
                        chosen_idx = i
                        break
            
            selected.append(available_nodes.pop(chosen_idx))
            available_weights.pop(chosen_idx)
        
        return selected
    
    def calculate_node_weight(self, node: 'FastFluxNode') -> float:
        """Calculate node weight based on performance metrics"""
        base_weight = 1.0
        
        # Health score (0.0 to 2.0)
        health_multiplier = 2.0 if node.health_score > 0.8 else (
            1.5 if node.health_score > 0.6 else (
                1.0 if node.health_score > 0.4 else 0.5
            )
        )
        
        # Response time penalty (faster = higher weight)
        response_time_multiplier = max(0.1, 2.0 - (node.avg_response_time / 1000))
        
        # Uptime bonus
        uptime_multiplier = 1.0 + (node.uptime_percentage / 100)
        
        # Provider diversity bonus (prefer different providers)
        provider_bonus = 1.0
        if hasattr(self, '_last_selected_providers'):
            if node.provider not in self._last_selected_providers:
                provider_bonus = 1.2
        
        final_weight = base_weight * health_multiplier * response_time_multiplier * uptime_multiplier * provider_bonus
        return max(0.1, final_weight)  # Minimum weight
    
    def update_dns_records(self, domain: str, nodes: List['FastFluxNode']) -> bool:
        """Update DNS records for domain with selected nodes"""
        try:
            dns_servers = self.config.get('dns_servers', [])
            
            if not dns_servers:
                print("[!] No DNS servers configured")
                return False
            
            # Prepare DNS update
            ttl = random.choice(self.config.get('ttl_values', [300]))
            
            for dns_server_config in dns_servers:
                server = dns_server_config['server']
                
                try:
                    # Create DNS update message
                    update = dns.update.Update(domain)
                    
                    # Clear existing A records
                    update.delete(domain, 'A')
                    
                    # Add new A records for selected nodes
                    for node in nodes:
                        update.add(domain, ttl, 'A', node.ip_address)
                    
                    # Send update (simulated for research)
                    print(f"[+] DNS update for {domain} on {server}")
                    print(f"    Records: {[n.ip_address for n in nodes]} (TTL: {ttl})")
                    
                    # In real implementation, would send actual DNS update:
                    # response = dns.query.tcp(update, server)
                    
                    return True
                    
                except Exception as e:
                    print(f"[!] DNS update failed for {server}: {e}")
                    continue
            
            return False
            
        except Exception as e:
            print(f"[!] DNS record update error: {e}")
            return False
    
    def health_monitor_loop(self):
        """Monitor node health continuously"""
        check_interval = self.config.get('algorithm_settings', {}).get('health_check_interval', 60)
        
        while self.is_running:
            try:
                # Check all nodes
                all_nodes = self.active_nodes + self.backup_nodes
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {executor.submit(self.check_node_health, node): node for node in all_nodes}
                    
                    for future in futures:
                        node = futures[future]
                        try:
                            health_result = future.result(timeout=30)
                            node.update_health(health_result)
                        except Exception as e:
                            print(f"[!] Health check failed for {node.ip_address}: {e}")
                            node.mark_unhealthy()
                
                # Promote backup nodes if needed
                self.manage_node_failover()
                
                time.sleep(check_interval)
                
            except Exception as e:
                print(f"[!] Health monitor error: {e}")
                time.sleep(30)
    
    def check_node_health(self, node: 'FastFluxNode') -> Dict:
        """Check individual node health"""
        health_result = {
            'reachable': False,
            'response_time': float('inf'),
            'http_status': None,
            'timestamp': time.time()
        }
        
        try:
            # Test 1: Basic connectivity (ping simulation)
            start_time = time.time()
            
            # Simulate network connectivity test
            # In real implementation, would use actual ping or socket connection
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                result = sock.connect_ex((node.ip_address, 80))
                if result == 0:
                    health_result['reachable'] = True
            except:
                pass
            finally:
                sock.close()
            
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            health_result['response_time'] = response_time
            
            # Test 2: HTTP health check (simulated)
            if health_result['reachable']:
                # Simulate HTTP health check
                # In real implementation, would make actual HTTP request
                health_result['http_status'] = 200 if random.random() > 0.1 else 500
            
        except Exception as e:
            print(f"[!] Node health check error for {node.ip_address}: {e}")
        
        return health_result
    
    def manage_node_failover(self):
        """Manage node failover and recovery"""
        failure_threshold = self.config.get('algorithm_settings', {}).get('failure_threshold', 3)
        
        # Check for failed active nodes
        failed_active_nodes = [node for node in self.active_nodes if node.consecutive_failures >= failure_threshold]
        
        # Check for recovered backup nodes
        recovered_backup_nodes = [node for node in self.backup_nodes if node.is_healthy() and node.consecutive_failures == 0]
        
        # Promote backup nodes to replace failed active nodes
        for i, failed_node in enumerate(failed_active_nodes):
            if i < len(recovered_backup_nodes):
                backup_node = recovered_backup_nodes[i]
                
                # Swap nodes
                self.active_nodes.remove(failed_node)
                self.backup_nodes.remove(backup_node)
                
                self.active_nodes.append(backup_node)
                self.backup_nodes.append(failed_node)
                
                print(f"[+] Node failover: {failed_node.ip_address} -> {backup_node.ip_address}")
                
                # Reset failed node for potential recovery
                failed_node.reset_health_metrics()
    
    def metrics_collector_loop(self):
        """Collect and log metrics for analysis"""
        while self.is_running:
            try:
                metrics = self.collect_system_metrics()
                self.log_metrics(metrics)
                time.sleep(300)  # Collect metrics every 5 minutes
                
            except Exception as e:
                print(f"[!] Metrics collection error: {e}")
                time.sleep(60)
    
    def collect_system_metrics(self) -> Dict:
        """Collect system performance metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'active_nodes': len([n for n in self.active_nodes if n.is_healthy()]),
            'backup_nodes': len([n for n in self.backup_nodes if n.is_healthy()]),
            'total_rotations': sum(getattr(node, 'rotation_count', 0) for node in self.active_nodes),
            'average_response_time': sum(node.avg_response_time for node in self.active_nodes) / len(self.active_nodes) if self.active_nodes else 0,
            'dns_queries_served': sum(getattr(node, 'queries_served', 0) for node in self.active_nodes),
            'geographic_distribution': {}
        }
        
        # Geographic distribution
        for node in self.active_nodes:
            if node.is_healthy():
                region = node.location.split('-')[0]
                metrics['geographic_distribution'][region] = metrics['geographic_distribution'].get(region, 0) + 1
        
        return metrics
    
    def log_metrics(self, metrics: Dict):
        """Log metrics for research analysis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        metrics_file = f"fast_flux_metrics_{timestamp}.json"
        
        try:
            with open(f"logs/{metrics_file}", 'w') as f:
                json.dump(metrics, f, indent=2)
        except:
            # Create logs directory if it doesn't exist
            os.makedirs("logs", exist_ok=True)
            with open(f"logs/{metrics_file}", 'w') as f:
                json.dump(metrics, f, indent=2)
    
    def generate_dga_domains(self, seed: str, count: int = 10) -> List[str]:
        """Generate domain names using Domain Generation Algorithm"""
        domains = []
        current_seed = hashlib.md5(seed.encode()).digest()
        
        tlds = ['.com', '.net', '.org', '.info', '.biz']
        
        for i in range(count):
            # Generate pseudo-random domain name
            hash_input = current_seed + struct.pack('<I', i)
            domain_hash = hashlib.sha256(hash_input).digest()
            
            # Create domain name from hash
            domain_chars = []
            for j in range(8, 16):  # Use bytes 8-15 for domain name
                char_val = domain_hash[j] % 26
                domain_chars.append(chr(ord('a') + char_val))
            
            domain_name = ''.join(domain_chars)
            tld = tlds[domain_hash[0] % len(tlds)]
            
            domains.append(domain_name + tld)
        
        return domains
    
    def test_dns_propagation(self, domain: str) -> Dict:
        """Test DNS propagation across multiple resolvers"""
        test_resolvers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222', # OpenDNS
            '9.9.9.9'       # Quad9
        ]
        
        propagation_results = {}
        
        for resolver_ip in test_resolvers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                
                start_time = time.time()
                answers = resolver.resolve(domain, 'A')
                response_time = (time.time() - start_time) * 1000
                
                ip_addresses = [str(rdata) for rdata in answers]
                
                propagation_results[resolver_ip] = {
                    'success': True,
                    'ip_addresses': ip_addresses,
                    'response_time_ms': response_time,
                    'ttl': answers.rrset.ttl if answers.rrset else None
                }
                
            except Exception as e:
                propagation_results[resolver_ip] = {
                    'success': False,
                    'error': str(e),
                    'response_time_ms': None
                }
        
        return propagation_results
    
    def get_status_report(self) -> Dict:
        """Generate comprehensive status report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_status': 'running' if self.is_running else 'stopped',
            'active_nodes': [],
            'backup_nodes': [],
            'dns_records': {},
            'performance_metrics': {},
            'recent_rotations': []
        }
        
        # Node status
        for node in self.active_nodes:
            report['active_nodes'].append({
                'ip': node.ip_address,
                'location': node.location,
                'provider': node.provider,
                'health_score': node.health_score,
                'uptime_percentage': node.uptime_percentage,
                'avg_response_time': node.avg_response_time,
                'consecutive_failures': node.consecutive_failures,
                'is_healthy': node.is_healthy()
            })
        
        for node in self.backup_nodes:
            report['backup_nodes'].append({
                'ip': node.ip_address,
                'location': node.location,
                'provider': node.provider,
                'health_score': node.health_score,
                'is_healthy': node.is_healthy()
            })
        
        # DNS records status
        for domain, record_info in self.dns_records.items():
            report['dns_records'][domain] = {
                'node_ips': [node.ip_address for node in record_info['nodes']],
                'last_updated': record_info['updated_at'].isoformat(),
                'ttl': record_info['ttl']
            }
        
        return report


class FastFluxNode:
    def __init__(self, ip_address: str, location: str, provider: str, node_type: str = 'active'):
        self.ip_address = ip_address
        self.location = location
        self.provider = provider
        self.node_type = node_type
        
        # Health metrics
        self.health_score = 1.0
        self.uptime_percentage = 100.0
        self.avg_response_time = 100.0  # milliseconds
        self.consecutive_failures = 0
        self.last_health_check = datetime.now()
        
        # Performance metrics
        self.queries_served = 0
        self.rotation_count = 0
        self.bytes_transferred = 0
        
        # Health history for analysis
        self.health_history = []
    
    def is_healthy(self) -> bool:
        """Check if node is considered healthy"""
        health_threshold = 0.5
        max_failures = 3
        
        return (
            self.health_score >= health_threshold and
            self.consecutive_failures < max_failures and
            self.uptime_percentage >= 70.0
        )
    
    def update_health(self, health_result: Dict):
        """Update node health based on check result"""
        self.last_health_check = datetime.now()
        
        if health_result['reachable'] and health_result.get('http_status') == 200:
            # Successful health check
            self.consecutive_failures = 0
            self.health_score = min(1.0, self.health_score + 0.1)
            self.avg_response_time = (self.avg_response_time * 0.8) + (health_result['response_time'] * 0.2)
            self.uptime_percentage = min(100.0, self.uptime_percentage + 1.0)
        else:
            # Failed health check
            self.consecutive_failures += 1
            self.health_score = max(0.0, self.health_score - 0.2)
            self.uptime_percentage = max(0.0, self.uptime_percentage - 5.0)
        
        # Store health history (keep last 100 entries)
        self.health_history.append({
            'timestamp': time.time(),
            'health_score': self.health_score,
            'response_time': health_result['response_time'],
            'reachable': health_result['reachable']
        })
        
        if len(self.health_history) > 100:
            self.health_history.pop(0)
    
    def mark_unhealthy(self):
        """Mark node as unhealthy due to check failure"""
        self.consecutive_failures += 1
        self.health_score = max(0.0, self.health_score - 0.3)
        self.uptime_percentage = max(0.0, self.uptime_percentage - 10.0)
    
    def reset_health_metrics(self):
        """Reset health metrics for recovery attempt"""
        self.consecutive_failures = 0
        self.health_score = 0.5  # Start with medium health for recovery
        self.uptime_percentage = 50.0
    
    def __str__(self) -> str:
        return f"FastFluxNode({self.ip_address}, {self.location}, health={self.health_score:.2f})"


# Example usage for defensive research
if __name__ == "__main__":
    print("[+] BYJY-RwGen Fast-Flux DNS Infrastructure")
    print("[!] For defensive cybersecurity research purposes only")
    
    # Initialize fast-flux manager
    ff_manager = FastFluxDNSManager()
    
    # Start the fast-flux system
    try:
        ff_manager.start_fast_flux()
        
        # Run for demonstration (in production, this would run indefinitely)
        print("[+] Fast-Flux DNS system running...")
        print("[+] Press Ctrl+C to stop")
        
        # Generate some DGA domains for research
        dga_domains = ff_manager.generate_dga_domains("research_seed_2024", 5)
        print(f"[+] Generated DGA domains: {dga_domains}")
        
        # Test DNS propagation
        test_domain = ff_manager.config['domains'][0]
        propagation_results = ff_manager.test_dns_propagation(test_domain)
        print(f"[+] DNS propagation test for {test_domain}:")
        for resolver, result in propagation_results.items():
            status = "✓" if result['success'] else "✗"
            print(f"    {status} {resolver}: {result}")
        
        # Run for a short time for demonstration
        time.sleep(30)
        
        # Generate status report
        status_report = ff_manager.get_status_report()
        print(f"\n[+] System Status Report:")
        print(f"    Active Nodes: {len(status_report['active_nodes'])}")
        print(f"    Backup Nodes: {len(status_report['backup_nodes'])}")
        print(f"    DNS Records: {len(status_report['dns_records'])}")
        
        # Show node health
        for node_info in status_report['active_nodes']:
            print(f"    Node {node_info['ip']} ({node_info['location']}): "
                  f"Health={node_info['health_score']:.2f}, "
                  f"RT={node_info['avg_response_time']:.1f}ms")
        
    except KeyboardInterrupt:
        print("\n[+] Stopping Fast-Flux DNS system...")
        ff_manager.stop_fast_flux()
    except Exception as e:
        print(f"[-] Fast-Flux DNS error: {e}")
    finally:
        if ff_manager.is_running:
            ff_manager.stop_fast_flux()
    
    print("\n[!] Fast-Flux DNS research session complete")
    print("[!] Data collected for defensive cybersecurity research")
