# BYJY-RwGen - Exemples d'Usage pour Recherche Défensive

## 🎓 Guide Pratique pour Chercheurs en Cybersécurité

---

## 1. Scénarios de Recherche Défensive

### 1.1. Test de Détection Antivirus

#### Objectif
Évaluer les capacités de détection des solutions de sécurité contre les techniques d'évasion modernes.

#### Configuration
```json
// build_config.json
{
  "obfuscation_level": "high",
  "enable_anti_analysis": true,
  "pack_executable": true,
  "target_extensions": [".test", ".research"],
  "excluded_paths": [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Users\\*\\AppData"
  ]
}
```

#### Procédure
```bash
# 1. Générer échantillon avec obfuscation minimale
python3 master_builder.py --config low_obfuscation.json --build windows

# 2. Tester avec solutions AV
./test_av_detection.py --sample dist/payload_low.exe

# 3. Générer échantillon avec obfuscation maximale  
python3 master_builder.py --config high_obfuscation.json --build windows

# 4. Comparer taux de détection
./compare_detection_rates.py --samples dist/
```

#### Métriques de Recherche
- Taux de détection statique (%)
- Taux de détection dynamique (%)
- Temps de détection (secondes)
- Techniques d'évasion efficaces

---

### 1.2. Analyse des Communications C&C

#### Objectif
Étudier les patterns de communication et développer des signatures de détection.

#### Configuration DNS Tunneling
```json
// c2_config.json
{
  "c2_domain": "research-test.local",
  "communication": {
    "method": "dns_tunneling",
    "chunk_size": 30,
    "poll_interval": 60,
    "encryption_key": "research_key_12345678901234567890123456789012"
  },
  "logging": {
    "enabled": true,
    "capture_traffic": true,
    "decrypt_logs": true
  }
}
```

#### Setup Environnement de Test
```bash
# 1. Configurer serveur DNS local
sudo dnsmasq --no-daemon --log-queries --log-facility=/var/log/dns.log

# 2. Configurer capture de trafic
sudo tcpdump -i any -w dns_tunnel.pcap 'port 53'

# 3. Lancer payload en mode recherche
./payload.exe --research-mode --log-traffic

# 4. Analyser patterns
python3 analyze_dns_patterns.py --capture dns_tunnel.pcap
```

#### Signatures Détectées
```python
# Exemples de signatures identifiées
DNS_TUNNEL_SIGNATURES = {
    'high_query_frequency': 'Query rate > 1/sec',
    'long_subdomain_names': 'Subdomain length > 50 chars',
    'base32_patterns': 'Base32 encoding detected in queries',
    'unusual_record_types': 'TXT records with binary data'
}
```

---

### 1.3. Étude de Persistance Windows

#### Objectif
Analyser les mécanismes de persistance et leur détectabilité.

#### Configuration Multi-Persistance
```json
// payload_config.json
{
  "persistence": {
    "methods": [
      "registry",
      "scheduled_task", 
      "startup_folder",
      "wmi_event"
    ],
    "stealth_mode": true,
    "service_name": "ResearchTestService",
    "task_name": "SystemMaintenanceTask"
  }
}
```

#### Script d'Analyse
```python
# persistence_analyzer.py
import winreg
import subprocess
import os

def analyze_registry_persistence():
    """Analyser les clés de registre créées"""
    keys_to_check = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Classes\CLSID"
    ]
    
    for key_path in keys_to_check:
        # Logique d'analyse...
        pass

def analyze_scheduled_tasks():
    """Analyser les tâches planifiées"""
    result = subprocess.run(['schtasks', '/query', '/fo', 'csv'], 
                          capture_output=True, text=True)
    # Analyser les tâches suspectes...

def analyze_startup_persistence():
    """Analyser le dossier de démarrage"""
    startup_paths = [
        os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    ]
    # Analyser les fichiers...

if __name__ == "__main__":
    print("[+] Analyzing persistence mechanisms...")
    analyze_registry_persistence()
    analyze_scheduled_tasks()
    analyze_startup_persistence()
```

---

### 1.4. Test de Performance de Chiffrement

#### Objectif
Mesurer l'impact performance et optimiser la détection comportementale.

#### Configuration Benchmark
```json
// payload_config.json
{
  "encryption": {
    "benchmark_mode": true,
    "threads": [1, 2, 4, 8, 16],
    "algorithms": ["aes256", "xchacha20poly1305"],
    "chunk_sizes": [65536, 1048576, 10485760],
    "measure_metrics": [
      "throughput_mbps",
      "cpu_usage_percent", 
      "memory_usage_mb",
      "io_operations_per_sec"
    ]
  }
}
```

#### Script de Benchmark
```python
# encryption_benchmark.py
import time
import psutil
import os
from pathlib import Path

class EncryptionBenchmark:
    def __init__(self, test_data_size_mb=100):
        self.test_data_size = test_data_size_mb * 1024 * 1024
        self.test_file = "benchmark_data.test"
        
    def create_test_data(self):
        """Créer données de test"""
        with open(self.test_file, 'wb') as f:
            f.write(os.urandom(self.test_data_size))
    
    def measure_encryption_performance(self, threads=4):
        """Mesurer performance chiffrement"""
        start_time = time.time()
        start_cpu = psutil.cpu_percent()
        start_memory = psutil.virtual_memory().used
        
        # Lancer le processus de chiffrement
        # (Implémentation spécifique...)
        
        end_time = time.time()
        end_cpu = psutil.cpu_percent()
        end_memory = psutil.virtual_memory().used
        
        metrics = {
            'duration_seconds': end_time - start_time,
            'throughput_mbps': self.test_data_size / (end_time - start_time) / 1024 / 1024,
            'cpu_usage_percent': end_cpu - start_cpu,
            'memory_increase_mb': (end_memory - start_memory) / 1024 / 1024,
            'threads_used': threads
        }
        
        return metrics
```

---

## 2. Cas d'Usage Spécialisés

### 2.1. Recherche sur l'Évasion de Sandbox

#### Configuration Anti-Sandbox Avancée
```json
{
  "execution": {
    "sandbox_evasion": {
      "check_memory_size": true,
      "minimum_ram_gb": 4,
      "check_cpu_cores": true,
      "minimum_cores": 2,
      "check_processes": true,
      "blacklisted_processes": [
        "vmsrvc.exe", "vboxtray.exe", "prl_cc.exe",
        "vmware", "virtualbox", "parallels"
      ],
      "check_registry": true,
      "vm_registry_keys": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVBOX",
        "HKLM\\SOFTWARE\\VMware, Inc."
      ],
      "timing_checks": true,
      "sleep_acceleration_threshold": 0.5,
      "mouse_movement_check": true,
      "minimum_movement_pixels": 50
    }
  }
}
```

#### Méthodologie de Test
```bash
# 1. Test dans environnement normal
./payload.exe --research-mode --log-evasion

# 2. Test dans différentes sandboxes
# - VirtualBox
# - VMware
# - Cuckoo Sandbox
# - Any.run
# - Hybrid Analysis

# 3. Analyser les techniques d'évasion efficaces
python3 analyze_evasion_effectiveness.py
```

### 2.2. Simulation d'Attaque Complète

#### Scénario : APT Simulation
```json
{
  "campaign": {
    "name": "Research_APT_Simulation_2024",
    "phases": [
      {
        "name": "reconnaissance",
        "duration_hours": 24,
        "activities": ["network_scan", "service_enumeration"]
      },
      {
        "name": "initial_access",
        "method": "phishing_simulation",
        "payload_delivery": "email_attachment"
      },
      {
        "name": "persistence",
        "methods": ["registry", "scheduled_task"],
        "stealth_level": "high"
      },
      {
        "name": "lateral_movement",
        "techniques": ["smb_enumeration", "credential_dumping"],
        "scope": "limited_research_network"
      },
      {
        "name": "data_exfiltration", 
        "method": "dns_tunneling",
        "targets": ["*.research", "*.test"]
      }
    ]
  }
}
```

---

## 3. Intégration avec Outils de Sécurité

### 3.1. Test avec Solutions EDR

#### Configuration pour Tests EDR
```json
{
  "edr_testing": {
    "simulate_common_behaviors": true,
    "behaviors": [
      "file_encryption",
      "registry_modification", 
      "network_communication",
      "process_injection",
      "privilege_escalation_attempt"
    ],
    "timing": {
      "behavior_interval_seconds": 60,
      "total_duration_minutes": 30
    },
    "logging": {
      "detailed_behavior_log": true,
      "api_calls_log": true,
      "network_connections_log": true
    }
  }
}
```

#### Script d'Évaluation EDR
```python
# edr_evaluation.py
class EDRTestFramework:
    def __init__(self, edr_solution):
        self.edr = edr_solution
        self.test_results = []
    
    def test_file_encryption_detection(self):
        """Test détection chiffrement de fichiers"""
        start_time = time.time()
        
        # Déclencher comportement de chiffrement
        self.trigger_encryption_behavior()
        
        # Attendre alerte EDR
        alert_time = self.wait_for_edr_alert(timeout=300)
        
        result = {
            'test': 'file_encryption_detection',
            'detected': alert_time is not None,
            'detection_time_seconds': alert_time - start_time if alert_time else None,
            'alert_accuracy': self.evaluate_alert_accuracy()
        }
        
        self.test_results.append(result)
        return result
    
    def test_c2_communication_detection(self):
        """Test détection communication C&C"""
        # Implémentation similaire...
        pass
    
    def generate_report(self):
        """Générer rapport d'évaluation"""
        report = {
            'edr_solution': self.edr,
            'test_date': datetime.now().isoformat(),
            'overall_detection_rate': self.calculate_overall_rate(),
            'detailed_results': self.test_results,
            'recommendations': self.generate_recommendations()
        }
        return report
```

### 3.2. Validation avec Outils DFIR

#### Configuration pour Analyse Forensique
```json
{
  "forensics_research": {
    "artifact_generation": true,
    "artifacts": [
      "registry_modifications",
      "file_system_changes",
      "network_connections", 
      "process_creation_events",
      "memory_artifacts"
    ],
    "timeline_generation": true,
    "ioc_generation": true,
    "persistence_artifacts": true
  }
}
```

---

## 4. Développement de Signatures de Détection

### 4.1. Signatures YARA

#### Génération Automatique
```python
# yara_signature_generator.py
def generate_string_signatures(binary_path):
    """Générer signatures basées sur les chaînes"""
    strings = extract_strings(binary_path)
    
    yara_rule = """
rule BYJY_RwGen_Research_Sample
{
    meta:
        description = "BYJY-RwGen Research Sample"
        author = "Academic Research"
        date = "%s"
    
    strings:
""" % datetime.now().strftime("%Y-%m-%d")
    
    for i, string in enumerate(unique_strings):
        if len(string) > 8 and is_significant(string):
            yara_rule += f'        $s{i} = "{string}"\n'
    
    yara_rule += """
    condition:
        3 of ($s*)
}
"""
    return yara_rule

def generate_behavior_signatures():
    """Générer signatures comportementales"""
    # Basé sur les API calls, patterns réseau, etc.
    pass
```

### 4.2. Règles Suricata

#### Détection DNS Tunneling
```bash
# dns_tunneling.rules
alert dns any any -> any 53 (msg:"RESEARCH: Potential DNS Tunneling - High Frequency Queries"; 
    threshold:type both, track by_src, count 50, seconds 60; 
    reference:research,"BYJY-RwGen DNS Tunneling"; 
    sid:1000001;)

alert dns any any -> any 53 (msg:"RESEARCH: Suspicious DNS Query - Long Subdomain"; 
    dns_query; content:"."; 
    isdataat:50,relative; 
    reference:research,"Long DNS Subdomain"; 
    sid:1000002;)

alert dns any any -> any 53 (msg:"RESEARCH: Base32 Encoded DNS Query"; 
    dns_query; 
    pcre:"/[A-Z2-7]{20,}/"; 
    reference:research,"Base32 DNS Encoding"; 
    sid:1000003;)
```

---

## 5. Validation et Benchmarking

### 5.1. Framework de Test Automatisé

```python
# automated_testing_framework.py
class RansomwareResearchFramework:
    def __init__(self, config_path):
        self.config = self.load_config(config_path)
        self.test_suite = []
        
    def setup_test_environment(self):
        """Préparer environnement de test isolé"""
        self.create_test_vm()
        self.setup_network_isolation()
        self.configure_monitoring()
        
    def run_comprehensive_test_suite(self):
        """Exécuter suite de tests complète"""
        results = {}
        
        # Test 1: Évasion
        results['evasion'] = self.test_evasion_techniques()
        
        # Test 2: Persistance
        results['persistence'] = self.test_persistence_mechanisms()
        
        # Test 3: Chiffrement
        results['encryption'] = self.test_encryption_performance()
        
        # Test 4: C&C
        results['c2'] = self.test_c2_communication()
        
        # Test 5: Détection
        results['detection'] = self.test_av_edr_detection()
        
        return results
    
    def generate_research_report(self, results):
        """Générer rapport de recherche"""
        report = ResearchReport()
        report.add_methodology()
        report.add_results(results)
        report.add_defensive_recommendations()
        report.save_to_file("research_findings.pdf")
```

### 5.2. Métriques de Recherche

#### KPIs Défensifs
```python
DEFENSIVE_RESEARCH_METRICS = {
    'detection_rates': {
        'static_analysis': 'Percentage detected by static analysis',
        'dynamic_analysis': 'Percentage detected by sandbox',
        'behavioral_analysis': 'Percentage detected by EDR'
    },
    'evasion_effectiveness': {
        'sandbox_bypass_rate': 'Success rate bypassing sandboxes',
        'av_bypass_rate': 'Success rate bypassing antivirus',
        'edr_bypass_rate': 'Success rate bypassing EDR'
    },
    'performance_impact': {
        'encryption_speed_mbps': 'File encryption throughput',
        'cpu_usage_percent': 'Average CPU utilization',
        'memory_footprint_mb': 'Memory consumption',
        'disk_io_operations': 'Disk I/O operations per second'
    },
    'network_signatures': {
        'c2_detection_rate': 'C&C communication detection rate',
        'dns_tunnel_signatures': 'Number of effective DNS tunnel signatures',
        'network_anomaly_score': 'Network behavior anomaly score'
    }
}
```

---

## ✅ Validation Finale

L'outil BYJY-RwGen est maintenant complètement configuré et documenté pour la recherche académique défensive. Tous les exemples et configurations fournis permettent une utilisation sécurisée et éthique dans un cadre de recherche en cybersécurité.

**Rappel Important** : Utilisation exclusivement autorisée pour la recherche académique défensive dans des environnements isolés et contrôlés.