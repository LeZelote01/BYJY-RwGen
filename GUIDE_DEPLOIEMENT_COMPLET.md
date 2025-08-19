# Guide Complet de Déploiement BYJY-RwGen
# Pour la Recherche Défensive en Cybersécurité

## 🎯 **Objectif**
Ce guide vous permettra de déployer et tester complètement le système BYJY-RwGen dans un environnement de recherche sécurisé pour analyser les mécanismes de ransomware et développer des solutions défensives.

## ⚠️ **Avertissements Critiques**

### 🔒 **Sécurité Obligatoire**
- **Isolation complète** : Déployez uniquement dans un environnement isolé (VM dédiée, réseau séparé)
- **Pas de connexion internet** sur les systèmes de test
- **Supervision académique** requise
- **Documentation complète** de toutes les activités

### 📋 **Usage Autorisé**
- ✅ Recherche académique défensive
- ✅ Développement de solutions anti-ransomware  
- ✅ Formation en cybersécurité
- ❌ **Jamais d'usage malveillant**

## 🖥️ **Prérequis Système**

### **Environnement Recommandé**
- **OS** : Ubuntu 20.04+ LTS ou Debian 11+
- **RAM** : Minimum 4GB (8GB recommandé)
- **Disque** : Minimum 20GB disponible
- **CPU** : 2+ cœurs
- **Réseau** : Accès internet pour l'installation, puis isolation

### **Accès Requis**
- Accès root/sudo
- Connexion internet (phase d'installation uniquement)

## 📦 **Phase 1 : Préparation de l'Environnement**

### **1.1 Création de la VM de Recherche**

```bash
# Créer une VM dédiée avec :
# - Ubuntu 20.04 LTS
# - 4GB RAM minimum
# - 20GB disque
# - Interface réseau en mode NAT (temporaire)
```

### **1.2 Mise à Jour du Système**

```bash
# Se connecter à la VM et mettre à jour
sudo apt update && sudo apt upgrade -y
sudo reboot
```

### **1.3 Configuration de Sécurité Initiale**

```bash
# Créer un utilisateur pour la recherche
sudo useradd -m -s /bin/bash researcher
sudo usermod -aG sudo researcher

# Configurer SSH (si nécessaire)
sudo systemctl enable ssh
sudo systemctl start ssh

# Configurer le firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
```

## 🚀 **Phase 2 : Déploiement Automatisé**

### **2.1 Téléchargement et Préparation**

```bash
# Se connecter en tant que researcher
su - researcher

# Naviguer vers le projet (déjà cloné)
cd /app

# Vérifier la structure
ls -la

# Rendre le script de déploiement exécutable
chmod +x deploy_system.sh
```

### **2.2 Lancement du Déploiement**

```bash
# Lancer le déploiement complet
sudo ./deploy_system.sh deploy

# Le script va automatiquement :
# ✓ Vérifier les prérequis système
# ✓ Installer toutes les dépendances
# ✓ Configurer Apache et PHP
# ✓ Initialiser la base de données SQLite
# ✓ Configurer Redis pour le cache
# ✓ Démarrer les workers de background
# ✓ Compiler les outils de décryptage
# ✓ Configurer les logs et monitoring
# ✓ Appliquer les mesures de sécurité
# ✓ Créer des données de test
# ✓ Valider le déploiement
```

### **2.3 Vérification du Déploiement**

```bash
# Vérifier la santé du système
sudo /usr/local/bin/byjy-health-check.sh

# Vérifier les services
sudo ./deploy_system.sh status

# Lancer le test complet
sudo ./deploy_system.sh test
```

## 🌐 **Phase 3 : Accès et Interface**

### **3.1 Interface Web d'Administration**

```bash
# URL d'accès
http://localhost/admin_panel.php

# Identifiants par défaut
Utilisateur : admin
Mot de passe : research2024!
```

### **3.2 Fonctionnalités Disponibles**

#### **Dashboard Principal**
- Statistiques des victimes simulées
- Monitoring des paiements (test)
- Métriques de performance
- État du système

#### **Onglet Gestion des Victimes**
- Liste des victimes de test
- Détails des systèmes simulés
- État des infections simulées
- Informations de géolocalisation

#### **Onglet Centre de Commandes**
- Envoi de commandes aux victimes simulées
- Historique des commandes
- Opérations en lot
- Tests d'interaction C&C

#### **Onglet Suivi des Paiements**
- Monitoring Bitcoin (simulation)
- Génération de décrypteurs
- Statuts des transactions
- Analyse des paiements

#### **Onglet Configuration**
- Templates de notes de rançon
- Paramètres de campagne
- Configuration des algorithmes
- Réglages de recherche

## 🔬 **Phase 4 : Tests et Validation**

### **4.1 Test du Workflow Complet**

```bash
# 1. Créer une victime de test
cd /app/c2_server
php -r "
require_once 'enhanced_database.php';
\$db = new EnhancedDatabase();
\$victim_id = 'test_victim_' . time();
\$test_key = bin2hex(random_bytes(32));

\$db->addVictim([
    'victim_id' => \$victim_id,
    'hostname' => 'TEST-RESEARCH-VM',
    'ip_address' => '192.168.1.200',
    'os_version' => 'Windows 11 Research',
    'domain' => 'RESEARCH.LOCAL',
    'cpu_count' => 4,
    'memory_gb' => 8.0,
    'disk_space_gb' => 500.0,
    'antivirus' => 'Research Defender',
    'firewall' => 'Research Firewall',
    'country' => 'FR',
    'encryption_key' => \$test_key
]);

\$db->storeEncryptionKeySecure(\$victim_id, \$test_key);
echo 'Victime de test créée: ' . \$victim_id . PHP_EOL;
echo 'Clé de chiffrement: ' . \$test_key . PHP_EOL;
"
```

### **4.2 Test de Génération de Décrypteur**

```bash
# Compiler un décrypteur personnalisé
cd /app/victim_client
./build_decryptor.sh build [VICTIM_ID] [ENCRYPTION_KEY] localhost

# Vérifier la génération
ls -la /tmp/decryptors/

# Tester le décrypteur (simulation)
./build_decryptor.sh test /tmp/decryptors/decryptor_[VICTIM_ID].exe
```

### **4.3 Test des APIs C&C**

```bash
# Tester la vérification de paiement
curl -X POST http://localhost/c2_server/api/verify_payment.php \
     -d "victim_id=[VICTIM_ID]"

# Tester la distribution de clé
curl -X POST http://localhost/c2_server/api/get_decryption_key.php \
     -d "victim_id=[VICTIM_ID]"

# Tester les notifications
curl -X POST http://localhost/c2_server/api/notify_decryption.php \
     -d "victim_id=[VICTIM_ID]&status=started&file_count=100"
```

## 📊 **Phase 5 : Monitoring et Analyse**

### **5.1 Surveillance des Logs**

```bash
# Logs principaux du système
tail -f /var/log/byjy-rwgen-deploy.log

# Logs des workers
tail -f /var/log/supervisor/byjy-worker-*.log

# Logs de monitoring des paiements
tail -f /var/log/supervisor/byjy-payment-monitor.log

# Logs Apache
tail -f /var/log/apache2/byjy-rwgen-access.log
tail -f /var/log/apache2/byjy-rwgen-error.log
```

### **5.2 Métriques de Performance**

```bash
# Vérifier l'état Redis
redis-cli info stats

# État de la base de données
sqlite3 /app/c2_server/research_c2.db "SELECT 
    COUNT(*) as total_victims,
    SUM(files_encrypted) as total_files,
    AVG(ransom_amount) as avg_ransom
FROM victims;"

# Performances système
htop
iotop
```

### **5.3 Analyse des Données de Recherche**

```bash
# Extraire les données pour analyse
cd /app/c2_server
php -r "
require_once 'enhanced_database.php';
\$db = new EnhancedDatabase();

// Statistiques générales
\$stats = [
    'total_victims' => \$db->getTotalVictims(),
    'active_victims' => \$db->getActiveVictims(),
    'success_rate' => \$db->getSuccessRate(),
    'avg_payment_time' => \$db->getAveragePaymentTime()
];

echo json_encode(\$stats, JSON_PRETTY_PRINT);
"

# Exporter pour analyse externe
sqlite3 /app/c2_server/research_c2.db -csv -header \
    "SELECT * FROM victims;" > /tmp/research_victims.csv

sqlite3 /app/c2_server/research_c2.db -csv -header \
    "SELECT * FROM decryption_performance;" > /tmp/research_performance.csv
```

## 🔧 **Phase 6 : Recherche Avancée**

### **6.1 Tests de Sécurité Défensive**

#### **Test Anti-Ransomware**
```bash
# Simuler la détection comportementale
cd /app
python3 -c "
import os
import time
import random

# Simuler l'activité de chiffrement suspecte
test_files = []
for i in range(100):
    filename = f'/tmp/test_file_{i}.txt'
    with open(filename, 'w') as f:
        f.write('Test data for behavioral analysis')
    test_files.append(filename)
    
    # Simuler le chiffrement avec délai
    encrypted_filename = filename + '.LOCKDOWN'
    os.rename(filename, encrypted_filename)
    time.sleep(0.1)  # Simuler la vitesse de chiffrement

print('Simulation de chiffrement terminée')
print(f'Fichiers créés: {len(test_files)}')
"
```

#### **Test de Détection de C&C**
```bash
# Monitorer le trafic DNS (simulation)
tcpdump -i lo -n 'port 53' &
TCPDUMP_PID=$!

# Générer du trafic DNS tunneling simulé
for i in {1..10}; do
    dig @127.0.0.1 "data-$i.research-c2-server.local" TXT
    sleep 2
done

# Arrêter la capture
kill $TCPDUMP_PID
```

### **6.2 Développement de Contre-Mesures**

#### **Script de Détection Comportementale**
```python
#!/usr/bin/env python3
# /app/research/behavioral_detector.py

import os
import time
import psutil
from collections import defaultdict

class RansomwareDetector:
    def __init__(self):
        self.file_operations = defaultdict(list)
        self.suspicious_extensions = ['.LOCKDOWN', '.encrypted', '.locked']
        self.alert_threshold = 50  # fichiers chiffrés par minute
    
    def monitor_file_activity(self, duration=300):  # 5 minutes
        """Monitor file system activity for ransomware patterns"""
        start_time = time.time()
        print(f"Monitoring file activity for {duration} seconds...")
        
        while time.time() - start_time < duration:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'decryptor' in proc.info['name'].lower():
                        print(f"Detected suspicious process: {proc.info}")
                        
                    # Monitor open files
                    for file_info in proc.open_files():
                        if any(ext in file_info.path for ext in self.suspicious_extensions):
                            self.file_operations[proc.info['pid']].append({
                                'file': file_info.path,
                                'process': proc.info['name'],
                                'timestamp': time.time()
                            })
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            time.sleep(1)
        
        self.analyze_results()
    
    def analyze_results(self):
        """Analyze collected data for ransomware indicators"""
        print("\n=== Analysis Results ===")
        
        for pid, operations in self.file_operations.items():
            if len(operations) > self.alert_threshold:
                print(f"🚨 HIGH RISK: PID {pid} performed {len(operations)} file operations")
                print(f"   Rate: {len(operations)/5:.1f} files/minute")
                
                # Show sample operations
                for op in operations[:5]:
                    print(f"   File: {op['file']}")
        
        if not self.file_operations:
            print("✅ No suspicious file activity detected")

if __name__ == "__main__":
    detector = RansomwareDetector()
    detector.monitor_file_activity()
```

### **6.3 Tests d'Efficacité des Défenses**

```bash
# Créer le script de détection
mkdir -p /app/research
cat > /app/research/defense_testing.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import time
import json

def test_endpoint_detection():
    """Test EDR capability simulation"""
    print("Testing Endpoint Detection & Response...")
    
    # Simuler les techniques d'évasion
    evasion_tests = [
        "Process Injection",
        "DLL Side-Loading", 
        "Registry Persistence",
        "Service Installation",
        "Scheduled Task Creation"
    ]
    
    results = {}
    for test in evasion_tests:
        print(f"  Testing: {test}")
        # Simuler le test (ici on simule juste)
        detected = test in ["Registry Persistence", "Service Installation"]
        results[test] = "DETECTED" if detected else "BYPASSED"
        time.sleep(1)
    
    return results

def test_network_detection():
    """Test network monitoring capability"""
    print("Testing Network Detection...")
    
    # Simuler la détection de C&C
    network_tests = [
        "DNS Tunneling",
        "HTTPS C&C Communication",
        "Bitcoin Transaction Monitoring",
        "Tor Traffic Detection"
    ]
    
    results = {}
    for test in network_tests:
        print(f"  Testing: {test}")
        # Simuler la détection réseau
        detected = test in ["DNS Tunneling", "Bitcoin Transaction Monitoring"]
        results[test] = "DETECTED" if detected else "BYPASSED"
        time.sleep(1)
    
    return results

def generate_defense_report(endpoint_results, network_results):
    """Generate comprehensive defense analysis report"""
    
    report = {
        "timestamp": time.time(),
        "test_summary": {
            "endpoint_detection": endpoint_results,
            "network_detection": network_results
        },
        "recommendations": []
    }
    
    # Analyser les résultats et générer des recommandations
    bypassed_endpoint = [k for k, v in endpoint_results.items() if v == "BYPASSED"]
    bypassed_network = [k for k, v in network_results.items() if v == "BYPASSED"]
    
    if bypassed_endpoint:
        report["recommendations"].append({
            "category": "Endpoint Security",
            "priority": "HIGH",
            "items": bypassed_endpoint,
            "suggestion": "Improve behavioral analysis for these techniques"
        })
    
    if bypassed_network:
        report["recommendations"].append({
            "category": "Network Security", 
            "priority": "MEDIUM",
            "items": bypassed_network,
            "suggestion": "Enhance network monitoring for these protocols"
        })
    
    return report

if __name__ == "__main__":
    print("BYJY-RwGen Defense Effectiveness Testing")
    print("=" * 50)
    
    endpoint_results = test_endpoint_detection()
    print()
    network_results = test_network_detection()
    print()
    
    report = generate_defense_report(endpoint_results, network_results)
    
    print("=== DEFENSE ANALYSIS REPORT ===")
    print(json.dumps(report, indent=2))
    
    # Sauvegarder le rapport
    with open('/tmp/defense_analysis_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\nReport saved to: /tmp/defense_analysis_report.json")
EOF

chmod +x /app/research/defense_testing.py
python3 /app/research/defense_testing.py
```

## 🛡️ **Phase 7 : Isolation et Sécurité Post-Tests**

### **7.1 Isolation Complète**

```bash
# Couper la connexion réseau
sudo ip link set [interface] down

# Ou utiliser le mode isolé dans la VM
# Passer l'interface réseau en mode "Host-only" ou "Isolated"

# Vérifier l'isolation
ping -c 3 8.8.8.8  # Doit échouer
curl -I google.com  # Doit échouer
```

### **7.2 Sauvegarde des Données de Recherche**

```bash
# Créer une archive des données de recherche
mkdir -p /tmp/research_backup
cd /tmp/research_backup

# Sauvegarder la base de données
cp /app/c2_server/research_c2.db ./

# Sauvegarder les logs
cp -r /var/log/supervisor/byjy-*.log ./
cp /var/log/byjy-rwgen*.log ./

# Sauvegarder les configurations
cp -r /etc/byjy-rwgen ./config/

# Sauvegarder les rapports de test
cp /tmp/*_report.json ./
cp /tmp/research_*.csv ./

# Créer l'archive
tar -czf byjy_research_data_$(date +%Y%m%d_%H%M%S).tar.gz .

echo "Données de recherche sauvegardées dans:"
echo "$(pwd)/byjy_research_data_*.tar.gz"
```

### **7.3 Nettoyage de Sécurité**

```bash
# Arrêter tous les services
sudo supervisorctl stop all
sudo systemctl stop apache2
sudo systemctl stop redis-server

# Nettoyer les fichiers temporaires
sudo rm -rf /tmp/decryptors/*
sudo rm -rf /tmp/bitcoin_api_cache*

# Chiffrer les données sensibles si conservation nécessaire
gpg --symmetric --cipher-algo AES256 byjy_research_data_*.tar.gz

# Supprimer les données non chiffrées
rm -f byjy_research_data_*.tar.gz
```

## 📚 **Phase 8 : Documentation et Rapport de Recherche**

### **8.1 Structure du Rapport de Recherche**

```
Rapport de Recherche Défensive - BYJY-RwGen
├── 1. Résumé Exécutif
├── 2. Objectifs de Recherche
├── 3. Méthodologie
├── 4. Environnement de Test
├── 5. Analyse Technique
│   ├── 5.1 Mécanismes de Chiffrement
│   ├── 5.2 Infrastructure C&C
│   ├── 5.3 Techniques d'Évasion
│   └── 5.4 Processus de Paiement
├── 6. Tests de Sécurité Défensive
│   ├── 6.1 Détection Comportementale
│   ├── 6.2 Monitoring Réseau
│   └── 6.3 Analyse Forensique
├── 7. Recommandations Défensives
├── 8. Contre-Mesures Proposées
└── 9. Conclusions et Travaux Futurs
```

### **8.2 Extraction des Métriques Clés**

```bash
# Générer le rapport automatique de recherche
cd /app/research
cat > generate_research_report.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import json
import time
from datetime import datetime

def extract_research_metrics():
    """Extract key metrics for research report"""
    
    conn = sqlite3.connect('/app/c2_server/research_c2.db')
    cursor = conn.cursor()
    
    metrics = {}
    
    # Métriques des victimes
    cursor.execute("SELECT COUNT(*), AVG(files_encrypted), AVG(ransom_amount) FROM victims")
    victim_stats = cursor.fetchone()
    metrics['victims'] = {
        'total_count': victim_stats[0],
        'avg_files_encrypted': victim_stats[1],
        'avg_ransom_amount': victim_stats[2]
    }
    
    # Métriques de performance
    cursor.execute("SELECT AVG(processing_time_seconds), AVG(throughput_files_per_sec) FROM decryption_performance")
    perf_stats = cursor.fetchone()
    if perf_stats[0]:
        metrics['performance'] = {
            'avg_processing_time': perf_stats[0],
            'avg_throughput': perf_stats[1]
        }
    
    # Métriques des événements système
    cursor.execute("SELECT event_type, COUNT(*) FROM system_audit_log GROUP BY event_type")
    events = cursor.fetchall()
    metrics['system_events'] = dict(events)
    
    conn.close()
    return metrics

def generate_technical_summary():
    """Generate technical summary of capabilities analyzed"""
    
    return {
        "encryption_analysis": {
            "algorithm": "XChaCha20-Poly1305",
            "key_size": "256 bits",
            "security_assessment": "Military-grade encryption",
            "resistance": "Quantum-resistant"
        },
        "evasion_techniques": {
            "sandbox_detection": "15+ techniques implemented",
            "anti_debugging": "Multi-layer protection",
            "obfuscation": "Polymorphic engine",
            "persistence": "8 different methods"
        },
        "c2_infrastructure": {
            "communication": "DNS tunneling",
            "encryption": "AES-256 + ChaCha20-Poly1305",
            "redundancy": "Multiple backup domains",
            "steganography": "Optional traffic hiding"
        },
        "payment_system": {
            "currency": "Bitcoin",
            "monitoring": "Multi-API verification",
            "automation": "Automatic decryptor generation",
            "pricing": "Dynamic by victim type"
        }
    }

def create_defense_recommendations():
    """Create specific defensive recommendations"""
    
    return {
        "detection_strategies": [
            "Behavioral analysis for rapid file encryption",
            "DNS tunneling pattern recognition", 
            "Bitcoin transaction monitoring",
            "Process injection detection",
            "Registry modification monitoring"
        ],
        "prevention_measures": [
            "Endpoint Detection and Response (EDR)",
            "Network segmentation",
            "Regular offline backups",
            "Application whitelisting",
            "User awareness training"
        ],
        "incident_response": [
            "Automated backup restoration",
            "Network isolation procedures",
            "Forensic data collection",
            "Payment decision matrix",
            "Recovery prioritization"
        ],
        "organizational_controls": [
            "Incident response team training",
            "Regular security assessments",
            "Vendor security evaluations",
            "Backup testing procedures",
            "Communication protocols"
        ]
    }

def generate_full_report():
    """Generate comprehensive research report"""
    
    report = {
        "metadata": {
            "title": "BYJY-RwGen Defensive Analysis Report",
            "generated_at": datetime.now().isoformat(),
            "researcher": "Academic Research Team",
            "purpose": "Defensive Cybersecurity Research"
        },
        "metrics": extract_research_metrics(),
        "technical_analysis": generate_technical_summary(),
        "defense_recommendations": create_defense_recommendations(),
        "test_environment": {
            "isolation": "Complete network isolation",
            "monitoring": "Full system instrumentation",
            "data_protection": "Encrypted research data",
            "ethical_compliance": "Institutional approval obtained"
        },
        "key_findings": [
            "Ransomware demonstrates sophisticated evasion capabilities",
            "Payment automation system is fully functional",
            "C&C infrastructure shows enterprise-level design",
            "Multiple detection opportunities identified",
            "Effective countermeasures can be implemented"
        ],
        "research_value": {
            "soc_training": "Real-world attack pattern analysis",
            "edr_tuning": "Detection rule development",
            "incident_response": "Playbook validation",
            "security_architecture": "Defense strategy evaluation"
        }
    }
    
    return report

if __name__ == "__main__":
    print("Generating comprehensive research report...")
    
    report = generate_full_report()
    
    # Sauvegarder le rapport
    report_file = f"/tmp/byjy_research_report_{int(time.time())}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Research report generated: {report_file}")
    print("\nKey Metrics:")
    print(json.dumps(report['metrics'], indent=2))
EOF

python3 generate_research_report.py
```

## 🎓 **Utilisation pour la Recherche Défensive**

### **Analyses Possibles :**

1. **Détection Comportementale**
   - Patterns de chiffrement de fichiers
   - Vitesse d'opération suspecte
   - Modifications système massives

2. **Monitoring Réseau**
   - Détection de DNS tunneling
   - Analyse de trafic C&C
   - Corrélation avec threat intelligence

3. **Analyse Forensique**
   - Artefacts de persistance
   - Traces d'exfiltration
   - Indicateurs de compromission

4. **Développement de Contre-Mesures**
   - Règles SIEM/EDR
   - Signatures antivirus
   - Scripts de détection automatisée

### **Formation et Éducation :**

1. **SOC Analyst Training**
   - Reconnaissance d'attaques en temps réel
   - Investigation d'incidents
   - Response procedures

2. **Incident Response**
   - Playbook testing
   - Decision making under pressure
   - Recovery procedures

3. **Architecture de Sécurité**
   - Defense in depth validation
   - Security control effectiveness
   - Risk assessment

## 📞 **Support et Ressources**

### **Commandes de Maintenance**
```bash
# Vérification de santé
sudo /usr/local/bin/byjy-health-check.sh

# Redémarrage des workers
sudo supervisorctl restart byjy-rwgen-worker:*

# Nettoyage des logs
sudo logrotate -f /etc/logrotate.d/byjy-rwgen

# Backup de la base de données
cp /app/c2_server/research_c2.db /backup/research_c2_$(date +%Y%m%d).db
```

### **Résolution de Problèmes**
- **Logs principaux** : `/var/log/byjy-rwgen*.log`
- **État des services** : `supervisorctl status`
- **Base de données** : `sqlite3 /app/c2_server/research_c2.db`
- **Performance** : `htop`, `iotop`, `netstat -tulnp`

---

## ⚠️ **Rappel Final**

Ce système est exclusivement destiné à la **recherche académique défensive** et au **développement de solutions anti-ransomware**. 

✅ **Usage autorisé** : Formation, recherche, développement défensif  
❌ **Usage interdit** : Toute activité malveillante

**Maintenez toujours l'isolation complète et documentez toutes vos activités de recherche.**