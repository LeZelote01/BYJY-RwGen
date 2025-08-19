# BYJY-RwGen - Analyse Complète des Fichiers de Configuration

## 📋 ÉNUMÉRATION EXHAUSTIVE DES FICHIERS DE CONFIGURATION

---

## 1. FICHIERS DE CONFIGURATION PRINCIPAUX

### 1.1. **build_config.json** 
**Localisation** : `/app/build_config.json`
**Utilisé par** : 
- `builders/windows_builder.py` (classe `AdvancedWindowsBuilder.__init__()`)
- `master_builder.py` (méthode `load_configs()`)

**Utilisation exacte dans le code** :
```python
# builders/windows_builder.py ligne 15-16
def __init__(self, config_file="build_config.json"):
    self.config = self.load_config(config_file)

# Accès aux paramètres :
self.config["source_dir"]              # Répertoire source
self.config["output_dir"]              # Répertoire sortie  
self.config["main_executable"]         # Nom exécutable
self.config["target_architecture"]     # Architecture
self.config["compiler_flags"]          # Flags compilation
self.config["linker_flags"]            # Flags linkage
self.config["obfuscation_level"]       # Niveau obfuscation
self.config["enable_anti_analysis"]    # Anti-analyse
self.config["pack_executable"]         # Empaquetage
self.config["inject_dll"]              # Injection DLL
self.config["sign_binary"]             # Signature binaire
```

**Impact fonctionnel** :
- Contrôle compilation (flags, architecture)
- Définit niveau obfuscation (low/medium/high)
- Active/désactive anti-analyse
- Configure injection DLL et signature

---

### 1.2. **c2_config.json**
**Localisation** : `/app/c2_config.json`
**Utilisé par** :
- `command_control/dns_tunneling/dns_exfil.py` (classe `StealthyDNSTunnel.__init__()`)
- `master_builder.py` (génération ransom note)

**Utilisation exacte dans le code** :
```python
# command_control/dns_tunneling/dns_exfil.py ligne 16-24
def __init__(self, c2_domain, encryption_key, mode="exfil"):
    self.c2_domain = c2_domain                    # Depuis c2_config.json
    self.encryption_key = encryption_key[:32]      # Clé C&C
    self.chunk_size = 30                          # Taille chunks DNS
    self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # DNS servers

# Paramètres utilisés :
config["c2_domain"]                    # Domaine principal C&C
config["backup_domains"]               # Domaines secours
config["dns_servers"]                  # Serveurs DNS
config["communication"]["chunk_size"]   # Taille fragments
config["communication"]["poll_interval"] # Intervalle polling
config["encryption_key"]               # Clé chiffrement C&C
config["exfiltration"]["targets"]      # Fichiers à exfiltrer
config["ransom_note"]                  # Configuration note rançon
```

**Impact fonctionnel** :
- Configure communication DNS tunneling
- Définit domaines C&C et backup
- Paramètre chiffrement communications
- Configure exfiltration automatique

---

### 1.3. **payload_config.json**
**Localisation** : `/app/payload_config.json`
**Utilisé par** :
- `src/main.cpp` (compilation avec paramètres intégrés)
- `core_engine/encryption/file_handler.cpp` (paramètres chiffrement)
- `core_engine/persistence/windows/registry_hook.cpp` (persistance)

**Utilisation exacte dans le code** :
```cpp
// Paramètres intégrés à la compilation dans src/main.cpp
const char* RESEARCH_ID = "DEFENSIVE-CYBER-2024";
const bool RESEARCH_MODE = true;

// core_engine/encryption/file_handler.cpp utilise :
config["encryption"]["threads"]              // Nombre threads chiffrement
config["encryption"]["chunk_size"]           // Taille chunks fichiers
config["encryption"]["secure_delete_passes"] // Passes effacement sécurisé

// core_engine/persistence/windows/registry_hook.cpp utilise :
config["persistence"]["service_name"]        // Nom service Windows
config["persistence"]["task_name"]          // Nom tâche planifiée
config["persistence"]["methods"]            // Méthodes persistance
```

**Impact fonctionnel** :
- Contrôle performance chiffrement (threads, chunks)
- Configure vérifications anti-analyse
- Définit méthodes de persistance
- Paramètre comportement UI

---

### 1.4. **linux_build.conf**
**Localisation** : `/app/linux_build.conf`
**Utilisé par** :
- `builders/linux_builder.sh` (script bash, ligne 7-21)
- `master_builder.py` (méthode `parse_bash_config()`)

**Utilisation exacte dans le code** :
```bash
# builders/linux_builder.sh lit directement :
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"           # Charge toutes variables
    
# Variables utilisées :
SRC_DIR="src"                      # Répertoire source
OUT_DIR="dist"                     # Répertoire sortie
TARGET_ARCH="x86_64"               # Architecture cible
OBFUSCATION_LEVEL="high"           # Niveau obfuscation
ENABLE_ANTI_ANALYSIS=1             # Anti-analyse
CFLAGS="-O3 -fno-stack-protector"  # Flags compilation
LDFLAGS="-s -Wl,--gc-sections"     # Flags linkage
```

**Impact fonctionnel** :
- Configure compilation Linux/cross-compilation
- Définit architecture cible
- Paramètre obfuscation LLVM
- Configure flags optimisation

---

## 2. FICHIERS DE CONFIGURATION SECONDAIRES

### 2.1. **resources/config.json**
**Localisation** : `/app/resources/config.json`
**Utilisé par** : Intégré comme ressource dans l'exécutable final
**Contenu** :
```json
{
  "research_mode": true,
  "study_id": "DEFENSIVE-CYBER-2024",
  "encryption_key": "RESEARCH_KEY_PLACEHOLDER",
  "target_extensions": [".txt", ".doc", ".pdf"],
  "contact": "security-research@university.edu"
}
```

### 2.2. **requirements.txt**
**Localisation** : `/app/requirements.txt`
**Utilisé par** : Installation automatique des dépendances Python
**Impact** : Définit versions exactes cryptography, dnspython, requests, psutil

---

## 3. UTILISATION DYNAMIQUE DES CONFIGURATIONS

### 3.1. **Chaîne de chargement Master Builder**
```python
# master_builder.py - load_configs()
config_files = {
    'build': 'build_config.json',      → AdvancedWindowsBuilder
    'c2': 'c2_config.json',            → StealthyDNSTunnel  
    'payload': 'payload_config.json'   → Payload runtime
}
```

### 3.2. **Intégration à la compilation**
```python
# master_builder.py - generate_main_source()
# Intègre paramètres directement dans le code C++
encryption_key = config["build"]["encryption"]["key"]
target_extensions = config["build"]["target_extensions"] 
excluded_paths = config["build"]["excluded_paths"]
```

### 3.3. **Runtime payload**
```cpp
// src/main.cpp utilise paramètres compilés :
std::string encryption_key = "CONFIGURED_KEY_FROM_BUILD";
std::vector<std::string> extensions = {CONFIG_EXTENSIONS};
```

---

## 4. FLUX DE DONNÉES CONFIGURATION

```
build_config.json
    ↓
windows_builder.py → Compilation avec paramètres
    ↓
payload.exe (paramètres intégrés)
    ↓
Exécution runtime avec c2_config.json + payload_config.json
```

---

## 5. POINTS CRITIQUES DE CONFIGURATION

### 5.1. **Sécurité Cryptographique**
- `build_config.json["encryption"]["key_derivation"]` → Force Argon2ID
- `c2_config.json["encryption_key"]` → Clé 256-bit C&C
- `payload_config.json["encryption"]["verify_integrity"]` → Vérification intégrité

### 5.2. **Techniques d'Évasion**
- `build_config.json["obfuscation_level"]` → Active passes LLVM
- `payload_config.json["execution"]["check_sandbox"]` → Détection VM
- `build_config.json["enable_anti_analysis"]` → Injection anti-debug

### 5.3. **Performance vs Détection**
- `payload_config.json["encryption"]["threads"]` → Plus threads = plus rapide mais plus visible
- `c2_config.json["communication"]["poll_interval"]` → Plus court = plus réactif mais détectable
- `payload_config.json["execution"]["delay_start"]` → Évite détection heuristique

---

**TOTAL** : 4 fichiers configuration principaux + 2 secondaires = **6 fichiers de configuration** utilisés par l'outil BYJY-RwGen.