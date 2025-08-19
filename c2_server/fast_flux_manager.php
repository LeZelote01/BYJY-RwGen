<?php
/**
 * Fast Flux Domain Management System
 * Manages rotating domains and DNS infrastructure for C&C resilience
 * For defensive cybersecurity research purposes only
 */

require_once 'database.php';

class FastFluxManager {
    private $db;
    private $primary_domains;
    private $backup_domains;
    private $dns_servers;
    private $domain_rotation_interval = 3600; // 1 hour
    
    public function __construct() {
        $this->db = new Database();
        $this->loadConfiguration();
    }
    
    private function loadConfiguration() {
        $config_path = '/app/c2_config.json';
        if (file_exists($config_path)) {
            $config = json_decode(file_get_contents($config_path), true);
            $this->primary_domains = [$config['c2_domain']];
            $this->backup_domains = $config['backup_domains'] ?? [];
            $this->dns_servers = $config['dns_servers'] ?? [];
        }
    }
    
    public function generateDomainPool($count = 50) {
        echo "[+] Generating fast-flux domain pool ($count domains)\n";
        
        $domains = [];
        
        // Generate domains using common legitimate-looking patterns
        $legitimate_prefixes = [
            'cdn', 'static', 'assets', 'media', 'content', 'api', 'app',
            'secure', 'update', 'service', 'system', 'windows', 'microsoft',
            'adobe', 'google', 'amazon', 'cloudflare', 'akamai',
            'analytics', 'metrics', 'tracking', 'ads', 'scripts'
        ];
        
        $legitimate_suffixes = [
            'services', 'systems', 'solutions', 'technologies', 'platform',
            'network', 'cloud', 'server', 'hosting', 'domain', 'web',
            'online', 'digital', 'tech', 'data', 'secure', 'pro'
        ];
        
        $tlds = [
            '.com', '.net', '.org', '.info', '.biz', '.co', '.io', '.tech',
            '.online', '.site', '.website', '.store', '.app', '.dev'
        ];
        
        for ($i = 0; $i < $count; $i++) {
            $prefix = $legitimate_prefixes[array_rand($legitimate_prefixes)];
            $suffix = $legitimate_suffixes[array_rand($legitimate_suffixes)];
            $number = rand(1, 999);
            $tld = $tlds[array_rand($tlds)];
            
            // Create variation patterns
            $patterns = [
                "{$prefix}-{$suffix}-{$number}{$tld}",
                "{$prefix}{$number}-{$suffix}{$tld}",
                "{$prefix}-{$suffix}{$tld}",
                "{$prefix}{$suffix}{$number}{$tld}",
                "{$prefix}-{$number}{$tld}",
                "{$suffix}-{$prefix}-{$number}{$tld}"
            ];
            
            $domain = $patterns[array_rand($patterns)];
            
            // Ensure uniqueness
            if (!in_array($domain, $domains)) {
                $domains[] = $domain;
            } else {
                $i--; // Retry
            }
        }
        
        // Store domains in database
        $this->storeDomainPool($domains);
        
        echo "[+] Generated " . count($domains) . " domains\n";
        return $domains;
    }
    
    private function storeDomainPool($domains) {
        try {
            // Create domains table if not exists
            $this->db->db->exec("
                CREATE TABLE IF NOT EXISTS flux_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    status TEXT DEFAULT 'available',
                    ip_address TEXT,
                    last_used DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    burnt BOOLEAN DEFAULT 0,
                    reputation_score INTEGER DEFAULT 100
                )
            ");
            
            $stmt = $this->db->db->prepare("
                INSERT OR IGNORE INTO flux_domains (domain) VALUES (?)
            ");
            
            foreach ($domains as $domain) {
                $stmt->execute([$domain]);
            }
            
        } catch (Exception $e) {
            error_log("Error storing domain pool: " . $e->getMessage());
        }
    }
    
    public function getActiveDomains($limit = 10) {
        $stmt = $this->db->db->prepare("
            SELECT domain, ip_address, reputation_score 
            FROM flux_domains 
            WHERE status = 'active' AND burnt = 0 AND reputation_score > 50
            ORDER BY last_used ASC, reputation_score DESC
            LIMIT ?
        ");
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function rotateDomains() {
        echo "[+] Rotating fast-flux domains\n";
        
        // Get current active domains
        $current_domains = $this->getActiveDomains(20);
        
        // Mark some as burnt if they've been active too long
        $this->burnStaledomains();
        
        // Activate new domains
        $new_domains = $this->activateNewDomains(10);
        
        // Update DNS records
        $this->updateDNSRecords($new_domains);
        
        echo "[+] Domain rotation complete\n";
        return $new_domains;
    }
    
    private function burnStaleDomains() {
        $burn_threshold = time() - (24 * 3600); // 24 hours
        
        $stmt = $this->db->db->prepare("
            UPDATE flux_domains 
            SET status = 'burnt', burnt = 1
            WHERE last_used < ? AND status = 'active'
        ");
        $stmt->execute([date('Y-m-d H:i:s', $burn_threshold)]);
    }
    
    private function activateNewDomains($count) {
        $stmt = $this->db->db->prepare("
            SELECT domain FROM flux_domains 
            WHERE status = 'available' AND burnt = 0
            ORDER BY RANDOM()
            LIMIT ?
        ");
        $stmt->execute([$count]);
        $domains = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        foreach ($domains as $domain) {
            $this->activateDomain($domain);
        }
        
        return $domains;
    }
    
    private function activateDomain($domain) {
        // Generate random IP from bulletproof hosting ranges (simulated)
        $ip_pools = [
            '185.220.', '185.221.', '185.222.', '185.223.',  // Simulated bulletproof IPs
            '194.180.', '194.181.', '194.182.', '194.183.',
            '91.245.', '91.246.', '91.247.', '91.248.',
            '37.139.', '37.140.', '37.141.', '37.142.'
        ];
        
        $ip_base = $ip_pools[array_rand($ip_pools)];
        $ip = $ip_base . rand(1, 254) . '.' . rand(1, 254);
        
        $stmt = $this->db->db->prepare("
            UPDATE flux_domains 
            SET status = 'active', ip_address = ?, last_used = datetime('now')
            WHERE domain = ?
        ");
        $stmt->execute([$ip, $domain]);
        
        echo "[+] Activated domain: $domain -> $ip\n";
    }
    
    private function updateDNSRecords($domains) {
        // In a real scenario, this would update actual DNS records
        // For research purposes, we simulate the process
        echo "[+] Updating DNS records for " . count($domains) . " domains\n";
        
        foreach ($domains as $domain) {
            $this->createDNSRecord($domain);
        }
    }
    
    private function createDNSRecord($domain) {
        // Simulate DNS record creation
        $record_types = ['A', 'CNAME', 'MX'];
        $record_type = $record_types[array_rand($record_types)];
        
        // Log DNS operation
        error_log("DNS Record: $domain -> $record_type (research simulation)");
        
        // Store in database for tracking
        $this->db->db->exec("
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER DEFAULT 300,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ");
        
        $stmt = $this->db->db->prepare("
            INSERT INTO dns_records (domain, record_type, value)
            VALUES (?, ?, ?)
        ");
        
        $value = ($record_type === 'A') ? $this->getRandomIP() : 'redirect.example.com';
        $stmt->execute([$domain, $record_type, $value]);
    }
    
    private function getRandomIP() {
        return rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255);
    }
    
    public function getDomainGenerationAlgorithm($seed, $date = null) {
        if (!$date) {
            $date = date('Y-m-d');
        }
        
        $hash = hash('sha256', $seed . $date);
        $domains = [];
        
        $tlds = ['.com', '.net', '.org', '.info', '.biz'];
        
        // Generate 20 domains for the day
        for ($i = 0; $i < 20; $i++) {
            $chunk = substr($hash, $i * 3, 10);
            $domain_name = '';
            
            // Convert hash chunk to domain name
            for ($j = 0; $j < 8; $j++) {
                $char_code = ord($chunk[$j]) % 26;
                $domain_name .= chr(97 + $char_code); // a-z
            }
            
            $tld = $tlds[$i % count($tlds)];
            $domains[] = $domain_name . $tld;
        }
        
        return $domains;
    }
    
    public function generateBulletproofHostingMap() {
        $hosting_providers = [
            'Research-Hosting-1' => [
                'country' => 'Country-A',
                'ip_ranges' => ['185.220.0.0/16', '194.180.0.0/16'],
                'reputation' => 'research_only',
                'features' => ['DDoS_Protection', 'Anonymous_Registration', 'Bitcoin_Payment']
            ],
            'Research-Hosting-2' => [
                'country' => 'Country-B', 
                'ip_ranges' => ['91.245.0.0/16', '37.139.0.0/16'],
                'reputation' => 'research_only',
                'features' => ['Offshore_Location', 'No_Logs', 'Instant_Setup']
            ],
            'Research-Hosting-3' => [
                'country' => 'Country-C',
                'ip_ranges' => ['185.221.0.0/16', '194.181.0.0/16'],
                'reputation' => 'research_only',
                'features' => ['High_Uptime', 'Multiple_Locations', 'API_Access']
            ]
        ];
        
        return $hosting_providers;
    }
    
    public function getReputationScore($domain) {
        $stmt = $this->db->db->prepare("
            SELECT reputation_score FROM flux_domains WHERE domain = ?
        ");
        $stmt->execute([$domain]);
        return $stmt->fetchColumn() ?: 100;
    }
    
    public function updateReputationScore($domain, $score) {
        $stmt = $this->db->db->prepare("
            UPDATE flux_domains SET reputation_score = ? WHERE domain = ?
        ");
        $stmt->execute([$score, $domain]);
    }
    
    public function generateDomainReport() {
        $report = [
            'total_domains' => 0,
            'active_domains' => 0,
            'burnt_domains' => 0,
            'available_domains' => 0,
            'average_reputation' => 0
        ];
        
        $stmt = $this->db->db->query("
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
                COUNT(CASE WHEN burnt = 1 THEN 1 END) as burnt,
                COUNT(CASE WHEN status = 'available' THEN 1 END) as available,
                AVG(reputation_score) as avg_reputation
            FROM flux_domains
        ");
        
        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $report['total_domains'] = $data['total'];
        $report['active_domains'] = $data['active'];
        $report['burnt_domains'] = $data['burnt'];
        $report['available_domains'] = $data['available'];
        $report['average_reputation'] = round($data['avg_reputation'], 2);
        
        return $report;
    }
}

// CLI usage
if (php_sapi_name() === 'cli') {
    $action = $argv[1] ?? 'help';
    $flux_manager = new FastFluxManager();
    
    switch ($action) {
        case 'generate':
            $count = intval($argv[2] ?? 50);
            $domains = $flux_manager->generateDomainPool($count);
            echo "Generated " . count($domains) . " domains\n";
            break;
            
        case 'rotate':
            $new_domains = $flux_manager->rotateDomains();
            echo "Rotated to " . count($new_domains) . " new domains\n";
            break;
            
        case 'report':
            $report = $flux_manager->generateDomainReport();
            echo "Domain Pool Report:\n";
            echo "Total: {$report['total_domains']}\n";
            echo "Active: {$report['active_domains']}\n";
            echo "Burnt: {$report['burnt_domains']}\n"; 
            echo "Available: {$report['available_domains']}\n";
            echo "Avg Reputation: {$report['average_reputation']}\n";
            break;
            
        case 'dga':
            $seed = $argv[2] ?? 'research_seed_2024';
            $domains = $flux_manager->getDomainGenerationAlgorithm($seed);
            echo "DGA Domains for today:\n";
            foreach ($domains as $domain) {
                echo "- $domain\n";
            }
            break;
            
        case 'hosting':
            $hosting = $flux_manager->generateBulletproofHostingMap();
            echo "Research Hosting Providers:\n";
            foreach ($hosting as $name => $info) {
                echo "- $name: {$info['country']} ({$info['reputation']})\n";
            }
            break;
            
        default:
            echo "Fast Flux Manager - Academic Research Tool\n";
            echo "Usage: php fast_flux_manager.php <command> [options]\n\n";
            echo "Commands:\n";
            echo "  generate [count]  Generate domain pool (default: 50)\n";
            echo "  rotate           Rotate active domains\n";
            echo "  report           Show domain statistics\n";
            echo "  dga [seed]       Show DGA domains for today\n";
            echo "  hosting          Show hosting provider map\n";
            break;
    }
}
?>