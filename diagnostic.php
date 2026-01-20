<?php
require_once '/home/engine/project/public_html/default.php';

$functions = [
    'getSetting',
    'checkRateLimit',
    'filterContent',
    'saveDeviceFingerprint',
    'generateCSRFToken',
    'validateCSRFToken'
];

echo "=== FUNCTION VALIDATION ===\n";
foreach ($functions as $function) {
    if (function_exists($function)) {
        echo "✓ $function - EXISTS\n";
    } else {
        echo "✗ $function - MISSING\n";
    }
}

echo "\n=== DATABASE TABLE VALIDATION ===\n";
$tables = [
    'admin_settings',
    'rate_limits',
    'csrf_tokens',
    'device_fingerprints',
    'ai_response_reports',
    'response_corrections',
    'response_versions',
    'response_cache',
    'ip_blocks'
];

try {
    $db = getDBConnection();
    foreach ($tables as $table) {
        $result = $db->query("SHOW TABLES LIKE '$table'");
        if ($result && $result->num_rows > 0) {
            echo "✓ $table - EXISTS\n";
        } else {
            echo "✗ $table - MISSING\n";
        }
    }
} catch (Exception $e) {
    echo "Database error: " . $e->getMessage() . "\n";
}

echo "\n=== BACKUP SYSTEM CHECK ===\n";
$backupPath = '/home/engine/project/public_html/backup.php';
$backupContent = file_get_contents($backupPath);
if (strpos($backupContent, 'DB_HOST') !== false || strpos($backupContent, 'localhost') !== false) {
    echo "✗ backup.php - Has hardcoded credentials\n";
} else {
    echo "✓ backup.php - Using .env.php\n";
}

echo "\n=== MOBILE-FIRST CHECK ===\n";
echo "Checking for viewport meta tag...\n";
$defaultContent = file_get_contents('/home/engine/project/public_html/default.php');
if (strpos($defaultContent, 'viewport') !== false) {
    echo "✓ Found viewport meta tag\n";
} else {
    echo "✗ Missing viewport meta tag\n";
}

echo "\n=== COMMENT CHECK ===\n";
$commentCount = substr_count($defaultContent, '//');
$blockCommentCount = preg_match_all('/\/\*(.|\n)*?\*\//', $defaultContent);
echo "Line comments: $commentCount\n";
echo "Block comments: $blockCommentCount\n";

echo "\n=== DIAGNOSTIC COMPLETE ===\n";
?>