<?php
// download.php - File download handler
require_once 'config.php';

if (!isAdmin()) {
    header('HTTP/1.0 403 Forbidden');
    die('Access denied');
}

$file = $_GET['file'] ?? '';
$type = $_GET['type'] ?? 'backup';

if (empty($file)) {
    die('No file specified');
}

// Validate file path
$allowed_dirs = [
    'backup' => BACKUP_DIR,
    'document' => UPLOAD_DIR . 'documents/',
    'profile' => UPLOAD_DIR . 'profiles/'
];

if (!isset($allowed_dirs[$type])) {
    die('Invalid file type');
}

$filepath = $allowed_dirs[$type] . basename($file);

// Security check: ensure file is within allowed directory
$realpath = realpath($filepath);
$allowed_base = realpath($allowed_dirs[$type]);
if (strpos($realpath, $allowed_base) !== 0) {
    die('Invalid file path');
}

if (!file_exists($filepath)) {
    die('File not found');
}

// Set headers for download
header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . filesize($filepath));

// Clear output buffer
flush();
readfile($filepath);
exit;