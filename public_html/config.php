<?php
// config.php - Database configuration and core functions
// Place this file outside web root for security

// ============================================
// SECURITY CONFIGURATION
// ============================================
define('APP_ROOT', dirname(__DIR__)); // Adjust based on your structure
define('CONFIG_DIR', __DIR__);

// Disable error display in production, enable logging
define('ENVIRONMENT', 'development'); // Change to 'production' in live

if (ENVIRONMENT === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

ini_set('log_errors', 1);
ini_set('error_log', APP_ROOT . '/logs/php_errors.log');

// ============================================
// DATABASE CONFIGURATION (MySQL on Hostinger)
// ============================================
define('DB_HOST', 'localhost');
define('DB_NAME', 'target2030');
define('DB_USER', 'djyoti2030');
define('DB_PASS', 'Pass@1234');
define('DB_CHARSET', 'utf8mb4');
define('DB_PORT', 3306);

// ============================================
// APPLICATION CONSTANTS
// ============================================
define('UPLOAD_DIR', APP_ROOT . '/uploads/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
define('ALLOWED_TYPES', ['pdf', 'txt', 'doc', 'docx', 'csv', 'md', 'rtf', 'xls', 'xlsx', 'ppt', 'pptx']);
define('IMAGE_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('SESSION_LIFETIME', 24 * 60 * 60); // 24 hours
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 15 * 60); // 15 minutes
define('API_RATE_LIMIT', 100); // Requests per hour
define('PASSWORD_MIN_LENGTH', 8);
define('TOKEN_EXPIRY', 3600); // 1 hour

// ============================================
// FILE PATHS
// ============================================
define('TEMPLATES_DIR', APP_ROOT . '/templates/');
define('LOGS_DIR', APP_ROOT . '/logs/');
define('CACHE_DIR', APP_ROOT . '/cache/');
define('BACKUP_DIR', APP_ROOT . '/backups/');

// ============================================
// SECURITY FUNCTIONS
// ============================================

/**
 * Generate cryptographically secure token
 */
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

/**
 * Generate secure password hash
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

/**
 * Validate password strength
 */
function validatePassword($password) {
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        return "Password must be at least " . PASSWORD_MIN_LENGTH . " characters long";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        return "Password must contain at least one uppercase letter";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        return "Password must contain at least one lowercase letter";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        return "Password must contain at least one number";
    }
    
    if (!preg_match('/[\W_]/', $password)) {
        return "Password must contain at least one special character";
    }
    
    return true;
}

/**
 * Sanitize input data
 */
function sanitize($input, $type = 'string') {
    if (is_array($input)) {
        return array_map('sanitize', $input);
    }
    
    $input = trim($input);
    
    switch ($type) {
        case 'email':
            $input = filter_var($input, FILTER_SANITIZE_EMAIL);
            break;
        case 'url':
            $input = filter_var($input, FILTER_SANITIZE_URL);
            break;
        case 'int':
            $input = filter_var($input, FILTER_SANITIZE_NUMBER_INT);
            break;
        case 'float':
            $input = filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
            break;
        case 'string':
        default:
            $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
            break;
    }
    
    return $input;
}

/**
 * Validate email format
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

/**
 * Get client IP address
 */
function getClientIP() {
    $headers = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];
    
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip_list = explode(',', $_SERVER[$header]);
            foreach ($ip_list as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }
    
    return '0.0.0.0';
}

/**
 * Check if IP is blocked
 */
function isIPBlocked($ip) {
    $db = getDBConnection();
    $stmt = $db->prepare("SELECT COUNT(*) FROM ip_blocks WHERE ip_address = ? AND expires_at > NOW()");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $result = $stmt->get_result();
    $count = $result->fetch_array()[0];
    $stmt->close();
    
    return $count > 0;
}

// ============================================
// DATABASE CONNECTION
// ============================================

/**
 * Get database connection
 */
function getDBConnection() {
    static $db = null;
    
    if ($db === null || !$db->ping()) {
        try {
            $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
            
            if ($db->connect_error) {
                throw new Exception("MySQL Connection failed: " . $db->connect_error);
            }
            
            $db->set_charset(DB_CHARSET);
            
            // Set timezone
            $db->query("SET time_zone = '+00:00'");
            
        } catch (Exception $e) {
            error_log("Database connection error: " . $e->getMessage());
            
            // Try to create database if it doesn't exist
            if ($e->getCode() == 1049) {
                try {
                    $temp_db = new mysqli(DB_HOST, DB_USER, DB_PASS, '', DB_PORT);
                    $temp_db->query("CREATE DATABASE IF NOT EXISTS " . DB_NAME . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    $temp_db->select_db(DB_NAME);
                    $db = $temp_db;
                    $db->set_charset(DB_CHARSET);
                    return $db;
                } catch (Exception $create_error) {
                    // Continue to throw original error
                }
            }
            
            // In production, show user-friendly message
            if (ENVIRONMENT === 'production') {
                die("Database connection failed. Please try again later.");
            } else {
                die("Database connection failed: " . $e->getMessage());
            }
        }
    }
    
    return $db;
}

/**
 * Initialize database structure
 */
function initDatabase() {
    $db = getDBConnection();
    
    try {
        // Create tables if they don't exist
        $tables = [
            'users' => "CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE,
                phone VARCHAR(20),
                user_type VARCHAR(20) NOT NULL DEFAULT 'user',
                full_name VARCHAR(255),
                department VARCHAR(100),
                profile_image VARCHAR(255),
                reset_token VARCHAR(64),
                reset_expiry DATETIME,
                two_factor_secret VARCHAR(255),
                two_factor_enabled TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                last_password_change DATETIME,
                is_active TINYINT(1) DEFAULT 1,
                failed_login_attempts INT DEFAULT 0,
                lockout_until DATETIME,
                preferences TEXT,
                INDEX idx_user_type (user_type),
                INDEX idx_username (username),
                INDEX idx_email (email),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'documents' => "CREATE TABLE IF NOT EXISTS documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                title VARCHAR(255),
                description TEXT,
                filepath VARCHAR(500) NOT NULL,
                thumbnail VARCHAR(255),
                file_type VARCHAR(50) NOT NULL,
                file_size INT,
                checksum VARCHAR(64),
                category VARCHAR(100),
                tags TEXT,
                content_text TEXT,
                processed TINYINT(1) DEFAULT 0,
                uploaded_by INT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending',
                is_deleted TINYINT(1) DEFAULT 0,
                version INT DEFAULT 1,
                INDEX idx_processed (processed),
                INDEX idx_uploaded_by (uploaded_by),
                INDEX idx_is_deleted (is_deleted),
                INDEX idx_status (status),
                INDEX idx_category (category),
                FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'knowledge_base' => "CREATE TABLE IF NOT EXISTS knowledge_base (
                id INT AUTO_INCREMENT PRIMARY KEY,
                document_id INT,
                title VARCHAR(255),
                content_chunk TEXT NOT NULL,
                chunk_hash VARCHAR(32) UNIQUE,
                metadata TEXT,
                importance INT DEFAULT 1,
                vector_embedding TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP NULL,
                INDEX idx_chunk_hash (chunk_hash),
                INDEX idx_document_id (document_id),
                INDEX idx_importance (importance),
                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'chat_sessions' => "CREATE TABLE IF NOT EXISTS chat_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id VARCHAR(100) UNIQUE NOT NULL,
                user_id INT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                device_type VARCHAR(50),
                country VARCHAR(50),
                language VARCHAR(10) DEFAULT 'en',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                message_count INT DEFAULT 0,
                INDEX idx_ip_address (ip_address),
                INDEX idx_started_at (started_at),
                INDEX idx_user_id (user_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'chat_messages' => "CREATE TABLE IF NOT EXISTS chat_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id VARCHAR(100) NOT NULL,
                message_type VARCHAR(20) NOT NULL,
                content TEXT NOT NULL,
                response_options TEXT,
                selected_option INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_session_id (session_id),
                INDEX idx_created_at (created_at),
                INDEX idx_session_type (session_id, message_type),
                FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'ai_training' => "CREATE TABLE IF NOT EXISTS ai_training (
                id INT AUTO_INCREMENT PRIMARY KEY,
                question TEXT NOT NULL,
                question_hash VARCHAR(32) UNIQUE,
                category VARCHAR(100),
                tags TEXT,
                difficulty VARCHAR(20) DEFAULT 'medium',
                requires_context TINYINT(1) DEFAULT 0,
                context_example TEXT,
                response1 TEXT NOT NULL,
                response2 TEXT NOT NULL,
                response3 TEXT NOT NULL,
                custom_response TEXT,
                best_response INT DEFAULT 1,
                is_custom TINYINT(1) DEFAULT 0,
                trained_by INT,
                trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                usage_count INT DEFAULT 0,
                helpful_count INT DEFAULT 0,
                not_helpful_count INT DEFAULT 0,
                INDEX idx_question_hash (question_hash),
                INDEX idx_trained_by (trained_by),
                INDEX idx_helpful_count (helpful_count),
                INDEX idx_category (category),
                FOREIGN KEY (trained_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'system_logs' => "CREATE TABLE IF NOT EXISTS system_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                log_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) DEFAULT 'info',
                message TEXT NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                request_url VARCHAR(500),
                user_id INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_log_type (log_type),
                INDEX idx_created_at (created_at),
                INDEX idx_user_id (user_id),
                INDEX idx_severity (severity)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'api_keys' => "CREATE TABLE IF NOT EXISTS api_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                api_key VARCHAR(64) UNIQUE NOT NULL,
                name VARCHAR(100),
                domain VARCHAR(255) NOT NULL,
                user_id INT,
                is_active TINYINT(1) DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                usage_count INT DEFAULT 0,
                rate_limit INT DEFAULT 100,
                INDEX idx_api_key (api_key),
                INDEX idx_domain (domain),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'response_ratings' => "CREATE TABLE IF NOT EXISTS response_ratings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                message_id INT,
                session_id VARCHAR(100) NOT NULL,
                user_id INT,
                question TEXT NOT NULL,
                response TEXT NOT NULL,
                rating TINYINT(1) NOT NULL COMMENT '1=helpful, 0=not helpful',
                feedback TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_session_id (session_id),
                INDEX idx_rating (rating),
                INDEX idx_message_id (message_id),
                INDEX idx_user_id (user_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'ip_blocks' => "CREATE TABLE IF NOT EXISTS ip_blocks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                reason VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                INDEX idx_ip_address (ip_address),
                INDEX idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'user_sessions' => "CREATE TABLE IF NOT EXISTS user_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                session_token VARCHAR(64) UNIQUE NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                INDEX idx_user_id (user_id),
                INDEX idx_session_token (session_token),
                INDEX idx_expires_at (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'audit_logs' => "CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(100) NOT NULL,
                entity_type VARCHAR(50),
                entity_id INT,
                old_value TEXT,
                new_value TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_action (action),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        ];
        
        foreach ($tables as $table => $sql) {
            $db->query($sql);
        }
        
        // Create default admin user if not exists
        $check = $db->query("SELECT COUNT(*) as count FROM users WHERE username = 'admin'");
        $result = $check->fetch_assoc();
        
        if ($result['count'] == 0) {
            $stmt = $db->prepare("INSERT INTO users (username, password_hash, user_type, full_name, email, is_active) 
                                  VALUES (?, ?, 'admin', 'Administrator', ?, 1)");
            $stmt->bind_param("sss", 
                $username, 
                $password_hash, 
                $email
            );
            
            $username = 'admin';
            $password_hash = hashPassword('Admin@123');
            $email = 'admin@example.com';
            $stmt->execute();
            $stmt->close();
            
            logEvent('system', 'Default admin account created', null, 'info');
        }
        
        // Create necessary directories
        createDirectories();
        
        return $db;
        
    } catch (Exception $e) {
        error_log("Database initialization failed: " . $e->getMessage());
        logEvent('error', "Database initialization failed: " . $e->getMessage(), null, 'critical');
        
        if (ENVIRONMENT === 'production') {
            die("System initialization failed. Please contact administrator.");
        } else {
            die("Database initialization failed: " . $e->getMessage());
        }
    }
}

// ============================================
// LOGGING FUNCTIONS
// ============================================

/**
 * Log system events
 */
function logEvent($type, $message, $userId = null, $severity = 'info', $details = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO system_logs (log_type, severity, message, details, ip_address, request_url, user_id) 
                              VALUES (?, ?, ?, ?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("ssssssi", 
                $type, 
                $severity, 
                $message, 
                $details,
                $ip, 
                $request_url,
                $userId
            );
            
            $ip = getClientIP();
            $request_url = $_SERVER['REQUEST_URI'] ?? '';
            $stmt->execute();
            $stmt->close();
        }
    } catch (Exception $e) {
        // Fallback to file logging if database fails
        $log_message = date('[Y-m-d H:i:s]') . " [$severity] [$type] $message";
        if ($userId) $log_message .= " UserID: $userId";
        if ($details) $log_message .= " Details: $details";
        error_log($log_message);
    }
}

/**
 * Log audit trail
 */
function auditLog($action, $entityType = null, $entityId = null, $oldValue = null, $newValue = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO audit_logs (user_id, action, entity_type, entity_id, old_value, new_value, ip_address, user_agent) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("issiisss",
            $userId,
            $action,
            $entityType,
            $entityId,
            $oldValue,
            $newValue,
            $ip,
            $userAgent
        );
        
        $userId = $_SESSION['user_id'] ?? null;
        $ip = getClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $stmt->execute();
        $stmt->close();
    } catch (Exception $e) {
        error_log("Audit log failed: " . $e->getMessage());
    }
}

// ============================================
// DIRECTORY MANAGEMENT
// ============================================

/**
 * Create necessary directories
 */
function createDirectories() {
    $directories = [
        UPLOAD_DIR,
        UPLOAD_DIR . 'documents/',
        UPLOAD_DIR . 'profiles/',
        UPLOAD_DIR . 'temp/',
        UPLOAD_DIR . 'backups/',
        LOGS_DIR,
        CACHE_DIR,
        BACKUP_DIR
    ];
    
    foreach ($directories as $dir) {
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
            // Create .htaccess for security
            if (strpos($dir, 'uploads') !== false) {
                file_put_contents($dir . '.htaccess', 
                    "Order deny,allow\nDeny from all\n<FilesMatch \"\.(jpg|jpeg|png|gif|pdf|txt)$\">\nAllow from all\n</FilesMatch>");
            }
        }
    }
    
    // Create index.html in each directory to prevent directory listing
    $index_html = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Access Forbidden</h1></body></html>';
    foreach ($directories as $dir) {
        if (!file_exists($dir . 'index.html')) {
            file_put_contents($dir . 'index.html', $index_html);
        }
    }
}

// ============================================
// SESSION MANAGEMENT
// ============================================

/**
 * Start secure session
 */
function startSecureSession() {
    // Use cookies only
    ini_set('session.use_only_cookies', 1);
    ini_set('session.use_strict_mode', 1);
    
    // Set session cookie parameters
    session_set_cookie_params([
        'lifetime' => SESSION_LIFETIME,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? '',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    
    // Set session name
    session_name('AI_CHAT_SESSION');
    
    // Start session
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // Regenerate session ID periodically
    if (!isset($_SESSION['last_regeneration'])) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    } elseif (time() - $_SESSION['last_regeneration'] > 1800) { // 30 minutes
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

// ============================================
// FILE UPLOAD FUNCTIONS
// ============================================

/**
 * Validate uploaded file
 */
function validateUploadedFile($file, $allowedTypes = ALLOWED_TYPES) {
    $errors = [];
    
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $uploadErrors = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive in php.ini',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE directive in HTML form',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'File upload stopped by extension'
        ];
        $errors[] = $uploadErrors[$file['error']] ?? 'Unknown upload error';
        return [false, $errors];
    }
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        $errors[] = 'File too large (max ' . (MAX_FILE_SIZE / (1024*1024)) . 'MB)';
    }
    
    // Check file type
    $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_ext, $allowedTypes)) {
        $errors[] = 'File type not allowed. Allowed: ' . implode(', ', $allowedTypes);
    }
    
    // Check for malicious files (simple check)
    $dangerous_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'html', 'htm', 'js'];
    if (in_array($file_ext, $dangerous_extensions) && !in_array($file_ext, $allowedTypes)) {
        $errors[] = 'Potentially dangerous file type';
    }
    
    // Check MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowed_mimes = [
        'pdf' => 'application/pdf',
        'txt' => 'text/plain',
        'doc' => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'csv' => 'text/csv',
        'md' => 'text/markdown',
        'rtf' => 'application/rtf',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif'
    ];
    
    if (isset($allowed_mimes[$file_ext]) && $allowed_mimes[$file_ext] !== $mime_type) {
        $errors[] = 'File MIME type does not match extension';
    }
    
    return [empty($errors), $errors];
}

/**
 * Generate safe filename
 */
function generateSafeFilename($original_name) {
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
    $basename = preg_replace('/[^a-zA-Z0-9_-]/', '_', pathinfo($original_name, PATHINFO_FILENAME));
    $basename = substr($basename, 0, 100); // Limit length
    return time() . '_' . $basename . '.' . $extension;
}

/**
 * Calculate file checksum
 */
function calculateFileChecksum($filepath) {
    return hash_file('sha256', $filepath);
}

// ============================================
// MISSING TEXT EXTRACTION FUNCTIONS
// ============================================

/**
 * Extract text from Excel files
 */
function extractTextFromExcel($filepath) {
    if (!class_exists('ZipArchive')) {
        return "Excel file uploaded. For text extraction, please convert to CSV or TXT format.";
    }
    
    $content = '';
    
    try {
        // For XLSX files (ZIP-based)
        $zip = new ZipArchive;
        if ($zip->open($filepath) === TRUE) {
            // Look for shared strings
            if (($index = $zip->locateName('xl/sharedStrings.xml')) !== FALSE) {
                $xml_content = $zip->getFromIndex($index);
                // Extract text from XML
                $xml = simplexml_load_string($xml_content);
                if ($xml) {
                    foreach ($xml->children() as $si) {
                        $content .= $si->t . ' ';
                    }
                }
            }
            $zip->close();
        }
    } catch (Exception $e) {
        // Fallback message
        $content = "Excel file uploaded. Content extracted partially. For better results, save as CSV.";
    }
    
    if (empty($content)) {
        $content = "Excel file processed. To extract all text, please save as CSV format.";
    }
    
    return $content;
}

/**
 * Extract text from PowerPoint files
 */
function extractTextFromPowerPoint($filepath) {
    if (!class_exists('ZipArchive')) {
        return "PowerPoint file uploaded. For text extraction, please save as PDF or TXT.";
    }
    
    $content = '';
    
    try {
        $zip = new ZipArchive;
        if ($zip->open($filepath) === TRUE) {
            // Look for slide content
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $filename = $zip->getNameIndex($i);
                if (preg_match('/ppt\/slides\/slide\d+\.xml/', $filename)) {
                    $xml_content = $zip->getFromIndex($i);
                    // Simple XML extraction
                    $xml_content = preg_replace('/<[^>]+>/', ' ', $xml_content);
                    $xml_content = preg_replace('/\s+/', ' ', $xml_content);
                    $content .= $xml_content . ' ';
                }
            }
            $zip->close();
        }
    } catch (Exception $e) {
        $content = "PowerPoint file uploaded. Text extraction limited.";
    }
    
    if (empty($content)) {
        $content = "PowerPoint file uploaded. For full text extraction, save as PDF or export text.";
    }
    
    return $content;
}

// ============================================
// MISSING SYSTEM FUNCTIONS
// ============================================

/**
 * Check write permissions for all directories
 */
function checkWritePermissions() {
    $directories = [
        UPLOAD_DIR,
        UPLOAD_DIR . 'documents/',
        UPLOAD_DIR . 'profiles/',
        UPLOAD_DIR . 'temp/',
        LOGS_DIR,
        CACHE_DIR
    ];
    
    $errors = [];
    foreach ($directories as $dir) {
        if (!is_writable($dir)) {
            $errors[] = "Directory not writable: $dir";
        }
    }
    
    return $errors;
}

/**
 * Backup database
 */
function backupDatabase() {
    $db = getDBConnection();
    $backup_file = BACKUP_DIR . 'backup_' . date('Y-m-d_H-i-s') . '.sql';
    
    try {
        $tables = [];
        $result = $db->query('SHOW TABLES');
        while ($row = $result->fetch_row()) {
            $tables[] = $row[0];
        }
        
        $sql = "-- Database Backup\n";
        $sql .= "-- Generated: " . date('Y-m-d H:i:s') . "\n\n";
        
        foreach ($tables as $table) {
            // Drop table if exists
            $sql .= "DROP TABLE IF EXISTS `$table`;\n";
            
            // Create table
            $create = $db->query("SHOW CREATE TABLE `$table`");
            $row = $create->fetch_row();
            $sql .= $row[1] . ";\n\n";
            
            // Insert data
            $result = $db->query("SELECT * FROM `$table`");
            if ($result->num_rows > 0) {
                $sql .= "INSERT INTO `$table` VALUES\n";
                $rows = [];
                while ($row = $result->fetch_row()) {
                    $values = array_map(function($value) use ($db) {
                        if ($value === null) return 'NULL';
                        return "'" . $db->real_escape_string($value) . "'";
                    }, $row);
                    $rows[] = "(" . implode(', ', $values) . ")";
                }
                $sql .= implode(",\n", $rows) . ";\n\n";
            }
        }
        
        file_put_contents($backup_file, $sql);
        logEvent('backup', 'Database backup created: ' . basename($backup_file));
        
        return [true, 'Backup created successfully', basename($backup_file)];
    } catch (Exception $e) {
        logEvent('error', 'Backup failed: ' . $e->getMessage());
        return [false, 'Backup failed: ' . $e->getMessage()];
    }
}

/**
 * Get system information
 */
function getSystemInfo() {
    $info = [
        'php_version' => PHP_VERSION,
        'mysql_version' => 'N/A',
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'post_max_size' => ini_get('post_max_size'),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'disk_free_space' => disk_free_space(__DIR__),
        'disk_total_space' => disk_total_space(__DIR__),
        'server_time' => date('Y-m-d H:i:s'),
        'timezone' => date_default_timezone_get()
    ];
    
    try {
        $db = getDBConnection();
        $result = $db->query('SELECT VERSION() as version');
        $row = $result->fetch_assoc();
        $info['mysql_version'] = $row['version'] ?? 'N/A';
    } catch (Exception $e) {
        // Ignore
    }
    
    return $info;
}


// ============================================
// INITIALIZE SYSTEM
// ============================================

// Start session
startSecureSession();

// Initialize database
$db = initDatabase();

// Test write permissions
if (!is_writable(UPLOAD_DIR)) {
    logEvent('error', 'Upload directory not writable: ' . UPLOAD_DIR, null, 'critical');
    if (ENVIRONMENT === 'development') {
        die("Upload directory not writable. Please check permissions for: " . UPLOAD_DIR);
    }
}
// ============================================
// SYSTEM INITIALIZATION CHECKS
// ============================================

/**
 * Check for required PHP extensions
 */
function checkPHPExtensions() {
    $required = [
        'mysqli' => 'MySQL database support',
        'json' => 'JSON data handling',
        'mbstring' => 'Multibyte string support',
        'zip' => 'ZIP archive handling (for DOCX files)',
        'gd' => 'Image processing (for profile images)',
        'fileinfo' => 'File type detection'
    ];
    
    $missing = [];
    foreach ($required as $ext => $description) {
        if (!extension_loaded($ext)) {
            $missing[] = "$ext ($description)";
        }
    }
    
    return $missing;
}

/**
 * Check directory permissions
 */
function checkDirectoryPermissions() {
    $directories = [
        UPLOAD_DIR => 'File uploads',
        UPLOAD_DIR . 'documents/' => 'Document storage',
        UPLOAD_DIR . 'profiles/' => 'Profile images',
        UPLOAD_DIR . 'temp/' => 'Temporary files',
        LOGS_DIR => 'System logs',
        CACHE_DIR => 'Cache files',
        BACKUP_DIR => 'Backup storage'
    ];
    
    $errors = [];
    foreach ($directories as $dir => $purpose) {
        if (!file_exists($dir)) {
            if (!@mkdir($dir, 0755, true)) {
                $errors[] = "Cannot create directory: $dir ($purpose)";
            }
        } elseif (!is_writable($dir)) {
            $errors[] = "Directory not writable: $dir ($purpose)";
        }
    }
    
    return $errors;
}

/**
 * Check database structure
 */
function checkDatabaseStructure() {
    $db = getDBConnection();
    $errors = [];
    
    $required_tables = [
        'users', 'documents', 'knowledge_base', 'chat_sessions', 
        'chat_messages', 'ai_training', 'system_logs', 'api_keys', 
        'response_ratings'
    ];
    
    try {
        $result = $db->query("SHOW TABLES");
        $existing_tables = [];
        while ($row = $result->fetch_array()) {
            $existing_tables[] = $row[0];
        }
        
        foreach ($required_tables as $table) {
            if (!in_array($table, $existing_tables)) {
                $errors[] = "Missing table: $table";
            }
        }
        
        // Check for required columns in users table
        if (in_array('users', $existing_tables)) {
            $result = $db->query("DESCRIBE users");
            $columns = [];
            while ($row = $result->fetch_assoc()) {
                $columns[] = $row['Field'];
            }
            
            $required_columns = ['id', 'username', 'password_hash', 'user_type', 'is_active'];
            foreach ($required_columns as $column) {
                if (!in_array($column, $columns)) {
                    $errors[] = "Missing column in users table: $column";
                }
            }
        }
        
    } catch (Exception $e) {
        $errors[] = "Database structure check failed: " . $e->getMessage();
    }
    
    return $errors;
}

/**
 * Check PHP configuration
 */
function checkPHPConfiguration() {
    $errors = [];
    
    $required_settings = [
        'upload_max_filesize' => '10M',
        'post_max_size' => '10M',
        'max_execution_time' => '30',
        'memory_limit' => '128M'
    ];
    
    foreach ($required_settings as $setting => $min_value) {
        $current = ini_get($setting);
        
        // Convert to bytes for comparison
        $current_bytes = return_bytes($current);
        $min_bytes = return_bytes($min_value);
        
        if ($current_bytes < $min_bytes) {
            $errors[] = "PHP setting $setting is $current (minimum $min_value required)";
        }
    }
    
    return $errors;
}

/**
 * Convert shorthand byte values to bytes
 */
function return_bytes($val) {
    $val = trim($val);
    $last = strtolower($val[strlen($val)-1]);
    $val = (int)$val;
    
    switch($last) {
        case 'g':
            $val *= 1024 * 1024 * 1024;
            break;
        case 'm':
            $val *= 1024 * 1024;
            break;
        case 'k':
            $val *= 1024;
            break;
    }
    
    return $val;
}

/**
 * Perform comprehensive system check
 */
function performSystemCheck() {
    $all_errors = [];
    $warnings = [];
    
    // 1. Check PHP extensions
    $missing_extensions = checkPHPExtensions();
    if (!empty($missing_extensions)) {
        $all_errors[] = "Missing PHP extensions: " . implode(', ', $missing_extensions);
    }
    
    // 2. Check directory permissions
    $permission_errors = checkDirectoryPermissions();
    if (!empty($permission_errors)) {
        $all_errors = array_merge($all_errors, $permission_errors);
    }
    
    // 3. Check PHP configuration
    $config_errors = checkPHPConfiguration();
    if (!empty($config_errors)) {
        $warnings = array_merge($warnings, $config_errors);
    }
    
    // 4. Check database connection
    try {
        $db = getDBConnection();
        if (!$db->ping()) {
            $all_errors[] = "Database connection is unstable";
        } else {
            // 5. Check database structure
            $db_errors = checkDatabaseStructure();
            if (!empty($db_errors)) {
                $all_errors = array_merge($all_errors, $db_errors);
            }
        }
    } catch (Exception $e) {
        $all_errors[] = "Database connection failed: " . $e->getMessage();
    }
    
    // 6. Check if default admin exists
    try {
        $db = getDBConnection();
        $result = $db->query("SELECT COUNT(*) as count FROM users WHERE username = 'admin'");
        $row = $result->fetch_assoc();
        if ($row['count'] == 0) {
            $warnings[] = "Default admin account not found";
        }
    } catch (Exception $e) {
        // Ignore - database might not be ready yet
    }
    
    // 7. Check for SSL/HTTPS (warning only)
    if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
        $warnings[] = "Site is not using HTTPS (recommended for security)";
    }
    
    return [
        'errors' => $all_errors,
        'warnings' => $warnings,
        'passed' => empty($all_errors)
    ];
}

/**
 * Run system check and log results
 */
function runSystemChecks() {
    if (ENVIRONMENT === 'production' && !isset($_SESSION['system_checks_run'])) {
        // Only run once per session in production
        $_SESSION['system_checks_run'] = true;
        $checks = performSystemCheck();
        
        if (!empty($checks['errors'])) {
            logEvent('system', 'System check errors: ' . implode('; ', $checks['errors']), null, 'critical');
        }
        
        if (!empty($checks['warnings'])) {
            logEvent('system', 'System warnings: ' . implode('; ', $checks['warnings']), null, 'warning');
        }
        
        if ($checks['passed']) {
            logEvent('system', 'System checks passed', null, 'info');
        }
        
        return $checks;
    } elseif (ENVIRONMENT === 'development') {
        // Always run in development
        return performSystemCheck();
    }
    
    return ['errors' => [], 'warnings' => [], 'passed' => true];
}

/**
 * Display system check results (development only)
 */
function displaySystemCheckResults() {
    if (ENVIRONMENT !== 'development') {
        return;
    }
    
    $checks = performSystemCheck();
    
    if (!empty($checks['errors']) || !empty($checks['warnings'])) {
        echo '<div style="position: fixed; bottom: 10px; right: 10px; z-index: 9999; max-width: 400px; background: white; border: 2px solid #dc3545; border-radius: 5px; padding: 15px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">';
        echo '<h4 style="margin-top: 0; color: #dc3545;">System Check Results</h4>';
        
        if (!empty($checks['errors'])) {
            echo '<div style="color: #dc3545; margin-bottom: 10px;">';
            echo '<strong>Errors:</strong><ul style="margin: 5px 0; padding-left: 20px;">';
            foreach ($checks['errors'] as $error) {
                echo "<li>$error</li>";
            }
            echo '</ul></div>';
        }
        
        if (!empty($checks['warnings'])) {
            echo '<div style="color: #ffc107; margin-bottom: 10px;">';
            echo '<strong>Warnings:</strong><ul style="margin: 5px 0; padding-left: 20px;">';
            foreach ($checks['warnings'] as $warning) {
                echo "<li>$warning</li>";
            }
            echo '</ul></div>';
        }
        
        if ($checks['passed'] && empty($checks['errors'])) {
            echo '<div style="color: #28a745;"><strong>✓ All system checks passed</strong></div>';
        }
        
        echo '</div>';
    }
}

// ============================================
// RUN SYSTEM CHECKS ON STARTUP
// ============================================

// Initialize database first
$db = initDatabase();

// Run system checks
$system_checks = runSystemChecks();

// Display results in development mode
if (ENVIRONMENT === 'development' && (isset($_GET['debug']) || !empty($system_checks['errors']))) {
    register_shutdown_function('displaySystemCheckResults');
}

// Log if there are critical errors
if (!empty($system_checks['errors'])) {
    $error_count = count($system_checks['errors']);
    logEvent('system', "System initialization completed with $error_count errors", null, 'critical');
} elseif (!empty($system_checks['warnings'])) {
    $warning_count = count($system_checks['warnings']);
    logEvent('system', "System initialization completed with $warning_count warnings", null, 'warning');
} else {
    logEvent('system', 'System initialization completed successfully', null, 'info');
}

// Create a system status session variable
$_SESSION['system_status'] = [
    'last_check' => time(),
    'errors' => count($system_checks['errors']),
    'warnings' => count($system_checks['warnings']),
    'passed' => $system_checks['passed']
];

?>

