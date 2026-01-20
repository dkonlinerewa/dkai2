<?php

define('APP_ROOT', dirname(__DIR__));
define('CONFIG_DIR', __DIR__);

define('CONFIG_LOADED', true);
if (file_exists(APP_ROOT . '/.env.php')) {
    require_once APP_ROOT . '/.env.php';
} else {
    die('Configuration file not found. Please create .env.php');
}

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

define('UPLOAD_DIR', APP_ROOT . '/uploads/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024);
define('ALLOWED_TYPES', ['pdf', 'txt', 'doc', 'docx', 'csv', 'md', 'rtf', 'xls', 'xlsx', 'ppt', 'pptx']);
define('IMAGE_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('SESSION_LIFETIME', 24 * 60 * 60);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 15 * 60);
define('API_RATE_LIMIT', 100);
define('PASSWORD_MIN_LENGTH', 8);
define('TOKEN_EXPIRY', 3600);

define('TEMPLATES_DIR', APP_ROOT . '/templates/');
define('LOGS_DIR', APP_ROOT . '/logs/');
define('CACHE_DIR', APP_ROOT . '/cache/');
define('BACKUP_DIR', APP_ROOT . '/backups/');

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

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

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

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

function getSetting($key, $default = null) {
    $db = getDBConnection();
    $stmt = $db->prepare("SELECT setting_value, setting_type FROM admin_settings WHERE setting_key = ?");
    $stmt->bind_param("s", $key);
    $stmt->execute();
    $result = $stmt->get_result();
    $setting = $result->fetch_assoc();
    $stmt->close();
    
    if (!$setting) {
        return $default;
    }
    
    $value = $setting['setting_value'];
    
    switch ($setting['setting_type']) {
        case 'boolean':
            return $value === '1' || $value === true;
        case 'integer':
            return (int)$value;
        case 'float':
            return (float)$value;
        case 'json':
            return json_decode($value, true) ?? $default;
        default:
            return $value;
    }
}

function checkRateLimit($identifier, $identifierType = 'session') {
    if (!getSetting('rate_limit_enabled', true)) {
        return [true, 0, 0];
    }
    
    $db = getDBConnection();
    $window = getSetting('rate_limit_window', 3600);
    $maxRequests = getSetting('rate_limit_requests', 100);
    
    $db->begin_transaction();
    try {
        $stmt = $db->prepare("SELECT limit_id, request_count, window_start, blocked_until FROM rate_limits 
                             WHERE identifier = ? AND identifier_type = ? FOR UPDATE");
        $stmt->bind_param("ss", $identifier, $identifierType);
        $stmt->execute();
        $result = $stmt->get_result();
        $rateLimit = $result->fetch_assoc();
        $stmt->close();
        
        $now = date('Y-m-d H:i:s');
        $windowStart = date('Y-m-d H:i:s', time() - $window);
        
        if ($rateLimit) {
            if ($rateLimit['blocked_until'] && $rateLimit['blocked_until'] > $now) {
                $db->commit();
                return [false, 0, strtotime($rateLimit['blocked_until']) - time()];
            }
            
            if ($rateLimit['window_start'] < $windowStart) {
                $stmt = $db->prepare("UPDATE rate_limits SET request_count = 1, window_start = NOW(), last_request = NOW() 
                                     WHERE limit_id = ?");
                $stmt->bind_param("i", $rateLimit['limit_id']);
                $stmt->execute();
                $stmt->close();
                $currentCount = 1;
            } else {
                $stmt = $db->prepare("UPDATE rate_limits SET request_count = request_count + 1, last_request = NOW() 
                                     WHERE limit_id = ?");
                $stmt->bind_param("i", $rateLimit['limit_id']);
                $stmt->execute();
                $stmt->close();
                $currentCount = $rateLimit['request_count'] + 1;
            }
        } else {
            $stmt = $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, request_count, window_start, last_request) 
                                 VALUES (?, ?, 1, NOW(), NOW())");
            $stmt->bind_param("ss", $identifier, $identifierType);
            $stmt->execute();
            $stmt->close();
            $currentCount = 1;
        }
        
        if ($currentCount > $maxRequests) {
            $blockDuration = 3600;
            $stmt = $db->prepare("UPDATE rate_limits SET blocked_until = DATE_ADD(NOW(), INTERVAL ? SECOND) 
                                 WHERE identifier = ? AND identifier_type = ?");
            $stmt->bind_param("iss", $blockDuration, $identifier, $identifierType);
            $stmt->execute();
            $stmt->close();
            $db->commit();
            return [false, $currentCount, $blockDuration];
        }
        
        $db->commit();
        return [true, $currentCount, 0];
        
    } catch (Exception $e) {
        $db->rollback();
        error_log("Rate limit check failed: " . $e->getMessage());
        return [true, 0, 0];
    }
}

function filterContent($content) {
    if (!getSetting('content_filtering_enabled', true)) {
        return $content;
    }
    
    $spamPatterns = [
        '/\b(viagra|cialis|levitra|pharmacy|pills|drugs)\b/i',
        '/\b(earn money|make cash|work from home|get rich)\b/i',
        '/\b(casino|gambling|betting|lottery|jackpot)\b/i',
        '/\b(sex|porn|xxx|nude|adult)\b/i',
        '/<script[^>]*>.*?<\/script>/is',
        '/<iframe[^>]*>.*?<\/iframe>/is',
        '/<object[^>]*>.*?<\/object>/is',
        '/javascript:/i'
    ];
    
    foreach ($spamPatterns as $pattern) {
        $content = preg_replace($pattern, '[filtered]', $content);
    }
    
    return $content;
}

function saveDeviceFingerprint($userId = null) {
    if (!getSetting('device_fingerprinting_enabled', true)) {
        return null;
    }
    
    $fingerprintData = [
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'ip' => getClientIP(),
        'sr' => $_COOKIE['screen_resolution'] ?? '',
        'tz' => $_COOKIE['timezone'] ?? '',
        'lang' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        'platform' => $_COOKIE['platform'] ?? ''
    ];
    
    $fingerprintString = implode('|', array_values($fingerprintData));
    $fingerprintHash = hash('sha256', $fingerprintString);
    
    $db = getDBConnection();
    $stmt = $db->prepare("INSERT INTO device_fingerprints 
                         (user_id, fingerprint_hash, user_agent, ip_address, screen_resolution, timezone, language, platform) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?) 
                         ON DUPLICATE KEY UPDATE last_seen = NOW()");
    $stmt->bind_param("isssssss",
        $userId,
        $fingerprintHash,
        $fingerprintData['ua'],
        $fingerprintData['ip'],
        $fingerprintData['sr'],
        $fingerprintData['tz'],
        $fingerprintData['lang'],
        $fingerprintData['platform']
    );
    $stmt->execute();
    $stmt->close();
    
    return $fingerprintHash;
}

function generateCSRFToken($formName = 'default') {
    if (!getSetting('csrf_protection_enabled', true)) {
        return 'csrf_disabled';
    }
    
    $token = bin2hex(random_bytes(32));
    $sessionId = session_id();
    $userId = $_SESSION['user_id'] ?? null;
    $expiresAt = date('Y-m-d H:i:s', time() + 3600);
    
    $db = getDBConnection();
    $stmt = $db->prepare("INSERT INTO csrf_tokens (token, user_id, session_id, ip_address, expires_at) 
                         VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sisss",
        $token,
        $userId,
        $sessionId,
        getClientIP(),
        $expiresAt
    );
    $stmt->execute();
    $stmt->close();
    
    return $token;
}

function validateCSRFToken($token, $formName = 'default') {
    if (!getSetting('csrf_protection_enabled', true)) {
        return true;
    }
    
    if (!$token || $token === 'csrf_disabled') {
        return false;
    }
    
    $db = getDBConnection();
    $stmt = $db->prepare("SELECT token_id, used, expires_at FROM csrf_tokens 
                         WHERE token = ? AND (user_id = ? OR session_id = ?) AND used = 0 FOR UPDATE");
    $userId = $_SESSION['user_id'] ?? null;
    $sessionId = session_id();
    $stmt->bind_param("sis", $token, $userId, $sessionId);
    $stmt->execute();
    $result = $stmt->get_result();
    $csrfToken = $result->fetch_assoc();
    $stmt->close();
    
    if (!$csrfToken) {
        return false;
    }
    
    if ($csrfToken['expires_at'] < date('Y-m-d H:i:s')) {
        return false;
    }
    
    $stmt = $db->prepare("UPDATE csrf_tokens SET used = 1 WHERE token_id = ?");
    $stmt->bind_param("i", $csrfToken['token_id']);
    $stmt->execute();
    $stmt->close();
    
    return true;
}

function getDBConnection() {
    static $db = null;
    
    if ($db === null || !$db->ping()) {
        try {
            $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
            
            if ($db->connect_error) {
                throw new Exception("MySQL Connection failed: " . $db->connect_error);
            }
            
            $db->set_charset(DB_CHARSET);
            $db->query("SET time_zone = '+00:00'");
            
        } catch (Exception $e) {
            error_log("Database connection error: " . $e->getMessage());
            
            if ($e->getCode() == 1049) {
                try {
                    $temp_db = new mysqli(DB_HOST, DB_USER, DB_PASS, '', DB_PORT);
                    $temp_db->query("CREATE DATABASE IF NOT EXISTS " . DB_NAME . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    $temp_db->select_db(DB_NAME);
                    $db = $temp_db;
                    $db->set_charset(DB_CHARSET);
                    return $db;
                } catch (Exception $create_error) {
                }
            }
            
            if (ENVIRONMENT === 'production') {
                die("Database connection failed. Please try again later.");
            } else {
                die("Database connection failed: " . $e->getMessage());
            }
        }
    }
    
    return $db;
}

function initDatabase() {
    $db = getDBConnection();
    
    try {
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
                is_unique TINYINT(1) DEFAULT 1,
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
                was_reported TINYINT(1) DEFAULT 0,
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'ai_response_reports' => "CREATE TABLE IF NOT EXISTS ai_response_reports (
                report_id INT AUTO_INCREMENT PRIMARY KEY,
                response_id INT,
                reporter_id INT,
                reporter_session VARCHAR(100),
                reporter_ip VARCHAR(45),
                report_type ENUM('incorrect', 'inappropriate', 'spam', 'other') NOT NULL DEFAULT 'incorrect',
                description TEXT,
                question_text TEXT,
                response_text TEXT,
                status ENUM('pending', 'verified', 'false', 'closed') NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_by INT,
                resolved_at DATETIME,
                resolution_notes TEXT,
                is_false_report TINYINT(1) DEFAULT 0,
                priority INT DEFAULT 0,
                INDEX idx_response_id (response_id),
                INDEX idx_reporter_id (reporter_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at),
                INDEX idx_report_type (report_type),
                INDEX idx_reporter_session (reporter_session),
                FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'response_corrections' => "CREATE TABLE IF NOT EXISTS response_corrections (
                correction_id INT AUTO_INCREMENT PRIMARY KEY,
                response_id INT,
                report_id INT,
                suggested_by INT NOT NULL,
                correction_text TEXT NOT NULL,
                original_response_text TEXT,
                reasoning TEXT,
                admin_approved TINYINT(1) DEFAULT 0,
                approved_by INT,
                approved_at DATETIME,
                activated_at DATETIME,
                is_active TINYINT(1) DEFAULT 0,
                version INT DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_response_id (response_id),
                INDEX idx_report_id (report_id),
                INDEX idx_suggested_by (suggested_by),
                INDEX idx_admin_approved (admin_approved),
                INDEX idx_is_active (is_active),
                FOREIGN KEY (suggested_by) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (report_id) REFERENCES ai_response_reports(report_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'admin_settings' => "CREATE TABLE IF NOT EXISTS admin_settings (
                setting_id INT AUTO_INCREMENT PRIMARY KEY,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT,
                setting_type VARCHAR(50) DEFAULT 'string',
                description TEXT,
                updated_by INT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_setting_key (setting_key),
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'ai_responses' => "CREATE TABLE IF NOT EXISTS ai_responses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                question_hash VARCHAR(32) UNIQUE,
                question_text TEXT NOT NULL,
                response_text TEXT NOT NULL,
                training_id INT,
                source_type VARCHAR(50) DEFAULT 'dynamic',
                confidence_score DECIMAL(3,2) DEFAULT 0.00,
                reporting_count INT DEFAULT 0,
                correction_count INT DEFAULT 0,
                helpful_count INT DEFAULT 0,
                not_helpful_count INT DEFAULT 0,
                is_active TINYINT(1) DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                version INT DEFAULT 1,
                INDEX idx_question_hash (question_hash),
                INDEX idx_is_active (is_active),
                INDEX idx_reporting_count (reporting_count),
                INDEX idx_created_at (created_at),
                FOREIGN KEY (training_id) REFERENCES ai_training(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'response_versions' => "CREATE TABLE IF NOT EXISTS response_versions (
                version_id INT AUTO_INCREMENT PRIMARY KEY,
                response_id INT NOT NULL,
                version_number INT NOT NULL,
                response_text TEXT NOT NULL,
                changed_by INT,
                change_reason VARCHAR(255),
                change_type VARCHAR(50) DEFAULT 'correction',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_response_id (response_id),
                INDEX idx_version_number (version_number),
                FOREIGN KEY (response_id) REFERENCES ai_responses(id) ON DELETE CASCADE,
                FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'response_cache' => "CREATE TABLE IF NOT EXISTS response_cache (
                cache_id INT AUTO_INCREMENT PRIMARY KEY,
                cache_key VARCHAR(64) UNIQUE NOT NULL,
                question_text TEXT,
                response_text TEXT NOT NULL,
                metadata TEXT,
                hit_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                INDEX idx_cache_key (cache_key),
                INDEX idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'rate_limits' => "CREATE TABLE IF NOT EXISTS rate_limits (
                limit_id INT AUTO_INCREMENT PRIMARY KEY,
                identifier VARCHAR(100) NOT NULL,
                identifier_type VARCHAR(50) NOT NULL,
                request_count INT DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked_until DATETIME,
                INDEX idx_identifier (identifier, identifier_type),
                INDEX idx_window_start (window_start),
                INDEX idx_blocked_until (blocked_until)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'csrf_tokens' => "CREATE TABLE IF NOT EXISTS csrf_tokens (
                token_id INT AUTO_INCREMENT PRIMARY KEY,
                token VARCHAR(64) UNIQUE NOT NULL,
                user_id INT,
                session_id VARCHAR(100),
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                used TINYINT(1) DEFAULT 0,
                INDEX idx_token (token),
                INDEX idx_user_id (user_id),
                INDEX idx_expires_at (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'device_fingerprints' => "CREATE TABLE IF NOT EXISTS device_fingerprints (
                fingerprint_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                fingerprint_hash VARCHAR(64) NOT NULL,
                user_agent TEXT,
                ip_address VARCHAR(45),
                screen_resolution VARCHAR(20),
                timezone VARCHAR(50),
                language VARCHAR(10),
                platform VARCHAR(50),
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                is_trusted TINYINT(1) DEFAULT 0,
                INDEX idx_user_id (user_id),
                INDEX idx_fingerprint_hash (fingerprint_hash),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        ];
        
        foreach ($tables as $table => $sql) {
            $db->query($sql);
        }
        
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
        
        $settings_check = $db->query("SELECT COUNT(*) as count FROM admin_settings");
        if ($settings_check) {
            $settings_result = $settings_check->fetch_assoc();
            if ($settings_result['count'] == 0) {
                $default_settings = [
                    ['reporting_enabled', '1', 'boolean', 'Enable or disable the AI response reporting system'],
                    ['approval_type', 'manual', 'string', 'Correction approval type: auto or manual'],
                    ['auto_close_false_reports', '1', 'boolean', 'Automatically close reports marked as false'],
                    ['notification_email', 'admin@example.com', 'string', 'Email for system notifications'],
                    ['max_reports_per_user_per_day', '10', 'integer', 'Maximum number of reports a user can submit per day'],
                    ['require_description', '0', 'boolean', 'Require description when submitting reports'],
                    ['allow_anonymous_reports', '1', 'boolean', 'Allow reports from non-logged-in users'],
                    ['response_cache_enabled', '1', 'boolean', 'Enable response caching for performance'],
                    ['response_cache_ttl', '3600', 'integer', 'Response cache time-to-live in seconds'],
                    ['rate_limit_enabled', '1', 'boolean', 'Enable rate limiting for API and chat'],
                    ['rate_limit_requests', '100', 'integer', 'Number of requests allowed per time window'],
                    ['rate_limit_window', '3600', 'integer', 'Rate limit time window in seconds'],
                    ['csrf_protection_enabled', '1', 'boolean', 'Enable CSRF token protection'],
                    ['content_filtering_enabled', '1', 'boolean', 'Enable basic content filtering for spam/NSFW'],
                    ['device_fingerprinting_enabled', '1', 'boolean', 'Enable device fingerprinting for security']
                ];
                
                $stmt = $db->prepare("INSERT INTO admin_settings (setting_key, setting_value, setting_type, description) 
                                      VALUES (?, ?, ?, ?)");
                foreach ($default_settings as $setting) {
                    $stmt->bind_param("ssss", $setting[0], $setting[1], $setting[2], $setting[3]);
                    $stmt->execute();
                }
                $stmt->close();
                logEvent('system', 'Default admin settings created', null, 'info');
            }
        }
        
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
        $log_message = date('[Y-m-d H:i:s]') . " [$severity] [$type] $message";
        if ($userId) $log_message .= " UserID: $userId";
        if ($details) $log_message .= " Details: $details";
        error_log($log_message);
    }
}

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
            if (strpos($dir, 'uploads') !== false) {
                file_put_contents($dir . '.htaccess', 
                    "Order deny,allow\nDeny from all\n<FilesMatch \"\.(jpg|jpeg|png|gif|pdf|txt)$\">\nAllow from all\n</FilesMatch>");
            }
        }
    }
    
    $index_html = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Access Forbidden</h1></body></html>';
    foreach ($directories as $dir) {
        if (!file_exists($dir . 'index.html')) {
            file_put_contents($dir . 'index.html', $index_html);
        }
    }
}

function startSecureSession() {
    ini_set('session.use_only_cookies', 1);
    ini_set('session.use_strict_mode', 1);
    
    session_set_cookie_params([
        'lifetime' => SESSION_LIFETIME,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? '',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    
    session_name('AI_CHAT_SESSION');
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['last_regeneration'])) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    } elseif (time() - $_SESSION['last_regeneration'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

function validateUploadedFile($file, $allowedTypes = ALLOWED_TYPES) {
    $errors = [];
    
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
    
    if ($file['size'] > MAX_FILE_SIZE) {
        $errors[] = 'File too large (max ' . (MAX_FILE_SIZE / (1024*1024)) . 'MB)';
    }
    
    $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_ext, $allowedTypes)) {
        $errors[] = 'File type not allowed. Allowed: ' . implode(', ', $allowedTypes);
    }
    
    $dangerous_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'html', 'htm', 'js'];
    if (in_array($file_ext, $dangerous_extensions) && !in_array($file_ext, $allowedTypes)) {
        $errors[] = 'Potentially dangerous file type';
    }
    
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

function generateSafeFilename($original_name) {
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
    $basename = preg_replace('/[^a-zA-Z0-9_-]/', '_', pathinfo($original_name, PATHINFO_FILENAME));
    $basename = substr($basename, 0, 100);
    return time() . '_' . $basename . '.' . $extension;
}

function calculateFileChecksum($filepath) {
    return hash_file('sha256', $filepath);
}

function extractTextFromExcel($filepath) {
    if (!class_exists('ZipArchive')) {
        return "Excel file uploaded. For text extraction, please convert to CSV or TXT format.";
    }
    
    $content = '';
    
    try {
        $zip = new ZipArchive;
        if ($zip->open($filepath) === TRUE) {
            if (($index = $zip->locateName('xl/sharedStrings.xml')) !== FALSE) {
                $xml_content = $zip->getFromIndex($index);
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
        $content = "Excel file uploaded. Content extracted partially. For better results, save as CSV.";
    }
    
    if (empty($content)) {
        $content = "Excel file processed. To extract all text, please save as CSV format.";
    }
    
    return $content;
}

function extractTextFromPowerPoint($filepath) {
    if (!class_exists('ZipArchive')) {
        return "PowerPoint file uploaded. For text extraction, please save as PDF or TXT.";
    }
    
    $content = '';
    
    try {
        $zip = new ZipArchive;
        if ($zip->open($filepath) === TRUE) {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $filename = $zip->getNameIndex($i);
                if (preg_match('/ppt\/slides\/slide\d+\.xml/', $filename)) {
                    $xml_content = $zip->getFromIndex($i);
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

function processDocument($documentId, $filepath, $filename) {
    $db = getDBConnection();
    
    $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $content = '';
    $chunkCount = 0;
    
    switch ($file_ext) {
        case 'txt':
        case 'md':
        case 'csv':
            $content = file_get_contents($filepath);
            break;
        case 'pdf':
            $content = "PDF file uploaded. Full text extraction requires additional libraries.";
            break;
        case 'docx':
            $content = "Word document uploaded. Content stored for AI processing.";
            break;
        case 'xlsx':
            $content = extractTextFromExcel($filepath);
            break;
        case 'pptx':
            $content = extractTextFromPowerPoint($filepath);
            break;
        default:
            $content = "Document uploaded: $filename";
    }
    
    if (!empty($content)) {
        $chunks = str_split($content, 500);
        $totalChunks = min(count($chunks), 20);
        
        $stmt = $db->prepare("INSERT INTO knowledge_base (document_id, content_chunk, chunk_hash, metadata) 
                              VALUES (?, ?, ?, ?)");
        
        for ($i = 0; $i < $totalChunks; $i++) {
            $chunk = trim($chunks[$i]);
            $chunk_hash = md5($chunk);
            $metadata = json_encode([
                'chunk_index' => $i,
                'total_chunks' => $totalChunks,
                'source_file' => $filename,
                'importance' => 1
            ]);
            
            $stmt->bind_param("isss", $documentId, $chunk, $chunk_hash, $metadata);
            $stmt->execute();
            $chunkCount++;
        }
        
        $stmt->close();
        
        $stmt = $db->prepare("UPDATE documents SET processed = 1, status = 'processed' WHERE id = ?");
        $stmt->bind_param("i", $documentId);
        $stmt->execute();
        $stmt->close();
    }
    
    return $chunkCount;
}

function uploadDocument($file, $metadata = [], $userId = null) {
    list($valid, $errors) = validateUploadedFile($file);
    if (!$valid) {
        return [false, implode(', ', $errors), null];
    }
    
    $original_name = $file['name'];
    $safe_filename = generateSafeFilename($original_name);
    $filepath = UPLOAD_DIR . 'documents/' . $safe_filename;
    
    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
        return [false, 'Failed to save file', null];
    }
    
    $checksum = calculateFileChecksum($filepath);
    
    $db = getDBConnection();
    try {
        $stmt = $db->prepare("INSERT INTO documents 
                            (filename, original_filename, title, description, filepath, file_type, file_size, 
                             checksum, category, tags, uploaded_by) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssssisssi",
            $safe_filename,
            $original_name,
            $metadata['title'] ?? null,
            $metadata['description'] ?? null,
            $filepath,
            $file['type'],
            $file['size'],
            $checksum,
            $metadata['category'] ?? null,
            $metadata['tags'] ?? null,
            $userId
        );
        $stmt->execute();
        $documentId = $db->insert_id;
        $stmt->close();
        
        $chunks = processDocument($documentId, $filepath, $original_name);
        
        auditLog('upload_document', 'document', $documentId, null, $original_name);
        logEvent('document', "Document uploaded: $original_name ($chunks chunks)", $userId);
        
        return [true, "Document uploaded successfully. Processed into $chunks knowledge chunks.", $documentId];
    } catch (Exception $e) {
        if (file_exists($filepath)) {
            unlink($filepath);
        }
        
        error_log("Document upload failed: " . $e->getMessage());
        return [false, "Upload failed: " . $e->getMessage(), null];
    }
}

function deleteDocument($documentId) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT filepath FROM documents WHERE id = ? AND is_deleted = 0");
        $stmt->bind_param("i", $documentId);
        $stmt->execute();
        $result = $stmt->get_result();
        $document = $result->fetch_assoc();
        $stmt->close();
        
        if (!$document) {
            return [false, 'Document not found or already deleted'];
        }
        
        if (file_exists($document['filepath'])) {
            if (!unlink($document['filepath'])) {
                return [false, 'Failed to delete physical file'];
            }
        }
        
        $stmt = $db->prepare("UPDATE documents SET is_deleted = 1, status = 'deleted' WHERE id = ?");
        $stmt->bind_param("i", $documentId);
        $stmt->execute();
        $stmt->close();
        
        logEvent('document', "Document file deleted: ID $documentId", $_SESSION['user_id'] ?? null);
        
        return [true, 'Document file deleted successfully. Knowledge base entries preserved.'];
        
    } catch (Exception $e) {
        error_log("Document deletion failed: " . $e->getMessage());
        return [false, 'Error deleting document: ' . $e->getMessage()];
    }
}

function getStorageStats() {
    $db = getDBConnection();
    $stats = [];
    
    try {
        $result = $db->query("SELECT COUNT(*) as total, SUM(file_size) as total_size FROM documents WHERE is_deleted = 0");
        $row = $result->fetch_assoc();
        $stats['total_documents'] = intval($row['total'] ?? 0);
        $stats['total_size'] = intval($row['total_size'] ?? 0);
        
        $result = $db->query("SELECT COUNT(*) as deleted_count, SUM(file_size) as deleted_size FROM documents WHERE is_deleted = 1");
        $row = $result->fetch_assoc();
        $stats['deleted_documents'] = intval($row['deleted_count'] ?? 0);
        $stats['deleted_size'] = intval($row['deleted_size'] ?? 0);
        
        $result = $db->query("SELECT file_type, COUNT(*) as count FROM documents WHERE is_deleted = 0 GROUP BY file_type");
        $stats['by_type'] = [];
        while ($row = $result->fetch_assoc()) {
            $stats['by_type'][] = $row;
        }
        
        $stats['storage_limit'] = 100 * 1024 * 1024;
        $stats['used_percentage'] = $stats['total_size'] > 0 ? 
            round(($stats['total_size'] / $stats['storage_limit']) * 100, 2) : 0;
        
        $result = $db->query("SELECT COUNT(*) as total_chunks FROM knowledge_base");
        $row = $result->fetch_assoc();
        $stats['knowledge_chunks'] = intval($row['total_chunks'] ?? 0);
        
        return $stats;
        
    } catch (Exception $e) {
        error_log("Storage stats failed: " . $e->getMessage());
        return ['error' => $e->getMessage()];
    }
}

function validateApiKey($api_key, $domain = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $result = $stmt->get_result();
        $api_data = $result->fetch_assoc();
        $stmt->close();
        
        if (!$api_data) {
            return false;
        }
        
        $update = $db->prepare("UPDATE api_keys SET last_used = NOW(), usage_count = usage_count + 1 WHERE id = ?");
        $update->bind_param("i", $api_data['id']);
        $update->execute();
        $update->close();
        
        if ($domain && $api_data['domain'] !== '*' && $api_data['domain'] !== $domain) {
            return false;
        }
        
        return $api_data;
        
    } catch (Exception $e) {
        error_log("API key validation failed: " . $e->getMessage());
        return false;
    }
}

function createApiKey($domain, $user_id = null) {
    $db = getDBConnection();
    
    $api_key = generateToken(32);
    
    try {
        $stmt = $db->prepare("INSERT INTO api_keys (api_key, domain, user_id) 
                              VALUES (?, ?, ?)");
        $stmt->bind_param("ssi", $api_key, $domain, $user_id);
        $stmt->execute();
        $stmt->close();
        
        logEvent('api', "API key created for domain: $domain", $user_id);
        
        return $api_key;
        
    } catch (Exception $e) {
        error_log("API key creation failed: " . $e->getMessage());
        return false;
    }
}

function deleteApiKey($api_key_id) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("DELETE FROM api_keys WHERE id = ?");
        $stmt->bind_param("i", $api_key_id);
        $stmt->execute();
        $stmt->close();
        
        logEvent('api', "API key deleted: ID $api_key_id", $_SESSION['user_id'] ?? null);
        
        return true;
        
    } catch (Exception $e) {
        error_log("API key deletion failed: " . $e->getMessage());
        return false;
    }
}

function getApiKeys($user_id = null) {
    $db = getDBConnection();
    
    try {
        if ($user_id) {
            $stmt = $db->prepare("SELECT *, (SELECT username FROM users WHERE id = api_keys.user_id) as username 
                                  FROM api_keys WHERE user_id = ? ORDER BY created_at DESC");
            $stmt->bind_param("i", $user_id);
        } else {
            $stmt = $db->query("SELECT *, (SELECT username FROM users WHERE id = api_keys.user_id) as username 
                               FROM api_keys ORDER BY created_at DESC");
        }
        
        if (isset($user_id)) {
            $stmt->execute();
            $result = $stmt->get_result();
        } else {
            $result = $stmt;
        }
        
        $api_keys = [];
        while ($row = $result->fetch_assoc()) {
            $api_keys[] = $row;
        }
        
        if (isset($stmt) && method_exists($stmt, 'close')) {
            $stmt->close();
        }
        
        return $api_keys;
        
    } catch (Exception $e) {
        error_log("Get API keys failed: " . $e->getMessage());
        return [];
    }
}

function getDocuments($filters = []) {
    $db = getDBConnection();
    
    $sql = "SELECT d.*, u.username as uploaded_by_username, u.full_name as uploaded_by_name,
                   (SELECT COUNT(*) FROM knowledge_base WHERE document_id = d.id) as chunks_count
            FROM documents d 
            LEFT JOIN users u ON d.uploaded_by = u.id
            WHERE d.is_deleted = 0";
    
    $params = [];
    $types = "";
    
    if (!empty($filters['status'])) {
        $sql .= " AND d.status = ?";
        $params[] = $filters['status'];
        $types .= "s";
    }
    
    if (!empty($filters['category'])) {
        $sql .= " AND d.category = ?";
        $params[] = $filters['category'];
        $types .= "s";
    }
    
    if (!empty($filters['processed'])) {
        $sql .= " AND d.processed = ?";
        $params[] = $filters['processed'];
        $types .= "i";
    }
    
    if (!empty($filters['uploaded_by'])) {
        $sql .= " AND d.uploaded_by = ?";
        $params[] = $filters['uploaded_by'];
        $types .= "i";
    }
    
    if (!empty($filters['date_from'])) {
        $sql .= " AND DATE(d.uploaded_at) >= ?";
        $params[] = $filters['date_from'];
        $types .= "s";
    }
    
    if (!empty($filters['date_to'])) {
        $sql .= " AND DATE(d.uploaded_at) <= ?";
        $params[] = $filters['date_to'];
        $types .= "s";
    }
    
    $sql .= " ORDER BY d.uploaded_at DESC";
    
    try {
        $stmt = $db->prepare($sql);
        if ($params) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        
        $documents = [];
        while ($row = $result->fetch_assoc()) {
            $documents[] = $row;
        }
        
        $stmt->close();
        return $documents;
        
    } catch (Exception $e) {
        error_log("Get documents failed: " . $e->getMessage());
        return [];
    }
}

function getDocumentById($id) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT d.*, u.username as uploaded_by_username, u.full_name as uploaded_by_name,
                                     (SELECT COUNT(*) FROM knowledge_base WHERE document_id = d.id) as chunks_count
                              FROM documents d 
                              LEFT JOIN users u ON d.uploaded_by = u.id
                              WHERE d.id = ? AND d.is_deleted = 0");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
        $document = $result->fetch_assoc();
        $stmt->close();
        
        return $document;
        
    } catch (Exception $e) {
        error_log("Get document failed: " . $e->getMessage());
        return null;
    }
}

function getUserById($userId) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT id, username, email, full_name, user_type, department, profile_image, 
                                     phone, created_at, is_active, last_login
                              FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        return $user;
        
    } catch (Exception $e) {
        error_log("Get user failed: " . $e->getMessage());
        return null;
    }
}

function getUserByUsername($username) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT id, username, email, password_hash, full_name, user_type, 
                                     department, profile_image, created_at, is_active, last_login
                              FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        return $user;
        
    } catch (Exception $e) {
        error_log("Get user by username failed: " . $e->getMessage());
        return null;
    }
}

function getAllUsers($filters = []) {
    $db = getDBConnection();
    
    $sql = "SELECT id, username, email, full_name, user_type, department, profile_image, 
                   phone, created_at, last_login, is_active
            FROM users WHERE 1=1";
    
    $params = [];
    $types = "";
    
    if (!empty($filters['user_type'])) {
        $sql .= " AND user_type = ?";
        $params[] = $filters['user_type'];
        $types .= "s";
    }
    
    if (isset($filters['is_active'])) {
        $sql .= " AND is_active = ?";
        $params[] = $filters['is_active'];
        $types .= "i";
    }
    
    if (!empty($filters['search'])) {
        $sql .= " AND (username LIKE ? OR email LIKE ? OR full_name LIKE ?)";
        $search = '%' . $filters['search'] . '%';
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
        $types .= "sss";
    }
    
    $sql .= " ORDER BY created_at DESC";
    
    try {
        $stmt = $db->prepare($sql);
        if ($params) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        
        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        
        $stmt->close();
        return $users;
        
    } catch (Exception $e) {
        error_log("Get all users failed: " . $e->getMessage());
        return [];
    }
}

function createUser($data) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO users 
                              (username, email, password_hash, full_name, user_type, department, phone, is_active) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, 1)");
        $stmt->bind_param("sssssss",
            $data['username'],
            $data['email'],
            $data['password_hash'],
            $data['full_name'],
            $data['user_type'],
            $data['department'] ?? null,
            $data['phone'] ?? null
        );
        $stmt->execute();
        $userId = $db->insert_id;
        $stmt->close();
        
        logEvent('auth', "User created: {$data['username']}", $userId);
        
        return $userId;
        
    } catch (Exception $e) {
        error_log("Create user failed: " . $e->getMessage());
        logEvent('error', "Create user failed: " . $e->getMessage(), null, 'error');
        return false;
    }
}

function updateUser($userId, $data) {
    $db = getDBConnection();
    
    $fields = [];
    $values = [];
    $types = "";
    
    if (isset($data['email'])) {
        $fields[] = "email = ?";
        $values[] = $data['email'];
        $types .= "s";
    }
    
    if (isset($data['full_name'])) {
        $fields[] = "full_name = ?";
        $values[] = $data['full_name'];
        $types .= "s";
    }
    
    if (isset($data['department'])) {
        $fields[] = "department = ?";
        $values[] = $data['department'];
        $types .= "s";
    }
    
    if (isset($data['phone'])) {
        $fields[] = "phone = ?";
        $values[] = $data['phone'];
        $types .= "s";
    }
    
    if (isset($data['user_type'])) {
        $fields[] = "user_type = ?";
        $values[] = $data['user_type'];
        $types .= "s";
    }
    
    if (isset($data['is_active'])) {
        $fields[] = "is_active = ?";
        $values[] = $data['is_active'];
        $types .= "i";
    }
    
    if (isset($data['password_hash'])) {
        $fields[] = "password_hash = ?";
        $values[] = $data['password_hash'];
        $types .= "s";
        $last_password_change = date('Y-m-d H:i:s');
        $fields[] = "last_password_change = ?";
        $values[] = $last_password_change;
        $types .= "s";
    }
    
    if (empty($fields)) {
        return false;
    }
    
    $types .= "i";
    $values[] = $userId;
    $sql = "UPDATE users SET " . implode(', ', $fields) . " WHERE id = ?";
    
    try {
        $stmt = $db->prepare($sql);
        $stmt->bind_param($types, ...$values);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        
        if ($affected > 0) {
            auditLog('update_user', 'user', $userId, json_encode($data), null);
            logEvent('auth', "User updated: ID $userId", $userId);
        }
        
        return $affected > 0;
        
    } catch (Exception $e) {
        error_log("Update user failed: " . $e->getMessage());
        logEvent('error', "Update user failed: " . $e->getMessage(), null, 'error');
        return false;
    }
}

function deleteUser($userId) {
    $db = getDBConnection();
    
    $adminCount = $db->query("SELECT COUNT(*) as count FROM users WHERE user_type = 'admin' AND is_active = 1");
    $adminData = $adminCount->fetch_assoc();
    
    if ($adminData['count'] <= 1) {
        return [false, 'Cannot delete the last active admin user'];
    }
    
    try {
        $stmt = $db->prepare("UPDATE users SET is_active = 0 WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->close();
        
        auditLog('delete_user', 'user', $userId, "User ID: $userId", 'soft_deleted');
        logEvent('auth', "User deactivated: ID $userId", $userId);
        
        return [true, 'User deactivated successfully'];
        
    } catch (Exception $e) {
        error_log("Delete user failed: " . $e->getMessage());
        logEvent('error', "Delete user failed: " . $e->getMessage(), null, 'error');
        return [false, "Error deleting user: " . $e->getMessage()];
    }
}

function loginUser($username, $password) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT id, username, password_hash, user_type, is_active, 
                                     failed_login_attempts, lockout_until 
                              FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        if (!$user) {
            logEvent('auth', "Login failed: User not found - $username", null, 'warning');
            return [false, 'Invalid username or password'];
        }
        
        if (!$user['is_active']) {
            logEvent('auth', "Login failed: Inactive user - $username", $user['id'], 'warning');
            return [false, 'Account is deactivated'];
        }
        
        if ($user['lockout_until'] && $user['lockout_until'] > date('Y-m-d H:i:s')) {
            $remaining = strtotime($user['lockout_until']) - time();
            $minutes = ceil($remaining / 60);
            logEvent('auth', "Login failed: Account locked - $username", $user['id'], 'warning');
            return [false, "Account locked. Try again in $minutes minutes"];
        }
        
        if (!password_verify($password, $user['password_hash'])) {
            $attempts = $user['failed_login_attempts'] + 1;
            $lockout_until = null;
            
            if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                $lockout_until = date('Y-m-d H:i:s', time() + LOCKOUT_TIME);
                logEvent('auth', "Account locked: Too many failed attempts - $username", $user['id'], 'error');
            } else {
                logEvent('auth', "Login failed: Invalid password - $username (attempt $attempts/" . MAX_LOGIN_ATTEMPTS . ")", 
                        $user['id'], 'warning');
            }
            
            $stmt = $db->prepare("UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?");
            $stmt->bind_param("isi", $attempts, $lockout_until, $user['id']);
            $stmt->execute();
            $stmt->close();
            
            return [false, 'Invalid username or password'];
        }
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['user_type'] = $user['user_type'];
        $_SESSION['login_time'] = time();
        $_SESSION['ip_address'] = getClientIP();
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $stmt = $db->prepare("UPDATE users SET last_login = NOW(), failed_login_attempts = 0, lockout_until = NULL 
                              WHERE id = ?");
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();
        $stmt->close();
        
        $sessionId = generateToken(32);
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $expires = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);
        
        $stmt = $db->prepare("INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at) 
                              VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("issss", $user['id'], $sessionId, getClientIP(), $ua, $expires);
        $stmt->execute();
        $stmt->close();
        
        $_SESSION['session_token'] = $sessionId;
        
        saveDeviceFingerprint($user['id']);
        auditLog('login', 'user', $user['id']);
        logEvent('auth', "User logged in: {$user['username']}", $user['id'], 'info');
        
        return [true, 'Login successful', $user];
        
    } catch (Exception $e) {
        error_log("Login failed: " . $e->getMessage());
        logEvent('error', "Login error: " . $e->getMessage(), null, 'error');
        return [false, "Login error. Please try again."];
    }
}

function logoutUser() {
    if (isset($_SESSION['user_id'])) {
        $userId = $_SESSION['user_id'];
        
        if (isset($_SESSION['session_token'])) {
            $db = getDBConnection();
            $stmt = $db->prepare("DELETE FROM user_sessions WHERE session_token = ?");
            $stmt->bind_param("s", $_SESSION['session_token']);
            $stmt->execute();
            $stmt->close();
        }
        
        auditLog('logout', 'user', $userId);
        logEvent('auth', "User logged out: User ID $userId", $userId, 'info');
    }
    
    $_SESSION = [];
    
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    session_destroy();
    
    return true;
}

function getCurrentSessionId() {
    if (!isset($_SESSION['chat_session_id'])) {
        $_SESSION['chat_session_id'] = generateToken(24);
        
        $db = getDBConnection();
        try {
            $stmt = $db->prepare("INSERT INTO chat_sessions (session_id, ip_address, user_agent, country) 
                                  VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss",
                $session_id,
                $ip,
                $user_agent,
                $country
            );
            
            $session_id = $_SESSION['chat_session_id'];
            $ip = getClientIP();
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            $country = 'Unknown';
            $stmt->execute();
            $stmt->close();
            
            logEvent('session', 'New chat session started', $_SESSION['user_id'] ?? null);
        } catch (Exception $e) {
            error_log("Session creation failed: " . $e->getMessage());
        }
    }
    return $_SESSION['chat_session_id'];
}

function saveChatMessage($sessionId, $messageType, $content, $responseOptions = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO chat_messages (session_id, message_type, content, response_options) 
                              VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", 
            $sessionId, 
            $messageType, 
            $content, 
            $responseOptions
        );
        $stmt->execute();
        $messageId = $db->insert_id;
        $stmt->close();
        
        $stmt = $db->prepare("UPDATE chat_sessions SET message_count = message_count + 1, 
                             last_activity = NOW() WHERE session_id = ?");
        $stmt->bind_param("s", $sessionId);
        $stmt->execute();
        $stmt->close();
        
        return $messageId;
        
    } catch (Exception $e) {
        error_log("Save chat message failed: " . $e->getMessage());
        return false;
    }
}

function getChatHistory($sessionId, $limit = 50) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT * FROM chat_messages WHERE session_id = ? 
                             ORDER BY created_at DESC LIMIT ?");
        $stmt->bind_param("si", $sessionId, $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $messages = [];
        while ($row = $result->fetch_assoc()) {
            $messages[] = $row;
        }
        
        $stmt->close();
        return array_reverse($messages);
        
    } catch (Exception $e) {
        error_log("Get chat history failed: " . $e->getMessage());
        return [];
    }
}

function getChatSessions($filters = []) {
    $db = getDBConnection();
    
    $sql = "SELECT cs.*, u.username, u.full_name 
            FROM chat_sessions cs 
            LEFT JOIN users u ON cs.user_id = u.id 
            WHERE 1=1";
    
    $params = [];
    $types = "";
    
    if (!empty($filters['user_id'])) {
        $sql .= " AND cs.user_id = ?";
        $params[] = $filters['user_id'];
        $types .= "i";
    }
    
    if (!empty($filters['ip_address'])) {
        $sql .= " AND cs.ip_address = ?";
        $params[] = $filters['ip_address'];
        $types .= "s";
    }
    
    if (!empty($filters['date_from'])) {
        $sql .= " AND DATE(cs.started_at) >= ?";
        $params[] = $filters['date_from'];
        $types .= "s";
    }
    
    if (!empty($filters['date_to'])) {
        $sql .= " AND DATE(cs.started_at) <= ?";
        $params[] = $filters['date_to'];
        $types .= "s";
    }
    
    if (!empty($filters['is_unique'])) {
        $sql .= " AND cs.is_unique = ?";
        $params[] = $filters['is_unique'];
        $types .= "i";
    }
    
    $sql .= " ORDER BY cs.last_activity DESC";
    
    if (!empty($filters['limit'])) {
        $sql .= " LIMIT ?";
        $params[] = $filters['limit'];
        $types .= "i";
    }
    
    try {
        $stmt = $db->prepare($sql);
        if ($params) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        
        $sessions = [];
        while ($row = $result->fetch_assoc()) {
            $sessions[] = $row;
        }
        
        $stmt->close();
        return $sessions;
        
    } catch (Exception $e) {
        error_log("Get chat sessions failed: " . $e->getMessage());
        return [];
    }
}

function getDashboardStats() {
    $db = getDBConnection();
    
    try {
        $stats = [];
        
        $result = $db->query("SELECT COUNT(*) as total FROM users WHERE is_active = 1");
        $stats['total_users'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(*) as total FROM documents WHERE is_deleted = 0");
        $stats['total_documents'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(*) as total FROM knowledge_base");
        $stats['total_knowledge_chunks'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(DISTINCT session_id) as total FROM chat_sessions 
                            WHERE last_activity >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        $stats['active_sessions_24h'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(*) as total FROM ai_response_reports WHERE status = 'pending'");
        $stats['pending_reports'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(*) as total FROM response_corrections WHERE admin_approved = 0");
        $stats['pending_corrections'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(*) as total FROM chat_sessions WHERE started_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)");
        $stats['sessions_this_week'] = $result->fetch_assoc()['total'];
        
        $result = $db->query("SELECT COUNT(*) as total FROM documents WHERE uploaded_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)");
        $stats['documents_this_week'] = $result->fetch_assoc()['total'];
        
        return $stats;
        
    } catch (Exception $e) {
        error_log("Dashboard stats failed: " . $e->getMessage());
        return [];
    }
}

function getSystemLogs($filters = []) {
    $db = getDBConnection();
    
    $sql = "SELECT sl.*, u.username, u.full_name 
            FROM system_logs sl 
            LEFT JOIN users u ON sl.user_id = u.id 
            WHERE 1=1";
    
    $params = [];
    $types = "";
    
    if (!empty($filters['log_type'])) {
        $sql .= " AND sl.log_type = ?";
        $params[] = $filters['log_type'];
        $types .= "s";
    }
    
    if (!empty($filters['severity'])) {
        $sql .= " AND sl.severity = ?";
        $params[] = $filters['severity'];
        $types .= "s";
    }
    
    if (!empty($filters['user_id'])) {
        $sql .= " AND sl.user_id = ?";
        $params[] = $filters['user_id'];
        $types .= "i";
    }
    
    if (!empty($filters['date'])) {
        $sql .= " AND DATE(sl.created_at) = ?";
        $params[] = $filters['date'];
        $types .= "s";
    }
    
    if (!empty($filters['date_from'])) {
        $sql .= " AND DATE(sl.created_at) >= ?";
        $params[] = $filters['date_from'];
        $types .= "s";
    }
    
    if (!empty($filters['date_to'])) {
        $sql .= " AND DATE(sl.created_at) <= ?";
        $params[] = $filters['date_to'];
        $types .= "s";
    }
    
    $sql .= " ORDER BY sl.created_at DESC";
    
    if (!empty($filters['limit'])) {
        $sql .= " LIMIT ?";
        $params[] = $filters['limit'];
        $types .= "i";
    }
    
    try {
        $stmt = $db->prepare($sql);
        if ($params) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        
        $logs = [];
        while ($row = $result->fetch_assoc()) {
            $logs[] = $row;
        }
        
        $stmt->close();
        return $logs;
        
    } catch (Exception $e) {
        error_log("Get system logs failed: " . $e->getMessage());
        return [];
    }
}

function clearOldLogs($days = 30) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("DELETE FROM system_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)");
        $stmt->bind_param("i", $days);
        $stmt->execute();
        $deleted = $stmt->affected_rows;
        $stmt->close();
        
        logEvent('system', "Cleared $deleted old system logs older than $days days", null, 'info');
        
        return $deleted;
        
    } catch (Exception $e) {
        error_log("Clear old logs failed: " . $e->getMessage());
        return 0;
    }
}

function generateAIResponse($question, $sessionId, $userId = null) {
    $db = getDBConnection();
    
    try {
        $cacheKey = md5(trim(strtolower($question)));
        
        if (getSetting('response_cache_enabled', true)) {
            $stmt = $db->prepare("SELECT response_text, metadata FROM response_cache 
                                 WHERE cache_key = ? AND (expires_at IS NULL OR expires_at > NOW())");
            $stmt->bind_param("s", $cacheKey);
            $stmt->execute();
            $result = $stmt->get_result();
            $cached = $result->fetch_assoc();
            $stmt->close();
            
            if ($cached) {
                $stmt = $db->prepare("UPDATE response_cache SET hit_count = hit_count + 1, 
                                     last_accessed = NOW() WHERE cache_key = ?");
                $stmt->bind_param("s", $cacheKey);
                $stmt->execute();
                $stmt->close();
                
                $stmt = $db->prepare("SELECT id FROM ai_responses WHERE question_hash = ? LIMIT 1");
                $stmt->bind_param("s", $cacheKey);
                $stmt->execute();
                $result = $stmt->get_result();
                $response = $result->fetch_assoc();
                $stmt->close();
                
                return [
                    'response' => $cached['response_text'],
                    'confidence' => 0.85,
                    'cached' => true,
                    'response_id' => $response['id'] ?? null
                ];
            }
        }
        
        $question_hash = md5(trim(strtolower($question)));
        
        $stmt = $db->prepare("SELECT * FROM ai_responses WHERE question_hash = ? AND is_active = 1");
        $stmt->bind_param("s", $question_hash);
        $stmt->execute();
        $result = $stmt->get_result();
        $response = $result->fetch_assoc();
        $stmt->close();
        
        if ($response) {
            $stmt = $db->prepare("UPDATE ai_responses SET last_used_at = NOW(), usage_count = usage_count + 1 
                                 WHERE id = ?");
            $stmt->bind_param("i", $response['id']);
            $stmt->execute();
            $stmt->close();
            
            $ai_response = $response['response_text'];
            $confidence = $response['confidence_score'];
            $response_id = $response['id'];
            $source = 'database';
        } else {
            $stmt = $db->prepare("SELECT * FROM ai_training WHERE question_hash = ?");
            $stmt->bind_param("s", $question_hash);
            $stmt->execute();
            $result = $stmt->get_result();
            $training = $result->fetch_assoc();
            $stmt->close();
            
            if ($training) {
                $field = 'response' . $training['best_response'];
                $ai_response = $training[$field];
                $confidence = 0.9;
                $source = 'training';
                
                $stmt = $db->prepare("INSERT INTO ai_responses (question_hash, question_text, response_text, 
                                     confidence_score, source_type, training_id) 
                                     VALUES (?, ?, ?, ?, 'training', ?)");
                $stmt->bind_param("ssssi", $question_hash, $question, $ai_response, $confidence, $training['id']);
                $stmt->execute();
                $response_id = $db->insert_id;
                $stmt->close();
            } else {
                $knowledgeResults = $db->query("SELECT content_chunk, 
                    MATCH(content_chunk) AGAINST('$question' IN NATURAL LANGUAGE MODE) as score 
                    FROM knowledge_base 
                    WHERE MATCH(content_chunk) AGAINST('$question' IN NATURAL LANGUAGE MODE) > 0
                    ORDER BY score DESC LIMIT 3");
                
                if ($knowledgeResults && $knowledgeResults->num_rows > 0) {
                    $chunks = [];
                    while ($row = $knowledgeResults->fetch_assoc()) {
                        $chunks[] = $row['content_chunk'];
                    }
                    
                    $context = implode(" ", $chunks);
                    $ai_response = generateFallbackResponse($question, $context);
                    $confidence = 0.6;
                    $source = 'knowledge';
                } else {
                    $ai_response = generateFallbackResponse($question);
                    $confidence = 0.4;
                    $source = 'fallback';
                }
                
                $stmt = $db->prepare("INSERT INTO ai_responses (question_hash, question_text, response_text, 
                                     confidence_score, source_type) 
                                     VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssds", $question_hash, $question, $ai_response, $confidence, $source);
                $stmt->execute();
                $response_id = $db->insert_id;
                $stmt->close();
            }
        }
        
        if (getSetting('response_cache_enabled', true)) {
            $cacheTtl = getSetting('response_cache_ttl', 3600);
            $expiresAt = date('Y-m-d H:i:s', time() + $cacheTtl);
            
            $metadata = json_encode([
                'question' => $question,
                'confidence' => $confidence,
                'source' => $source ?? 'unknown',
                'session_id' => $sessionId
            ]);
            
            $stmt = $db->prepare("INSERT INTO response_cache (cache_key, question_text, response_text, metadata, expires_at) 
                                 VALUES (?, ?, ?, ?, ?)
                                 ON DUPLICATE KEY UPDATE 
                                 response_text = VALUES(response_text),
                                 hit_count = hit_count + 1,
                                 last_accessed = NOW()");
            $stmt->bind_param("sssss", $cacheKey, $question, $ai_response, $metadata, $expiresAt);
            $stmt->execute();
            $stmt->close();
        }
        
        $stmt = $db->prepare("UPDATE ai_responses SET helpful_count = helpful_count + 1 
                             WHERE id = ?");
        $stmt->bind_param("i", $response_id);
        $stmt->execute();
        $stmt->close();
        
        return [
            'response' => $ai_response,
            'confidence' => $confidence,
            'cached' => false,
            'response_id' => $response_id
        ];
        
    } catch (Exception $e) {
        error_log("Generate AI response failed: " . $e->getMessage());
        
        if ($response_id) {
            $stmt = $db->prepare("UPDATE ai_responses SET not_helpful_count = not_helpful_count + 1 
                                 WHERE id = ?");
            $stmt->bind_param("i", $response_id);
            $stmt->execute();
            $stmt->close();
        }
        
        return [
            'response' => "I apologize, but I'm having trouble processing your question right now. Please try again.",
            'confidence' => 0.0,
            'error' => true
        ];
    }
}

function generateFallbackResponse($question, $context = null) {
    $responses = [
        "I understand you're asking about: {$question}. Based on my knowledge base, I'll provide the best available information.",
        "Let me help you with that. Regarding {$question}, here's what I can tell you:",
        "That's an interesting question about {$question}. Based on available information:",
        "I can help you with {$question}. From my knowledge base:",
        "Regarding your question about {$question}, here's the information I have:"
    ];
    
    $prefix = $responses[array_rand($responses)];
    
    if ($context) {
        $truncatedContext = substr($context, 0, 300);
        return $prefix . " " . $truncatedContext . "... I'm still learning, so my response may not be perfect. You can help improve it by rating this response.";
    }
    
    return $prefix . " I don't have specific information about this topic yet. You can help train me by providing feedback on my responses.";
}

function rateResponse($responseId, $sessionId, $question, $response, $rating, $feedback = null, $userId = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO response_ratings 
                              (message_id, session_id, user_id, question, response, rating, feedback) 
                              VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("sisssi",
            $responseId,
            $sessionId,
            $userId,
            $question,
            $response,
            $rating
        );
        $stmt->execute();
        $ratingId = $db->insert_id;
        $stmt->close();
        
        if ($rating == 1) {
            $stmt = $db->prepare("UPDATE ai_responses SET helpful_count = helpful_count + 1 
                                 WHERE id = ?");
        } else {
            $stmt = $db->prepare("UPDATE ai_responses SET not_helpful_count = not_helpful_count + 1 
                                 WHERE id = ?");
        }
        $stmt->bind_param("i", $responseId);
        $stmt->execute();
        $stmt->close();
        
        logEvent('chat', "Response rated: {$rating} (response_id: $responseId)", $userId);
        
        return $ratingId;
        
    } catch (Exception $e) {
        error_log("Rate response failed: " . $e->getMessage());
        return false;
    }
}

function submitReport($responseId, $reporterSession, $reportType, $description = '', $questionText = '', $responseText = '', $reporterId = null) {
    $db = getDBConnection();
    
    if (!getSetting('reporting_enabled', true)) {
        return [false, 'Reporting system is currently disabled'];
    }
    
    $maxReportsPerDay = getSetting('max_reports_per_user_per_day', 10);
    $requireDescription = getSetting('require_description', false);
    
    if ($requireDescription && empty(trim($description))) {
        return [false, 'Description is required when submitting a report'];
    }
    
    try {
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM ai_response_reports 
                             WHERE reporter_session = ? AND DATE(created_at) = CURDATE()");
        $stmt->bind_param("s", $reporterSession);
        $stmt->execute();
        $result = $stmt->get_result();
        $count = $result->fetch_assoc()['count'];
        $stmt->close();
        
        if ($count >= $maxReportsPerDay) {
            return [false, "You have reached the maximum number of reports per day ($maxReportsPerDay)"];
        }
        
        $stmt = $db->prepare("INSERT INTO ai_response_reports 
                             (response_id, reporter_id, reporter_session, reporter_ip, report_type, 
                              description, question_text, response_text) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("iissssss",
            $responseId,
            $reporterId,
            $reporterSession,
            getClientIP(),
            $reportType,
            $description,
            $questionText,
            $responseText
        );
        $stmt->execute();
        $reportId = $db->insert_id;
        $stmt->close();
        
        $stmt = $db->prepare("UPDATE ai_responses SET reporting_count = reporting_count + 1 
                             WHERE id = ?");
        $stmt->bind_param("i", $responseId);
        $stmt->execute();
        $stmt->close();
        
        $notificationEmail = getSetting('notification_email', 'admin@example.com');
        
        $autoClose = getSetting('auto_close_false_reports', true);
        if ($autoClose) {
            $stmt = $db->prepare("SELECT COUNT(*) as count FROM ai_response_reports 
                                 WHERE response_id = ? AND is_false_report = 1");
            $stmt->bind_param("i", $responseId);
            $stmt->execute();
            $result = $stmt->get_result();
            $falseCount = $result->fetch_assoc()['count'];
            $stmt->close();
            
            if ($falseCount >= 3) {
                $stmt = $db->prepare("UPDATE ai_response_reports SET status = 'false' 
                                     WHERE report_id = ?");
                $stmt->bind_param("i", $reportId);
                $stmt->execute();
                $stmt->close();
                
                logEvent('report', "Report auto-closed as false (report_id: $reportId)", $reporterId, 'info');
            }
        }
        
        logEvent('report', "New report submitted (report_id: $reportId, type: $reportType)", $reporterId, 'info');
        
        return [true, 'Report submitted successfully', $reportId];
        
    } catch (Exception $e) {
        error_log("Submit report failed: " . $e->getMessage());
        logEvent('error', "Submit report failed: " . $e->getMessage(), $reporterId, 'error');
        return [false, "Failed to submit report: " . $e->getMessage()];
    }
}

function suggestCorrection($responseId, $reportId, $suggestedBy, $correctionText, $reasoning = '') {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT response_text FROM ai_responses WHERE id = ?");
        $stmt->bind_param("i", $responseId);
        $stmt->execute();
        $result = $stmt->get_result();
        $response = $result->fetch_assoc();
        $stmt->close();
        
        if (!$response) {
            return [false, 'Response not found'];
        }
        
        $approvalType = getSetting('approval_type', 'manual');
        $adminApproved = ($approvalType === 'auto') ? 1 : 0;
        $isActive = ($approvalType === 'auto') ? 1 : 0;
        $approvedAt = ($approvalType === 'auto') ? date('Y-m-d H:i:s') : null;
        $activatedAt = ($approvalType === 'auto') ? date('Y-m-d H:i:s') : null;
        
        $stmt = $db->prepare("INSERT INTO response_corrections 
                             (response_id, report_id, suggested_by, correction_text, 
                              original_response_text, reasoning, admin_approved, 
                              approved_by, approved_at, activated_at, is_active) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $approvedBy = $user_type = $_SESSION['user_id'] ?? null;
        $stmt->bind_param("iisssiissii",
            $responseId,
            $reportId,
            $suggestedBy,
            $correctionText,
            $response['response_text'],
            $reasoning,
            $adminApproved,
            $approvedBy,
            $approvedAt,
            $activatedAt,
            $isActive
        );
        $stmt->execute();
        $correctionId = $db->insert_id;
        $stmt->close();
        
        $stmt = $db->prepare("UPDATE ai_responses SET correction_count = correction_count + 1 
                             WHERE id = ?");
        $stmt->bind_param("i", $responseId);
        $stmt->execute();
        $stmt->close();
        
        if ($approvalType === 'auto') {
            $stmt = $db->prepare("SELECT version FROM ai_responses WHERE id = ?");
            $stmt->bind_param("i", $responseId);
            $stmt->execute();
            $result = $stmt->get_result();
            $versionInfo = $result->fetch_assoc();
            $currentVersion = $versionInfo['version'];
            $stmt->close();
            
            $stmt = $db->prepare("INSERT INTO response_versions 
                                 (response_id, version_number, response_text, changed_by, change_reason) 
                                 VALUES (?, ?, ?, ?, ?)");
            $changeReason = "Auto-approved correction (ID: $correctionId)";
            $stmt->bind_param("iisis",
                $responseId,
                $currentVersion,
                $response['response_text'],
                $suggestedBy,
                $changeReason
            );
            $stmt->execute();
            $stmt->close();
            
            $stmt = $db->prepare("UPDATE ai_responses SET response_text = ?, version = version + 1 
                                 WHERE id = ?");
            $stmt->bind_param("si", $correctionText, $responseId);
            $stmt->execute();
            $stmt->close();
            
            $stmt = $db->prepare("UPDATE response_corrections SET activated_at = NOW() 
                                 WHERE correction_id = ?");
            $stmt->bind_param("i", $correctionId);
            $stmt->execute();
            $stmt->close();
            
            if ($reportId) {
                $stmt = $db->prepare("UPDATE ai_response_reports SET status = 'closed' 
                                     WHERE report_id = ?");
                $stmt->bind_param("i", $reportId);
                $stmt->execute();
                $stmt->close();
            }
            
            logEvent('correction', "Correction auto-approved and applied (correction_id: $correctionId)", $suggestedBy, 'info');
        } else {
            logEvent('correction', "Correction suggested (correction_id: $correctionId, pending approval)", $suggestedBy, 'info');
        }
        
        return [true, 'Correction submitted successfully', $correctionId];
        
    } catch (Exception $e) {
        error_log("Suggest correction failed: " . $e->getMessage());
        logEvent('error', "Suggest correction failed: " . $e->getMessage(), $suggestedBy, 'error');
        return [false, "Failed to submit correction: " . $e->getMessage()];
    }
}

function approveCorrection($correctionId, $approvedBy, $approve = true) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT rc.*, ar.response_text as original_response 
                             FROM response_corrections rc 
                             INNER JOIN ai_responses ar ON rc.response_id = ar.id 
                             WHERE rc.correction_id = ? AND rc.admin_approved = 0");
        $stmt->bind_param("i", $correctionId);
        $stmt->execute();
        $result = $stmt->get_result();
        $correction = $result->fetch_assoc();
        $stmt->close();
        
        if (!$correction) {
            return [false, 'Correction not found or already processed'];
        }
        
        if ($approve) {
            $stmt = $db->prepare("SELECT version FROM ai_responses WHERE id = ?");
            $stmt->bind_param("i", $correction['response_id']);
            $stmt->execute();
            $result = $stmt->get_result();
            $versionInfo = $result->fetch_assoc();
            $currentVersion = $versionInfo['version'];
            $stmt->close();
            
            $stmt = $db->prepare("INSERT INTO response_versions 
                                 (response_id, version_number, response_text, changed_by, change_reason) 
                                 VALUES (?, ?, ?, ?, ?)");
            $changeReason = "Correction approved (ID: $correctionId)";
            $stmt->bind_param("iisis",
                $correction['response_id'],
                $currentVersion,
                $correction['original_response_text'],
                $approvedBy,
                $changeReason
            );
            $stmt->execute();
            $stmt->close();
            
            $stmt = $db->prepare("UPDATE ai_responses SET response_text = ?, version = version + 1 
                                 WHERE id = ?");
            $stmt->bind_param("si", $correction['correction_text'], $correction['response_id']);
            $stmt->execute();
            $stmt->close();
            
            $stmt = $db->prepare("UPDATE response_corrections SET 
                                 admin_approved = 1, approved_by = ?, approved_at = NOW(), 
                                 activated_at = NOW(), is_active = 1 
                                 WHERE correction_id = ?");
            $stmt->bind_param("ii", $approvedBy, $correctionId);
            $stmt->execute();
            $stmt->close();
            
            if ($correction['report_id']) {
                $stmt = $db->prepare("UPDATE ai_response_reports SET status = 'closed' 
                                     WHERE report_id = ?");
                $stmt->bind_param("i", $correction['report_id']);
                $stmt->execute();
                $stmt->close();
            }
            
            logEvent('correction', "Correction approved and applied (correction_id: $correctionId)", $approvedBy, 'info');
            
            return [true, 'Correction approved and applied successfully'];
        } else {
            $stmt = $db->prepare("UPDATE response_corrections SET admin_approved = 1, approved_by = ?, approved_at = NOW() 
                                 WHERE correction_id = ?");
            $disapprovedValue = 2;
            $stmt->bind_param("ii", $approvedBy, $correctionId);
            $stmt->execute();
            $stmt->close();
            
            if ($correction['report_id']) {
                $stmt = $db->prepare("UPDATE ai_response_reports SET status = 'closed' 
                                     WHERE report_id = ?");
                $stmt->bind_param("i", $correction['report_id']);
                $stmt->execute();
                $stmt->close();
            }
            
            logEvent('correction', "Correction rejected (correction_id: $correctionId)", $approvedBy, 'info');
            
            return [true, 'Correction rejected'];
        }
        
    } catch (Exception $e) {
        error_log("Approve correction failed: " . $e->getMessage());
        logEvent('error', "Approve correction failed: " . $e->getMessage(), $approvedBy, 'error');
        return [false, "Failed to process correction: " . $e->getMessage()];
    }
}

function getReportStats() {
    $db = getDBConnection();
    
    try {
        $stats = [];
        
        $result = $db->query("SELECT 
            COUNT(*) as total_reports,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_reports,
            SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified_reports,
            SUM(CASE WHEN status = 'false' THEN 1 ELSE 0 END) as false_reports,
            SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closed_reports,
            COUNT(DISTINCT DATE(created_at)) as days_with_reports,
            COUNT(DISTINCT reporter_ip) as unique_reporters
            FROM ai_response_reports");
        $stats = $result->fetch_assoc();
        
        $result = $db->query("SELECT report_type, COUNT(*) as count 
                              FROM ai_response_reports 
                              GROUP BY report_type");
        $stats['by_type'] = [];
        while ($row = $result->fetch_assoc()) {
            $stats['by_type'][$row['report_type']] = $row['count'];
        }
        
        $result = $db->query("SELECT DATE(created_at) as report_date, COUNT(*) as count 
                              FROM ai_response_reports 
                              WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) 
                              GROUP BY DATE(created_at) 
                              ORDER BY report_date DESC");
        $stats['daily_trend'] = [];
        while ($row = $result->fetch_assoc()) {
            $stats['daily_trend'][$row['report_date']] = $row['count'];
        }
        
        $result = $db->query("SELECT 
            AVG(response_time) as avg_response_time,
            MIN(response_time) as min_response_time,
            MAX(response_time) as max_response_time
            FROM (
                SELECT TIMESTAMPDIFF(HOUR, created_at, resolved_at) as response_time
                FROM ai_response_reports 
                WHERE resolved_at IS NOT NULL AND status = 'closed'
            ) as response_times");
        $response_time_stats = $result->fetch_assoc();
        $stats['response_time'] = $response_time_stats;
        
        $result = $db->query("SELECT COUNT(*) as total_corrections,
                              SUM(CASE WHEN admin_approved = 1 THEN 1 ELSE 0 END) as approved_corrections,
                              SUM(CASE WHEN admin_approved = 0 THEN 1 ELSE 0 END) as pending_corrections,
                              SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_corrections
                              FROM response_corrections");
        $correction_stats = $result->fetch_assoc();
        $stats = array_merge($stats, $correction_stats);
        
        return $stats;
        
    } catch (Exception $e) {
        error_log("Get report stats failed: " . $e->getMessage());
        return [];
    }
}

function getReports($filters = []) {
    $db = getDBConnection();
    
    $sql = "SELECT arr.*, 
                   rr.correction_id, rr.correction_text, rr.admin_approved, rr.is_active,
                   ru.username as reporter_username, ru.full_name as reporter_name,
                   rbu.username as resolved_by_username, rbu.full_name as resolved_by_name
            FROM ai_response_reports arr
            LEFT JOIN response_corrections rr ON arr.report_id = rr.report_id
            LEFT JOIN users ru ON arr.reporter_id = ru.id
            LEFT JOIN users rbu ON arr.resolved_by = rbu.id
            WHERE 1=1";
    
    $params = [];
    $types = "";
    
    if (!empty($filters['status'])) {
        $sql .= " AND arr.status = ?";
        $params[] = $filters['status'];
        $types .= "s";
    }
    
    if (!empty($filters['report_type'])) {
        $sql .= " AND arr.report_type = ?";
        $params[] = $filters['report_type'];
        $types .= "s";
    }
    
    if (!empty($filters['priority'])) {
        $sql .= " AND arr.priority = ?";
        $params[] = $filters['priority'];
        $types .= "i";
    }
    
    if (!empty($filters['reporter_id'])) {
        $sql .= " AND arr.reporter_id = ?";
        $params[] = $filters['reporter_id'];
        $types .= "i";
    }
    
    if (!empty($filters['date_from'])) {
        $sql .= " AND DATE(arr.created_at) >= ?";
        $params[] = $filters['date_from'];
        $types .= "s";
    }
    
    if (!empty($filters['date_to'])) {
        $sql .= " AND DATE(arr.created_at) <= ?";
        $params[] = $filters['date_to'];
        $types .= "s";
    }
    
    $sql .= " ORDER BY 
        CASE arr.status 
            WHEN 'pending' THEN 1 
            WHEN 'verified' THEN 2 
            WHEN 'false' THEN 3 
            ELSE 4 
        END,
        arr.priority DESC,
        arr.created_at DESC";
    
    if (!empty($filters['limit'])) {
        $sql .= " LIMIT ?";
        $params[] = $filters['limit'];
        $types .= "i";
    }
    
    try {
        $stmt = $db->prepare($sql);
        if ($params) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        
        $reports = [];
        while ($row = $result->fetch_assoc()) {
            $reports[] = $row;
        }
        
        $stmt->close();
        return $reports;
        
    } catch (Exception $e) {
        error_log("Get reports failed: " . $e->getMessage());
        return [];
    }
}

function updateReport($reportId, $status, $userId, $resolutionNotes = '') {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("UPDATE ai_response_reports SET status = ?, resolved_by = ?, 
                             resolved_at = NOW(), resolution_notes = ? WHERE report_id = ?");
        $stmt->bind_param("sisi",
            $status,
            $userId,
            $resolutionNotes,
            $reportId
        );
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        
        if ($affected > 0) {
            logEvent('report', "Report status updated (report_id: $reportId, status: $status)", $userId, 'info');
        }
        
        return $affected > 0;
        
    } catch (Exception $e) {
        error_log("Update report failed: " . $e->getMessage());
        logEvent('error', "Update report failed: " . $e->getMessage(), $userId, 'error');
        return false;
    }
}

function isAdmin() {
    return isset($_SESSION['user_type']) && $_SESSION['user_type'] === 'admin';
}

function isStaff() {
    return isset($_SESSION['user_type']) && ($_SESSION['user_type'] === 'staff' || $_SESSION['user_type'] === 'admin');
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getUserType() {
    return $_SESSION['user_type'] ?? 'public';
}

startSecureSession();

$db = initDatabase();

$action = $_POST['action'] ?? $_GET['action'] ?? 'view_home';

$csrfToken = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';

header('Content-Type: application/json');

switch ($action) {
    case 'login':
        [$allowed, $count, $retryAfter] = checkRateLimit(getClientIP(), 'ip');
        if (!$allowed) {
            http_response_code(429);
            echo json_encode(['success' => false, 'message' => "Too many login attempts. Please try again in $retryAfter seconds."]);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'login')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        [$success, $message, $user] = loginUser($username, $password);
        
        echo json_encode(['success' => $success, 'message' => $message, 'user' => $user ? ['id' => $user['id'], 'username' => $user['username'], 'user_type' => $user['user_type']] : null]);
        break;
        
    case 'logout':
        $result = logoutUser();
        echo json_encode(['success' => $result]);
        break;
        
    case 'chat':
        [$allowed, $count, $retryAfter] = checkRateLimit(getCurrentSessionId(), 'session');
        if (!$allowed) {
            http_response_code(429);
            echo json_encode(['success' => false, 'message' => "Rate limit exceeded. Please wait $retryAfter seconds."]);
            exit;
        }
        
        $sessionId = getCurrentSessionId();
        $question = $_POST['question'] ?? '';
        $userId = $_SESSION['user_id'] ?? null;
        
        if (empty($question)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Question is required']);
            exit;
        }
        
        saveChatMessage($sessionId, 'user', $question);
        $question = filterContent($question);
        
        $response = generateAIResponse($question, $sessionId, $userId);
        
        if (empty($response['error'])) {
            saveChatMessage($sessionId, 'ai', $response['response'], json_encode(['response_id' => $response['response_id']]));
        }
        
        echo json_encode([
            'success' => true,
            'question' => $question,
            'response' => $response['response'],
            'confidence' => $response['confidence'],
            'cached' => $response['cached'] ?? false,
            'response_id' => $response['response_id'] ?? null,
            'session_id' => $sessionId
        ]);
        break;
        
    case 'rate_response':
        if (!isLoggedIn()) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'Authentication required']);
            exit;
        }
        
        $responseId = $_POST['response_id'] ?? null;
        $rating = $_POST['rating'] ?? null;
        $feedback = $_POST['feedback'] ?? null;
        
        if ($responseId === null || $rating === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Response ID and rating are required']);
            exit;
        }
        
        $ratingId = rateResponse($responseId, getCurrentSessionId(), $_POST['question'] ?? '', 
                                $_POST['response_text'] ?? '', $rating, $feedback, $_SESSION['user_id'] ?? null);
        
        if ($ratingId) {
            echo json_encode(['success' => true, 'message' => 'Rating submitted successfully']);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to submit rating']);
        }
        break;
        
    case 'report_response':
        $responseId = $_POST['response_id'] ?? null;
        $reportType = $_POST['report_type'] ?? 'incorrect';
        $description = $_POST['description'] ?? '';
        $questionText = $_POST['question_text'] ?? '';
        $responseText = $_POST['response_text'] ?? '';
        
        if ($responseId === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Response ID is required']);
            exit;
        }
        
        [$success, $message, $reportId] = submitReport($responseId, getCurrentSessionId(), 
            $reportType, $description, $questionText, $responseText, $_SESSION['user_id'] ?? null);
        
        if ($success) {
            echo json_encode(['success' => true, 'message' => $message, 'report_id' => $reportId]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $message]);
        }
        break;
        
    case 'upload_document':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'upload_document')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        if (empty($_FILES['document'])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'No file uploaded']);
            exit;
        }
        
        $metadata = [
            'title' => $_POST['title'] ?? '',
            'description' => $_POST['description'] ?? '',
            'category' => $_POST['category'] ?? '',
            'tags' => $_POST['tags'] ?? ''
        ];
        
        [$success, $message, $documentId] = uploadDocument($_FILES['document'], $metadata, $_SESSION['user_id'] ?? null);
        
        if ($success) {
            echo json_encode(['success' => true, 'message' => $message, 'document_id' => $documentId]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $message]);
        }
        break;
        
    case 'delete_document':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'delete_document')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $documentId = $_POST['document_id'] ?? null;
        
        if ($documentId === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Document ID is required']);
            exit;
        }
        
        [$success, $message] = deleteDocument($documentId);
        
        if ($success) {
            echo json_encode(['success' => true, 'message' => $message]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $message]);
        }
        break;
        
    case 'get_dashboard_stats':
        if (!isLoggedIn()) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'Authentication required']);
            exit;
        }
        
        $stats = getDashboardStats();
        echo json_encode(['success' => true, 'stats' => $stats]);
        break;
        
    case 'get_system_logs':
        if (!isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        $filters = [
            'log_type' => $_GET['log_type'] ?? null,
            'severity' => $_GET['severity'] ?? null,
            'date' => $_GET['date'] ?? null,
            'date_from' => $_GET['date_from'] ?? null,
            'date_to' => $_GET['date_to'] ?? null,
            'limit' => $_GET['limit'] ?? 100
        ];
        
        $filters = array_filter($filters);
        
        $logs = getSystemLogs($filters);
        echo json_encode(['success' => true, 'logs' => $logs]);
        break;
        
    case 'clear_old_logs':
        if (!isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'clear_logs')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $days = $_POST['days'] ?? 30;
        $deleted = clearOldLogs($days);
        
        if ($deleted !== false) {
            echo json_encode(['success' => true, 'message' => "Cleared $deleted logs", 'deleted' => $deleted]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to clear logs']);
        }
        break;
        
    case 'get_reports':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        $filters = [
            'status' => $_GET['status'] ?? null,
            'report_type' => $_GET['report_type'] ?? null,
            'priority' => $_GET['priority'] ?? null,
            'reporter_id' => $_GET['reporter_id'] ?? null,
            'date_from' => $_GET['date_from'] ?? null,
            'date_to' => $_GET['date_to'] ?? null,
            'limit' => $_GET['limit'] ?? 50
        ];
        
        $filters = array_filter($filters);
        
        $reports = getReports($filters);
        $stats = getReportStats();
        
        echo json_encode(['success' => true, 'reports' => $reports, 'stats' => $stats]);
        break;
        
    case 'update_report':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'update_report')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $reportId = $_POST['report_id'] ?? null;
        $status = $_POST['status'] ?? 'verified';
        $resolutionNotes = $_POST['resolution_notes'] ?? '';
        
        if ($reportId === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Report ID is required']);
            exit;
        }
        
        $result = updateReport($reportId, $status, $_SESSION['user_id'], $resolutionNotes);
        
        if ($result) {
            echo json_encode(['success' => true, 'message' => 'Report updated successfully']);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to update report']);
        }
        break;
        
    case 'suggest_correction':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'suggest_correction')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $responseId = $_POST['response_id'] ?? null;
        $reportId = $_POST['report_id'] ?? null;
        $correctionText = $_POST['correction_text'] ?? '';
        $reasoning = $_POST['reasoning'] ?? '';
        
        if ($responseId === null || empty($correctionText)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Response ID and correction text are required']);
            exit;
        }
        
        [$success, $message, $correctionId] = suggestCorrection($responseId, $reportId, 
            $_SESSION['user_id'], $correctionText, $reasoning);
        
        if ($success) {
            echo json_encode(['success' => true, 'message' => $message, 'correction_id' => $correctionId]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $message]);
        }
        break;
        
    case 'approve_correction':
        if (!isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'approve_correction')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $correctionId = $_POST['correction_id'] ?? null;
        $approve = $_POST['approve'] ?? true;
        
        if ($correctionId === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Correction ID is required']);
            exit;
        }
        
        [$success, $message] = approveCorrection($correctionId, $_SESSION['user_id'], $approve);
        
        if ($success) {
            echo json_encode(['success' => true, 'message' => $message]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $message]);
        }
        break;
        
    case 'get_report_stats':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        $stats = getReportStats();
        echo json_encode(['success' => true, 'stats' => $stats]);
        break;
        
    case 'get_documents':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        $filters = [
            'status' => $_GET['status'] ?? null,
            'category' => $_GET['category'] ?? null,
            'processed' => isset($_GET['processed']) ? (int)$_GET['processed'] : null,
            'uploaded_by' => $_GET['uploaded_by'] ?? null,
            'date_from' => $_GET['date_from'] ?? null,
            'date_to' => $_GET['date_to'] ?? null
        ];
        
        $filters = array_filter($filters, function($value) {
            return $value !== null && $value !== '';
        });
        
        $documents = getDocuments($filters);
        echo json_encode(['success' => true, 'documents' => $documents]);
        break;
        
    case 'get_users':
        if (!isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        $filters = [
            'user_type' => $_GET['user_type'] ?? null,
            'is_active' => isset($_GET['is_active']) ? (int)$_GET['is_active'] : null,
            'search' => $_GET['search'] ?? null
        ];
        
        $filters = array_filter($filters, function($value) {
            return $value !== null && $value !== '';
        });
        
        $users = getAllUsers($filters);
        echo json_encode(['success' => true, 'users' => $users]);
        break;
        
    case 'update_user':
        if (!isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'update_user')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $userId = $_POST['user_id'] ?? null;
        
        if ($userId === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'User ID is required']);
            exit;
        }
        
        $userData = [];
        $fields = ['email', 'full_name', 'department', 'user_type', 'is_active', 'phone'];
        foreach ($fields as $field) {
            if (isset($_POST[$field])) {
                $userData[$field] = $_POST[$field];
            }
        }
        
        if (isset($_POST['password']) && !empty($_POST['password'])) {
            $passwordValidation = validatePassword($_POST['password']);
            if ($passwordValidation !== true) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => $passwordValidation]);
                exit;
            }
            $userData['password_hash'] = hashPassword($_POST['password']);
        }
        
        $result = updateUser($userId, $userData);
        
        if ($result) {
            echo json_encode(['success' => true, 'message' => 'User updated successfully']);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to update user or no changes made']);
        }
        break;
        
    case 'delete_user':
        if (!isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        if (!validateCSRFToken($csrfToken, 'delete_user')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
            exit;
        }
        
        $userId = $_POST['user_id'] ?? null;
        
        if ($userId === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'User ID is required']);
            exit;
        }
        
        [$success, $message] = deleteUser($userId);
        
        if ($success) {
            echo json_encode(['success' => true, 'message' => $message]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $message]);
        }
        break;
        
    case 'get_storage_stats':
        if (!isStaff()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Access denied']);
            exit;
        }
        
        $stats = getStorageStats();
        echo json_encode(['success' => true, 'stats' => $stats]);
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}
?>