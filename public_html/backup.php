<?php
// Enable detailed error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/php_errors.log');

// Test if we can write to directory
$test_file = __DIR__ . '/test_write.txt';
if (file_put_contents($test_file, 'test') !== false) {
    unlink($test_file);
} else {
    die("Cannot write to directory. Please check permissions.");
}

// ============================================
// DATABASE CONFIGURATION (MySQL on Hostinger)
// ============================================

define('DB_HOST', 'localhost'); // Hostinger uses localhost
define('DB_NAME', 'u182854778_target2030');
define('DB_USER', 'u182854778_djyoti2030');
define('DB_PASS', 'DkRewa@#1995');
define('DB_CHARSET', 'utf8mb4');

define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
define('ALLOWED_TYPES', ['pdf', 'txt', 'doc', 'docx', 'csv', 'md', 'rtf']);
define('SESSION_LIFETIME', 24 * 60 * 60); // 24 hours

// Set session lifetime
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
session_set_cookie_params(SESSION_LIFETIME);

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Create necessary directories
@mkdir(UPLOAD_DIR, 0755, true);
@mkdir(UPLOAD_DIR . 'documents/', 0755, true);
@mkdir(UPLOAD_DIR . 'temp/', 0755, true);

// ============================================
// DATABASE CONNECTION (MySQL)
// ============================================

function getDBConnection() {
    static $db = null;
    
    if ($db === null) {
        try {
            $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
            
            if ($db->connect_error) {
                throw new Exception("MySQL Connection failed: " . $db->connect_error);
            }
            
            $db->set_charset(DB_CHARSET);
            
        } catch (Exception $e) {
            error_log("Database connection error: " . $e->getMessage());
            die("Database connection failed. Please check configuration.");
        }
    }
    
    return $db;
}

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
                user_type VARCHAR(20) NOT NULL DEFAULT 'user',
                full_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active TINYINT(1) DEFAULT 1,
                last_login DATETIME,
                INDEX idx_user_type (user_type),
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'documents' => "CREATE TABLE IF NOT EXISTS documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                filepath VARCHAR(500) NOT NULL,
                file_type VARCHAR(50) NOT NULL,
                file_size INT,
                content_text TEXT,
                processed TINYINT(1) DEFAULT 0,
                uploaded_by INT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending',
                is_deleted TINYINT(1) DEFAULT 0,
                INDEX idx_processed (processed),
                INDEX idx_uploaded_by (uploaded_by),
                INDEX idx_is_deleted (is_deleted),
                FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'knowledge_base' => "CREATE TABLE IF NOT EXISTS knowledge_base (
                id INT AUTO_INCREMENT PRIMARY KEY,
                document_id INT,
                content_chunk TEXT NOT NULL,
                chunk_hash VARCHAR(32) UNIQUE,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_chunk_hash (chunk_hash),
                INDEX idx_document_id (document_id),
                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'chat_sessions' => "CREATE TABLE IF NOT EXISTS chat_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id VARCHAR(100) UNIQUE NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                country VARCHAR(50),
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                message_count INT DEFAULT 0,
                INDEX idx_ip_address (ip_address),
                INDEX idx_started_at (started_at)
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
                FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'ai_training' => "CREATE TABLE IF NOT EXISTS ai_training (
                id INT AUTO_INCREMENT PRIMARY KEY,
                question TEXT NOT NULL,
                question_hash VARCHAR(32) UNIQUE,
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
                FOREIGN KEY (trained_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'system_logs' => "CREATE TABLE IF NOT EXISTS system_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                log_type VARCHAR(50) NOT NULL,
                message TEXT NOT NULL,
                ip_address VARCHAR(45),
                user_id INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_log_type (log_type),
                INDEX idx_created_at (created_at),
                INDEX idx_user_id (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'api_keys' => "CREATE TABLE IF NOT EXISTS api_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                api_key VARCHAR(64) UNIQUE NOT NULL,
                domain VARCHAR(255) NOT NULL,
                user_id INT,
                is_active TINYINT(1) DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                usage_count INT DEFAULT 0,
                INDEX idx_api_key (api_key),
                INDEX idx_domain (domain),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            
            'response_ratings' => "CREATE TABLE IF NOT EXISTS response_ratings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                message_id INT,
                session_id VARCHAR(100) NOT NULL,
                question TEXT NOT NULL,
                response TEXT NOT NULL,
                rating TINYINT(1) NOT NULL COMMENT '1=helpful, 0=not helpful',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_session_id (session_id),
                INDEX idx_rating (rating),
                INDEX idx_message_id (message_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        ];
        
        foreach ($tables as $table => $sql) {
            $db->query($sql);
        }
        
        // Create default admin user if not exists
        $check = $db->query("SELECT COUNT(*) as count FROM users WHERE username = 'admin'");
        $result = $check->fetch_assoc();
        
        if ($result['count'] == 0) {
            $stmt = $db->prepare("INSERT INTO users (username, password_hash, user_type, full_name, email) 
                                  VALUES (?, ?, 'admin', 'Administrator', ?)");
            $stmt->bind_param("sss", 
                $username, 
                $password_hash, 
                $email
            );
            
            $username = 'admin';
            $password_hash = password_hash('admin123', PASSWORD_DEFAULT);
            $email = 'admin@example.com';
            $stmt->execute();
            $stmt->close();
            
            logEvent('system', 'Default admin account created');
        }
        
        return $db;
        
    } catch (Exception $e) {
        error_log("Database initialization failed: " . $e->getMessage());
        die("Database initialization failed. Please check MySQL permissions and configuration.");
    }
}

// Initialize database
$db = initDatabase();

// ============================================
// SECURITY & HELPER FUNCTIONS
// ============================================

function sanitize($input) {
    if (is_array($input)) {
        return array_map('sanitize', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function generateSessionId() {
    return session_id() . '_' . bin2hex(random_bytes(8));
}

function generateApiKey() {
    return bin2hex(random_bytes(32));
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
            $ip = trim(current(explode(',', $_SERVER[$header])));
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    
    return '0.0.0.0';
}

function getCountryFromIP($ip) {
    if ($ip === '127.0.0.1' || $ip === '::1' || $ip === '0.0.0.0') {
        return 'Local';
    }
    
    // Simple IP to country mapping (in production, use a proper service)
    $ip_parts = explode('.', $ip);
    if (count($ip_parts) >= 2) {
        $countries = ['US', 'GB', 'CA', 'AU', 'IN', 'DE', 'FR', 'JP', 'BR', 'CN'];
        $index = intval($ip_parts[1]) % count($countries);
        return $countries[$index];
    }
    
    return 'Unknown';
}

function logEvent($type, $message, $userId = null) {
    $db = getDBConnection();
    try {
        $stmt = $db->prepare("INSERT INTO system_logs (log_type, message, ip_address, user_id) 
                              VALUES (?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("sssi", 
                $type, 
                $message, 
                $ip, 
                $userId
            );
            $ip = getClientIP();
            $stmt->execute();
            $stmt->close();
        }
    } catch (Exception $e) {
        error_log("Log event failed: " . $e->getMessage());
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

function getSessionId() {
    if (!isset($_SESSION['chat_session_id'])) {
        $_SESSION['chat_session_id'] = generateSessionId();
        
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
            $country = getCountryFromIP(getClientIP());
            $stmt->execute();
            $stmt->close();
            
            logEvent('session', 'New chat session started', $_SESSION['user_id'] ?? null);
        } catch (Exception $e) {
            error_log("Session creation failed: " . $e->getMessage());
        }
    }
    return $_SESSION['chat_session_id'];
}

// ============================================
// DOCUMENT MANAGEMENT FUNCTIONS
// ============================================

function deleteDocument($documentId) {
    $db = getDBConnection();
    
    try {
        // Get document details first
        $stmt = $db->prepare("SELECT filepath FROM documents WHERE id = ? AND is_deleted = 0");
        $stmt->bind_param("i", $documentId);
        $stmt->execute();
        $result = $stmt->get_result();
        $document = $result->fetch_assoc();
        $stmt->close();
        
        if (!$document) {
            return [false, 'Document not found or already deleted'];
        }
        
        // Delete physical file only
        if (file_exists($document['filepath'])) {
            if (!unlink($document['filepath'])) {
                return [false, 'Failed to delete physical file'];
            }
        }
        
        // Mark document as deleted but keep the record
        $stmt = $db->prepare("UPDATE documents SET is_deleted = 1, status = 'deleted' WHERE id = ?");
        $stmt->bind_param("i", $documentId);
        $stmt->execute();
        $stmt->close();
        
        // NOTE: We do NOT delete knowledge base entries - they remain for AI to use
        
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
        // Get total documents count (non-deleted)
        $result = $db->query("SELECT COUNT(*) as total, SUM(file_size) as total_size FROM documents WHERE is_deleted = 0");
        $row = $result->fetch_assoc();
        $stats['total_documents'] = intval($row['total'] ?? 0);
        $stats['total_size'] = intval($row['total_size'] ?? 0);
        
        // Get deleted documents count
        $result = $db->query("SELECT COUNT(*) as deleted_count, SUM(file_size) as deleted_size FROM documents WHERE is_deleted = 1");
        $row = $result->fetch_assoc();
        $stats['deleted_documents'] = intval($row['deleted_count'] ?? 0);
        $stats['deleted_size'] = intval($row['deleted_size'] ?? 0);
        
        // Get documents by type
        $result = $db->query("SELECT file_type, COUNT(*) as count FROM documents WHERE is_deleted = 0 GROUP BY file_type");
        $stats['by_type'] = [];
        while ($row = $result->fetch_assoc()) {
            $stats['by_type'][] = $row;
        }
        
        // Get available storage (assuming 100MB limit)
        $stats['storage_limit'] = 100 * 1024 * 1024; // 100MB
        $stats['used_percentage'] = $stats['total_size'] > 0 ? 
            round(($stats['total_size'] / $stats['storage_limit']) * 100, 2) : 0;
        
        // Get knowledge base stats
        $result = $db->query("SELECT COUNT(*) as total_chunks FROM knowledge_base");
        $row = $result->fetch_assoc();
        $stats['knowledge_chunks'] = intval($row['total_chunks'] ?? 0);
        
        return $stats;
        
    } catch (Exception $e) {
        error_log("Storage stats failed: " . $e->getMessage());
        return ['error' => $e->getMessage()];
    }
}

// ============================================
// API KEY MANAGEMENT FUNCTIONS
// ============================================

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
        
        // Update usage stats
        $update = $db->prepare("UPDATE api_keys SET last_used = NOW(), usage_count = usage_count + 1 WHERE id = ?");
        $update->bind_param("i", $api_data['id']);
        $update->execute();
        $update->close();
        
        // If domain is provided, check if it matches
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
    
    try {
        $api_key = generateApiKey();
        $stmt = $db->prepare("INSERT INTO api_keys (api_key, domain, user_id) VALUES (?, ?, ?)");
        $stmt->bind_param("ssi", $api_key, $domain, $user_id);
        $stmt->execute();
        $key_id = $db->insert_id;
        $stmt->close();
        
        logEvent('api', "API key created for domain: $domain", $user_id);
        return $api_key;
        
    } catch (Exception $e) {
        error_log("API key creation failed: " . $e->getMessage());
        return false;
    }
}

function revokeApiKey($api_key_id, $user_id = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("UPDATE api_keys SET is_active = 0 WHERE id = ?");
        $stmt->bind_param("i", $api_key_id);
        $stmt->execute();
        $stmt->close();
        
        logEvent('api', "API key revoked: $api_key_id", $user_id);
        return true;
        
    } catch (Exception $e) {
        error_log("API key revocation failed: " . $e->getMessage());
        return false;
    }
}

// ============================================
// RATING SYSTEM FUNCTIONS
// ============================================

function rateResponse($message_id, $session_id, $question, $response, $rating) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO response_ratings (message_id, session_id, question, response, rating) 
                              VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("isssi", $message_id, $session_id, $question, $response, $rating);
        $stmt->execute();
        $rating_id = $db->insert_id;
        $stmt->close();
        
        // Also update AI training helpful counts if this response matches trained ones
        $question_hash = md5(strtolower(trim($question)));
        
        // Find similar trained questions
        $stmt = $db->prepare("SELECT id, helpful_count, not_helpful_count FROM ai_training 
                              WHERE question_hash = ? OR question LIKE ? 
                              LIMIT 1");
        $like_param = '%' . $question . '%';
        $stmt->bind_param("ss", $question_hash, $like_param);
        $stmt->execute();
        $result = $stmt->get_result();
        $training = $result->fetch_assoc();
        $stmt->close();
        
        if ($training) {
            if ($rating == 1) {
                $update = $db->prepare("UPDATE ai_training SET helpful_count = helpful_count + 1 WHERE id = ?");
            } else {
                $update = $db->prepare("UPDATE ai_training SET not_helpful_count = not_helpful_count + 1 WHERE id = ?");
            }
            $update->bind_param("i", $training['id']);
            $update->execute();
            $update->close();
        }
        
        logEvent('rating', "Response rated: " . ($rating == 1 ? 'Helpful' : 'Not Helpful'), null);
        
        return $rating_id;
        
    } catch (Exception $e) {
        error_log("Rating failed: " . $e->getMessage());
        return false;
    }
}

function getResponseRatingStats($message_id = null) {
    $db = getDBConnection();
    
    try {
        if ($message_id) {
            $stmt = $db->prepare("SELECT 
                SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as helpful,
                SUM(CASE WHEN rating = 0 THEN 1 ELSE 0 END) as not_helpful
                FROM response_ratings WHERE message_id = ?");
            $stmt->bind_param("i", $message_id);
        } else {
            $stmt = $db->prepare("SELECT 
                SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as helpful,
                SUM(CASE WHEN rating = 0 THEN 1 ELSE 0 END) as not_helpful
                FROM response_ratings");
        }
        
        $stmt->execute();
        $result = $stmt->get_result();
        $stats = $result->fetch_assoc();
        $stmt->close();
        
        return [
            'helpful' => intval($stats['helpful'] ?? 0),
            'not_helpful' => intval($stats['not_helpful'] ?? 0),
            'total' => (intval($stats['helpful'] ?? 0) + intval($stats['not_helpful'] ?? 0))
        ];
        
    } catch (Exception $e) {
        error_log("Rating stats failed: " . $e->getMessage());
        return ['helpful' => 0, 'not_helpful' => 0, 'total' => 0];
    }
}

// ============================================
// DOCUMENT PROCESSING FUNCTIONS
// ============================================

function extractTextFromFile($filepath, $filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $content = '';
    
    try {
        switch ($extension) {
            case 'txt':
            case 'md':
            case 'csv':
            case 'rtf':
                $content = file_get_contents($filepath);
                if ($content === false) {
                    throw new Exception("Failed to read file");
                }
                break;
                
            case 'pdf':
                $content = extractTextFromPDF($filepath);
                break;
                
            case 'doc':
            case 'docx':
                $content = extractTextFromDOC($filepath, $extension);
                break;
                
            default:
                throw new Exception("Unsupported file type: $extension");
        }
        
        // Clean up content
        $content = preg_replace('/\s+/', ' ', $content);
        $content = trim($content);
        
        return $content;
        
    } catch (Exception $e) {
        return "Error extracting text from $filename: " . $e->getMessage();
    }
}

function extractTextFromPDF($filepath) {
    // Pure PHP PDF text extraction without external libraries
    $content = '';
    
    if (!file_exists($filepath)) {
        return "PDF file not found";
    }
    
    $file = fopen($filepath, 'rb');
    if (!$file) {
        return "Cannot open PDF file";
    }
    
    // Read PDF header
    $header = fread($file, 8);
    if (strpos($header, '%PDF') !== 0) {
        fclose($file);
        return "Invalid PDF file";
    }
    
    // Simple text extraction from PDF
    $pdf_content = file_get_contents($filepath);
    fclose($file);
    
    // Extract text between parentheses (common in PDFs)
    preg_match_all('/\((.*?)\)/', $pdf_content, $matches);
    if (!empty($matches[1])) {
        foreach ($matches[1] as $match) {
            // Decode PDF string escapes
            $text = preg_replace('/\\\\(.)/', '$1', $match);
            $content .= $text . ' ';
        }
    }
    
    // Also look for text streams
    if (preg_match_all('/stream(.*?)endstream/s', $pdf_content, $stream_matches)) {
        foreach ($stream_matches[1] as $stream) {
            // Try to extract readable text
            $clean_stream = preg_replace('/[^\x20-\x7E\x0A\x0D]/', '', $stream);
            if (strlen($clean_stream) > 50) {
                $content .= $clean_stream . ' ';
            }
        }
    }
    
    if (empty($content)) {
        $content = "PDF content extracted but no readable text found. Consider converting PDF to text first.";
        
        // Try shell command if available (common on Hostinger)
        if (function_exists('shell_exec') && is_callable('shell_exec')) {
            $output = @shell_exec("pdftotext -v 2>&1");
            if (strpos($output, 'pdftotext') !== false) {
                $temp_txt = tempnam(sys_get_temp_dir(), 'pdf_') . '.txt';
                @shell_exec("pdftotext \"$filepath\" \"$temp_txt\" 2>&1");
                if (file_exists($temp_txt)) {
                    $content = file_get_contents($temp_txt);
                    unlink($temp_txt);
                }
            }
        }
    }
    
    return $content ?: "Unable to extract text from PDF. Please upload TXT, DOC, or DOCX files for better results.";
}

function extractTextFromDOC($filepath, $extension) {
    // For DOCX files (ZIP-based)
    if ($extension === 'docx') {
        return extractTextFromDOCX($filepath);
    }
    
    // For DOC files (binary) - provide instructions
    return "DOC file uploaded. For best results, please convert to DOCX or TXT format. " .
           "DOCX files are automatically processed.";
}

function extractTextFromDOCX($filepath) {
    $content = '';
    
    // DOCX is a ZIP file containing XML
    $zip = new ZipArchive;
    if ($zip->open($filepath) === TRUE) {
        // Look for document content
        if (($index = $zip->locateName('word/document.xml')) !== FALSE) {
            $xml_content = $zip->getFromIndex($index);
            // Remove XML tags and get text
            $content = strip_tags($xml_content);
            $content = preg_replace('/\s+/', ' ', $content);
        }
        $zip->close();
    }
    
    if (empty($content)) {
        $content = "DOCX file processed but no text extracted. Please ensure it's a valid Word document.";
    }
    
    return $content;
}

function processDocument($documentId, $filepath, $filename) {
    $db = getDBConnection();
    
    try {
        // Extract text
        $content = extractTextFromFile($filepath, $filename);
        
        if (empty($content) || strlen($content) < 10) {
            throw new Exception("No extractable text found in document");
        }
        
        // Split content into manageable chunks (sentences/paragraphs)
        $chunks = splitIntoChunks($content);
        $chunk_count = 0;
        
        foreach ($chunks as $chunk) {
            $clean_chunk = trim($chunk);
            if (strlen($clean_chunk) < 20) continue;
            
            $chunk_hash = md5($clean_chunk);
            
            // Check if chunk already exists
            $check = $db->prepare("SELECT id FROM knowledge_base WHERE chunk_hash = ?");
            $check->bind_param("s", $chunk_hash);
            $check->execute();
            $result = $check->get_result();
            
            if (!$result->fetch_assoc()) {
                $stmt = $db->prepare("INSERT INTO knowledge_base (document_id, content_chunk, chunk_hash, metadata) 
                                      VALUES (?, ?, ?, ?)");
                $stmt->bind_param("isss",
                    $documentId,
                    $clean_chunk,
                    $chunk_hash,
                    $metadata
                );
                
                $metadata = json_encode([
                    'filename' => $filename,
                    'length' => strlen($clean_chunk),
                    'timestamp' => time()
                ]);
                $stmt->execute();
                $stmt->close();
                
                $chunk_count++;
            }
            $check->close();
        }
        
        // Update document status
        $stmt = $db->prepare("UPDATE documents SET processed = 1, status = ?, content_text = ? 
                              WHERE id = ?");
        $stmt->bind_param("ssi",
            $status,
            $content_preview,
            $documentId
        );
        
        $status = 'processed';
        $content_preview = substr($content, 0, 1000) . (strlen($content) > 1000 ? '...' : '');
        $stmt->execute();
        $stmt->close();
        
        logEvent('document', "Document processed: $filename ($chunk_count chunks)", $_SESSION['user_id'] ?? null);
        
        return $chunk_count;
        
    } catch (Exception $e) {
        // Mark as failed
        $stmt = $db->prepare("UPDATE documents SET status = ? WHERE id = ?");
        $error_status = 'failed: ' . $e->getMessage();
        $stmt->bind_param("si", $error_status, $documentId);
        $stmt->execute();
        $stmt->close();
        
        logEvent('error', "Document processing failed: " . $e->getMessage(), $_SESSION['user_id'] ?? null);
        return 0;
    }
}

function splitIntoChunks($content, $max_chunk_size = 1000) {
    // Split by sentences first
    $sentences = preg_split('/(?<=[.!?])\s+/', $content);
    $chunks = [];
    $current_chunk = '';
    
    foreach ($sentences as $sentence) {
        $trimmed = trim($sentence);
        if (empty($trimmed)) continue;
        
        if (strlen($current_chunk) + strlen($trimmed) + 1 <= $max_chunk_size) {
            $current_chunk .= ($current_chunk ? ' ' : '') . $trimmed;
        } else {
            if ($current_chunk) {
                $chunks[] = $current_chunk;
            }
            $current_chunk = $trimmed;
        }
    }
    
    if ($current_chunk) {
        $chunks[] = $current_chunk;
    }
    
    // If still too large, split by length
    if (empty($chunks)) {
        $chunks = str_split($content, $max_chunk_size);
    }
    
    return $chunks;
}

// ============================================
// AI & KNOWLEDGE FUNCTIONS
// ============================================

function findInKnowledgeBase($query, $limit = 3) {
    $db = getDBConnection();
    
    $keywords = preg_split('/\s+/', strtolower(trim($query)));
    $keywords = array_filter($keywords, function($word) {
        return strlen($word) > 2 && !in_array($word, ['the', 'and', 'for', 'with', 'that', 'this', 'have', 'from']);
    });
    
    if (empty($keywords)) {
        return [];
    }
    
    // Build search query
    $conditions = [];
    $params = [];
    $types = '';
    
    foreach ($keywords as $i => $keyword) {
        $conditions[] = "LOWER(content_chunk) LIKE ?";
        $params[] = '%' . $keyword . '%';
        $types .= 's';
    }
    
    $where = implode(' OR ', $conditions);
    $sql = "SELECT content_chunk, metadata FROM knowledge_base 
            WHERE $where 
            ORDER BY LENGTH(content_chunk) DESC 
            LIMIT ?";
    
    $params[] = $limit;
    $types .= 'i';
    
    $stmt = $db->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $knowledge = [];
    while ($row = $result->fetch_assoc()) {
        $knowledge[] = $row['content_chunk'];
    }
    
    $stmt->close();
    return $knowledge;
}

// Human-like responses for common greetings
function getHumanResponse($question) {
    $question_lower = strtolower(trim($question));
    
    // Greetings and basic conversations
    $greetings = [
        'hi' => ["Hello! 👋 How can I assist you today?", "Hi there! 😊 What can I help you with?", "Hey! Nice to meet you. How can I be of service?"],
        'hello' => ["Hello! How are you doing today? 😊", "Hi there! 👋 What brings you here?", "Hello! It's nice to chat with you. How can I help?"],
        'hey' => ["Hey! 👋 What's up?", "Hey there! 😊 How can I assist you?", "Hey! Nice to see you. What can I do for you?"],
        'good morning' => ["Good morning! ☀️ I hope you're having a great start to your day. How can I help?", "Morning! 🌅 Ready to tackle the day? How can I assist?", "Good morning! 😊 What can I do for you today?"],
        'good afternoon' => ["Good afternoon! 🌤️ How's your day going so far?", "Afternoon! 😊 Hope you're having a productive day. How can I help?", "Good afternoon! What can I assist you with?"],
        'good evening' => ["Good evening! 🌙 Hope you're having a pleasant evening. How can I help?", "Evening! 😊 How was your day?", "Good evening! What can I do for you tonight?"],
        'how are you' => ["I'm doing great, thank you for asking! 😊 How about you?", "I'm functioning perfectly, thanks! How are you doing today?", "All systems operational! How can I help make your day better?"],
        'what\'s up' => ["Not much, just here ready to help you! 😊 What's up with you?", "Just hanging out in the digital world, ready to assist! 👨‍💻", "All good here! What's new with you?"],
        'thank you' => ["You're very welcome! 😊 Is there anything else I can help with?", "My pleasure! Happy to assist. 👍", "Anytime! Let me know if you need anything else."],
        'thanks' => ["You're welcome! 😊", "No problem at all! 👍", "Happy to help! 😄"],
        'please' => ["Of course! 😊 What can I do for you?", "Certainly! How can I assist?", "I'd be happy to help! What do you need?"],
        'sorry' => ["No need to apologize! 😊 How can I help?", "It's completely okay! 😊 What can I do for you?", "No worries at all! How can I assist you?"],
        'bye' => ["Goodbye! 👋 Have a wonderful day!", "Take care! 😊 Hope to chat with you again soon!", "Bye! 👋 Stay awesome!"],
        'goodbye' => ["Goodbye! 👋 Take care!", "Farewell! 😊 Have a great day ahead!", "See you later! 👋"],
        'see you' => ["See you! 👋 Take care!", "Looking forward to our next chat! 😊", "Catch you later! 👋"],
        'who are you' => ["I'm an AI assistant here to help answer your questions! 🤖 I learn from uploaded documents to provide you with accurate information.", "I'm your friendly AI assistant! 😊 I can help you find information from documents and answer your questions.", "I'm an AI chatbot designed to assist you with information from our knowledge base. How can I help?"],
        'what can you do' => ["I can help you find information from uploaded documents, answer questions, and assist with various topics! 📚 Just ask me anything!", "I can search through our knowledge base, answer your questions, and help you find information from documents. Try asking me something! 😊", "I'm here to help you find information, answer questions, and assist with anything in our knowledge base. What would you like to know?"],
        'help' => ["I'd be happy to help! 😊 You can ask me questions about topics in our knowledge base, or try greetings like 'hi', 'hello', or 'what can you do?'", "Sure! I'm here to assist. Try asking a question, or say 'hi' to start a conversation. What do you need help with?", "I'm ready to help! You can ask me anything about the documents in our knowledge base, or just chat with me. 😊"],
    ];
    
    // Check for exact matches
    if (isset($greetings[$question_lower])) {
        $responses = $greetings[$question_lower];
        return $responses[array_rand($responses)];
    }
    
    // Check for partial matches
    foreach ($greetings as $key => $responses) {
        if (strpos($question_lower, $key) === 0 || strpos($question_lower, ' ' . $key . ' ') !== false) {
            return $responses[array_rand($responses)];
        }
    }
    
    return null;
}

function getAIResponse($question, $isStaff = false) {
    $db = getDBConnection();
    
    // First check for human-like responses
    $humanResponse = getHumanResponse($question);
    if ($humanResponse !== null) {
        return [
            'response' => $humanResponse,
            'source' => 'human_like',
            'confidence' => 'high'
        ];
    }
    
    $question_hash = md5(strtolower(trim($question)));
    
    // Check training data
    $stmt = $db->prepare("SELECT response1, response2, response3, best_response, usage_count, is_custom, custom_response, 
                          helpful_count, not_helpful_count 
                          FROM ai_training 
                          WHERE question_hash = ? 
                          OR question LIKE ? 
                          ORDER BY (helpful_count - not_helpful_count) DESC, usage_count DESC, trained_at DESC 
                          LIMIT 1");
    $like_param = '%' . $question . '%';
    $stmt->bind_param("ss", $question_hash, $like_param);
    $stmt->execute();
    $result = $stmt->get_result();
    $training = $result->fetch_assoc();
    
    if ($training) {
        // Update usage count
        $update = $db->prepare("UPDATE ai_training SET usage_count = usage_count + 1 WHERE question_hash = ?");
        $update->bind_param("s", $question_hash);
        $update->execute();
        $update->close();
        
        $responses = [
            $training['response1'],
            $training['response2'],
            $training['response3']
        ];
        
        if (!$isStaff) {
            $response_text = $training['is_custom'] && !empty($training['custom_response']) 
                ? $training['custom_response']
                : $responses[$training['best_response'] - 1];
            
            return [
                'response' => $response_text,
                'source' => 'trained',
                'confidence' => 'high',
                'is_custom' => $training['is_custom'],
                'helpful_count' => $training['helpful_count'],
                'not_helpful_count' => $training['not_helpful_count']
            ];
        }
        
        // For staff, return all responses for training
        return [
            'responses' => $responses,
            'question' => $question,
            'has_training' => true,
            'source' => 'trained',
            'training_data' => $training
        ];
    }
    
    // Search knowledge base
    $knowledge = findInKnowledgeBase($question, 3);
    
    if (!empty($knowledge)) {
        $base_response = "Based on the information available:\n\n";
        foreach ($knowledge as $i => $chunk) {
            $base_response .= ($i + 1) . ". " . substr($chunk, 0, 200) . (strlen($chunk) > 200 ? "..." : "") . "\n";
        }
        
        $responses = [
            $base_response . "\nWould you like me to provide more details on any specific point?",
            "I found relevant information in our knowledge base:\n\n" . 
            implode("\n\n", array_slice($knowledge, 0, 2)) . 
            "\n\nThis information comes from uploaded documents.",
            "Here's what I know about this:\n\n" . 
            $knowledge[0] . 
            "\n\nYou can ask follow-up questions for more details."
        ];
        
        if (!$isStaff) {
            return [
                'response' => $responses[0],
                'source' => 'knowledge_base',
                'confidence' => 'medium'
            ];
        }
        
        return [
            'responses' => $responses,
            'question' => $question,
            'has_training' => false,
            'source' => 'knowledge_base'
        ];
    }
    
    // Default responses when no knowledge found
    $default_responses = [
        "I don't have specific information about that in my knowledge base yet. " .
        "That's an interesting question! You might want to check with someone more knowledgeable about this topic.",
        
        "I'm not trained on that topic yet. " .
        "However, I'm always learning! You can ask our support team to add more information to my knowledge base.",
        
        "Hmm, I don't have information about that right now. " .
        "You could try rephrasing your question, or ask about something else in my knowledge base! 😊",
        
        "I don't have enough information to answer that question accurately. " .
        "Would you like me to help you with something else I might know about?"
    ];
    
    if (!$isStaff) {
        return [
            'response' => $default_responses[array_rand($default_responses)],
            'source' => 'default',
            'confidence' => 'low'
        ];
    }
    
    return [
        'responses' => $default_responses,
        'question' => $question,
        'has_training' => false,
        'source' => 'default'
    ];
}

function saveChatMessage($sessionId, $type, $content, $options = null, $selected = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO chat_messages (session_id, message_type, content, response_options, selected_option) 
                              VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssi",
            $sessionId,
            $type,
            $content,
            $options_json,
            $selected
        );
        
        $options_json = $options ? json_encode($options) : null;
        $stmt->execute();
        $message_id = $db->insert_id;
        $stmt->close();
        
        // Update session message count
        $update = $db->prepare("UPDATE chat_sessions 
                                SET message_count = message_count + 1, last_activity = NOW() 
                                WHERE session_id = ?");
        $update->bind_param("s", $sessionId);
        $update->execute();
        $update->close();
        
        return $message_id;
        
    } catch (Exception $e) {
        logEvent('error', 'Failed to save chat message: ' . $e->getMessage());
        return false;
    }
}

// ============================================
// AUTHENTICATION FUNCTIONS
// ============================================

function handleLogin() {
    $db = getDBConnection();
    
    $username = sanitize($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        return [false, 'Username and password are required'];
    }
    
    try {
        $stmt = $db->prepare("SELECT id, username, password_hash, user_type, full_name, is_active 
                              FROM users 
                              WHERE username = ? 
                              LIMIT 1");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        if (!$user) {
            logEvent('auth', 'Failed login attempt - user not found: ' . $username);
            return [false, 'Invalid credentials'];
        }
        
        if (!$user['is_active']) {
            logEvent('auth', 'Login attempt to inactive account: ' . $username);
            return [false, 'Account is disabled'];
        }
        
        if (password_verify($password, $user['password_hash'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['user_type'] = $user['user_type'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['login_time'] = time();
            
            // Update last login
            $update = $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $update->bind_param("i", $user['id']);
            $update->execute();
            $update->close();
            
            logEvent('auth', 'Successful login: ' . $username, $user['id']);
            return [true, 'Login successful'];
        } else {
            logEvent('auth', 'Failed login - wrong password: ' . $username);
            return [false, 'Invalid credentials'];
        }
        
    } catch (Exception $e) {
        logEvent('error', 'Login error: ' . $e->getMessage());
        return [false, 'System error during login'];
    }
}

function handleLogout() {
    if (isset($_SESSION['username'])) {
        logEvent('auth', 'User logged out: ' . $_SESSION['username'], $_SESSION['user_id'] ?? null);
    }
    
    $_SESSION = [];
    session_destroy();
    session_start();
}

// ============================================
// API ENDPOINT FUNCTIONS
// ============================================

function handleApiRequest() {
    $method = $_SERVER['REQUEST_METHOD'];
    $response = ['success' => false, 'message' => 'Invalid API request'];
    
    // Get API key from header or GET parameter
    $api_key = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? null;
    $domain = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? $_GET['domain'] ?? null;
    
    if (!$api_key) {
        $response['message'] = 'API key required';
        return $response;
    }
    
    // Validate API key
    $api_data = validateApiKey($api_key, $domain);
    if (!$api_data) {
        $response['message'] = 'Invalid or expired API key';
        return $response;
    }
    
    // Handle different API methods
    if ($method === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        
        if (isset($input['action'])) {
            switch ($input['action']) {
                case 'chat':
                    $question = sanitize($input['message'] ?? '');
                    if (empty($question)) {
                        $response['message'] = 'Message is required';
                        break;
                    }
                    
                    // Create or get session for API
                    $session_id = 'api_' . $api_data['id'] . '_' . bin2hex(random_bytes(8));
                    
                    // Save user message
                    saveChatMessage($session_id, 'user', $question);
                    
                    // Get AI response
                    $aiResponse = getAIResponse($question, false);
                    saveChatMessage($session_id, 'ai', $aiResponse['response']);
                    
                    $response = [
                        'success' => true,
                        'response' => $aiResponse['response'],
                        'source' => $aiResponse['source'],
                        'confidence' => $aiResponse['confidence'],
                        'session_id' => $session_id
                    ];
                    break;
                    
                case 'search':
                    $query = sanitize($input['query'] ?? '');
                    if (empty($query)) {
                        $response['message'] = 'Search query is required';
                        break;
                    }
                    
                    $knowledge = findInKnowledgeBase($query, 5);
                    $response = [
                        'success' => true,
                        'results' => $knowledge,
                        'count' => count($knowledge)
                    ];
                    break;
                    
                case 'rate_response':
                    $message_id = intval($input['message_id'] ?? 0);
                    $session_id = sanitize($input['session_id'] ?? '');
                    $question = sanitize($input['question'] ?? '');
                    $response_text = sanitize($input['response'] ?? '');
                    $rating = intval($input['rating'] ?? 0);
                    
                    if ($message_id <= 0 || empty($session_id) || empty($question) || empty($response_text)) {
                        $response['message'] = 'Missing required parameters';
                        break;
                    }
                    
                    if ($rating !== 0 && $rating !== 1) {
                        $response['message'] = 'Invalid rating value';
                        break;
                    }
                    
                    $rating_id = rateResponse($message_id, $session_id, $question, $response_text, $rating);
                    
                    if ($rating_id) {
                        $response = [
                            'success' => true,
                            'message' => 'Rating saved successfully',
                            'rating_id' => $rating_id
                        ];
                    } else {
                        $response['message'] = 'Failed to save rating';
                    }
                    break;
                    
                default:
                    $response['message'] = 'Unknown action';
            }
        } else {
            $response['message'] = 'Action parameter required';
        }
    } elseif ($method === 'GET') {
        // Handle GET requests
        if (isset($_GET['action'])) {
            switch ($_GET['action']) {
                case 'status':
                    $response = ['success' => true, 'status' => 'operational', 'timestamp' => date('c')];
                    break;
                    
                case 'stats':
                    if ($api_data['user_id'] && isAdminUserId($api_data['user_id'])) {
                        $stats = getSystemStats();
                        $response = ['success' => true, 'stats' => $stats];
                    } else {
                        $response['message'] = 'Unauthorized for stats';
                    }
                    break;
                    
                default:
                    $response['message'] = 'Unknown action';
            }
        }
    }
    
    return $response;
}

function isAdminUserId($user_id) {
    $db = getDBConnection();
    $stmt = $db->prepare("SELECT user_type FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    return $user && $user['user_type'] === 'admin';
}

function getSystemStats() {
    $db = getDBConnection();
    $stats = [];
    
    $tables = ['users', 'documents', 'knowledge_base', 'chat_sessions', 'ai_training'];
    foreach ($tables as $table) {
        if ($table === 'documents') {
            $result = $db->query("SELECT COUNT(*) as count FROM documents WHERE is_deleted = 0");
        } else {
            $result = $db->query("SELECT COUNT(*) as count FROM $table");
        }
        $row = $result->fetch_assoc();
        $stats[$table] = intval($row['count']);
    }
    
    // Add rating stats
    $result = $db->query("SELECT 
        SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as helpful,
        SUM(CASE WHEN rating = 0 THEN 1 ELSE 0 END) as not_helpful
        FROM response_ratings");
    $row = $result->fetch_assoc();
    $stats['helpful_ratings'] = intval($row['helpful'] ?? 0);
    $stats['not_helpful_ratings'] = intval($row['not_helpful'] ?? 0);
    
    return $stats;
}

// ============================================
// REQUEST HANDLER
// ============================================

// Check if this is an API request
if (isset($_GET['api']) || (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
    $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest' && 
    isset($_SERVER['HTTP_X_API_KEY']))) {
    
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-API-Key, X-Requested-With');
    
    // Handle preflight requests
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }
    
    $api_response = handleApiRequest();
    echo json_encode($api_response);
    exit;
}

// Handle AJAX requests from the main interface
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    
    // Prevent caching
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    $action = sanitize($_POST['action']);
    $response = ['success' => false, 'message' => 'Unknown action'];
    
    try {
        switch ($action) {
            case 'login':
                list($success, $message) = handleLogin();
                $response = [
                    'success' => $success,
                    'message' => $message,
                    'user_type' => $success ? $_SESSION['user_type'] : null
                ];
                break;
                
            case 'logout':
                handleLogout();
                $response = ['success' => true, 'message' => 'Logged out'];
                break;
                
            case 'upload_document':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                if (!isset($_FILES['document']) || $_FILES['document']['error'] !== UPLOAD_ERR_OK) {
                    throw new Exception('File upload failed');
                }
                
                $file = $_FILES['document'];
                $filename = basename($file['name']);
                $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                
                // Validate file
                if ($file['size'] > MAX_FILE_SIZE) {
                    throw new Exception('File too large (max 10MB)');
                }
                
                if (!in_array($file_ext, ALLOWED_TYPES)) {
                    throw new Exception('File type not allowed. Allowed: ' . implode(', ', ALLOWED_TYPES));
                }
                
                // Generate safe filename
                $safe_filename = time() . '_' . preg_replace('/[^a-zA-Z0-9\._-]/', '_', $filename);
                $filepath = UPLOAD_DIR . 'documents/' . $safe_filename;
                
                if (!move_uploaded_file($file['tmp_name'], $filepath)) {
                    throw new Exception('Failed to save file');
                }
                
                // Save to database
                $db = getDBConnection();
                $stmt = $db->prepare("INSERT INTO documents (filename, filepath, file_type, file_size, uploaded_by) 
                                      VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssii",
                    $filename,
                    $filepath,
                    $file_type,
                    $file_size,
                    $user_id
                );
                
                $file_type = $file['type'];
                $file_size = $file['size'];
                $user_id = $_SESSION['user_id'];
                $stmt->execute();
                $docId = $db->insert_id;
                $stmt->close();
                
                // Process in background (simulated)
                $chunks = processDocument($docId, $filepath, $filename);
                
                $response = [
                    'success' => true,
                    'message' => "Document uploaded successfully. Processed into $chunks knowledge chunks.",
                    'document_id' => $docId
                ];
                break;
                
            case 'delete_document':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $document_id = intval($_POST['document_id'] ?? 0);
                if ($document_id <= 0) {
                    throw new Exception('Invalid document ID');
                }
                
                list($success, $message) = deleteDocument($document_id);
                
                $response = [
                    'success' => $success,
                    'message' => $message
                ];
                break;
                
            case 'get_storage_stats':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $stats = getStorageStats();
                $response = [
                    'success' => true,
                    'stats' => $stats
                ];
                break;
                
            case 'rate_response':
                $message_id = intval($_POST['message_id'] ?? 0);
                $session_id = sanitize($_POST['session_id'] ?? '');
                $question = sanitize($_POST['question'] ?? '');
                $response_text = sanitize($_POST['response'] ?? '');
                $rating = intval($_POST['rating'] ?? 0);
                
                if ($message_id <= 0 || empty($session_id) || empty($question) || empty($response_text)) {
                    throw new Exception('Missing required parameters');
                }
                
                if ($rating !== 0 && $rating !== 1) {
                    throw new Exception('Invalid rating value');
                }
                
                $rating_id = rateResponse($message_id, $session_id, $question, $response_text, $rating);
                
                if ($rating_id) {
                    $rating_stats = getResponseRatingStats($message_id);
                    $response = [
                        'success' => true,
                        'message' => 'Thank you for your feedback!',
                        'rating_id' => $rating_id,
                        'stats' => $rating_stats
                    ];
                } else {
                    throw new Exception('Failed to save rating');
                }
                break;
                
            case 'chat':
                $sessionId = getSessionId();
                $question = sanitize($_POST['message'] ?? '');
                $isStaff = isStaff();
                $trainingMode = ($_POST['training_mode'] ?? 'false') === 'true';
                
                if (empty($question)) {
                    throw new Exception('Message is required');
                }
                
                // Save user message
                $user_message_id = saveChatMessage($sessionId, 'user', $question);
                
                // Get AI response
                if ($isStaff && $trainingMode) {
                    $aiResponse = getAIResponse($question, true);
                    
                    if (isset($_POST['train_response']) && $_POST['train_response'] === 'true') {
                        // Save training data
                        $question_hash = md5(strtolower(trim($_POST['question'])));
                        
                        $db = getDBConnection();
                        $stmt = $db->prepare("INSERT INTO ai_training 
                                              (question, question_hash, response1, response2, response3, custom_response, best_response, is_custom, trained_by) 
                                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                              ON DUPLICATE KEY UPDATE 
                                              response1 = VALUES(response1),
                                              response2 = VALUES(response2),
                                              response3 = VALUES(response3),
                                              custom_response = VALUES(custom_response),
                                              best_response = VALUES(best_response),
                                              is_custom = VALUES(is_custom),
                                              trained_by = VALUES(trained_by),
                                              usage_count = usage_count + 1");
                        $stmt->bind_param("ssssssiii",
                            $question_text,
                            $question_hash,
                            $response1,
                            $response2,
                            $response3,
                            $custom_response,
                            $best_response,
                            $is_custom,
                            $trained_by
                        );
                        
                        $question_text = sanitize($_POST['question']);
                        $response1 = sanitize($_POST['response1']);
                        $response2 = sanitize($_POST['response2']);
                        $response3 = sanitize($_POST['response3']);
                        $custom_response = sanitize($_POST['custom_response'] ?? '');
                        $best_response = intval($_POST['best_response']);
                        $is_custom = isset($_POST['custom_response']) && !empty($_POST['custom_response']) ? 1 : 0;
                        $trained_by = $_SESSION['user_id'];
                        $stmt->execute();
                        $training_id = $db->insert_id;
                        $stmt->close();
                        
                        $training_type = isset($_POST['custom_response']) ? 'with custom response' : 'with selected response';
                        logEvent('training', 'AI trained on: ' . substr($_POST['question'], 0, 50) . ' (' . $training_type . ')', $_SESSION['user_id']);
                        
                        $response = [
                            'success' => true,
                            'message' => isset($_POST['custom_response']) ? 'AI trained with custom response!' : 'AI trained successfully!',
                            'training_id' => $training_id
                        ];
                    } else {
                        // Return multiple responses for staff training
                        $ai_message_id = saveChatMessage($sessionId, 'ai', 'Training options presented', 
                                       json_encode($aiResponse['responses']));
                        
                        $response = [
                            'success' => true,
                            'responses' => $aiResponse['responses'],
                            'question' => $question,
                            'training_mode' => true,
                            'source' => $aiResponse['source'] ?? 'unknown',
                            'user_message_id' => $user_message_id,
                            'ai_message_id' => $ai_message_id
                        ];
                    }
                } else {
                    // Regular response
                    $aiResponse = getAIResponse($question, false);
                    $ai_message_id = saveChatMessage($sessionId, 'ai', $aiResponse['response']);
                    
                    $response = [
                        'success' => true,
                        'message' => $aiResponse['response'],
                        'source' => $aiResponse['source'],
                        'confidence' => $aiResponse['confidence'],
                        'user_message_id' => $user_message_id,
                        'ai_message_id' => $ai_message_id,
                        'helpful_count' => $aiResponse['helpful_count'] ?? 0,
                        'not_helpful_count' => $aiResponse['not_helpful_count'] ?? 0
                    ];
                }
                break;
                
            case 'get_chat_history':
                $sessionId = getSessionId();
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT id, message_type, content, created_at 
                                      FROM chat_messages 
                                      WHERE session_id = ? 
                                      ORDER BY created_at ASC 
                                      LIMIT 100");
                $stmt->bind_param("s", $sessionId);
                $stmt->execute();
                $result = $stmt->get_result();
                
                $messages = [];
                while ($row = $result->fetch_assoc()) {
                    // Try to parse JSON for training options
                    if ($row['message_type'] === 'ai' && strpos($row['content'], '[') === 0) {
                        $parsed = json_decode($row['content'], true);
                        if (is_array($parsed)) {
                            $row['content'] = $parsed[0] ?? $row['content'];
                        }
                    }
                    $messages[] = $row;
                }
                $stmt->close();
                
                $response = [
                    'success' => true,
                    'messages' => $messages,
                    'session_id' => $sessionId
                ];
                break;
                
            case 'get_documents':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT d.*, u.username as uploaded_by_name 
                                      FROM documents d 
                                      LEFT JOIN users u ON d.uploaded_by = u.id 
                                      WHERE d.is_deleted = 0 
                                      ORDER BY d.uploaded_at DESC 
                                      LIMIT 100");
                $stmt->execute();
                $result = $stmt->get_result();
                
                $documents = [];
                while ($row = $result->fetch_assoc()) {
                    $row['file_size_mb'] = round($row['file_size'] / (1024 * 1024), 2);
                    $row['uploaded_date'] = date('Y-m-d H:i', strtotime($row['uploaded_at']));
                    $documents[] = $row;
                }
                $stmt->close();
                
                $response = [
                    'success' => true,
                    'documents' => $documents,
                    'count' => count($documents)
                ];
                break;
                
            case 'get_users':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT id, username, email, user_type, full_name, 
                                      created_at, last_login, is_active 
                                      FROM users 
                                      ORDER BY user_type, created_at DESC");
                $stmt->execute();
                $result = $stmt->get_result();
                
                $users = [];
                while ($row = $result->fetch_assoc()) {
                    $row['created_date'] = date('Y-m-d', strtotime($row['created_at']));
                    $row['last_login_date'] = $row['last_login'] ? date('Y-m-d H:i', strtotime($row['last_login'])) : 'Never';
                    $users[] = $row;
                }
                $stmt->close();
                
                $response = ['success' => true, 'users' => $users];
                break;
                
            case 'create_user':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $username = sanitize($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                $email = sanitize($_POST['email'] ?? '');
                $full_name = sanitize($_POST['full_name'] ?? '');
                $user_type = sanitize($_POST['user_type'] ?? 'staff');
                
                if (empty($username) || empty($password)) {
                    throw new Exception('Username and password are required');
                }
                
                if (!in_array($user_type, ['staff', 'admin'])) {
                    throw new Exception('Invalid user type');
                }
                
                // Check if username exists
                $db = getDBConnection();
                $check = $db->prepare("SELECT id FROM users WHERE username = ?");
                $check->bind_param("s", $username);
                $check->execute();
                $result = $check->get_result();
                
                if ($result->fetch_assoc()) {
                    $check->close();
                    throw new Exception('Username already exists');
                }
                $check->close();
                
                $stmt = $db->prepare("INSERT INTO users (username, password_hash, email, user_type, full_name) 
                                      VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssss",
                    $username,
                    $password_hash,
                    $email,
                    $user_type,
                    $full_name
                );
                
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt->execute();
                $user_id = $db->insert_id;
                $stmt->close();
                
                logEvent('user', "User created: $username ($user_type)", $_SESSION['user_id']);
                
                $response = [
                    'success' => true,
                    'message' => 'User account created successfully',
                    'user_id' => $user_id
                ];
                break;
                
            case 'get_activity_logs':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $limit = intval($_POST['limit'] ?? 50);
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT cs.*, COUNT(cm.id) as message_count 
                                      FROM chat_sessions cs 
                                      LEFT JOIN chat_messages cm ON cs.session_id = cm.session_id 
                                      GROUP BY cs.id 
                                      ORDER BY cs.last_activity DESC 
                                      LIMIT ?");
                $stmt->bind_param("i", $limit);
                $stmt->execute();
                $result = $stmt->get_result();
                
                $logs = [];
                while ($row = $result->fetch_assoc()) {
                    $row['started_date'] = date('Y-m-d H:i', strtotime($row['started_at']));
                    $row['last_activity_date'] = date('Y-m-d H:i', strtotime($row['last_activity']));
                    $logs[] = $row;
                }
                $stmt->close();
                
                $response = ['success' => true, 'logs' => $logs];
                break;
                
            case 'get_stats':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $stats = getSystemStats();
                
                // Get recent activity
                $db = getDBConnection();
                $result = $db->query("SELECT COUNT(*) as today_sessions FROM chat_sessions 
                                      WHERE DATE(started_at) = CURDATE()");
                $row = $result->fetch_assoc();
                $stats['today_sessions'] = intval($row['today_sessions']);
                
                $result = $db->query("SELECT COUNT(*) as today_messages FROM chat_messages 
                                      WHERE DATE(created_at) = CURDATE()");
                $row = $result->fetch_assoc();
                $stats['today_messages'] = intval($row['today_messages']);
                
                // Get top trained questions
                $result = $db->query("SELECT question, usage_count, helpful_count, not_helpful_count FROM ai_training 
                                      ORDER BY (helpful_count - not_helpful_count) DESC LIMIT 5");
                $top_trained = [];
                while ($row = $result->fetch_assoc()) {
                    $top_trained[] = $row;
                }
                
                $response = [
                    'success' => true,
                    'stats' => $stats,
                    'top_trained' => $top_trained
                ];
                break;
                
            case 'get_training_history':
                if (!isStaff()) throw new Exception('Unauthorized');
                
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT t.*, u.username as trained_by_name 
                                      FROM ai_training t 
                                      LEFT JOIN users u ON t.trained_by = u.id 
                                      ORDER BY t.trained_at DESC 
                                      LIMIT 50");
                $stmt->execute();
                $result = $stmt->get_result();
                
                $history = [];
                while ($row = $result->fetch_assoc()) {
                    $row['trained_date'] = date('Y-m-d H:i', strtotime($row['trained_at']));
                    $row['question_short'] = strlen($row['question']) > 50 ? 
                                            substr($row['question'], 0, 50) . '...' : $row['question'];
                    $history[] = $row;
                }
                $stmt->close();
                
                $response = ['success' => true, 'history' => $history];
                break;
                
            case 'get_api_keys':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT ak.*, u.username as user_name 
                                      FROM api_keys ak 
                                      LEFT JOIN users u ON ak.user_id = u.id 
                                      ORDER BY ak.created_at DESC");
                $stmt->execute();
                $result = $stmt->get_result();
                
                $api_keys = [];
                while ($row = $result->fetch_assoc()) {
                    $row['created_date'] = date('Y-m-d H:i', strtotime($row['created_at']));
                    $row['last_used_date'] = $row['last_used'] ? date('Y-m-d H:i', strtotime($row['last_used'])) : 'Never';
                    // Mask API key for display
                    $row['api_key_display'] = substr($row['api_key'], 0, 8) . '...' . substr($row['api_key'], -8);
                    $api_keys[] = $row;
                }
                $stmt->close();
                
                $response = ['success' => true, 'api_keys' => $api_keys];
                break;
                
            case 'create_api_key':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $domain = sanitize($_POST['domain'] ?? '*');
                if (empty($domain)) {
                    throw new Exception('Domain is required');
                }
                
                $api_key = createApiKey($domain, $_SESSION['user_id']);
                if ($api_key) {
                    $response = [
                        'success' => true,
                        'message' => 'API key created successfully',
                        'api_key' => $api_key,
                        'domain' => $domain
                    ];
                } else {
                    throw new Exception('Failed to create API key');
                }
                break;
                
            case 'revoke_api_key':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $api_key_id = intval($_POST['api_key_id'] ?? 0);
                if ($api_key_id <= 0) {
                    throw new Exception('Invalid API key ID');
                }
                
                if (revokeApiKey($api_key_id, $_SESSION['user_id'])) {
                    $response = [
                        'success' => true,
                        'message' => 'API key revoked successfully'
                    ];
                } else {
                    throw new Exception('Failed to revoke API key');
                }
                break;
                
            default:
                $response = ['success' => false, 'message' => 'Invalid action'];
        }
        
    } catch (Exception $e) {
        $response = [
            'success' => false,
            'message' => $e->getMessage(),
            'error_type' => get_class($e)
        ];
        logEvent('error', "API Error [$action]: " . $e->getMessage(), $_SESSION['user_id'] ?? null);
    }
    
    echo json_encode($response);
    exit;
}

// ============================================
// HTML INTERFACE
// ============================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Chat Assistant | Knowledge Base</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* All your existing CSS remains the same */
        :root {
            --primary: #4361ee;
            --primary-dark: #3a56d4;
            --secondary: #7209b7;
            --success: #4cc9f0;
            --danger: #f72585;
            --warning: #f8961e;
            --light: #f8f9fa;
            --dark: #212529;
            --gray: #6c757d;
            --border: #dee2e6;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: var(--dark);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .app-container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            min-height: 95vh;
            margin-top: 20px;
            margin-bottom: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 20px 40px;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .logo-icon {
            font-size: 3rem;
            background: white;
            color: var(--primary);
            width: 70px;
            height: 70px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .logo h1 {
            font-size: 1.8rem;
            margin-bottom: 5px;
        }
        
        .logo p {
            opacity: 0.9;
            font-size: 0.9rem;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-avatar {
            width: 50px;
            height: 50px;
            background: white;
            color: var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 1.2rem;
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        }
        
        .user-details {
            text-align: right;
        }
        
        .user-name {
            font-weight: 600;
        }
        
        .user-role {
            font-size: 0.85rem;
            opacity: 0.9;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--primary-dark);
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-warning {
            background: var(--warning);
            color: white;
        }
        
        .btn-sm {
            padding: 8px 16px;
            font-size: 0.85rem;
        }
        
        .content-area {
            display: flex;
            min-height: calc(95vh - 110px);
        }
        
        .sidebar {
            width: 250px;
            background: var(--light);
            border-right: 1px solid var(--border);
            padding: 20px 0;
        }
        
        .sidebar-section {
            margin-bottom: 30px;
        }
        
        .sidebar-title {
            padding: 0 20px 10px;
            color: var(--gray);
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .nav-btn {
            width: 100%;
            padding: 12px 20px;
            background: none;
            border: none;
            text-align: left;
            color: var(--dark);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
            font-size: 0.95rem;
        }
        
        .nav-btn:hover {
            background: rgba(67, 97, 238, 0.1);
            color: var(--primary);
        }
        
        .nav-btn.active {
            background: var(--primary);
            color: white;
            border-right: 3px solid var(--secondary);
        }
        
        .nav-btn i {
            width: 20px;
        }
        
        .main-content {
            flex: 1;
            padding: 30px;
            overflow-y: auto;
        }
        
        .section {
            display: none;
        }
        
        .section.active {
            display: block;
        }
        
        .section-header {
            margin-bottom: 30px;
        }
        
        .section-header h2 {
            font-size: 1.8rem;
            color: var(--dark);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-header p {
            color: var(--gray);
            font-size: 1rem;
        }
        
        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.05);
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.1);
        }
        
        .card-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .card-stat {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 10px;
        }
        
        .card-stat-label {
            color: var(--gray);
            font-size: 0.95rem;
        }
        
        .chat-container {
            background: white;
            border-radius: 15px;
            border: 1px solid var(--border);
            overflow: hidden;
            display: flex;
            flex-direction: column;
            height: 600px;
        }
        
        .chat-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .chat-header h3 {
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .chat-status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            background: #4ade80;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .messages-container {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .message {
            max-width: 80%;
            padding: 15px;
            border-radius: 15px;
            position: relative;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message.user {
            align-self: flex-end;
            background: var(--primary);
            color: white;
            border-bottom-right-radius: 5px;
        }
        
        .message.ai {
            align-self: flex-start;
            background: var(--light);
            color: var(--dark);
            border-bottom-left-radius: 5px;
        }
        
        .message-time {
            font-size: 0.75rem;
            opacity: 0.7;
            margin-top: 5px;
            display: block;
        }
        
        .chat-input-area {
            padding: 20px;
            border-top: 1px solid var(--border);
            display: flex;
            gap: 10px;
        }
        
        .chat-input {
            flex: 1;
            padding: 15px;
            border: 1px solid var(--border);
            border-radius: 10px;
            font-size: 1rem;
            outline: none;
            transition: border-color 0.3s ease;
        }
        
        .chat-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.1);
        }
        
        .table-container {
            background: white;
            border-radius: 15px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .data-table th {
            background: var(--light);
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: var(--dark);
            border-bottom: 2px solid var(--border);
        }
        
        .data-table td {
            padding: 15px;
            border-bottom: 1px solid var(--border);
        }
        
        .data-table tr:hover {
            background: rgba(67, 97, 238, 0.05);
        }
        
        .data-table tr:last-child td {
            border-bottom: none;
        }
        
        .status-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            display: inline-block;
        }
        
        .status-success {
            background: rgba(76, 201, 240, 0.2);
            color: #0d6efd;
        }
        
        .status-warning {
            background: rgba(248, 150, 30, 0.2);
            color: #fd7e14;
        }
        
        .status-danger {
            background: rgba(247, 37, 133, 0.2);
            color: #dc3545;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray);
        }
        
        .empty-state i {
            font-size: 3rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        
        .empty-state h3 {
            margin-bottom: 10px;
            color: var(--dark);
        }
        
        .form-container {
            max-width: 500px;
            margin: 0 auto;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--dark);
        }
        
        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.1);
        }
        
        .file-upload {
            border: 2px dashed var(--border);
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 20px;
        }
        
        .file-upload:hover {
            border-color: var(--primary);
            background: rgba(67, 97, 238, 0.05);
        }
        
        .file-upload i {
            font-size: 3rem;
            color: var(--primary);
            margin-bottom: 15px;
        }
        
        .file-upload h4 {
            margin-bottom: 10px;
            color: var(--dark);
        }
        
        .file-upload p {
            color: var(--gray);
            font-size: 0.9rem;
        }
        
        .training-mode {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .training-mode input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--primary);
        }
        
        .training-options {
            background: var(--light);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border: 1px solid var(--border);
        }
        
        .training-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .training-response {
            background: white;
            padding: 15px;
            border: 2px solid var(--border);
            border-radius: 10px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .training-response:hover {
            border-color: var(--primary);
            background: rgba(67, 97, 238, 0.05);
        }
        
        .training-response.selected {
            border-color: var(--success);
            background: rgba(76, 201, 240, 0.1);
        }
        
        .response-number {
            display: inline-block;
            width: 25px;
            height: 25px;
            background: var(--primary);
            color: white;
            border-radius: 50%;
            text-align: center;
            line-height: 25px;
            font-size: 0.85rem;
            margin-right: 10px;
        }
        
        .notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: white;
            border-radius: 10px;
            padding: 15px 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            z-index: 1000;
            transform: translateX(150%);
            transition: transform 0.3s ease;
            max-width: 400px;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification.success {
            border-left: 4px solid var(--success);
        }
        
        .notification.error {
            border-left: 4px solid var(--danger);
        }
        
        .notification.warning {
            border-left: 4px solid var(--warning);
        }
        
        .notification-content {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .notification-icon {
            font-size: 1.5rem;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .message-rating {
            margin-top: 10px;
            display: flex;
            gap: 10px;
        }
        
        .rating-btn {
            padding: 5px 15px;
            border: 1px solid var(--border);
            background: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 5px;
            transition: all 0.3s ease;
        }
        
        .rating-btn:hover {
            transform: translateY(-2px);
        }
        
        .rating-btn.helpful:hover {
            background: rgba(76, 201, 240, 0.1);
            border-color: var(--success);
            color: var(--success);
        }
        
        .rating-btn.not-helpful:hover {
            background: rgba(247, 37, 133, 0.1);
            border-color: var(--danger);
            color: var(--danger);
        }
        
        .rating-btn.rated {
            pointer-events: none;
            opacity: 0.7;
        }
        
        .rating-count {
            font-size: 0.8rem;
            color: var(--gray);
            margin-left: 5px;
        }
        
        .storage-stats {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .storage-stat {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }
        
        .storage-stat h4 {
            margin-bottom: 10px;
            color: var(--gray);
            font-size: 0.9rem;
        }
        
        .storage-stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .delete-confirmation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }
        
        .delete-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 500px;
            width: 90%;
        }
        
        .delete-icon {
            font-size: 3rem;
            color: var(--danger);
            margin-bottom: 20px;
            text-align: center;
        }
        
        .delete-content h3 {
            margin-bottom: 15px;
            text-align: center;
        }
        
        .delete-content p {
            margin-bottom: 25px;
            text-align: center;
            color: var(--gray);
        }
        
        .delete-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
        }
        
        .action-buttons {
            display: flex;
            gap: 5px;
        }
        
        .btn-icon {
            width: 35px;
            height: 35px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .api-key-display {
            background: #f8f9fa;
            border: 2px dashed var(--primary);
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            font-family: monospace;
            word-break: break-all;
        }
        
        .api-key-warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 0.9rem;
        }
        
    </style>
</head>
<body>
    <div class="app-container">
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <div class="logo-icon">🤖</div>
                    <div>
                        <h1>AI Chat Assistant</h1>
                        <p>Powered by MySQL on Hostinger</p>
                    </div>
                </div>
                
                <div class="user-info">
                    <?php if (isLoggedIn()): ?>
                        <div class="user-avatar">
                            <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                        </div>
                        <div class="user-details">
                            <div class="user-name"><?php echo $_SESSION['full_name'] ?: $_SESSION['username']; ?></div>
                            <div class="user-role"><?php echo ucfirst($_SESSION['user_type']); ?></div>
                        </div>
                        <button class="btn btn-sm btn-danger" onclick="logout()">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </button>
                    <?php else: ?>
                        <div class="user-avatar">👤</div>
                        <div class="user-details">
                            <div class="user-name">Public User</div>
                            <div class="user-role">Guest</div>
                        </div>
                        <button class="btn btn-sm btn-primary" onclick="showSection('login')">
                            <i class="fas fa-sign-in-alt"></i> Admin Login
                        </button>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <div class="content-area">
            <!-- Sidebar Navigation -->
            <div class="sidebar">
                <?php if (!isLoggedIn()): ?>
                    <!-- Public User Navigation -->
                    <div class="sidebar-section">
                        <div class="sidebar-title">Main</div>
                        <button class="nav-btn active" onclick="showSection('publicChat')">
                            <i class="fas fa-comments"></i> Chat with AI
                        </button>
                        <button class="nav-btn" onclick="showSection('about')">
                            <i class="fas fa-info-circle"></i> About
                        </button>
                    </div>
                    
                <?php elseif (isAdmin()): ?>
                    <!-- Admin Navigation -->
                    <div class="sidebar-section">
                        <div class="sidebar-title">Dashboard</div>
                        <button class="nav-btn active" onclick="showSection('dashboard')">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </button>
                        <button class="nav-btn" onclick="showSection('chat')">
                            <i class="fas fa-robot"></i> AI Chat
                        </button>
                        <button class="nav-btn" onclick="showSection('api')">
                            <i class="fas fa-code"></i> API Management
                        </button>
                    </div>
                    
                    <div class="sidebar-section">
                        <div class="sidebar-title">Knowledge Base</div>
                        <button class="nav-btn" onclick="showSection('documents')">
                            <i class="fas fa-file-upload"></i> Upload Documents
                        </button>
                        <button class="nav-btn" onclick="showSection('knowledge')">
                            <i class="fas fa-database"></i> Knowledge Base
                        </button>
                    </div>
                    
                    <div class="sidebar-section">
                        <div class="sidebar-title">User Management</div>
                        <button class="nav-btn" onclick="showSection('staff')">
                            <i class="fas fa-users-cog"></i> Manage Staff
                        </button>
                        <button class="nav-btn" onclick="showSection('users')">
                            <i class="fas fa-users"></i> All Users
                        </button>
                    </div>
                    
                    <div class="sidebar-section">
                        <div class="sidebar-title">Monitoring</div>
                        <button class="nav-btn" onclick="showSection('activity')">
                            <i class="fas fa-history"></i> Activity Logs
                        </button>
                        <button class="nav-btn" onclick="showSection('logs')">
                            <i class="fas fa-clipboard-list"></i> System Logs
                        </button>
                    </div>
                    
                <?php elseif (isStaff()): ?>
                    <!-- Staff Navigation -->
                    <div class="sidebar-section">
                        <div class="sidebar-title">AI Training</div>
                        <button class="nav-btn active" onclick="showSection('staffChat')">
                            <i class="fas fa-robot"></i> Train AI
                        </button>
                        <button class="nav-btn" onclick="showSection('trainingHistory')">
                            <i class="fas fa-history"></i> Training History
                        </button>
                    </div>
                    
                    <div class="sidebar-section">
                        <div class="sidebar-title">Knowledge</div>
                        <button class="nav-btn" onclick="showSection('knowledge')">
                            <i class="fas fa-book"></i> Browse Knowledge
                        </button>
                        <button class="nav-btn" onclick="showSection('documents')">
                            <i class="fas fa-file-alt"></i> Documents
                        </button>
                    </div>
                    
                <?php endif; ?>
                
                <div class="sidebar-section">
                    <div class="sidebar-title">System</div>
                    <button class="nav-btn" onclick="showSection('help')">
                        <i class="fas fa-question-circle"></i> Help
                    </button>
                    <button class="nav-btn" onclick="showSection('settings')">
                        <i class="fas fa-cog"></i> Settings
                    </button>
                </div>
            </div>
            
            <!-- Main Content Area -->
            <div class="main-content">
                <?php if (!isLoggedIn()): ?>
                    <!-- PUBLIC USER SECTIONS -->
                    <div id="publicChat" class="section active">
                        <div class="chat-container">
                            <div class="chat-header">
                                <h3><i class="fas fa-robot"></i> Chat with AI Assistant</h3>
                                <div class="chat-status">
                                    <span class="status-indicator"></span>
                                    <span>AI is online</span>
                                </div>
                            </div>
                            <div class="messages-container" id="publicMessages"></div>
                            <div class="chat-input-area">
                                <input type="text" class="chat-input" id="publicMessageInput" 
                                       placeholder="Say hi, ask questions, or rate responses..." 
                                       onkeypress="if(event.key === 'Enter') sendPublicMessage()">
                                <button class="btn btn-primary" onclick="sendPublicMessage()">
                                    <i class="fas fa-paper-plane"></i> Send
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div id="about" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-info-circle"></i> About AI Chat Assistant</h2>
                            <p>Learn how this AI system works</p>
                        </div>
                        <div class="cards-grid">
                            <div class="card">
                                <div class="card-icon">🤖</div>
                                <h3>AI-Powered Responses</h3>
                                <p>The AI learns from uploaded documents and provides intelligent responses based on the knowledge base.</p>
                            </div>
                            <div class="card">
                                <div class="card-icon">📚</div>
                                <h3>Knowledge Base</h3>
                                <p>Administrators can upload PDF, DOC, TXT files to train the AI with specific information.</p>
                            </div>
                            <div class="card">
                                <div class="card-icon">👨‍🏫</div>
                                <h3>Staff Training</h3>
                                <p>Staff members continuously train the AI by selecting the best responses to improve accuracy.</p>
                            </div>
                        </div>
                    </div>
                    
                    <div id="login" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-sign-in-alt"></i> Administrator Login</h2>
                            <p>Access admin panel to manage the system</p>
                        </div>
                        <div class="form-container">
                            <div class="card">
                                <form id="loginForm">
                                    <div class="form-group">
                                        <label class="form-label">Username</label>
                                        <input type="text" class="form-control" id="loginUsername" 
                                               placeholder="Enter username" required>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Password</label>
                                        <input type="password" class="form-control" id="loginPassword" 
                                               placeholder="Enter password" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary" style="width: 100%; padding: 15px;">
                                        <i class="fas fa-sign-in-alt"></i> Login to Admin Panel
                                    </button>
                                </form>
                            </div>
                            <div class="card" style="margin-top: 20px; text-align: center;">
                                
                            </div>
                        </div>
                    </div>
                    
                <?php elseif (isAdmin()): ?>
                    <!-- ADMIN SECTIONS -->
                    <div id="dashboard" class="section active">
                        <div class="section-header">
                            <h2><i class="fas fa-tachometer-alt"></i> Admin Dashboard</h2>
                            <p>System overview and statistics</p>
                        </div>
                        <div class="storage-stats" id="storageStats"></div>
                        <div class="cards-grid" id="dashboardStats"></div>
                        
                        <div class="section-header">
                            <h2><i class="fas fa-chart-line"></i> Recent Activity</h2>
                            <p>Latest system events and chats</p>
                        </div>
                        <div class="table-container">
                            <div id="recentActivity">Loading...</div>
                        </div>
                    </div>
                    
                    <div id="api" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-code"></i> API Management</h2>
                            <p>Manage API keys for subdomain integration</p>
                        </div>
                        
                        <div class="card">
                            <h3>Create New API Key</h3>
                            <form id="apiKeyForm">
                                <div class="form-group">
                                    <label class="form-label">Domain (for CORS)</label>
                                    <input type="text" class="form-control" id="apiDomain" 
                                           placeholder="Enter domain (e.g., *.hidk.in or specific subdomain)" 
                                           value="*.hidk.in">
                                    <small class="text-muted">Use * for all domains, or specific domain like chat.hidk.in</small>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-key"></i> Generate API Key
                                </button>
                            </form>
                            
                            <div id="apiKeyResult" style="display: none; margin-top: 20px;">
                                <div class="api-key-warning">
                                    <i class="fas fa-exclamation-triangle"></i> 
                                    Copy this API key now! It will not be shown again.
                                </div>
                                <div class="api-key-display" id="generatedApiKey"></div>
                                <div style="margin-top: 10px;">
                                    <strong>Usage Example:</strong>
                                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 0.9rem;">
// JavaScript fetch example
fetch('https://ai.hidk.in/?api=1', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': '<span id="apiKeyExample"></span>'
    },
    body: JSON.stringify({
        action: 'chat',
        message: 'Hello AI'
    })
})</pre>
                                </div>
                            </div>
                        </div>
                        
                        <div class="section-header">
                            <h2><i class="fas fa-list"></i> Existing API Keys</h2>
                            <p>All generated API keys</p>
                        </div>
                        <div class="table-container">
                            <div id="apiKeysList">Loading API keys...</div>
                        </div>
                    </div>
                    
                    <div id="chat" class="section">
                        <div class="chat-container">
                            <div class="chat-header">
                                <h3><i class="fas fa-robot"></i> Admin Chat Interface</h3>
                                <div class="chat-status">
                                    <span class="status-indicator"></span>
                                    <span>Testing mode</span>
                                </div>
                            </div>
                            <div class="messages-container" id="adminMessages"></div>
                            <div class="chat-input-area">
                                <input type="text" class="chat-input" id="adminMessageInput" 
                                       placeholder="Test the AI response..." 
                                       onkeypress="if(event.key === 'Enter') sendAdminMessage()">
                                <button class="btn btn-primary" onclick="sendAdminMessage()">
                                    <i class="fas fa-paper-plane"></i> Send
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div id="documents" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-file-upload"></i> Upload Documents</h2>
                            <p>Upload PDF, TXT, DOC, DOCX files to train the AI</p>
                        </div>
                        
                        <div class="card">
                            <h3>Upload New Document</h3>
                            <div class="file-upload" onclick="document.getElementById('fileInput').click()">
                                <i class="fas fa-cloud-upload-alt"></i>
                                <h4>Click to upload or drag & drop</h4>
                                <p>Supported formats: PDF, TXT, DOC, DOCX, CSV, RTF, MD</p>
                                <p>Max file size: 10MB</p>
                            </div>
                            <input type="file" id="fileInput" style="display: none;" 
                                   accept=".pdf,.txt,.doc,.docx,.csv,.rtf,.md" 
                                   onchange="handleFileSelect(this.files[0])">
                            <div style="margin-top: 20px; text-align: center;">
                                <button class="btn btn-primary" onclick="uploadDocument()" id="uploadBtn" disabled>
                                    <i class="fas fa-upload"></i> Upload Document
                                </button>
                            </div>
                        </div>
                        
                        <div class="section-header">
                            <h2><i class="fas fa-folder-open"></i> Storage Management</h2>
                            <p>Manage uploaded documents and free up space</p>
                        </div>
                        
                        <div class="storage-stats" id="documentStats"></div>
                        
                        <div class="section-header">
                            <h2><i class="fas fa-folder-open"></i> Uploaded Documents</h2>
                            <p>All documents in the knowledge base</p>
                        </div>
                        <div class="table-container">
                            <div id="documentsList">Loading documents...</div>
                        </div>
                    </div>
                    
                    <div id="staff" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-users-cog"></i> Manage Staff Accounts</h2>
                            <p>Create and manage staff members</p>
                        </div>
                        
                        <div class="card">
                            <h3>Create New Staff Account</h3>
                            <form id="staffForm">
                                <div class="form-group">
                                    <label class="form-label">Full Name</label>
                                    <input type="text" class="form-control" id="staffFullName" 
                                           placeholder="Enter full name" required>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" id="staffUsername" 
                                           placeholder="Enter username" required>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" id="staffEmail" 
                                           placeholder="Enter email address">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" id="staffPassword" 
                                           placeholder="Enter password" required>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">User Type</label>
                                    <select class="form-control" id="staffType">
                                        <option value="staff">Staff</option>
                                        <option value="admin">Administrator</option>
                                    </select>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-user-plus"></i> Create Account
                                </button>
                            </form>
                        </div>
                        
                        <div class="section-header">
                            <h2><i class="fas fa-list"></i> Existing Staff</h2>
                            <p>All staff and administrator accounts</p>
                        </div>
                        <div class="table-container">
                            <div id="staffList">Loading staff list...</div>
                        </div>
                    </div>
                    
                    <div id="activity" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-history"></i> Activity Logs</h2>
                            <p>Chat sessions and user activities</p>
                        </div>
                        <div class="table-container">
                            <div id="activityLogs">Loading activity logs...</div>
                        </div>
                    </div>
                    
                    <div id="users" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-users"></i> All Users</h2>
                            <p>Manage all user accounts in the system</p>
                        </div>
                        <div class="table-container">
                            <div id="usersList">Loading users...</div>
                        </div>
                    </div>
                    
                    <div id="knowledge" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-database"></i> Knowledge Base</h2>
                            <p>All knowledge chunks extracted from documents</p>
                        </div>
                        <div class="table-container">
                            <div id="knowledgeBase">Loading knowledge base...</div>
                        </div>
                    </div>
                    
                    <div id="logs" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-clipboard-list"></i> System Logs</h2>
                            <p>Application events and error logs</p>
                        </div>
                        <div class="table-container">
                            <div id="systemLogs">Loading system logs...</div>
                        </div>
                    </div>
                    
                <?php elseif (isStaff()): ?>
                    <!-- STAFF SECTIONS -->
                    <div id="staffChat" class="section active">
                        <div class="chat-container">
                            <div class="chat-header">
                                <h3><i class="fas fa-graduation-cap"></i> AI Training Mode</h3>
                                <div class="training-mode">
                                    <input type="checkbox" id="trainingMode" checked>
                                    <label for="trainingMode">Training Mode</label>
                                </div>
                            </div>
                            <div class="messages-container" id="staffMessages"></div>
                            <div id="trainingOptions" style="display: none;">
                                <div class="training-options">
                                    <div class="training-title">
                                        <i class="fas fa-brain"></i> Select the best response:
                                    </div>
                                    <div id="responsesContainer"></div>
                                    <div style="text-align: center; margin-top: 20px;">
                                        <button class="btn btn-success" onclick="submitTraining()">
                                            <i class="fas fa-check-circle"></i> Train AI with Selected Response
                                        </button>
                                        <button class="btn btn-danger" onclick="cancelTraining()">
                                            <i class="fas fa-times-circle"></i> Cancel
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="chat-input-area">
                                <input type="text" class="chat-input" id="staffMessageInput" 
                                       placeholder="Ask a question to train the AI..." 
                                       onkeypress="if(event.key === 'Enter') sendStaffMessage()">
                                <button class="btn btn-primary" onclick="sendStaffMessage()">
                                    <i class="fas fa-paper-plane"></i> Send
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div id="trainingHistory" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-history"></i> Training History</h2>
                            <p>All questions you've trained the AI on</p>
                        </div>
                        <div class="table-container">
                            <div id="trainingHistoryList">Loading training history...</div>
                        </div>
                    </div>
                    
                    <div id="knowledge" class="section">
                        <div class="section-header">
                            <h2><i class="fas fa-book"></i> Knowledge Base</h2>
                            <p>Browse knowledge extracted from documents</p>
                        </div>
                        <div class="table-container">
                            <div id="staffKnowledge">Loading knowledge base...</div>
                        </div>
                    </div>
                    
                <?php endif; ?>
                
                <!-- COMMON SECTIONS -->
                <div id="settings" class="section">
                    <div class="section-header">
                        <h2><i class="fas fa-cog"></i> Settings</h2>
                        <p>System configuration</p>
                    </div>
                    <div class="card">
                        <h3>Session Information</h3>
                        <p><strong>Session ID:</strong> <span id="sessionId"><?php echo session_id(); ?></span></p>
                        <p><strong>IP Address:</strong> <?php echo getClientIP(); ?></p>
                        <p><strong>User Agent:</strong> <?php echo htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'); ?></p>
                        <p><strong>Login Time:</strong> <?php echo isset($_SESSION['login_time']) ? date('Y-m-d H:i:s', $_SESSION['login_time']) : 'N/A'; ?></p>
                        <p><strong>Database:</strong> MySQL (Hostinger)</p>
                    </div>
                </div>
                
                <div id="help" class="section">
                    <div class="section-header">
                        <h2><i class="fas fa-question-circle"></i> Help & Documentation</h2>
                        <p>How to use the AI Chat Assistant</p>
                    </div>
                    <div class="card">
                        <h3>Getting Started</h3>
                        <p>This AI Chat Assistant learns from uploaded documents and can be trained by staff members to provide better responses.</p>
                        
                        <h3 style="margin-top: 30px;">API Integration for Subdomains</h3>
                        <p>You can embed the chat interface on any subdomain of hidk.in using the API:</p>
                        <ol>
                            <li>Generate an API key from the API Management section</li>
                            <li>Use the API endpoint: <code>https://ai.hidk.in/?api=1</code></li>
                            <li>Include the API key in the <code>X-API-Key</code> header</li>
                            <li>Send POST requests with JSON payload</li>
                        </ol>
                        
                        <h4>Example JavaScript integration:</h4>
                        <pre style="background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto;">
// Include on any hidk.in subdomain
async function askAI(question) {
    const response = await fetch('https://ai.hidk.in/?api=1', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': 'your_api_key_here'
        },
        body: JSON.stringify({
            action: 'chat',
            message: question
        })
    });
    return await response.json();
}</pre>
                        
                        <h3 style="margin-top: 30px;">For Public Users:</h3>
                        <ul>
                            <li>Simply type your question in the chat</li>
                            <li>The AI will search through uploaded documents</li>
                            <li>No login required</li>
                            <li>Rate responses as Helpful or Not Helpful to improve AI training</li>
                            <li>Try greetings like: hi, hello, good morning, how are you, thanks, bye</li>
                        </ul>
                        
                        <h3 style="margin-top: 30px;">For Staff Members:</h3>
                        <ul>
                            <li>Enable "Training Mode" in the chat</li>
                            <li>Ask questions and review 3 AI responses</li>
                            <li>Select the best response to train the AI</li>
                            <li>View training history</li>
                        </ul>
                        
                        <h3 style="margin-top: 30px;">For Administrators:</h3>
                        <ul>
                            <li>Upload documents (PDF, TXT, DOC, DOCX)</li>
                            <li>Delete documents to free up storage space (knowledge base preserved)</li>
                            <li>Create and manage staff accounts</li>
                            <li>Generate API keys for subdomain integration</li>
                            <li>Monitor activity logs</li>
                            <li>View system statistics and storage usage</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Delete Confirmation Modal -->
    <div class="delete-confirmation" id="deleteConfirmation">
        <div class="delete-content">
            <div class="delete-icon">
                <i class="fas fa-exclamation-triangle"></i>
            </div>
            <h3>Delete Document File</h3>
            <p id="deleteMessage">Are you sure you want to delete this document? This will only delete the file, not the knowledge base entries.</p>
            <div class="delete-buttons">
                <button class="btn btn-danger" onclick="confirmDelete()">Delete File Only</button>
                <button class="btn btn-secondary" onclick="cancelDelete()">Cancel</button>
            </div>
        </div>
    </div>
    
    <div id="notification" class="notification"></div>

    <script>
        // ============================================
        // GLOBAL VARIABLES
        // ============================================
        let currentSection = 'dashboard';
        let selectedFile = null;
        let trainingData = {
            question: '',
            responses: [],
            selectedResponse: 1
        };
        let documentToDelete = null;
        let ratedMessages = new Set();
        
        // ============================================
        // UTILITY FUNCTIONS
        // ============================================
        
        function showNotification(message, type = 'success', duration = 5000) {
            const notification = document.getElementById('notification');
            notification.innerHTML = `
                <div class="notification-content">
                    <div class="notification-icon">
                        ${type === 'success' ? '✅' : type === 'error' ? '❌' : '⚠️'}
                    </div>
                    <div>${message}</div>
                </div>
            `;
            notification.className = `notification ${type} show`;
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, duration);
        }
        
        async function apiCall(action, data = {}, method = 'POST') {
            const formData = new FormData();
            formData.append('action', action);
            
            for (const [key, value] of Object.entries(data)) {
                if (value instanceof File) {
                    formData.append(key, value);
                } else if (value !== null && value !== undefined) {
                    formData.append(key, value);
                }
            }
            
            // Show loading indicator
            const submitBtn = event?.target?.querySelector('button[type="submit"]');
            let originalText = '';
            if (submitBtn) {
                originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<div class="loading"></div> Processing...';
                submitBtn.disabled = true;
            }
            
            try {
                const response = await fetch(window.location.href, {
                    method: method,
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (!response.ok) {
                    let errorMsg = `Server error: ${response.status}`;
                    try {
                        const errorData = await response.json();
                        errorMsg = errorData.message || errorMsg;
                    } catch (e) {
                        try {
                            const text = await response.text();
                            if (text && text.length < 100) errorMsg = text;
                        } catch (e2) {
                            // Ignore
                        }
                    }
                    throw new Error(errorMsg);
                }
                
                const result = await response.json();
                
                if (!result.success && result.message) {
                    showNotification(result.message, 'error');
                }
                
                return result;
                
            } catch (error) {
                console.error('API Error Details:', error);
                
                let userMessage = 'Network error or server not responding';
                
                if (error.message.includes('Failed to fetch')) {
                    userMessage = 'Cannot connect to server. Please check your internet connection.';
                } else if (error.message.includes('500')) {
                    userMessage = 'Server error. Please check MySQL configuration.';
                } else if (error.message.includes('404')) {
                    userMessage = 'Page not found. Please refresh and try again.';
                } else if (error.message.includes('database')) {
                    userMessage = 'Database error. Please check MySQL connection.';
                } else if (error.message) {
                    userMessage = error.message;
                }
                
                showNotification(userMessage, 'error');
                return { success: false, message: userMessage };
                
            } finally {
                // Restore button
                if (submitBtn) {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            }
        }
        
        function formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // ============================================
        // SECTION MANAGEMENT
        // ============================================
        
        function showSection(sectionId) {
            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Update active nav button
            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Find and activate nav button for this section
            const navBtn = document.querySelector(`.nav-btn[onclick*="${sectionId}"]`);
            if (navBtn) {
                navBtn.classList.add('active');
            } else {
                // If no specific button, activate first one
                document.querySelector('.nav-btn')?.classList.add('active');
            }
            
            // Show selected section
            const section = document.getElementById(sectionId);
            if (section) {
                section.classList.add('active');
                currentSection = sectionId;
                
                // Load section data
                loadSectionData(sectionId);
            }
        }
        
        function loadSectionData(sectionId) {
            switch (sectionId) {
                case 'publicChat':
                    loadPublicChat();
                    break;
                case 'dashboard':
                    loadDashboard();
                    break;
                case 'documents':
                    loadDocuments();
                    break;
                case 'staff':
                    loadStaffList();
                    break;
                case 'activity':
                    loadActivityLogs();
                    break;
                case 'users':
                    loadUsers();
                    break;
                case 'trainingHistory':
                    loadTrainingHistory();
                    break;
                case 'knowledge':
                    loadKnowledgeBase();
                    break;
                case 'api':
                    loadApiKeys();
                    break;
            }
        }
        
        // ============================================
        // AUTHENTICATION FUNCTIONS
        // ============================================
        
        async function login() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            if (!username || !password) {
                showNotification('Please enter username and password', 'error');
                return;
            }
            
            const result = await apiCall('login', { username, password });
            
            if (result.success) {
                showNotification('Login successful!', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            }
        }
        
        async function logout() {
            const result = await apiCall('logout');
            if (result.success) {
                showNotification('Logged out successfully', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            }
        }
        
        // ============================================
        // PUBLIC CHAT FUNCTIONS
        // ============================================
        
        async function loadPublicChat() {
            const result = await apiCall('get_chat_history');
            if (result.success) {
                const container = document.getElementById('publicMessages');
                container.innerHTML = '';
                
                result.messages.forEach(msg => {
                    addMessageToChat(container, msg.content, msg.message_type, msg.created_at, msg.id);
                });
                
                container.scrollTop = container.scrollHeight;
            }
        }
        
        async function sendPublicMessage() {
            const input = document.getElementById('publicMessageInput');
            const message = input.value.trim();
            
            if (!message) return;
            
            const container = document.getElementById('publicMessages');
            addMessageToChat(container, message, 'user');
            input.value = '';
            
            // Show typing indicator
            const typingDiv = document.createElement('div');
            typingDiv.className = 'message ai';
            typingDiv.innerHTML = '<i class="fas fa-robot"></i> AI is thinking...';
            container.appendChild(typingDiv);
            container.scrollTop = container.scrollHeight;
            
            const result = await apiCall('chat', { message });
            
            // Remove typing indicator
            container.removeChild(typingDiv);
            
            if (result.success) {
                const messageId = result.ai_message_id;
                addMessageToChat(container, result.message, 'ai', null, messageId);
                
                // Add rating buttons for AI responses
                if (result.source !== 'human_like') {
                    const lastMessage = container.lastChild;
                    const sourceSpan = document.createElement('span');
                    sourceSpan.className = 'message-source';
                    sourceSpan.textContent = `Source: ${result.source} (${result.confidence} confidence)`;
                    lastMessage.appendChild(sourceSpan);
                    
                    // Add rating buttons
                    const ratingDiv = document.createElement('div');
                    ratingDiv.className = 'message-rating';
                    ratingDiv.innerHTML = `
                        <button class="rating-btn helpful" onclick="rateResponse(${messageId}, '${result.session_id}', '${message.replace(/'/g, "\\'")}', '${result.message.replace(/'/g, "\\'")}', 1)">
                            <i class="fas fa-thumbs-up"></i> Helpful
                            <span class="rating-count" id="helpful-count-${messageId}">${result.helpful_count || 0}</span>
                        </button>
                        <button class="rating-btn not-helpful" onclick="rateResponse(${messageId}, '${result.session_id}', '${message.replace(/'/g, "\\'")}', '${result.message.replace(/'/g, "\\'")}', 0)">
                            <i class="fas fa-thumbs-down"></i> Not Helpful
                            <span class="rating-count" id="not-helpful-count-${messageId}">${result.not_helpful_count || 0}</span>
                        </button>
                    `;
                    lastMessage.appendChild(ratingDiv);
                }
            } else {
                addMessageToChat(container, 'Error: ' + result.message, 'ai');
            }
        }
        
        async function rateResponse(messageId, sessionId, question, response, rating) {
            if (ratedMessages.has(messageId)) {
                showNotification('You have already rated this response', 'warning');
                return;
            }
            
            const result = await apiCall('rate_response', {
                message_id: messageId,
                session_id: sessionId,
                question: question,
                response: response,
                rating: rating
            });
            
            if (result.success) {
                ratedMessages.add(messageId);
                
                // Update UI
                const helpfulBtn = document.querySelector(`button[onclick*="rateResponse(${messageId}"]`);
                const notHelpfulBtn = document.querySelector(`button[onclick*="rateResponse(${messageId},"].not-helpful`);
                
                if (rating === 1) {
                    helpfulBtn.classList.add('rated');
                    helpfulBtn.innerHTML = `<i class="fas fa-thumbs-up"></i> Thank you!`;
                    helpfulBtn.onclick = null;
                } else {
                    notHelpfulBtn.classList.add('rated');
                    notHelpfulBtn.innerHTML = `<i class="fas fa-thumbs-down"></i> Thank you!`;
                    notHelpfulBtn.onclick = null;
                }
                
                // Update counts
                if (result.stats) {
                    const helpfulCount = document.getElementById(`helpful-count-${messageId}`);
                    const notHelpfulCount = document.getElementById(`not-helpful-count-${messageId}`);
                    
                    if (helpfulCount) helpfulCount.textContent = result.stats.helpful;
                    if (notHelpfulCount) notHelpfulCount.textContent = result.stats.not_helpful;
                }
            }
        }
        
        // ============================================
        // ADMIN FUNCTIONS
        // ============================================
        
        async function loadDashboard() {
            const result = await apiCall('get_stats');
            if (result.success) {
                const container = document.getElementById('dashboardStats');
                const stats = result.stats;
                
                container.innerHTML = `
                    <div class="card">
                        <div class="card-icon">👥</div>
                        <div class="card-stat">${stats.users || 0}</div>
                        <div class="card-stat-label">Total Users</div>
                    </div>
                    <div class="card">
                        <div class="card-icon">📄</div>
                        <div class="card-stat">${stats.documents || 0}</div>
                        <div class="card-stat-label">Active Documents</div>
                    </div>
                    <div class="card">
                        <div class="card-icon">🧠</div>
                        <div class="card-stat">${stats.knowledge_base || 0}</div>
                        <div class="card-stat-label">Knowledge Chunks</div>
                    </div>
                    <div class="card">
                        <div class="card-icon">💬</div>
                        <div class="card-stat">${stats.chat_sessions || 0}</div>
                        <div class="card-stat-label">Chat Sessions</div>
                    </div>
                    <div class="card">
                        <div class="card-icon">🤖</div>
                        <div class="card-stat">${stats.ai_training || 0}</div>
                        <div class="card-stat-label">Trained Responses</div>
                    </div>
                    <div class="card">
                        <div class="card-icon">⭐</div>
                        <div class="card-stat">${stats.helpful_ratings || 0}</div>
                        <div class="card-stat-label">Helpful Ratings</div>
                    </div>
                `;
                
                // Load storage stats
                const storageResult = await apiCall('get_storage_stats');
                if (storageResult.success) {
                    const storageContainer = document.getElementById('storageStats');
                    const storage = storageResult.stats;
                    
                    storageContainer.innerHTML = `
                        <div class="storage-stat">
                            <h4>Active Documents</h4>
                            <div class="storage-stat-value">${storage.total_documents || 0}</div>
                        </div>
                        <div class="storage-stat">
                            <h4>Storage Used</h4>
                            <div class="storage-stat-value">${formatFileSize(storage.total_size || 0)}</div>
                        </div>
                        <div class="storage-stat">
                            <h4>Storage Usage</h4>
                            <div class="storage-stat-value">${storage.used_percentage || 0}%</div>
                            <div style="height: 10px; background: #e9ecef; border-radius: 5px; margin-top: 10px; overflow: hidden;">
                                <div style="height: 100%; width: ${storage.used_percentage || 0}%; background: ${(storage.used_percentage || 0) > 80 ? 'var(--danger)' : 'var(--success)'}; border-radius: 5px;"></div>
                            </div>
                        </div>
                        <div class="storage-stat">
                            <h4>Knowledge Chunks</h4>
                            <div class="storage-stat-value">${storage.knowledge_chunks || 0}</div>
                        </div>
                    `;
                }
                
                // Load recent activity
                const activityResult = await apiCall('get_activity_logs', { limit: 10 });
                if (activityResult.success) {
                    const activityContainer = document.getElementById('recentActivity');
                    if (activityResult.logs.length > 0) {
                        let html = '<table class="data-table"><tr><th>Session ID</th><th>IP Address</th><th>Country</th><th>Started</th><th>Messages</th></tr>';
                        
                        activityResult.logs.forEach(log => {
                            html += `
                                <tr>
                                    <td title="${log.session_id}">${log.session_id.substring(0, 15)}...</td>
                                    <td>${log.ip_address}</td>
                                    <td>${log.country || 'Unknown'}</td>
                                    <td>${formatDate(log.started_at)}</td>
                                    <td>${log.message_count}</td>
                                </tr>
                            `;
                        });
                        
                        html += '</table>';
                        activityContainer.innerHTML = html;
                    } else {
                        activityContainer.innerHTML = '<div class="empty-state"><i class="fas fa-inbox"></i><h3>No recent activity</h3></div>';
                    }
                }
            }
        }
        
        function handleFileSelect(file) {
            if (!file) return;
            
            selectedFile = file;
            const uploadBtn = document.getElementById('uploadBtn');
            uploadBtn.disabled = false;
            uploadBtn.innerHTML = `<i class="fas fa-upload"></i> Upload "${file.name}"`;
            
            showNotification(`Selected file: ${file.name} (${formatFileSize(file.size)})`, 'success');
        }
        
        async function uploadDocument() {
            if (!selectedFile) {
                showNotification('Please select a file first', 'error');
                return;
            }
            
            const uploadBtn = document.getElementById('uploadBtn');
            uploadBtn.innerHTML = '<div class="loading"></div> Uploading...';
            uploadBtn.disabled = true;
            
            const result = await apiCall('upload_document', { document: selectedFile });
            
            if (result.success) {
                showNotification(result.message, 'success');
                selectedFile = null;
                uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload Document';
                uploadBtn.disabled = true;
                loadDocuments();
                loadDashboard();
            } else {
                uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload Document';
                uploadBtn.disabled = false;
            }
        }
        
        async function loadDocuments() {
            const result = await apiCall('get_documents');
            if (result.success) {
                const container = document.getElementById('documentsList');
                
                if (result.documents.length > 0) {
                    let html = '<table class="data-table"><tr><th>Filename</th><th>Type</th><th>Size</th><th>Uploaded By</th><th>Date</th><th>Status</th><th>Actions</th></tr>';
                    
                    result.documents.forEach(doc => {
                        const statusClass = doc.processed ? 'status-success' : doc.status?.includes('failed') ? 'status-danger' : 'status-warning';
                        const statusText = doc.processed ? 'Processed' : doc.status?.includes('failed') ? 'Failed' : 'Processing';
                        
                        html += `
                            <tr>
                                <td>${doc.filename}</td>
                                <td>${doc.file_type}</td>
                                <td>${formatFileSize(doc.file_size)}</td>
                                <td>${doc.uploaded_by_name || 'System'}</td>
                                <td>${formatDate(doc.uploaded_at)}</td>
                                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                                <td class="action-buttons">
                                    <button class="btn btn-sm btn-danger btn-icon" onclick="showDeleteDialog(${doc.id}, '${doc.filename.replace(/'/g, "\\'")}', ${doc.file_size})" title="Delete Document">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="empty-state"><i class="fas fa-file"></i><h3>No documents uploaded yet</h3><p>Upload documents to train the AI</p></div>';
                }
            }
            
            // Load storage stats for documents section
            const statsResult = await apiCall('get_storage_stats');
            if (statsResult.success) {
                const statsContainer = document.getElementById('documentStats');
                const storage = statsResult.stats;
                
                statsContainer.innerHTML = `
                    <div class="storage-stat">
                        <h4>Active Documents</h4>
                        <div class="storage-stat-value">${storage.total_documents || 0}</div>
                    </div>
                    <div class="storage-stat">
                        <h4>Storage Used</h4>
                        <div class="storage-stat-value">${formatFileSize(storage.total_size || 0)}</div>
                    </div>
                    <div class="storage-stat">
                        <h4>Deleted Files</h4>
                        <div class="storage-stat-value">${storage.deleted_documents || 0}</div>
                    </div>
                    <div class="storage-stat">
                        <h4>Knowledge Chunks</h4>
                        <div class="storage-stat-value">${storage.knowledge_chunks || 0}</div>
                    </div>
                `;
            }
        }
        
        function showDeleteDialog(documentId, filename, fileSize) {
            documentToDelete = documentId;
            document.getElementById('deleteMessage').innerHTML = `
                Are you sure you want to delete the file <strong>"${filename}"</strong>?<br><br>
                This will:
                <ul style="text-align: left; margin: 10px 0 10px 20px;">
                    <li>Delete the physical file (${formatFileSize(fileSize)}) from storage</li>
                    <li><strong style="color: var(--success);">✓ Keep all knowledge chunks in the database</strong></li>
                    <li><strong style="color: var(--success);">✓ AI will still respond using the knowledge</strong></li>
                    <li>Mark the document as deleted in the system</li>
                </ul>
                <p style="color: var(--success); font-weight: bold;">
                    <i class="fas fa-info-circle"></i> Knowledge base entries will be preserved!
                </p>
            `;
            document.getElementById('deleteConfirmation').style.display = 'flex';
        }
        
        function cancelDelete() {
            documentToDelete = null;
            document.getElementById('deleteConfirmation').style.display = 'none';
        }
        
        async function confirmDelete() {
            if (!documentToDelete) return;
            
            const result = await apiCall('delete_document', { document_id: documentToDelete });
            
            if (result.success) {
                showNotification(result.message, 'success');
                loadDocuments();
                loadDashboard();
            }
            
            document.getElementById('deleteConfirmation').style.display = 'none';
            documentToDelete = null;
        }
        
        async function loadStaffList() {
            const result = await apiCall('get_users');
            if (result.success) {
                const container = document.getElementById('staffList');
                const staff = result.users.filter(u => u.user_type === 'staff' || u.user_type === 'admin');
                
                if (staff.length > 0) {
                    let html = '<table class="data-table"><tr><th>Username</th><th>Full Name</th><th>Email</th><th>Type</th><th>Last Login</th><th>Status</th></tr>';
                    
                    staff.forEach(user => {
                        const statusClass = user.is_active ? 'status-success' : 'status-danger';
                        const statusText = user.is_active ? 'Active' : 'Inactive';
                        
                        html += `
                            <tr>
                                <td>${user.username}</td>
                                <td>${user.full_name || '-'}</td>
                                <td>${user.email || '-'}</td>
                                <td><span class="status-badge ${user.user_type === 'admin' ? 'status-warning' : 'status-success'}">${user.user_type}</span></td>
                                <td>${user.last_login_date}</td>
                                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="empty-state"><i class="fas fa-users"></i><h3>No staff accounts yet</h3><p>Create staff accounts to help train the AI</p></div>';
                }
            }
        }
        
        async function createStaff() {
            const username = document.getElementById('staffUsername').value;
            const password = document.getElementById('staffPassword').value;
            const email = document.getElementById('staffEmail').value;
            const fullName = document.getElementById('staffFullName').value;
            const userType = document.getElementById('staffType').value;
            
            if (!username || !password) {
                showNotification('Username and password are required', 'error');
                return;
            }
            
            const result = await apiCall('create_user', {
                username,
                password,
                email,
                full_name: fullName,
                user_type: userType
            });
            
            if (result.success) {
                showNotification(`User account created successfully`, 'success');
                document.getElementById('staffForm').reset();
                loadStaffList();
            }
        }
        
        async function loadActivityLogs() {
            const result = await apiCall('get_activity_logs');
            if (result.success) {
                const container = document.getElementById('activityLogs');
                
                if (result.logs.length > 0) {
                    let html = '<table class="data-table"><tr><th>Session ID</th><th>IP Address</th><th>Country</th><th>User Agent</th><th>Started</th><th>Last Activity</th><th>Messages</th></tr>';
                    
                    result.logs.forEach(log => {
                        html += `
                            <tr>
                                <td title="${log.session_id}">${log.session_id.substring(0, 12)}...</td>
                                <td>${log.ip_address}</td>
                                <td>${log.country || 'Unknown'}</td>
                                <td title="${log.user_agent}">${log.user_agent.substring(0, 30)}...</td>
                                <td>${formatDate(log.started_at)}</td>
                                <td>${formatDate(log.last_activity)}</td>
                                <td>${log.message_count}</td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="empty-state"><i class="fas fa-history"></i><h3>No activity logs yet</h3></div>';
                }
            }
        }
        
        async function loadUsers() {
            const result = await apiCall('get_users');
            if (result.success) {
                const container = document.getElementById('usersList');
                
                if (result.users.length > 0) {
                    let html = '<table class="data-table"><tr><th>ID</th><th>Username</th><th>Email</th><th>Type</th><th>Created</th><th>Last Login</th><th>Status</th></tr>';
                    
                    result.users.forEach(user => {
                        const statusClass = user.is_active ? 'status-success' : 'status-danger';
                        const statusText = user.is_active ? 'Active' : 'Inactive';
                        const typeClass = user.user_type === 'admin' ? 'status-warning' : 'status-success';
                        
                        html += `
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.username}</td>
                                <td>${user.email || '-'}</td>
                                <td><span class="status-badge ${typeClass}">${user.user_type}</span></td>
                                <td>${user.created_date}</td>
                                <td>${user.last_login_date}</td>
                                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="empty-state"><i class="fas fa-users"></i><h3>No users found</h3></div>';
                }
            }
        }
        
        async function loadKnowledgeBase() {
            // This would require a separate API endpoint
            const container = document.getElementById('knowledgeBase') || document.getElementById('staffKnowledge');
            if (container) {
                container.innerHTML = '<div class="empty-state"><i class="fas fa-database"></i><h3>Knowledge Base Browser</h3><p>This feature would show all knowledge chunks extracted from documents</p></div>';
            }
        }
        
        async function loadApiKeys() {
            const result = await apiCall('get_api_keys');
            if (result.success) {
                const container = document.getElementById('apiKeysList');
                
                if (result.api_keys.length > 0) {
                    let html = '<table class="data-table"><tr><th>API Key</th><th>Domain</th><th>Created By</th><th>Created Date</th><th>Last Used</th><th>Usage Count</th><th>Status</th><th>Action</th></tr>';
                    
                    result.api_keys.forEach(key => {
                        const statusClass = key.is_active ? 'status-success' : 'status-danger';
                        const statusText = key.is_active ? 'Active' : 'Revoked';
                        
                        html += `
                            <tr>
                                <td>${key.api_key_display}</td>
                                <td>${key.domain}</td>
                                <td>${key.user_name || 'System'}</td>
                                <td>${key.created_date}</td>
                                <td>${key.last_used_date}</td>
                                <td>${key.usage_count}</td>
                                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                                <td>
                                    ${key.is_active ? 
                                        `<button class="btn btn-sm btn-danger" onclick="revokeApiKey(${key.id})">Revoke</button>` : 
                                        'Revoked'
                                    }
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="empty-state"><i class="fas fa-key"></i><h3>No API keys generated yet</h3><p>Generate API keys to enable subdomain integration</p></div>';
                }
            }
        }
        
        async function createApiKey() {
            const domain = document.getElementById('apiDomain').value;
            if (!domain) {
                showNotification('Please enter a domain', 'error');
                return;
            }
            
            const result = await apiCall('create_api_key', { domain });
            
            if (result.success) {
                const resultDiv = document.getElementById('apiKeyResult');
                const keyDisplay = document.getElementById('generatedApiKey');
                const keyExample = document.getElementById('apiKeyExample');
                
                keyDisplay.textContent = result.api_key;
                keyExample.textContent = result.api_key;
                resultDiv.style.display = 'block';
                
                showNotification('API key generated successfully! Copy it now.', 'success');
                loadApiKeys();
                
                // Auto-scroll to result
                resultDiv.scrollIntoView({ behavior: 'smooth' });
            }
        }
        
        async function revokeApiKey(apiKeyId) {
            if (!confirm('Are you sure you want to revoke this API key?')) {
                return;
            }
            
            const result = await apiCall('revoke_api_key', { api_key_id: apiKeyId });
            
            if (result.success) {
                showNotification('API key revoked successfully', 'success');
                loadApiKeys();
            }
        }
        
        // ============================================
        // STAFF FUNCTIONS
        // ============================================
        
        async function sendStaffMessage() {
            const input = document.getElementById('staffMessageInput');
            const message = input.value.trim();
            const trainingMode = document.getElementById('trainingMode')?.checked || false;
            
            if (!message) return;
            
            const container = document.getElementById('staffMessages');
            addMessageToChat(container, message, 'user');
            input.value = '';
            
            // Show typing indicator
            const typingDiv = document.createElement('div');
            typingDiv.className = 'message ai';
            typingDiv.innerHTML = '<i class="fas fa-brain"></i> AI is thinking...';
            container.appendChild(typingDiv);
            container.scrollTop = container.scrollHeight;
            
            const data = { message };
            if (trainingMode) {
                data.training_mode = true;
            }
            
            const result = await apiCall('chat', data);
            
            // Remove typing indicator
            container.removeChild(typingDiv);
            
            if (result.success) {
                if (result.training_mode) {
                    // Show training options
                    trainingData.question = result.question;
                    trainingData.responses = result.responses;
                    showTrainingOptions(result.responses);
                } else {
                    addMessageToChat(container, result.message, 'ai');
                }
            } else {
                addMessageToChat(container, 'Error: ' + result.message, 'ai');
            }
        }
        
        function showTrainingOptions(responses) {
            const container = document.getElementById('responsesContainer');
            container.innerHTML = '';
            
            responses.forEach((response, index) => {
                const div = document.createElement('div');
                div.className = 'training-response';
                div.onclick = () => selectTrainingResponse(index + 1);
                div.innerHTML = `
                    <div>
                        <span class="response-number">${index + 1}</span>
                        <strong>Response ${index + 1}:</strong>
                    </div>
                    <div style="margin-top: 10px; padding-left: 35px;">${response}</div>
                `;
                container.appendChild(div);
            });
            
            // Add custom response option
            const customDiv = document.createElement('div');
            customDiv.className = 'training-response';
            customDiv.onclick = () => selectTrainingResponse('custom');
            customDiv.innerHTML = `
                <div>
                    <span class="response-number">✏️</span>
                    <strong>Custom Response:</strong>
                </div>
                <div style="margin-top: 10px; padding-left: 35px;">
                    <textarea id="customResponseText" 
                             placeholder="Write your own custom response here..." 
                             style="width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 5px;"
                             rows="4"
                             onclick="event.stopPropagation(); selectTrainingResponse('custom')"></textarea>
                    <p style="font-size: 0.85rem; color: var(--gray); margin-top: 5px;">
                        <i class="fas fa-info-circle"></i> Write a better response if none of the options above fit
                    </p>
                </div>
            `;
            container.appendChild(customDiv);
            
            document.getElementById('trainingOptions').style.display = 'block';
            trainingData.selectedResponse = 1;
            selectTrainingResponse(1);
        }
        
        function selectTrainingResponse(index) {
            trainingData.selectedResponse = index;
            const options = document.querySelectorAll('.training-response');
            options.forEach((opt, i) => {
                const isCustom = index === 'custom';
                const isSelected = isCustom ? (i === options.length - 1) : (i + 1 === index);
                opt.classList.toggle('selected', isSelected);
                
                // Focus custom textarea if selected
                if (isSelected && isCustom) {
                    const textarea = opt.querySelector('textarea');
                    if (textarea) {
                        setTimeout(() => textarea.focus(), 100);
                    }
                }
            });
        }
        
        function cancelTraining() {
            document.getElementById('trainingOptions').style.display = 'none';
            document.getElementById('staffMessageInput').focus();
        }
        
        async function submitTraining() {
            const isCustom = trainingData.selectedResponse === 'custom';
            const customResponse = isCustom ? document.getElementById('customResponseText').value.trim() : '';
            
            if (isCustom && !customResponse) {
                showNotification('Please write a custom response or select one of the AI responses', 'error');
                return;
            }
            
            const data = {
                train_response: true,
                question: trainingData.question,
                response1: trainingData.responses[0],
                response2: trainingData.responses[1],
                response3: trainingData.responses[2],
                best_response: isCustom ? 1 : trainingData.selectedResponse
            };
            
            if (isCustom && customResponse) {
                data.custom_response = customResponse;
            }
            
            const result = await apiCall('chat', data);
            
            if (result.success) {
                const message = isCustom 
                    ? 'AI trained with your custom response!' 
                    : `AI trained with response ${trainingData.selectedResponse}.`;
                
                showNotification(message + ' The AI will now use this for similar questions.', 'success');
                document.getElementById('trainingOptions').style.display = 'none';
                
                const container = document.getElementById('staffMessages');
                addMessageToChat(container, `✅ ${message} The AI will remember this choice for similar questions.`, 'ai');
                
                // Clear training data
                trainingData = { question: '', responses: [], selectedResponse: 1 };
            }
        }
        
        async function loadTrainingHistory() {
            const result = await apiCall('get_training_history');
            if (result.success) {
                const container = document.getElementById('trainingHistoryList');
                
                if (result.history.length > 0) {
                    let html = '<table class="data-table"><tr><th>Question</th><th>Best Response</th><th>Trained By</th><th>Date</th><th>Usage Count</th><th>Ratings</th></tr>';
                    
                    result.history.forEach(item => {
                        html += `
                            <tr>
                                <td title="${item.question}">${item.question_short}</td>
                                <td><span class="response-number">${item.best_response}</span> Response ${item.best_response}</td>
                                <td>${item.trained_by_name || 'System'}</td>
                                <td>${item.trained_date}</td>
                                <td>${item.usage_count}</td>
                                <td>
                                    <span style="color: var(--success);">👍 ${item.helpful_count || 0}</span>
                                    <span style="color: var(--danger); margin-left: 10px;">👎 ${item.not_helpful_count || 0}</span>
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="empty-state"><i class="fas fa-history"></i><h3>No training history yet</h3><p>Start training the AI in the chat interface</p></div>';
                }
            }
        }
        
        // ============================================
        // COMMON CHAT FUNCTIONS
        // ============================================
        
        function addMessageToChat(container, content, type, timestamp = null, messageId = null) {
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${type}`;
            if (messageId) {
                messageDiv.dataset.messageId = messageId;
            }
            
            let timeHtml = '';
            if (timestamp) {
                timeHtml = `<span class="message-time">${formatDate(timestamp)}</span>`;
            }
            
            messageDiv.innerHTML = `
                <div>${content}</div>
                ${timeHtml}
            `;
            
            container.appendChild(messageDiv);
            container.scrollTop = container.scrollHeight;
        }
        
        async function sendAdminMessage() {
            const input = document.getElementById('adminMessageInput');
            const message = input.value.trim();
            
            if (!message) return;
            
            const container = document.getElementById('adminMessages');
            addMessageToChat(container, message, 'user');
            input.value = '';
            
            const result = await apiCall('chat', { message });
            
            if (result.success) {
                addMessageToChat(container, result.message, 'ai');
            } else {
                addMessageToChat(container, 'Error: ' + result.message, 'ai');
            }
        }
        
        // ============================================
        // EVENT LISTENERS
        // ============================================
        
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize based on user type
            <?php if (!isLoggedIn()): ?>
                showSection('publicChat');
                loadPublicChat();
            <?php elseif (isAdmin()): ?>
                showSection('dashboard');
            <?php elseif (isStaff()): ?>
                showSection('staffChat');
            <?php endif; ?>
            
            // Login form
            const loginForm = document.getElementById('loginForm');
            if (loginForm) {
                loginForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    login();
                });
            }
            
            // Staff creation form
            const staffForm = document.getElementById('staffForm');
            if (staffForm) {
                staffForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    createStaff();
                });
            }
            
            // API key form
            const apiKeyForm = document.getElementById('apiKeyForm');
            if (apiKeyForm) {
                apiKeyForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    createApiKey();
                });
            }
            
            // Drag and drop for file upload
            const fileUpload = document.querySelector('.file-upload');
            if (fileUpload) {
                fileUpload.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    this.style.borderColor = 'var(--primary)';
                    this.style.background = '#f0f8ff';
                });
                
                fileUpload.addEventListener('dragleave', function(e) {
                    e.preventDefault();
                    this.style.borderColor = 'var(--border)';
                    this.style.background = '';
                });
                
                fileUpload.addEventListener('drop', function(e) {
                    e.preventDefault();
                    this.style.borderColor = 'var(--border)';
                    this.style.background = '';
                    
                    if (e.dataTransfer.files.length > 0) {
                        handleFileSelect(e.dataTransfer.files[0]);
                    }
                });
            }
            
            // Auto-focus chat input
            setTimeout(() => {
                const chatInput = document.getElementById('publicMessageInput') || 
                                document.getElementById('staffMessageInput') || 
                                document.getElementById('adminMessageInput');
                if (chatInput) {
                    chatInput.focus();
                }
            }, 500);
            
            // Auto-refresh dashboard every minute
            setInterval(() => {
                if (currentSection === 'dashboard' || currentSection === 'activity' || currentSection === 'api') {
                    loadSectionData(currentSection);
                }
            }, 60000);
        });
        
        // Global functions
        window.handleFileSelect = handleFileSelect;
        window.revokeApiKey = revokeApiKey;
        window.showDeleteDialog = showDeleteDialog;
        window.cancelDelete = cancelDelete;
        window.confirmDelete = confirmDelete;
        window.rateResponse = rateResponse;
    </script>
</body>
</html>