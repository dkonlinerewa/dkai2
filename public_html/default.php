<?php
// dkai.php - Main application logic
require_once 'config.php';

// ============================================
// TEMPLATE RENDERING FUNCTIONS
// ============================================

/**
 * Render template with data
 */
function render($template, $data = []) {
    extract($data);
    
    // Start output buffering
    ob_start();
    
    // Include template file if it exists
    $template_file = TEMPLATES_DIR . $template . '.php';
    if (file_exists($template_file)) {
        include $template_file;
    } else {
        // Fallback to inline template
        echo "<!-- Template $template not found -->\n";
        switch ($template) {
            case 'header':
                include 'templates/header.php';
                break;
            case 'footer':
                include 'templates/footer.php';
                break;
            default:
                echo "<!-- No template for $template -->";
        }
    }
    
    // Return captured content
    return ob_get_clean();
}

/**
 * Get human-like response
 */
function getHumanResponse($question) {
    $question_lower = strtolower(trim($question));
    
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

// ============================================
// USER MANAGEMENT FUNCTIONS
// ============================================

/**
 * Check if user is admin
 */
function isAdmin() {
    return isset($_SESSION['user_type']) && $_SESSION['user_type'] === 'admin';
}

/**
 * Check if user is staff
 */
function isStaff() {
    return isset($_SESSION['user_type']) && ($_SESSION['user_type'] === 'staff' || $_SESSION['user_type'] === 'admin');
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']) && isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

/**
 * Get current user type
 */
function getUserType() {
    return $_SESSION['user_type'] ?? 'public';
}

/**
 * Get user profile
 */
function getUserProfile($userId = null) {
    $db = getDBConnection();
    $userId = $userId ?? $_SESSION['user_id'] ?? null;
    
    if (!$userId) return null;
    
    try {
        $stmt = $db->prepare("SELECT id, username, email, phone, user_type, full_name, department, profile_image, 
                                     created_at, last_login, is_active, preferences 
                              FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        if ($user && $user['preferences']) {
            $user['preferences'] = json_decode($user['preferences'], true);
        }
        
        return $user;
    } catch (Exception $e) {
        logEvent('error', 'Failed to get user profile: ' . $e->getMessage(), $userId);
        return null;
    }
}

/**
 * Update user profile
 */
function updateUserProfile($userId, $data) {
    $db = getDBConnection();
    
    try {
        $allowedFields = ['full_name', 'email', 'phone', 'department', 'preferences'];
        $updates = [];
        $params = [];
        $types = '';
        
        foreach ($data as $field => $value) {
            if (in_array($field, $allowedFields)) {
                if ($field === 'preferences' && is_array($value)) {
                    $value = json_encode($value);
                }
                $updates[] = "$field = ?";
                $params[] = $value;
                $types .= 's';
            }
        }
        
        if (empty($updates)) {
            return [false, 'No valid fields to update'];
        }
        
        $params[] = $userId;
        $types .= 'i';
        
        $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
        $stmt = $db->prepare($sql);
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        
        if ($affected > 0) {
            auditLog('update_profile', 'user', $userId, null, json_encode($data));
            logEvent('profile', 'User profile updated', $userId);
            return [true, 'Profile updated successfully'];
        }
        
        return [false, 'No changes made'];
    } catch (Exception $e) {
        logEvent('error', 'Failed to update profile: ' . $e->getMessage(), $userId);
        return [false, 'Error updating profile: ' . $e->getMessage()];
    }
}

/**
 * Change user password (admin function)
 */
function changeUserPassword($userId, $newPassword, $requireCurrent = false, $currentPassword = null) {
    $db = getDBConnection();
    
    try {
        // Get current user info
        $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        if (!$user) {
            return [false, 'User not found'];
        }
        
        // If requiring current password, verify it
        if ($requireCurrent && $currentPassword) {
            if (!password_verify($currentPassword, $user['password_hash'])) {
                return [false, 'Current password is incorrect'];
            }
        }
        
        // Validate new password
        $validation = validatePassword($newPassword);
        if ($validation !== true) {
            return [false, $validation];
        }
        
        // Update password
        $newHash = hashPassword($newPassword);
        $stmt = $db->prepare("UPDATE users SET password_hash = ?, last_password_change = NOW() WHERE id = ?");
        $stmt->bind_param("si", $newHash, $userId);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        
        if ($affected > 0) {
            auditLog('change_password', 'user', $userId);
            logEvent('auth', 'Password changed', $userId);
            
            // Clear any reset tokens
            $db->query("UPDATE users SET reset_token = NULL, reset_expiry = NULL WHERE id = $userId");
            
            return [true, 'Password changed successfully'];
        }
        
        return [false, 'Failed to change password'];
    } catch (Exception $e) {
        logEvent('error', 'Failed to change password: ' . $e->getMessage(), $userId);
        return [false, 'Error changing password: ' . $e->getMessage()];
    }
}

/**
 * Reset password request
 */
function requestPasswordReset($email) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND is_active = 1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        if (!$user) {
            // Don't reveal if user exists for security
            return [true, 'If an account exists with this email, you will receive a reset link'];
        }
        
        // Generate reset token
        $token = generateToken(32);
        $expiry = date('Y-m-d H:i:s', time() + 3600); // 1 hour
        
        $stmt = $db->prepare("UPDATE users SET reset_token = ?, reset_expiry = ? WHERE id = ?");
        $stmt->bind_param("ssi", $token, $expiry, $user['id']);
        $stmt->execute();
        $stmt->close();
        
        // In a real application, send email here
        // For now, just log it
        logEvent('auth', 'Password reset requested for user ID: ' . $user['id'], $user['id']);
        
        // Return token for testing (in production, this would be sent via email)
        return [true, 'Reset token generated', $token];
    } catch (Exception $e) {
        logEvent('error', 'Password reset request failed: ' . $e->getMessage());
        return [false, 'Error processing request'];
    }
}

/**
 * Upload profile image
 */
function uploadProfileImage($userId, $file) {
    $allowedTypes = IMAGE_TYPES;
    list($valid, $errors) = validateUploadedFile($file, $allowedTypes);
    
    if (!$valid) {
        return [false, implode(', ', $errors)];
    }
    
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $filename = 'profile_' . $userId . '_' . time() . '.' . $extension;
    $filepath = UPLOAD_DIR . 'profiles/' . $filename;
    
    // Resize image if needed
    if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif'])) {
        list($width, $height) = getimagesize($file['tmp_name']);
        if ($width > 800 || $height > 800) {
            // Resize image
            $image = null;
            switch ($extension) {
                case 'jpg':
                case 'jpeg':
                    $image = imagecreatefromjpeg($file['tmp_name']);
                    break;
                case 'png':
                    $image = imagecreatefrompng($file['tmp_name']);
                    break;
                case 'gif':
                    $image = imagecreatefromgif($file['tmp_name']);
                    break;
            }
            
            if ($image) {
                $newWidth = 800;
                $newHeight = 800;
                $resized = imagescale($image, $newWidth, $newHeight);
                
                switch ($extension) {
                    case 'jpg':
                    case 'jpeg':
                        imagejpeg($resized, $filepath, 85);
                        break;
                    case 'png':
                        imagepng($resized, $filepath, 8);
                        break;
                    case 'gif':
                        imagegif($resized, $filepath);
                        break;
                }
                
                imagedestroy($image);
                imagedestroy($resized);
            } else {
                move_uploaded_file($file['tmp_name'], $filepath);
            }
        } else {
            move_uploaded_file($file['tmp_name'], $filepath);
        }
    } else {
        move_uploaded_file($file['tmp_name'], $filepath);
    }
    
    // Update user record
    $db = getDBConnection();
    $stmt = $db->prepare("UPDATE users SET profile_image = ? WHERE id = ?");
    $stmt->bind_param("si", $filename, $userId);
    $stmt->execute();
    $stmt->close();
    
    auditLog('upload_profile_image', 'user', $userId);
    logEvent('profile', 'Profile image uploaded', $userId);
    
    return [true, 'Profile image uploaded successfully', $filename];
}

// ============================================
// DOCUMENT MANAGEMENT FUNCTIONS
// ============================================

/**
 * Upload document
 */
function uploadDocument($file, $userId, $metadata = []) {
    list($valid, $errors) = validateUploadedFile($file);
    
    if (!$valid) {
        return [false, implode(', ', $errors)];
    }
    
    // Generate safe filename
    $original_name = $file['name'];
    $safe_filename = generateSafeFilename($original_name);
    $filepath = UPLOAD_DIR . 'documents/' . $safe_filename;
    
    // Move uploaded file
    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
        return [false, 'Failed to save file'];
    }
    
    // Calculate checksum
    $checksum = calculateFileChecksum($filepath);
    
    // Save to database
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
        
        // Process document in background
        $chunks = processDocument($documentId, $filepath, $original_name);
        
        auditLog('upload_document', 'document', $documentId, null, $original_name);
        logEvent('document', "Document uploaded: $original_name ($chunks chunks)", $userId);
        
        return [true, "Document uploaded successfully. Processed into $chunks knowledge chunks.", $documentId];
    } catch (Exception $e) {
        // Delete file if database insert failed
        if (file_exists($filepath)) {
            unlink($filepath);
        }
        logEvent('error', 'Document upload failed: ' . $e->getMessage(), $userId);
        return [false, 'Error uploading document: ' . $e->getMessage()];
    }
}

/**
 * Process document content
 */
function processDocument($documentId, $filepath, $filename) {
    $db = getDBConnection();
    
    try {
        // Extract text
        $content = extractTextFromFile($filepath, $filename);
        
        if (empty($content) || strlen($content) < 10) {
            throw new Exception("No extractable text found in document");
        }
        
        // Split content into chunks
        $chunks = splitIntoChunks($content);
        $chunk_count = 0;
        
        foreach ($chunks as $index => $chunk) {
            $clean_chunk = trim($chunk);
            if (strlen($clean_chunk) < 20) continue;
            
            $chunk_hash = md5($clean_chunk);
            
            // Check if chunk already exists
            $check = $db->prepare("SELECT id FROM knowledge_base WHERE chunk_hash = ?");
            $check->bind_param("s", $chunk_hash);
            $check->execute();
            $result = $check->get_result();
            
            if (!$result->fetch_assoc()) {
                $title = "Chunk " . ($index + 1) . " from " . substr($filename, 0, 50);
                $stmt = $db->prepare("INSERT INTO knowledge_base (document_id, title, content_chunk, chunk_hash, metadata) 
                                      VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("issss",
                    $documentId,
                    $title,
                    $clean_chunk,
                    $chunk_hash,
                    $metadata
                );
                
                $metadata = json_encode([
                    'filename' => $filename,
                    'chunk_index' => $index,
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
        $stmt = $db->prepare("UPDATE documents SET processed = 1, status = 'processed', content_text = ? 
                              WHERE id = ?");
        $stmt->bind_param("si",
            $content_preview,
            $documentId
        );
        
        $content_preview = substr($content, 0, 1000) . (strlen($content) > 1000 ? '...' : '');
        $stmt->execute();
        $stmt->close();
        
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

/**
 * Delete document (admin only)
 */
function deleteDocument($documentId) {
    $db = getDBConnection();
    
    try {
        // Get document details first
        $stmt = $db->prepare("SELECT filename, filepath FROM documents WHERE id = ? AND is_deleted = 0");
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
        
        auditLog('delete_document', 'document', $documentId, $document['filename'], 'deleted');
        logEvent('document', "Document file deleted: " . $document['filename'], $_SESSION['user_id'] ?? null);
        
        return [true, 'Document file deleted successfully. Knowledge base entries preserved.'];
        
    } catch (Exception $e) {
        logEvent('error', "Document deletion failed: " . $e->getMessage());
        return [false, 'Error deleting document: ' . $e->getMessage()];
    }
}

// ============================================
// TEXT EXTRACTION FUNCTIONS
// ============================================

/**
 * Extract text from various file types
 */
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
                
            case 'xls':
            case 'xlsx':
                $content = extractTextFromExcel($filepath);
                break;
                
            case 'ppt':
            case 'pptx':
                $content = extractTextFromPowerPoint($filepath);
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

/**
 * Extract text from PDF
 */
function extractTextFromPDF($filepath) {
    $content = '';
    
    if (!file_exists($filepath)) {
        return "PDF file not found";
    }
    
    // Try shell command first (pdftotext)
    if (function_exists('shell_exec') && is_callable('shell_exec')) {
        $output = @shell_exec("pdftotext -v 2>&1");
        if (strpos($output, 'pdftotext') !== false) {
            $temp_txt = tempnam(sys_get_temp_dir(), 'pdf_') . '.txt';
            @shell_exec("pdftotext \"$filepath\" \"$temp_txt\" 2>&1");
            if (file_exists($temp_txt)) {
                $content = file_get_contents($temp_txt);
                unlink($temp_txt);
                
                if (!empty($content)) {
                    return $content;
                }
            }
        }
    }
    
    // Fallback to PHP-based extraction
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
            $text = preg_replace('/\\\\(.)/', '$1', $match);
            $content .= $text . ' ';
        }
    }
    
    // Also look for text streams
    if (preg_match_all('/stream(.*?)endstream/s', $pdf_content, $stream_matches)) {
        foreach ($stream_matches[1] as $stream) {
            $clean_stream = preg_replace('/[^\x20-\x7E\x0A\x0D]/', '', $stream);
            if (strlen($clean_stream) > 50) {
                $content .= $clean_stream . ' ';
            }
        }
    }
    
    if (empty($content)) {
        $content = "PDF content extracted but no readable text found. Consider converting PDF to text first.";
    }
    
    return $content;
}

/**
 * Extract text from DOC/DOCX
 */
function extractTextFromDOC($filepath, $extension) {
    if ($extension === 'docx') {
        return extractTextFromDOCX($filepath);
    }
    
    return "DOC file uploaded. For best results, please convert to DOCX or TXT format.";
}

/**
 * Extract text from DOCX (ZIP-based)
 */
function extractTextFromDOCX($filepath) {
    $content = '';
    
    if (!class_exists('ZipArchive')) {
        return "ZipArchive class not available. Cannot process DOCX files.";
    }
    
    $zip = new ZipArchive;
    if ($zip->open($filepath) === TRUE) {
        // Look for document content
        if (($index = $zip->locateName('word/document.xml')) !== FALSE) {
            $xml_content = $zip->getFromIndex($index);
            
            // Remove XML tags and get text
            $xml_content = preg_replace('/<[^>]+>/', ' ', $xml_content);
            $xml_content = preg_replace('/\s+/', ' ', $xml_content);
            $content = html_entity_decode($xml_content);
        }
        $zip->close();
    }
    
    if (empty($content)) {
        $content = "DOCX file processed but no text extracted. Please ensure it's a valid Word document.";
    }
    
    return $content;
}

/**
 * Split content into chunks
 */
function splitIntoChunks($content, $max_chunk_size = 1000) {
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
// AI RESPONSE FUNCTIONS
// ============================================

/**
 * Get AI response
 */
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

/**
 * Search in knowledge base
 */
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
            ORDER BY importance DESC, LENGTH(content_chunk) DESC 
            LIMIT ?";
    
    $params[] = $limit;
    $types .= 'i';
    
    try {
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
    } catch (Exception $e) {
        logEvent('error', 'Knowledge base search failed: ' . $e->getMessage());
        return [];
    }
}

// ============================================
// API MANAGEMENT
// ============================================

/**
 * Validate API key
 */
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
        
        // Check rate limiting
        if ($api_data['rate_limit'] > 0 && $api_data['usage_count'] >= $api_data['rate_limit']) {
            logEvent('api', "API rate limit exceeded for key: " . substr($api_key, 0, 8) . '...');
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
        logEvent('error', 'API key validation failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Create API key
 */
function createApiKey($domain, $name = null, $userId = null) {
    $db = getDBConnection();
    
    try {
        $api_key = generateToken(32);
        $stmt = $db->prepare("INSERT INTO api_keys (api_key, name, domain, user_id) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("sssi", $api_key, $name, $domain, $userId);
        $stmt->execute();
        $key_id = $db->insert_id;
        $stmt->close();
        
        auditLog('create_api_key', 'api_key', $key_id, null, "Domain: $domain");
        logEvent('api', "API key created for domain: $domain", $userId);
        
        return $api_key;
        
    } catch (Exception $e) {
        logEvent('error', 'API key creation failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Revoke API key
 */
function revokeApiKey($api_key_id, $userId = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("UPDATE api_keys SET is_active = 0 WHERE id = ?");
        $stmt->bind_param("i", $api_key_id);
        $stmt->execute();
        $stmt->close();
        
        auditLog('revoke_api_key', 'api_key', $api_key_id);
        logEvent('api', "API key revoked: $api_key_id", $userId);
        
        return true;
        
    } catch (Exception $e) {
        logEvent('error', 'API key revocation failed: ' . $e->getMessage());
        return false;
    }
}

// ============================================
// AUTHENTICATION FUNCTIONS
// ============================================

/**
 * Handle user login
 */
function handleLogin($username, $password) {
    $db = getDBConnection();
    
    if (empty($username) || empty($password)) {
        return [false, 'Username and password are required'];
    }
    
    $username = sanitize($username);
    
    // Check IP blocking
    $ip = getClientIP();
    if (isIPBlocked($ip)) {
        logEvent('auth', 'Blocked IP attempted login: ' . $ip);
        return [false, 'Too many failed attempts. Please try again later.'];
    }
    
    try {
        $stmt = $db->prepare("SELECT id, username, password_hash, user_type, full_name, is_active, 
                                     failed_login_attempts, lockout_until 
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
        
        // Check if account is locked
        if ($user['lockout_until'] && strtotime($user['lockout_until']) > time()) {
            $remaining = strtotime($user['lockout_until']) - time();
            $minutes = ceil($remaining / 60);
            return [false, "Account locked. Try again in $minutes minutes."];
        }
        
        if (!$user['is_active']) {
            logEvent('auth', 'Login attempt to inactive account: ' . $username);
            return [false, 'Account is disabled'];
        }
        
        if (password_verify($password, $user['password_hash'])) {
            // Successful login
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['user_type'] = $user['user_type'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['authenticated'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            
            // Reset failed attempts
            $update = $db->prepare("UPDATE users SET last_login = NOW(), failed_login_attempts = 0, 
                                   lockout_until = NULL WHERE id = ?");
            $update->bind_param("i", $user['id']);
            $update->execute();
            $update->close();
            
            // Create user session record
            $session_token = generateToken(32);
            $expires = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);
            
            $stmt = $db->prepare("INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at) 
                                  VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("issss", $user['id'], $session_token, $ip, $_SERVER['HTTP_USER_AGENT'] ?? '', $expires);
            $stmt->execute();
            $stmt->close();
            
            $_SESSION['session_token'] = $session_token;
            
            auditLog('login', 'user', $user['id']);
            logEvent('auth', 'Successful login: ' . $username, $user['id']);
            
            return [true, 'Login successful'];
        } else {
            // Failed login
            $failed_attempts = $user['failed_login_attempts'] + 1;
            
            if ($failed_attempts >= MAX_LOGIN_ATTEMPTS) {
                $lockout_until = date('Y-m-d H:i:s', time() + LOCKOUT_TIME);
                $update = $db->prepare("UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?");
                $update->bind_param("isi", $failed_attempts, $lockout_until, $user['id']);
                logEvent('auth', 'Account locked due to too many failed attempts: ' . $username, $user['id']);
            } else {
                $update = $db->prepare("UPDATE users SET failed_login_attempts = ? WHERE id = ?");
                $update->bind_param("ii", $failed_attempts, $user['id']);
            }
            
            $update->execute();
            $update->close();
            
            logEvent('auth', 'Failed login - wrong password: ' . $username, $user['id']);
            return [false, 'Invalid credentials'];
        }
        
    } catch (Exception $e) {
        logEvent('error', 'Login error: ' . $e->getMessage());
        return [false, 'System error during login'];
    }
}

/**
 * Handle logout
 */
function handleLogout() {
    if (isset($_SESSION['user_id']) && isset($_SESSION['session_token'])) {
        $db = getDBConnection();
        $stmt = $db->prepare("DELETE FROM user_sessions WHERE session_token = ?");
        $stmt->bind_param("s", $_SESSION['session_token']);
        $stmt->execute();
        $stmt->close();
        
        logEvent('auth', 'User logged out: ' . $_SESSION['username'], $_SESSION['user_id']);
        auditLog('logout', 'user', $_SESSION['user_id']);
    }
    
    $_SESSION = [];
    session_destroy();
    session_start();
}

// ============================================
// CHAT FUNCTIONS
// ============================================

/**
 * Generate session ID
 */
function generateSessionId() {
    return session_id() . '_' . bin2hex(random_bytes(8));
}

/**
 * Get or create chat session
 */
function getSessionId() {
    if (!isset($_SESSION['chat_session_id'])) {
        $_SESSION['chat_session_id'] = generateSessionId();
        
        $db = getDBConnection();
        try {
            $stmt = $db->prepare("INSERT INTO chat_sessions (session_id, user_id, ip_address, user_agent, device_type, country) 
                                  VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sissss",
                $session_id,
                $user_id,
                $ip,
                $user_agent,
                $device_type,
                $country
            );
            
            $session_id = $_SESSION['chat_session_id'];
            $user_id = $_SESSION['user_id'] ?? null;
            $ip = getClientIP();
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            $device_type = getDeviceType($user_agent);
            $country = getCountryFromIP($ip);
            $stmt->execute();
            $stmt->close();
            
            logEvent('session', 'New chat session started', $user_id);
        } catch (Exception $e) {
            logEvent('error', 'Session creation failed: ' . $e->getMessage());
        }
    }
    return $_SESSION['chat_session_id'];
}

/**
 * Get device type from user agent
 */
function getDeviceType($user_agent) {
    if (stripos($user_agent, 'mobile') !== false) {
        return 'mobile';
    } elseif (stripos($user_agent, 'tablet') !== false) {
        return 'tablet';
    } else {
        return 'desktop';
    }
}

/**
 * Get country from IP (simplified)
 */
function getCountryFromIP($ip) {
    if ($ip === '127.0.0.1' || $ip === '::1' || $ip === '0.0.0.0') {
        return 'Local';
    }
    
    // In production, use a proper IP geolocation service
    // This is a simple fallback
    $ip_parts = explode('.', $ip);
    if (count($ip_parts) >= 2) {
        $countries = ['US', 'GB', 'CA', 'AU', 'IN', 'DE', 'FR', 'JP', 'BR', 'CN'];
        $index = intval($ip_parts[1]) % count($countries);
        return $countries[$index];
    }
    
    return 'Unknown';
}

/**
 * Save chat message
 */
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
// RATING SYSTEM
// ============================================

/**
 * Rate response
 */
function rateResponse($message_id, $session_id, $question, $response, $rating, $feedback = null) {
    $db = getDBConnection();
    
    try {
        $stmt = $db->prepare("INSERT INTO response_ratings (message_id, session_id, user_id, question, response, rating, feedback) 
                              VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("isisiss", 
            $message_id, 
            $session_id, 
            $user_id,
            $question, 
            $response, 
            $rating,
            $feedback
        );
        
        $user_id = $_SESSION['user_id'] ?? null;
        $stmt->execute();
        $rating_id = $db->insert_id;
        $stmt->close();
        
        // Update AI training helpful counts
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
        
        logEvent('rating', "Response rated: " . ($rating == 1 ? 'Helpful' : 'Not Helpful'), $user_id);
        
        return $rating_id;
        
    } catch (Exception $e) {
        logEvent('error', 'Rating failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Get response rating stats
 */
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
        logEvent('error', 'Rating stats failed: ' . $e->getMessage());
        return ['helpful' => 0, 'not_helpful' => 0, 'total' => 0];
    }
}

// ============================================
// STATISTICS FUNCTIONS
// ============================================

/**
 * Get storage statistics
 */
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
        
        // Get by category
        $result = $db->query("SELECT category, COUNT(*) as count FROM documents WHERE is_deleted = 0 AND category IS NOT NULL GROUP BY category");
        $stats['by_category'] = [];
        while ($row = $result->fetch_assoc()) {
            $stats['by_category'][] = $row;
        }
        
        return $stats;
        
    } catch (Exception $e) {
        logEvent('error', 'Storage stats failed: ' . $e->getMessage());
        return ['error' => $e->getMessage()];
    }
}

/**
 * Get system statistics
 */
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
    
    // Get today's activity
    $result = $db->query("SELECT COUNT(*) as today_sessions FROM chat_sessions WHERE DATE(started_at) = CURDATE()");
    $row = $result->fetch_assoc();
    $stats['today_sessions'] = intval($row['today_sessions'] ?? 0);
    
    $result = $db->query("SELECT COUNT(*) as today_messages FROM chat_messages WHERE DATE(created_at) = CURDATE()");
    $row = $result->fetch_assoc();
    $stats['today_messages'] = intval($row['today_messages'] ?? 0);
    
    // Get active users
    $result = $db->query("SELECT COUNT(DISTINCT user_id) as active_users FROM chat_sessions WHERE DATE(last_activity) = CURDATE()");
    $row = $result->fetch_assoc();
    $stats['active_users'] = intval($row['active_users'] ?? 0);
    
    return $stats;
}

// ============================================
// ADMIN USER MANAGEMENT
// ============================================

/**
 * Create user (admin function)
 */
function createUser($username, $password, $userType, $fullName = null, $email = null, $phone = null, $department = null) {
    $db = getDBConnection();
    
    try {
        // Check if username exists
        $check = $db->prepare("SELECT id FROM users WHERE username = ?");
        $check->bind_param("s", $username);
        $check->execute();
        $result = $check->get_result();
        
        if ($result->fetch_assoc()) {
            $check->close();
            return [false, 'Username already exists'];
        }
        $check->close();
        
        // Check if email exists
        if ($email) {
            $check = $db->prepare("SELECT id FROM users WHERE email = ?");
            $check->bind_param("s", $email);
            $check->execute();
            $result = $check->get_result();
            
            if ($result->fetch_assoc()) {
                $check->close();
                return [false, 'Email already exists'];
            }
            $check->close();
        }
        
        // Validate password
        $validation = validatePassword($password);
        if ($validation !== true) {
            return [false, $validation];
        }
        
        // Create user
        $stmt = $db->prepare("INSERT INTO users (username, password_hash, user_type, full_name, email, phone, department) 
                              VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("sssssss",
            $username,
            $password_hash,
            $userType,
            $fullName,
            $email,
            $phone,
            $department
        );
        
        $password_hash = hashPassword($password);
        $stmt->execute();
        $user_id = $db->insert_id;
        $stmt->close();
        
        auditLog('create_user', 'user', $user_id, null, "Type: $userType");
        logEvent('user', "User created: $username ($userType)", $_SESSION['user_id'] ?? null);
        
        return [true, 'User account created successfully', $user_id];
        
    } catch (Exception $e) {
        logEvent('error', 'User creation failed: ' . $e->getMessage());
        return [false, 'Error creating user: ' . $e->getMessage()];
    }
}

/**
 * Update user (admin function)
 */
function updateUser($userId, $data) {
    $db = getDBConnection();
    
    try {
        $allowedFields = ['full_name', 'email', 'phone', 'department', 'user_type', 'is_active'];
        $updates = [];
        $params = [];
        $types = '';
        
        foreach ($data as $field => $value) {
            if (in_array($field, $allowedFields)) {
                $updates[] = "$field = ?";
                $params[] = $value;
                $types .= 's';
            }
        }
        
        if (empty($updates)) {
            return [false, 'No valid fields to update'];
        }
        
        $params[] = $userId;
        $types .= 'i';
        
        $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
        $stmt = $db->prepare($sql);
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        
        if ($affected > 0) {
            auditLog('update_user', 'user', $userId, null, json_encode($data));
            logEvent('user', "User updated: ID $userId", $_SESSION['user_id'] ?? null);
            return [true, 'User updated successfully'];
        }
        
        return [false, 'No changes made'];
    } catch (Exception $e) {
        logEvent('error', 'User update failed: ' . $e->getMessage());
        return [false, 'Error updating user: ' . $e->getMessage()];
    }
}

/**
 * Get all users (admin function)
 */
function getAllUsers($filters = []) {
    $db = getDBConnection();
    
    try {
        $where = [];
        $params = [];
        $types = '';
        
        if (!empty($filters['user_type'])) {
            $where[] = "user_type = ?";
            $params[] = $filters['user_type'];
            $types .= 's';
        }
        
        if (!empty($filters['is_active'])) {
            $where[] = "is_active = ?";
            $params[] = $filters['is_active'];
            $types .= 'i';
        }
        
        $where_clause = $where ? "WHERE " . implode(' AND ', $where) : "";
        
        $sql = "SELECT id, username, email, phone, user_type, full_name, department, 
                       profile_image, created_at, last_login, is_active, failed_login_attempts,
                       lockout_until
                FROM users 
                $where_clause
                ORDER BY created_at DESC";
        
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
        return [true, 'Users retrieved successfully', $users];
        
    } catch (Exception $e) {
        logEvent('error', 'Get users failed: ' . $e->getMessage());
        return [false, 'Error retrieving users: ' . $e->getMessage()];
    }
}

// ============================================
// REQUEST HANDLER
// ============================================

// Handle API requests
if (isset($_GET['api']) || (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
    $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest' && 
    isset($_SERVER['HTTP_X_API_KEY']))) {
    
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-API-Key, X-Requested-With');
    
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }
    
    $api_response = handleApiRequest();
    echo json_encode($api_response);
    exit;
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    $action = sanitize($_POST['action']);
    $response = ['success' => false, 'message' => 'Unknown action'];
    
    try {
        switch ($action) {
            case 'login':
                $username = sanitize($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                list($success, $message) = handleLogin($username, $password);
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
                
                $metadata = [
                    'title' => sanitize($_POST['title'] ?? ''),
                    'description' => sanitize($_POST['description'] ?? ''),
                    'category' => sanitize($_POST['category'] ?? ''),
                    'tags' => sanitize($_POST['tags'] ?? '')
                ];
                
                list($success, $message, $documentId) = uploadDocument($_FILES['document'], $_SESSION['user_id'], $metadata);
                $response = [
                    'success' => $success,
                    'message' => $message,
                    'document_id' => $documentId ?? null
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
                
            case 'get_stats':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $stats = getSystemStats();
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
                $feedback = sanitize($_POST['feedback'] ?? '');
                
                if ($message_id <= 0 || empty($session_id) || empty($question) || empty($response_text)) {
                    throw new Exception('Missing required parameters');
                }
                
                if ($rating !== 0 && $rating !== 1) {
                    throw new Exception('Invalid rating value');
                }
                
                $rating_id = rateResponse($message_id, $session_id, $question, $response_text, $rating, $feedback);
                
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
                
                $user_message_id = saveChatMessage($sessionId, 'user', $question);
                
                if ($isStaff && $trainingMode) {
                    $aiResponse = getAIResponse($question, true);
                    
                    if (isset($_POST['train_response']) && $_POST['train_response'] === 'true') {
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
                
            case 'get_profile':
                if (!isLoggedIn()) {
                    throw new Exception('Not authenticated');
                }
                
                $profile = getUserProfile();
                $response = [
                    'success' => true,
                    'profile' => $profile
                ];
                break;
                
            case 'update_profile':
                if (!isLoggedIn()) {
                    throw new Exception('Not authenticated');
                }
                
                $data = [
                    'full_name' => sanitize($_POST['full_name'] ?? ''),
                    'email' => sanitize($_POST['email'] ?? '', 'email'),
                    'phone' => sanitize($_POST['phone'] ?? ''),
                    'department' => sanitize($_POST['department'] ?? ''),
                    'preferences' => json_decode($_POST['preferences'] ?? '{}', true)
                ];
                
                list($success, $message) = updateUserProfile($_SESSION['user_id'], $data);
                $response = [
                    'success' => $success,
                    'message' => $message
                ];
                break;
                
            case 'upload_profile_image':
                if (!isLoggedIn()) {
                    throw new Exception('Not authenticated');
                }
                
                if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
                    throw new Exception('Image upload failed');
                }
                
                list($success, $message, $filename) = uploadProfileImage($_SESSION['user_id'], $_FILES['image']);
                $response = [
                    'success' => $success,
                    'message' => $message,
                    'filename' => $filename ?? null
                ];
                break;
                
            case 'change_password':
                if (!isLoggedIn()) {
                    throw new Exception('Not authenticated');
                }
                
                $currentPassword = $_POST['current_password'] ?? null;
                $newPassword = $_POST['new_password'] ?? '';
                $confirmPassword = $_POST['confirm_password'] ?? '';
                
                if ($newPassword !== $confirmPassword) {
                    throw new Exception('New passwords do not match');
                }
                
                list($success, $message) = changeUserPassword($_SESSION['user_id'], $newPassword, true, $currentPassword);
                $response = [
                    'success' => $success,
                    'message' => $message
                ];
                break;
                
            case 'admin_change_password':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $userId = intval($_POST['user_id'] ?? 0);
                $newPassword = $_POST['new_password'] ?? '';
                $confirmPassword = $_POST['confirm_password'] ?? '';
                
                if ($newPassword !== $confirmPassword) {
                    throw new Exception('New passwords do not match');
                }
                
                list($success, $message) = changeUserPassword($userId, $newPassword, false);
                $response = [
                    'success' => $success,
                    'message' => $message
                ];
                break;
                
            case 'create_user':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $username = sanitize($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                $userType = sanitize($_POST['user_type'] ?? 'staff');
                $fullName = sanitize($_POST['full_name'] ?? '');
                $email = sanitize($_POST['email'] ?? '', 'email');
                $phone = sanitize($_POST['phone'] ?? '');
                $department = sanitize($_POST['department'] ?? '');
                
                list($success, $message, $userId) = createUser($username, $password, $userType, $fullName, $email, $phone, $department);
                $response = [
                    'success' => $success,
                    'message' => $message,
                    'user_id' => $userId ?? null
                ];
                break;
                
            case 'get_users':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $filters = [
                    'user_type' => sanitize($_POST['user_type'] ?? ''),
                    'is_active' => isset($_POST['is_active']) ? intval($_POST['is_active']) : null
                ];
                
                list($success, $message, $users) = getAllUsers($filters);
                $response = [
                    'success' => $success,
                    'message' => $message,
                    'users' => $users ?? []
                ];
                break;
                
            case 'update_user':
                if (!isAdmin()) {
                    throw new Exception('Unauthorized access');
                }
                
                $userId = intval($_POST['user_id'] ?? 0);
                $data = [
                    'full_name' => sanitize($_POST['full_name'] ?? ''),
                    'email' => sanitize($_POST['email'] ?? '', 'email'),
                    'phone' => sanitize($_POST['phone'] ?? ''),
                    'department' => sanitize($_POST['department'] ?? ''),
                    'user_type' => sanitize($_POST['user_type'] ?? ''),
                    'is_active' => isset($_POST['is_active']) ? intval($_POST['is_active']) : null
                ];
                
                list($success, $message) = updateUser($userId, $data);
                $response = [
                    'success' => $success,
                    'message' => $message
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
                
            case 'get_activity_logs':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $db = getDBConnection();
                $stmt = $db->prepare("SELECT cs.*, u.username as user_name 
                                      FROM chat_sessions cs 
                                      LEFT JOIN users u ON cs.user_id = u.id 
                                      ORDER BY cs.last_activity DESC 
                                      LIMIT 50");
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
                    $row['api_key_display'] = substr($row['api_key'], 0, 8) . '...' . substr($row['api_key'], -8);
                    $api_keys[] = $row;
                }
                $stmt->close();
                
                $response = ['success' => true, 'api_keys' => $api_keys];
                break;
                
            case 'create_api_key':
                if (!isAdmin()) throw new Exception('Unauthorized');
                
                $domain = sanitize($_POST['domain'] ?? '*');
                $name = sanitize($_POST['name'] ?? '');
                if (empty($domain)) {
                    throw new Exception('Domain is required');
                }
                
                $api_key = createApiKey($domain, $name, $_SESSION['user_id']);
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
                
            case 'get_system_checks':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    $checks = performSystemCheck();
    $response = [
        'success' => true,
        'checks' => $checks,
        'timestamp' => date('Y-m-d H:i:s'),
        'environment' => ENVIRONMENT
    ];
    break;
            
            case 'get_knowledge_base':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    $db = getDBConnection();
    $stmt = $db->prepare("SELECT k.*, d.filename as document_name 
                          FROM knowledge_base k 
                          LEFT JOIN documents d ON k.document_id = d.id 
                          ORDER BY k.created_at DESC 
                          LIMIT 100");
    $stmt->execute();
    $result = $stmt->get_result();
    
    $knowledge = [];
    while ($row = $result->fetch_assoc()) {
        $row['content_preview'] = substr($row['content_chunk'], 0, 100) . (strlen($row['content_chunk']) > 100 ? '...' : '');
        $knowledge[] = $row;
    }
    $stmt->close();
    
    $response = ['success' => true, 'knowledge' => $knowledge];
    break;

case 'get_user_details':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    $userId = intval($_POST['user_id'] ?? 0);
    if ($userId <= 0) {
        throw new Exception('Invalid user ID');
    }
    
    $user = getUserProfile($userId);
    if ($user) {
        $response = ['success' => true, 'user' => $user];
    } else {
        throw new Exception('User not found');
    }
    break;

case 'get_system_logs':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    $severity = sanitize($_POST['severity'] ?? '');
    $log_type = sanitize($_POST['log_type'] ?? '');
    $date = sanitize($_POST['date'] ?? '');
    
    $db = getDBConnection();
    $where = [];
    $params = [];
    $types = '';
    
    if (!empty($severity)) {
        $where[] = "severity = ?";
        $params[] = $severity;
        $types .= 's';
    }
    
    if (!empty($log_type)) {
        $where[] = "log_type = ?";
        $params[] = $log_type;
        $types .= 's';
    }
    
    if (!empty($date)) {
        $where[] = "DATE(created_at) = ?";
        $params[] = $date;
        $types .= 's';
    }
    
    $where_clause = $where ? "WHERE " . implode(' AND ', $where) : "";
    
    $sql = "SELECT sl.*, u.username as user_name 
            FROM system_logs sl 
            LEFT JOIN users u ON sl.user_id = u.id 
            $where_clause 
            ORDER BY sl.created_at DESC 
            LIMIT 100";
    
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
    
    $response = ['success' => true, 'logs' => $logs];
    break;

case 'clear_old_logs':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    $days = intval($_POST['days'] ?? 30);
    $db = getDBConnection();
    $stmt = $db->prepare("DELETE FROM system_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)");
    $stmt->bind_param("i", $days);
    $stmt->execute();
    $deleted = $db->affected_rows;
    $stmt->close();
    
    logEvent('system', "Cleared $deleted old logs (older than $days days)", $_SESSION['user_id']);
    $response = ['success' => true, 'message' => "Cleared $deleted old logs"];
    break;

case 'create_backup':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    list($success, $message, $filename) = backupDatabase();
    if ($success) {
        $filepath = BACKUP_DIR . $filename;
        $response = [
            'success' => true,
            'message' => $message,
            'backup_file' => $filename,
            'file_size' => formatFileSize(filesize($filepath)),
            'location' => $filepath
        ];
    } else {
        $response = ['success' => false, 'message' => $message];
    }
    break;

case 'get_system_info':
    if (!isAdmin()) throw new Exception('Unauthorized');
    
    $info = getSystemInfo();
    $response = ['success' => true, 'info' => $info];
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

/**
 * Handle API requests
 */
function handleApiRequest() {
    $method = $_SERVER['REQUEST_METHOD'];
    $response = ['success' => false, 'message' => 'Invalid API request'];
    
    $api_key = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? null;
    $domain = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? $_GET['domain'] ?? null;
    
    if (!$api_key) {
        $response['message'] = 'API key required';
        return $response;
    }
    
    $api_data = validateApiKey($api_key, $domain);
    if (!$api_data) {
        $response['message'] = 'Invalid or expired API key';
        return $response;
    }
    
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
                    
                    $session_id = 'api_' . $api_data['id'] . '_' . bin2hex(random_bytes(8));
                    
                    saveChatMessage($session_id, 'user', $question);
                    
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

/**
 * Check if user is admin by ID
 */
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

// ============================================
// HTML INTERFACE (SAME AS BEFORE, WITH PROFILE MANAGEMENT ADDED)
// ============================================
// The HTML interface remains largely the same, but with added profile management sections
// For brevity, I'll show the key additions:
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
    <style>
        /* All your existing CSS remains the same */
        /* Add profile management styles */
        .profile-container {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .profile-header {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        .profile-image-container {
            position: relative;
        }
        
        .profile-image {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            object-fit: cover;
            border: 4px solid white;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .profile-image-upload {
            position: absolute;
            bottom: 10px;
            right: 10px;
            background: var(--primary);
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        }
        
        .profile-info h2 {
            margin-bottom: 5px;
        }
        
        .profile-role {
            color: var(--primary);
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .profile-stats {
            display: flex;
            gap: 20px;
            margin-top: 10px;
        }
        
        .profile-stat {
            text-align: center;
        }
        
        .profile-stat-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .profile-stat-label {
            font-size: 0.85rem;
            color: var(--gray);
        }
        
        .profile-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }
        
        .profile-tab {
            padding: 10px 20px;
            background: none;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            color: var(--gray);
            transition: all 0.3s ease;
        }
        
        .profile-tab:hover {
            color: var(--primary);
            background: rgba(67, 97, 238, 0.1);
        }
        
        .profile-tab.active {
            color: white;
            background: var(--primary);
        }
        
        .profile-section {
            display: none;
        }
        
        .profile-section.active {
            display: block;
        }
        
        .password-strength {
            height: 5px;
            background: #e9ecef;
            border-radius: 3px;
            margin-top: 5px;
            overflow: hidden;
        }
        
        .password-strength-bar {
            height: 100%;
            width: 0;
            transition: width 0.3s ease;
        }
        
        .password-strength-weak {
            background: var(--danger);
        }
        
        .password-strength-medium {
            background: var(--warning);
        }
        
        .password-strength-strong {
            background: var(--success);
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Header remains the same -->
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
                        <div class="user-avatar" onclick="showSection('profile')" style="cursor: pointer;">
                            <?php 
                            $profile = getUserProfile();
                            if ($profile && $profile['profile_image']): ?>
                                <img src="<?php echo UPLOAD_DIR . 'profiles/' . $profile['profile_image']; ?>" 
                                     alt="<?php echo $profile['full_name']; ?>"
                                     style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">
                            <?php else: ?>
                                <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                            <?php endif; ?>
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
            <!-- Sidebar with profile management option -->
            <!-- In dkai.php - Inside the sidebar div -->
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
            <button class="nav-btn" onclick="showKnowledgeModal()">
                <i class="fas fa-search"></i> Search Knowledge
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
            <button class="nav-btn" onclick="showSection('profile')">
                <i class="fas fa-user-cog"></i> My Profile
            </button>
        </div>
        
        <div class="sidebar-section">
            <div class="sidebar-title">System Tools</div>
            <button class="nav-btn" onclick="showSection('activity')">
                <i class="fas fa-history"></i> Activity Logs
            </button>
            <button class="nav-btn" onclick="showSystemLogsModal()">
                <i class="fas fa-clipboard-list"></i> System Logs
            </button>
            <button class="nav-btn" onclick="showBackupModal()">
                <i class="fas fa-download"></i> Backup System
            </button>
            <button class="nav-btn" onclick="showSystemInfoModal()">
                <i class="fas fa-info-circle"></i> System Info
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
            <button class="nav-btn" onclick="showKnowledgeModal()">
                <i class="fas fa-search"></i> Search Knowledge
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
        
        <div class="sidebar-section">
            <div class="sidebar-title">Account</div>
            <button class="nav-btn" onclick="showSection('profile')">
                <i class="fas fa-user-circle"></i> My Profile
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
            
            <!-- Main content with new sections -->
            <div class="main-content">
                <!-- Profile Management Section -->
                <?php if (isLoggedIn()): ?>
                <div id="profile" class="section">
                    <div class="section-header">
                        <h2><i class="fas fa-user-circle"></i> My Profile</h2>
                        <p>Manage your account settings</p>
                    </div>
                    
                    <div class="profile-container">
                        <div class="profile-header">
                            <div class="profile-image-container">
                                <div id="profileImageDisplay" class="profile-image">
                                    <!-- Profile image will be loaded here -->
                                </div>
                                <div class="profile-image-upload" onclick="document.getElementById('profileImageInput').click()">
                                    <i class="fas fa-camera"></i>
                                </div>
                                <input type="file" id="profileImageInput" accept="image/*" style="display: none;" 
                                       onchange="uploadProfileImage(this.files[0])">
                            </div>
                            <div class="profile-info">
                                <h2 id="profileFullName">Loading...</h2>
                                <div class="profile-role" id="profileRole">Loading...</div>
                                <div class="profile-stats">
                                    <div class="profile-stat">
                                        <div class="profile-stat-value" id="profileLoginCount">0</div>
                                        <div class="profile-stat-label">Logins</div>
                                    </div>
                                    <div class="profile-stat">
                                        <div class="profile-stat-value" id="profileMessages">0</div>
                                        <div class="profile-stat-label">Messages</div>
                                    </div>
                                    <div class="profile-stat">
                                        <div class="profile-stat-value" id="profileTraining">0</div>
                                        <div class="profile-stat-label">Trainings</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="profile-tabs">
                            <button class="profile-tab active" onclick="showProfileTab('info')">Personal Info</button>
                            <button class="profile-tab" onclick="showProfileTab('security')">Security</button>
                            <button class="profile-tab" onclick="showProfileTab('preferences')">Preferences</button>
                            <?php if (isAdmin()): ?>
                            <button class="profile-tab" onclick="showProfileTab('activity')">Activity</button>
                            <?php endif; ?>
                        </div>
                        
                        <div id="profileInfo" class="profile-section active">
                            <div class="card">
                                <h3>Personal Information</h3>
                                <form id="profileForm">
                                    <div class="form-group">
                                        <label class="form-label">Full Name</label>
                                        <input type="text" class="form-control" id="profileFullNameInput" 
                                               placeholder="Enter your full name">
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Email Address</label>
                                        <input type="email" class="form-control" id="profileEmailInput" 
                                               placeholder="Enter your email">
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Phone Number</label>
                                        <input type="tel" class="form-control" id="profilePhoneInput" 
                                               placeholder="Enter your phone number">
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Department</label>
                                        <input type="text" class="form-control" id="profileDepartmentInput" 
                                               placeholder="Enter your department">
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save"></i> Save Changes
                                    </button>
                                </form>
                            </div>
                        </div>
                        
                        <div id="profileSecurity" class="profile-section">
                            <div class="card">
                                <h3>Change Password</h3>
                                <form id="passwordForm">
                                    <div class="form-group">
                                        <label class="form-label">Current Password</label>
                                        <input type="password" class="form-control" id="currentPassword" 
                                               placeholder="Enter current password">
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">New Password</label>
                                        <input type="password" class="form-control" id="newPassword" 
                                               placeholder="Enter new password"
                                               onkeyup="checkPasswordStrength(this.value)">
                                        <div class="password-strength">
                                            <div class="password-strength-bar" id="passwordStrengthBar"></div>
                                        </div>
                                        <small id="passwordStrengthText" class="text-muted"></small>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Confirm New Password</label>
                                        <input type="password" class="form-control" id="confirmPassword" 
                                               placeholder="Confirm new password">
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-key"></i> Change Password
                                    </button>
                                </form>
                            </div>
                        </div>
                        
                        <div id="profilePreferences" class="profile-section">
                            <div class="card">
                                <h3>Preferences</h3>
                                <form id="preferencesForm">
                                    <div class="form-group">
                                        <label class="form-label">Default Chat Mode</label>
                                        <select class="form-control" id="prefChatMode">
                                            <option value="public">Public Chat</option>
                                            <option value="training">Training Mode</option>
                                            <?php if (isAdmin()): ?>
                                            <option value="admin">Admin Mode</option>
                                            <?php endif; ?>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Theme</label>
                                        <select class="form-control" id="prefTheme">
                                            <option value="light">Light</option>
                                            <option value="dark">Dark</option>
                                            <option value="auto">Auto (System)</option>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">
                                            <input type="checkbox" id="prefNotifications"> Enable Notifications
                                        </label>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">
                                            <input type="checkbox" id="prefEmailUpdates"> Email Updates
                                        </label>
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save"></i> Save Preferences
                                    </button>
                                </form>
                            </div>
                        </div>
                        
                        <?php if (isAdmin()): ?>
                        <div id="profileActivity" class="profile-section">
                            <div class="card">
                                <h3>Recent Activity</h3>
                                <div id="userActivityLogs">Loading activity logs...</div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- User Management Section (Admin only) -->
                <?php if (isAdmin()): ?>
                <div id="userManagement" class="section">
                    <div class="section-header">
                        <h2><i class="fas fa-users-cog"></i> User Management</h2>
                        <p>Manage staff and user accounts</p>
                    </div>
                    
                    <div class="card">
                        <h3>Create New User</h3>
                        <form id="adminUserForm">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Username *</label>
                                        <input type="text" class="form-control" id="adminUsername" 
                                               placeholder="Enter username" required>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">User Type *</label>
                                        <select class="form-control" id="adminUserType" required>
                                            <option value="staff">Staff</option>
                                            <option value="admin">Administrator</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Password *</label>
                                        <input type="password" class="form-control" id="adminPassword" 
                                               placeholder="Enter password" required>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Confirm Password *</label>
                                        <input type="password" class="form-control" id="adminConfirmPassword" 
                                               placeholder="Confirm password" required>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Full Name</label>
                                        <input type="text" class="form-control" id="adminFullName" 
                                               placeholder="Enter full name">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Email</label>
                                        <input type="email" class="form-control" id="adminEmail" 
                                               placeholder="Enter email address">
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Phone</label>
                                        <input type="tel" class="form-control" id="adminPhone" 
                                               placeholder="Enter phone number">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label class="form-label">Department</label>
                                        <input type="text" class="form-control" id="adminDepartment" 
                                               placeholder="Enter department">
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-user-plus"></i> Create User Account
                            </button>
                        </form>
                    </div>
                    
                    <div class="section-header">
                        <h2><i class="fas fa-list"></i> All Users</h2>
                        <p>Manage existing user accounts</p>
                    </div>
                    
                    <div class="table-container">
                        <div id="allUsersList">Loading users...</div>
                    </div>
                </div>
                <?php endif; ?>
                <?php endif; ?>
                
                <!-- Rest of the sections remain the same -->
                <!-- ... -->
            </div>
        </div>
    </div>
    
    <!-- Add JavaScript for profile management -->
    <script>
        // Profile management functions
        let currentProfileTab = 'info';
        
        function showProfileTab(tabName) {
            currentProfileTab = tabName;
            
            // Update tab buttons
            document.querySelectorAll('.profile-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelector(`.profile-tab[onclick*="${tabName}"]`).classList.add('active');
            
            // Update sections
            document.querySelectorAll('.profile-section').forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(`profile${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`).classList.add('active');
        }
        
        function loadProfile() {
            apiCall('get_profile').then(result => {
                if (result.success && result.profile) {
                    const profile = result.profile;
                    
                    // Update profile display
                    document.getElementById('profileFullName').textContent = profile.full_name || profile.username;
                    document.getElementById('profileRole').textContent = profile.user_type ? profile.user_type.charAt(0).toUpperCase() + profile.user_type.slice(1) : 'User';
                    
                    // Update form fields
                    document.getElementById('profileFullNameInput').value = profile.full_name || '';
                    document.getElementById('profileEmailInput').value = profile.email || '';
                    document.getElementById('profilePhoneInput').value = profile.phone || '';
                    document.getElementById('profileDepartmentInput').value = profile.department || '';
                    
                    // Update profile image
                    const profileImageDisplay = document.getElementById('profileImageDisplay');
                    if (profile.profile_image) {
                        profileImageDisplay.innerHTML = `<img src="<?php echo UPLOAD_DIR; ?>profiles/${profile.profile_image}" 
                                                              alt="${profile.full_name}" 
                                                              style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`;
                    } else {
                        profileImageDisplay.innerHTML = `<div style="width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; 
                                                                background: var(--primary); color: white; font-size: 3rem; border-radius: 50%;">
                                                            ${(profile.full_name || profile.username).charAt(0).toUpperCase()}
                                                         </div>`;
                    }
                    
                    // Update preferences
                    if (profile.preferences) {
                        document.getElementById('prefChatMode').value = profile.preferences.chat_mode || 'public';
                        document.getElementById('prefTheme').value = profile.preferences.theme || 'light';
                        document.getElementById('prefNotifications').checked = profile.preferences.notifications || false;
                        document.getElementById('prefEmailUpdates').checked = profile.preferences.email_updates || false;
                    }
                }
            });
        }
        
        function uploadProfileImage(file) {
            if (!file) return;
            
            const formData = new FormData();
            formData.append('action', 'upload_profile_image');
            formData.append('image', file);
            
            apiCall('upload_profile_image', formData).then(result => {
                if (result.success) {
                    showNotification('Profile image updated successfully', 'success');
                    loadProfile();
                }
            });
        }
        
        function checkPasswordStrength(password) {
            let strength = 0;
            const strengthBar = document.getElementById('passwordStrengthBar');
            const strengthText = document.getElementById('passwordStrengthText');
            
            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[\W_]/.test(password)) strength++;
            
            let width = 0;
            let color = '';
            let text = '';
            
            switch (strength) {
                case 0:
                case 1:
                    width = 20;
                    color = 'password-strength-weak';
                    text = 'Very Weak';
                    break;
                case 2:
                    width = 40;
                    color = 'password-strength-weak';
                    text = 'Weak';
                    break;
                case 3:
                    width = 60;
                    color = 'password-strength-medium';
                    text = 'Medium';
                    break;
                case 4:
                    width = 80;
                    color = 'password-strength-strong';
                    text = 'Strong';
                    break;
                case 5:
                    width = 100;
                    color = 'password-strength-strong';
                    text = 'Very Strong';
                    break;
            }
            
            strengthBar.style.width = width + '%';
            strengthBar.className = 'password-strength-bar ' + color;
            strengthText.textContent = text;
        }
        
        // Load profile on page load
        if (isLoggedIn) {
            loadProfile();
        }
        
        // Profile form submission
        document.getElementById('profileForm')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const data = {
                full_name: document.getElementById('profileFullNameInput').value,
                email: document.getElementById('profileEmailInput').value,
                phone: document.getElementById('profilePhoneInput').value,
                department: document.getElementById('profileDepartmentInput').value
            };
            
            apiCall('update_profile', data).then(result => {
                if (result.success) {
                    showNotification('Profile updated successfully', 'success');
                    loadProfile();
                }
            });
        });
        
        // Password form submission
        document.getElementById('passwordForm')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (newPassword !== confirmPassword) {
                showNotification('New passwords do not match', 'error');
                return;
            }
            
            apiCall('change_password', {
                current_password: currentPassword,
                new_password: newPassword,
                confirm_password: confirmPassword
            }).then(result => {
                if (result.success) {
                    showNotification('Password changed successfully', 'success');
                    document.getElementById('passwordForm').reset();
                    document.getElementById('passwordStrengthBar').style.width = '0';
                }
            });
        });
        
        // Preferences form submission
        document.getElementById('preferencesForm')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const preferences = {
                chat_mode: document.getElementById('prefChatMode').value,
                theme: document.getElementById('prefTheme').value,
                notifications: document.getElementById('prefNotifications').checked,
                email_updates: document.getElementById('prefEmailUpdates').checked
            };
            
            apiCall('update_profile', { preferences: preferences }).then(result => {
                if (result.success) {
                    showNotification('Preferences saved successfully', 'success');
                }
            });
        });
        
        // Admin user form submission
        document.getElementById('adminUserForm')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const password = document.getElementById('adminPassword').value;
            const confirmPassword = document.getElementById('adminConfirmPassword').value;
            
            if (password !== confirmPassword) {
                showNotification('Passwords do not match', 'error');
                return;
            }
            
            const data = {
                username: document.getElementById('adminUsername').value,
                password: password,
                user_type: document.getElementById('adminUserType').value,
                full_name: document.getElementById('adminFullName').value,
                email: document.getElementById('adminEmail').value,
                phone: document.getElementById('adminPhone').value,
                department: document.getElementById('adminDepartment').value
            };
            
            apiCall('create_user', data).then(result => {
                if (result.success) {
                    showNotification('User created successfully', 'success');
                    document.getElementById('adminUserForm').reset();
                    loadUsersList();
                }
            });
        });
        
        function loadUsersList() {
            apiCall('get_users').then(result => {
                if (result.success && result.users) {
                    const container = document.getElementById('allUsersList');
                    let html = '<table class="data-table"><tr><th>Username</th><th>Full Name</th><th>Email</th><th>Type</th><th>Department</th><th>Status</th><th>Actions</th></tr>';
                    
                    result.users.forEach(user => {
                        const statusClass = user.is_active ? 'status-success' : 'status-danger';
                        const statusText = user.is_active ? 'Active' : 'Inactive';
                        
                        html += `
                            <tr>
                                <td>${user.username}</td>
                                <td>${user.full_name || '-'}</td>
                                <td>${user.email || '-'}</td>
                                <td><span class="status-badge ${user.user_type === 'admin' ? 'status-warning' : 'status-success'}">${user.user_type}</span></td>
                                <td>${user.department || '-'}</td>
                                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                                <td>
                                    <div class="action-buttons">
                                        <button class="btn btn-sm btn-warning btn-icon" onclick="editUser(${user.id})" title="Edit">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="btn btn-sm btn-primary btn-icon" onclick="resetUserPassword(${user.id})" title="Reset Password">
                                            <i class="fas fa-key"></i>
                                        </button>
                                        <button class="btn btn-sm btn-danger btn-icon" onclick="toggleUserStatus(${user.id}, ${user.is_active})" title="${user.is_active ? 'Deactivate' : 'Activate'}">
                                            <i class="fas fa-${user.is_active ? 'ban' : 'check'}"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += '</table>';
                    container.innerHTML = html;
                }
            });
        }
        
        function resetUserPassword(userId) {
            const newPassword = prompt('Enter new password for this user:');
            if (!newPassword) return;
            
            const confirmPassword = prompt('Confirm new password:');
            if (!confirmPassword) return;
            
            if (newPassword !== confirmPassword) {
                showNotification('Passwords do not match', 'error');
                return;
            }
            
            apiCall('admin_change_password', {
                user_id: userId,
                new_password: newPassword,
                confirm_password: confirmPassword
            }).then(result => {
                if (result.success) {
                    showNotification('Password reset successfully', 'success');
                }
            });
        }
        
        function toggleUserStatus(userId, currentStatus) {
            const action = currentStatus ? 'deactivate' : 'activate';
            if (!confirm(`Are you sure you want to ${action} this user?`)) return;
            
            apiCall('update_user', {
                user_id: userId,
                is_active: currentStatus ? 0 : 1
            }).then(result => {
                if (result.success) {
                    showNotification(`User ${action}d successfully`, 'success');
                    loadUsersList();
                }
            });
        }
        
        function showKnowledgeModal() {
    loadKnowledgeBaseContent();
    document.getElementById('knowledgeModal').style.display = 'flex';
}

function closeKnowledgeModal() {
    document.getElementById('knowledgeModal').style.display = 'none';
}

        async function loadKnowledgeBaseContent() {
    const container = document.getElementById('knowledgeContent');
    container.innerHTML = '<div class="loading"></div> Loading knowledge base...';
    
    try {
        const response = await fetch('?action=get_knowledge_base', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'action=get_knowledge_base'
        });
        
        const result = await response.json();
        
        if (result.success) {
            let html = '<table style="width: 100%; border-collapse: collapse;">';
            html += '<tr><th style="padding: 10px; border-bottom: 1px solid #ddd;">Document</th><th style="padding: 10px; border-bottom: 1px solid #ddd;">Chunk</th><th style="padding: 10px; border-bottom: 1px solid #ddd;">Content Preview</th></tr>';
            
            result.knowledge.forEach(item => {
                html += `
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.document_name || 'Unknown'}</td>
                        <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.chunk_index || 0}</td>
                        <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.content_preview || ''}</td>
                    </tr>
                `;
            });
            
            html += '</table>';
            container.innerHTML = html;
        } else {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-database"></i><h3>No knowledge base entries</h3></div>';
        }
    } catch (error) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><h3>Error loading knowledge base</h3></div>';
    }
}

        function showEditUserModal(userId) {
    loadUserForEdit(userId);
    document.getElementById('editUserModal').style.display = 'flex';
}

function closeEditUserModal() {
    document.getElementById('editUserModal').style.display = 'none';
}

async function loadUserForEdit(userId) {
    const container = document.getElementById('editUserFormContainer');
    container.innerHTML = '<div class="loading"></div> Loading user data...';
    
    try {
        // Get user data
        const formData = new FormData();
        formData.append('action', 'get_user_details');
        formData.append('user_id', userId);
        
        const response = await fetch(window.location.href, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            const user = result.user;
            let html = `
                <input type="hidden" id="editUserId" value="${userId}">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-control" id="editUsername" value="${user.username}" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Full Name</label>
                    <input type="text" class="form-control" id="editFullName" value="${user.full_name || ''}">
                </div>
                <div class="form-group">
                    <label class="form-label">Email</label>
                    <input type="email" class="form-control" id="editEmail" value="${user.email || ''}">
                </div>
                <div class="form-group">
                    <label class="form-label">User Type</label>
                    <select class="form-control" id="editUserType">
                        <option value="user" ${user.user_type === 'user' ? 'selected' : ''}>User</option>
                        <option value="staff" ${user.user_type === 'staff' ? 'selected' : ''}>Staff</option>
                        <option value="admin" ${user.user_type === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Status</label>
                    <select class="form-control" id="editIsActive">
                        <option value="1" ${user.is_active ? 'selected' : ''}>Active</option>
                        <option value="0" ${!user.is_active ? 'selected' : ''}>Inactive</option>
                    </select>
                </div>
            `;
            container.innerHTML = html;
        }
    } catch (error) {
        container.innerHTML = '<div class="empty-state">Error loading user data</div>';
    }
}

async function saveUserChanges() {
    const userId = document.getElementById('editUserId').value;
    
    const data = {
        user_id: userId,
        full_name: document.getElementById('editFullName').value,
        email: document.getElementById('editEmail').value,
        user_type: document.getElementById('editUserType').value,
        is_active: document.getElementById('editIsActive').value
    };
    
    const result = await apiCall('update_user', data);
    
    if (result.success) {
        showNotification('User updated successfully', 'success');
        closeEditUserModal();
        loadUsersList();
    }
}

function showSystemLogsModal() {
    loadSystemLogs();
    document.getElementById('systemLogsModal').style.display = 'flex';
}

function closeSystemLogsModal() {
    document.getElementById('systemLogsModal').style.display = 'none';
}

async function loadSystemLogs() {
    const container = document.getElementById('systemLogsContent');
    container.innerHTML = '<div class="loading"></div> Loading logs...';
    
    try {
        const formData = new FormData();
        formData.append('action', 'get_system_logs');
        formData.append('severity', document.getElementById('logSeverityFilter').value);
        formData.append('log_type', document.getElementById('logTypeFilter').value);
        formData.append('date', document.getElementById('logDateFilter').value);
        
        const response = await fetch(window.location.href, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            let html = '<table style="width: 100%; border-collapse: collapse; font-size: 0.9rem;">';
            html += '<tr><th style="padding: 8px; border-bottom: 1px solid #ddd;">Time</th><th style="padding: 8px; border-bottom: 1px solid #ddd;">Type</th><th style="padding: 8px; border-bottom: 1px solid #ddd;">Severity</th><th style="padding: 8px; border-bottom: 1px solid #ddd;">Message</th><th style="padding: 8px; border-bottom: 1px solid #ddd;">User</th></tr>';
            
            result.logs.forEach(log => {
                const severityClass = log.severity === 'error' ? 'status-danger' : 
                                    log.severity === 'warning' ? 'status-warning' : 
                                    log.severity === 'critical' ? 'status-danger' : 'status-success';
                
                html += `
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">${log.created_at}</td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">${log.log_type}</td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><span class="status-badge ${severityClass}">${log.severity}</span></td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">${log.message}</td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">${log.user_name || 'System'}</td>
                    </tr>
                `;
            });
            
            html += '</table>';
            container.innerHTML = html;
        } else {
            container.innerHTML = '<div class="empty-state">No logs found</div>';
        }
    } catch (error) {
        container.innerHTML = '<div class="empty-state">Error loading logs</div>';
    }
}

async function clearOldLogs() {
    if (!confirm('Clear logs older than 30 days?')) return;
    
    const result = await apiCall('clear_old_logs', { days: 30 });
    
    if (result.success) {
        showNotification('Old logs cleared successfully', 'success');
        loadSystemLogs();
    }
}

function showBackupModal() {
    document.getElementById('backupResult').style.display = 'none';
    document.getElementById('backupModal').style.display = 'flex';
}

function closeBackupModal() {
    document.getElementById('backupModal').style.display = 'none';
}

async function createBackup() {
    const resultContainer = document.getElementById('backupResult');
    resultContainer.style.display = 'block';
    resultContainer.innerHTML = '<div class="loading"></div> Creating backup...';
    
    const data = {
        backup_database: document.getElementById('backupDatabase').checked ? 1 : 0,
        backup_documents: document.getElementById('backupDocuments').checked ? 1 : 0,
        backup_profiles: document.getElementById('backupProfiles').checked ? 1 : 0
    };
    
    const result = await apiCall('create_backup', data);
    
    if (result.success) {
        resultContainer.innerHTML = `
            <div style="color: var(--success);">
                <i class="fas fa-check-circle"></i> Backup created successfully!
            </div>
            <div style="margin-top: 10px;">
                <strong>Backup file:</strong> ${result.backup_file}<br>
                <strong>Size:</strong> ${result.file_size}<br>
                <strong>Location:</strong> ${result.location}
            </div>
            <div style="margin-top: 10px;">
                <button class="btn btn-sm btn-primary" onclick="downloadBackup('${result.backup_file}')">
                    <i class="fas fa-download"></i> Download Backup
                </button>
            </div>
        `;
    } else {
        resultContainer.innerHTML = `
            <div style="color: var(--danger);">
                <i class="fas fa-times-circle"></i> Backup failed: ${result.message}
            </div>
        `;
    }
}

async function downloadBackup(filename) {
    window.open(`download.php?file=${encodeURIComponent(filename)}`, '_blank');
}

function showSystemInfoModal() {
    loadSystemInfo();
    document.getElementById('systemInfoModal').style.display = 'flex';
}

function closeSystemInfoModal() {
    document.getElementById('systemInfoModal').style.display = 'none';
}

async function loadSystemInfo() {
    const result = await apiCall('get_system_info');
    
    if (result.success) {
        const info = result.info;
        document.getElementById('infoPhpVersion').textContent = info.php_version;
        document.getElementById('infoMysqlVersion').textContent = info.mysql_version;
        document.getElementById('infoServerSoftware').textContent = info.server_software;
        document.getElementById('infoUploadLimit').textContent = info.upload_max_filesize;
        document.getElementById('infoMemoryLimit').textContent = info.memory_limit;
        document.getElementById('infoDiskFree').textContent = formatFileSize(info.disk_free_space);
        document.getElementById('infoServerTime').textContent = info.server_time;
        document.getElementById('infoTimezone').textContent = info.timezone;
    }
}

function refreshSystemInfo() {
    loadSystemInfo();
}

/**
 * Format file size for display
 */
function formatFileSize($bytes) {
    if ($bytes === 0) return '0 Bytes';
    $k = 1024;
    $sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    $i = floor(log($bytes) / log($k));
    return number_format($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
}

/**
 * Check if user is admin by ID (for API validation)
 */
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

async function checkSystemStatus() {
    const result = await apiCall('get_system_checks');
    if (result.success) {
        const checks = result.checks;
        let message = '';
        
        if (!checks.passed) {
            message = `System has ${checks.errors.length} error(s) and ${checks.warnings.length} warning(s)`;
            showNotification(message, 'warning');
        }
        
        return checks;
    }
    return null;
}

// Periodically check system status (every 5 minutes)
if (isAdmin) {
    setInterval(() => {
        if (currentSection === 'dashboard') {
            checkSystemStatus();
        }
    }, 5 * 60 * 1000);
}

        
        
        function editUser(userId) {
            // Load user data and show in modal
            showNotification('Edit user functionality would load user data here', 'info');
        }
        
        // Load users list when section is shown
        if (isAdmin) {
            document.addEventListener('DOMContentLoaded', function() {
                if (document.getElementById('userManagement')) {
                    loadUsersList();
                }
            });
        }
        
        
    </script>
    <!-- Knowledge Base Browser Modal -->
<div id="knowledgeModal" class="delete-confirmation">
    <div class="delete-content" style="max-width: 800px;">
        <div class="delete-icon">
            <i class="fas fa-database"></i>
        </div>
        <h3>Knowledge Base Browser</h3>
        <div id="knowledgeContent" style="max-height: 400px; overflow-y: auto; margin: 20px 0;">
            Loading knowledge base...
        </div>
        <div class="delete-buttons">
            <button class="btn btn-secondary" onclick="closeKnowledgeModal()">Close</button>
        </div>
    </div>
</div>

<!-- User Edit Modal (Admin only) -->
<div id="editUserModal" class="delete-confirmation">
    <div class="delete-content" style="max-width: 600px;">
        <div class="delete-icon">
            <i class="fas fa-user-edit"></i>
        </div>
        <h3>Edit User</h3>
        <div id="editUserFormContainer">
            <!-- Form will be loaded here -->
        </div>
        <div class="delete-buttons">
            <button class="btn btn-primary" onclick="saveUserChanges()">Save Changes</button>
            <button class="btn btn-secondary" onclick="closeEditUserModal()">Cancel</button>
        </div>
    </div>
</div>

<!-- System Logs Modal -->
<div id="systemLogsModal" class="delete-confirmation">
    <div class="delete-content" style="max-width: 900px;">
        <div class="delete-icon">
            <i class="fas fa-clipboard-list"></i>
        </div>
        <h3>System Logs</h3>
        <div style="margin-bottom: 20px;">
            <select id="logSeverityFilter" onchange="loadSystemLogs()">
                <option value="">All Severities</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
                <option value="critical">Critical</option>
            </select>
            <select id="logTypeFilter" onchange="loadSystemLogs()">
                <option value="">All Types</option>
                <option value="auth">Authentication</option>
                <option value="document">Document</option>
                <option value="chat">Chat</option>
                <option value="error">Errors</option>
                <option value="system">System</option>
            </select>
            <input type="date" id="logDateFilter" onchange="loadSystemLogs()">
        </div>
        <div id="systemLogsContent" style="max-height: 500px; overflow-y: auto;">
            Loading logs...
        </div>
        <div class="delete-buttons">
            <button class="btn btn-secondary" onclick="closeSystemLogsModal()">Close</button>
            <button class="btn btn-warning" onclick="clearOldLogs()">Clear Old Logs</button>
        </div>
    </div>
</div>

<!-- Backup Modal -->
<div id="backupModal" class="delete-confirmation">
    <div class="delete-content">
        <div class="delete-icon">
            <i class="fas fa-download"></i>
        </div>
        <h3>System Backup</h3>
        <p>Create a backup of the database and uploaded files.</p>
        <div id="backupOptions">
            <label><input type="checkbox" id="backupDatabase" checked> Database</label><br>
            <label><input type="checkbox" id="backupDocuments"> Documents</label><br>
            <label><input type="checkbox" id="backupProfiles"> Profile Images</label>
        </div>
        <div id="backupResult" style="display: none; margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 5px;"></div>
        <div class="delete-buttons">
            <button class="btn btn-primary" onclick="createBackup()">Create Backup</button>
            <button class="btn btn-secondary" onclick="closeBackupModal()">Cancel</button>
        </div>
    </div>
</div>

<!-- System Info Modal -->
<div id="systemInfoModal" class="delete-confirmation">
    <div class="delete-content" style="max-width: 700px;">
        <div class="delete-icon">
            <i class="fas fa-info-circle"></i>
        </div>
        <h3>System Information</h3>
        <div id="systemInfoContent" style="text-align: left; margin: 20px 0;">
            <table style="width: 100%;">
                <tr><td><strong>PHP Version:</strong></td><td id="infoPhpVersion">Loading...</td></tr>
                <tr><td><strong>MySQL Version:</strong></td><td id="infoMysqlVersion">Loading...</td></tr>
                <tr><td><strong>Server Software:</strong></td><td id="infoServerSoftware">Loading...</td></tr>
                <tr><td><strong>Upload Limit:</strong></td><td id="infoUploadLimit">Loading...</td></tr>
                <tr><td><strong>Memory Limit:</strong></td><td id="infoMemoryLimit">Loading...</td></tr>
                <tr><td><strong>Disk Free Space:</strong></td><td id="infoDiskFree">Loading...</td></tr>
                <tr><td><strong>Server Time:</strong></td><td id="infoServerTime">Loading...</td></tr>
                <tr><td><strong>Timezone:</strong></td><td id="infoTimezone">Loading...</td></tr>
            </table>
        </div>
        <div class="delete-buttons">
            <button class="btn btn-secondary" onclick="closeSystemInfoModal()">Close</button>
            <button class="btn btn-primary" onclick="refreshSystemInfo()">Refresh</button>
        </div>
    </div>
</div>
</body>
</html>