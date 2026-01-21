-- Database Migration for AI Response Reporting System
-- Generated: 2024
-- Run this file to add new tables and columns for the reporting feature

-- Create ai_response_reports table
CREATE TABLE IF NOT EXISTS ai_response_reports (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create response_corrections table
CREATE TABLE IF NOT EXISTS response_corrections (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create admin_settings table
CREATE TABLE IF NOT EXISTS admin_settings (
    setting_id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type VARCHAR(50) DEFAULT 'string',
    description TEXT,
    updated_by INT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_setting_key (setting_key),
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default admin settings
INSERT IGNORE INTO admin_settings (setting_key, setting_value, setting_type, description) VALUES
('reporting_enabled', '1', 'boolean', 'Enable or disable the AI response reporting system'),
('approval_type', 'manual', 'string', 'Correction approval type: auto or manual'),
('auto_close_false_reports', '1', 'boolean', 'Automatically close reports marked as false'),
('notification_email', 'admin@example.com', 'string', 'Email for system notifications'),
('max_reports_per_user_per_day', '10', 'integer', 'Maximum number of reports a user can submit per day'),
('require_description', '0', 'boolean', 'Require description when submitting reports'),
('allow_anonymous_reports', '1', 'boolean', 'Allow reports from non-logged-in users'),
('response_cache_enabled', '1', 'boolean', 'Enable response caching for performance'),
('response_cache_ttl', '3600', 'integer', 'Response cache time-to-live in seconds'),
('rate_limit_enabled', '1', 'boolean', 'Enable rate limiting for API and chat'),
('rate_limit_requests', '100', 'integer', 'Number of requests allowed per time window'),
('rate_limit_window', '3600', 'integer', 'Rate limit time window in seconds'),
('csrf_protection_enabled', '1', 'boolean', 'Enable CSRF token protection'),
('content_filtering_enabled', '1', 'boolean', 'Enable basic content filtering for spam/NSFW'),
('device_fingerprinting_enabled', '1', 'boolean', 'Enable device fingerprinting for security');

-- Create ai_responses table (if it doesn't exist)
CREATE TABLE IF NOT EXISTS ai_responses (
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
    usage_count INT DEFAULT 0,
    version INT DEFAULT 1,
    INDEX idx_question_hash (question_hash),
    INDEX idx_is_active (is_active),
    INDEX idx_reporting_count (reporting_count),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (training_id) REFERENCES ai_training(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create response_versions table for history tracking
CREATE TABLE IF NOT EXISTS response_versions (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create response_cache table
CREATE TABLE IF NOT EXISTS response_cache (
    cache_id INT AUTO_INCREMENT PRIMARY KEY,
    cache_key VARCHAR(64) UNIQUE NOT NULL,
    question_text TEXT,
    response_text TEXT NOT NULL,
    metadata TEXT,
    hit_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed DATETIME,
    expires_at DATETIME,
    INDEX idx_cache_key (cache_key),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create rate_limits table
CREATE TABLE IF NOT EXISTS rate_limits (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create csrf_tokens table
CREATE TABLE IF NOT EXISTS csrf_tokens (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create device_fingerprints table
CREATE TABLE IF NOT EXISTS device_fingerprints (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create training_qa table
CREATE TABLE IF NOT EXISTS training_qa (
    qa_id INT AUTO_INCREMENT PRIMARY KEY,
    question_text TEXT NOT NULL,
    response_text TEXT NOT NULL,
    response_order INT DEFAULT 1,
    is_active TINYINT(1) DEFAULT 1,
    approval_status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_by INT,
    approved_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    approved_at DATETIME,
    confidence_score DECIMAL(5,2) DEFAULT 0.00,
    usage_count INT DEFAULT 0,
    feedback_score INT DEFAULT 0,
    INDEX idx_is_active (is_active),
    INDEX idx_created_at (created_at),
    INDEX idx_created_by (created_by),
    INDEX idx_approval_status (approval_status),
    FULLTEXT INDEX ft_question_text (question_text),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE response_cache 
ADD COLUMN IF NOT EXISTS last_accessed DATETIME AFTER created_at;

ALTER TABLE ai_responses 
ADD COLUMN IF NOT EXISTS usage_count INT DEFAULT 0 AFTER last_used_at;

ALTER TABLE response_corrections 
ADD COLUMN IF NOT EXISTS staff_custom_response TEXT AFTER reasoning,
ADD COLUMN IF NOT EXISTS staff_selected_option ENUM('ai', 'custom', 'suggested', 'manual') DEFAULT 'custom' AFTER staff_custom_response,
ADD COLUMN IF NOT EXISTS staff_notes TEXT AFTER staff_selected_option;

-- Add new columns to existing tables if they don't exist
ALTER TABLE response_ratings 
ADD COLUMN IF NOT EXISTS response_id INT AFTER id,
ADD COLUMN IF NOT EXISTS was_reported TINYINT(1) DEFAULT 0 AFTER feedback,
ADD INDEX IF NOT EXISTS idx_response_id (response_id);

ALTER TABLE chat_messages 
ADD COLUMN IF NOT EXISTS response_id INT AFTER id,
ADD INDEX IF NOT EXISTS idx_response_id (response_id);

-- Create report_statistics view
CREATE OR REPLACE VIEW report_statistics AS
SELECT 
    DATE(created_at) as report_date,
    report_type,
    status,
    COUNT(*) as count
FROM ai_response_reports
GROUP BY DATE(created_at), report_type, status;

-- Create correction_statistics view
CREATE OR REPLACE VIEW correction_statistics AS
SELECT 
    DATE(created_at) as correction_date,
    admin_approved,
    is_active,
    COUNT(*) as count
FROM response_corrections
GROUP BY DATE(created_at), admin_approved, is_active;

-- Migration completed successfully
