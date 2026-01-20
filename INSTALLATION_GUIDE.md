# DKAI2 Installation & Setup Guide

## Prerequisites

### System Requirements
- **PHP:** 7.4 or higher
- **MySQL:** 5.7 or higher (or MariaDB 10.2+)
- **Web Server:** Apache 2.4+ or Nginx 1.18+
- **Memory:** Minimum 256MB PHP memory_limit
- **Disk Space:** At least 500MB free

### Required PHP Extensions
- mysqli (MySQL database support)
- json (JSON data handling)
- mbstring (Multibyte string support)
- zip (ZIP archive handling for DOCX files)
- gd (Image processing for profile images)
- fileinfo (File type detection)
- session (Session management)
- hash (Cryptographic hashing)

### Verify PHP Extensions
```bash
php -m | grep -E 'mysqli|json|mbstring|zip|gd|fileinfo|session|hash'
```

---

## Step 1: File Setup

### 1.1 Upload Files
Upload the following files to your server:
```
/your-web-root/
├── .env.php (from .env.php.example)
├── database_migration.sql
└── public_html/
    └── default.php
```

### 1.2 Set File Permissions
```bash
cd /your-web-root

chmod 600 .env.php
chmod 755 public_html
chmod 644 public_html/default.php
chmod 755 backups logs cache uploads
chmod 644 database_migration.sql
```

---

## Step 2: Database Setup

### 2.1 Create Database
```sql
CREATE DATABASE target2030 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'djyoti2030'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON target2030.* TO 'djyoti2030'@'localhost';
FLUSH PRIVILEGES;
```

### 2.2 Run Migration
```bash
mysql -u djyoti2030 -p target2030 < database_migration.sql
```

Or via phpMyAdmin:
1. Select database `target2030`
2. Go to "Import" tab
3. Choose `database_migration.sql`
4. Click "Go"

### 2.3 Verify Tables
```sql
USE target2030;
SHOW TABLES;
```

You should see 20+ tables including:
- users
- documents
- knowledge_base
- ai_responses
- ai_response_reports
- response_corrections
- admin_settings
- (and more...)

---

## Step 3: Environment Configuration

### 3.1 Copy Example Config
```bash
cp .env.php.example .env.php
```

### 3.2 Edit Configuration
```bash
nano .env.php  # or use your preferred editor
```

### 3.3 Update Database Credentials
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'target2030');
define('DB_USER', 'djyoti2030');
define('DB_PASS', 'your_actual_password_here');
```

### 3.4 Generate Secret Keys
Use a secure random string generator:
```bash
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
```

Run this twice and update:
```php
define('APP_SECRET_KEY', 'paste_first_64_char_string_here');
define('CSRF_TOKEN_SECRET', 'paste_second_64_char_string_here');
```

### 3.5 Set Environment
For production:
```php
define('ENVIRONMENT', 'production');
```

For development:
```php
define('ENVIRONMENT', 'development');
```

### 3.6 Configure SMTP (Optional)
For password reset emails:
```php
define('SMTP_HOST', 'smtp.gmail.com');  // or your SMTP server
define('SMTP_PORT', 587);
define('SMTP_USER', 'your-email@gmail.com');
define('SMTP_PASS', 'your-app-password');
define('SMTP_FROM', 'noreply@yourdomain.com');
define('SMTP_FROM_NAME', 'AI Chatbot System');
```

For Gmail, create an App Password:
https://myaccount.google.com/apppasswords

---

## Step 4: Directory Structure

### 4.1 Create Required Directories
```bash
mkdir -p backups logs cache uploads/documents uploads/profiles uploads/temp
```

### 4.2 Set Proper Permissions
```bash
chmod 755 backups logs cache uploads
chmod 755 uploads/documents uploads/profiles uploads/temp
chown -R www-data:www-data uploads logs cache backups
```

Replace `www-data` with your web server user (might be `apache`, `nginx`, or `nobody`).

### 4.3 Create Security Files
```bash
echo "<?php http_response_code(403); ?>" > uploads/index.php
echo "<?php http_response_code(403); ?>" > logs/index.php
echo "<?php http_response_code(403); ?>" > cache/index.php
echo "<?php http_response_code(403); ?>" > backups/index.php
```

---

## Step 5: Web Server Configuration

### Option A: Apache

#### 5.1 Create/Update .htaccess
```apache
# public_html/.htaccess

# Enable rewrite engine
RewriteEngine On

# Redirect to default.php
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ default.php [QSA,L]

# Security headers
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"

# Disable directory listing
Options -Indexes

# Protect sensitive files
<FilesMatch "\.(env|log|sql|bak|backup)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

#### 5.2 Parent Directory Protection
```apache
# /your-web-root/.htaccess

<FilesMatch "\.env\.php$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

### Option B: Nginx

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    root /your-web-root/public_html;
    index default.php;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Protect sensitive files
    location ~* \.(env|log|sql|bak|backup)$ {
        deny all;
        return 404;
    }

    # PHP handling
    location / {
        try_files $uri $uri/ /default.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index default.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        return 404;
    }
}
```

---

## Step 6: First Access

### 6.1 Access Application
Open browser and navigate to:
```
http://yourdomain.com/public_html/default.php
```

Or if configured with rewriting:
```
http://yourdomain.com
```

### 6.2 Default Admin Login
```
Username: admin
Password: Admin@123
```

**⚠️ IMPORTANT:** Change this password immediately after first login!

### 6.3 Change Admin Password
1. Login with default credentials
2. Go to Profile/Settings
3. Change password to a strong one
4. Logout and login with new password

---

## Step 7: System Verification

### 7.1 Check System Status
After logging in as admin:
1. Navigate to Admin Dashboard
2. Check "System Information"
3. Verify all components are green
4. Review any warnings or errors

### 7.2 Test Database Connection
```php
// Test file: test-db.php (delete after testing)
<?php
require_once '../.env.php';
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    die("Connection failed: " . $db->connect_error);
}
echo "Database connection successful!";
$db->close();
?>
```

### 7.3 Verify Tables
```sql
SELECT COUNT(*) as table_count FROM information_schema.tables 
WHERE table_schema = 'target2030';
```

Should return 20+ tables.

### 7.4 Check Default Settings
```sql
SELECT * FROM admin_settings;
```

Should show 15 default settings.

---

## Step 8: Feature Configuration

### 8.1 Enable/Disable Features
Login as admin and go to Settings:

- **Reporting System:** Enable/Disable user reports
- **CSRF Protection:** Should stay enabled (security)
- **Rate Limiting:** Adjust based on traffic
- **Response Caching:** Enable for performance
- **Content Filtering:** Enable to block spam

### 8.2 Customize Settings
```sql
-- Example: Change max reports per user per day
UPDATE admin_settings 
SET setting_value = '20' 
WHERE setting_key = 'max_reports_per_user_per_day';

-- Example: Enable auto-approval (not recommended)
UPDATE admin_settings 
SET setting_value = 'auto' 
WHERE setting_key = 'approval_type';
```

---

## Step 9: SSL/HTTPS Setup (Production)

### 9.1 Install Certbot (Let's Encrypt)
```bash
sudo apt-get update
sudo apt-get install certbot python3-certbot-apache
```

### 9.2 Obtain Certificate
```bash
sudo certbot --apache -d yourdomain.com
```

### 9.3 Auto-Renewal
```bash
sudo certbot renew --dry-run
```

### 9.4 Force HTTPS
Update `.htaccess` or Nginx config to redirect HTTP to HTTPS.

Apache:
```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

---

## Step 10: Backup Configuration

### 10.1 Automatic Database Backups
Create cron job:
```bash
crontab -e
```

Add:
```
0 2 * * * /usr/bin/mysqldump -u djyoti2030 -p'password' target2030 > /your-web-root/backups/db_backup_$(date +\%Y\%m\%d).sql
```

### 10.2 File Backups
```bash
0 3 * * * tar -czf /your-backups/files_$(date +\%Y\%m\%d).tar.gz /your-web-root/uploads
```

### 10.3 Log Rotation
```bash
# /etc/logrotate.d/dkai2
/your-web-root/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
}
```

---

## Step 11: Monitoring Setup

### 11.1 Error Monitoring
Monitor logs:
```bash
tail -f /your-web-root/logs/php_errors.log
```

### 11.2 Database Monitoring
Check system logs:
```sql
SELECT * FROM system_logs 
WHERE severity IN ('error', 'critical') 
ORDER BY created_at DESC 
LIMIT 50;
```

### 11.3 Performance Monitoring
Track cache hits:
```sql
SELECT cache_key, hit_count, created_at, expires_at 
FROM response_cache 
ORDER BY hit_count DESC 
LIMIT 20;
```

---

## Step 12: Security Hardening

### 12.1 File Permissions Review
```bash
find /your-web-root -type f -exec chmod 644 {} \;
find /your-web-root -type d -exec chmod 755 {} \;
chmod 600 /your-web-root/.env.php
chmod 755 /your-web-root/public_html
chmod 644 /your-web-root/public_html/default.php
```

### 12.2 Disable PHP Functions
In `php.ini`:
```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

### 12.3 Hide PHP Version
```ini
expose_php = Off
```

### 12.4 Enable Open Base Dir
```ini
open_basedir = /your-web-root:/tmp
```

### 12.5 Limit Upload Size
```ini
upload_max_filesize = 10M
post_max_size = 10M
max_file_uploads = 10
```

---

## Step 13: Testing Checklist

### Basic Functionality
- [ ] Can access homepage
- [ ] Can login as admin
- [ ] Can upload documents
- [ ] Can ask questions to AI
- [ ] Chat responses work
- [ ] Can create users (staff/admin)
- [ ] Can delete documents
- [ ] Can view statistics

### Reporting System
- [ ] Can submit report (public)
- [ ] Reports appear in staff dashboard
- [ ] Staff can suggest corrections
- [ ] Admin can approve corrections
- [ ] Corrections update responses
- [ ] Can mark reports as false
- [ ] Stats dashboard works

### Security Features
- [ ] CSRF protection active
- [ ] Rate limiting works
- [ ] Login attempts limited
- [ ] Session timeout works
- [ ] XSS protection active
- [ ] SQL injection prevented

### Performance
- [ ] Response caching active
- [ ] Cache hit rate > 0
- [ ] Page load time < 2 seconds
- [ ] Database queries optimized

---

## Troubleshooting

### Issue: "Configuration file not found"
**Cause:** .env.php missing or wrong location
**Fix:** 
```bash
ls -la /your-web-root/.env.php
cp .env.php.example .env.php
```

### Issue: "Database connection failed"
**Cause:** Wrong credentials or MySQL not running
**Fix:**
1. Verify MySQL running: `systemctl status mysql`
2. Test connection: `mysql -u djyoti2030 -p`
3. Check credentials in .env.php

### Issue: "Permission denied" errors
**Cause:** Wrong file/directory permissions
**Fix:**
```bash
chown -R www-data:www-data /your-web-root
chmod 755 uploads logs cache backups
```

### Issue: "Table doesn't exist"
**Cause:** Migration not run
**Fix:**
```bash
mysql -u djyoti2030 -p target2030 < database_migration.sql
```

### Issue: "CSRF token invalid"
**Cause:** Session issues or token expired
**Fix:**
1. Clear browser cache/cookies
2. Check session.save_path is writable
3. Verify CSRF_TOKEN_SECRET in .env.php

### Issue: Rate limit blocking admin
**Cause:** Too restrictive settings
**Fix:**
```sql
UPDATE admin_settings 
SET setting_value = '0' 
WHERE setting_key = 'rate_limit_enabled';
```

### Issue: Uploads failing
**Cause:** Directory permissions or file size
**Fix:**
```bash
chmod 755 /your-web-root/uploads
chown www-data:www-data /your-web-root/uploads
```

Check PHP settings:
```bash
php -i | grep upload_max_filesize
```

---

## Maintenance

### Daily Tasks
- Monitor error logs
- Check system health
- Review security logs

### Weekly Tasks
- Review reported responses
- Approve pending corrections
- Check backup integrity
- Update statistics

### Monthly Tasks
- Review user accounts
- Clean old cache entries
- Optimize database tables
- Update security patches
- Review access logs

### Database Optimization
```sql
-- Clean old cache entries
DELETE FROM response_cache WHERE expires_at < NOW();

-- Clean old rate limit records
DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Optimize tables
OPTIMIZE TABLE ai_responses, response_cache, rate_limits;
```

---

## Upgrade Path

When updating from older version:

1. **Backup everything:**
```bash
mysqldump -u djyoti2030 -p target2030 > backup_pre_upgrade.sql
tar -czf files_pre_upgrade.tar.gz /your-web-root
```

2. **Download new version**

3. **Run new migration:**
```bash
mysql -u djyoti2030 -p target2030 < database_migration_v2.sql
```

4. **Update files**

5. **Test thoroughly**

6. **Rollback if needed:**
```bash
mysql -u djyoti2030 -p target2030 < backup_pre_upgrade.sql
```

---

## Support

### Log Files Locations
- Application errors: `/your-web-root/logs/php_errors.log`
- System logs: Database table `system_logs`
- Audit logs: Database table `audit_logs`
- Access logs: Web server logs

### Useful SQL Queries

**Active sessions:**
```sql
SELECT COUNT(*) as active_sessions 
FROM user_sessions 
WHERE expires_at > NOW();
```

**Recent errors:**
```sql
SELECT * FROM system_logs 
WHERE severity = 'error' 
AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) 
ORDER BY created_at DESC;
```

**Top reported responses:**
```sql
SELECT question_text, COUNT(*) as report_count 
FROM ai_response_reports 
GROUP BY question_text 
ORDER BY report_count DESC 
LIMIT 10;
```

---

## Final Checklist

Before going live:
- [ ] .env.php configured correctly
- [ ] Database migrated successfully
- [ ] Admin password changed from default
- [ ] HTTPS/SSL enabled
- [ ] All directories have correct permissions
- [ ] Backups automated
- [ ] Error monitoring in place
- [ ] Rate limiting configured
- [ ] CSRF protection enabled
- [ ] Session security configured
- [ ] Firewall rules set
- [ ] Testing completed
- [ ] Documentation reviewed
- [ ] Staff trained on new features

---

**Installation Complete!**

For questions or issues, check:
- REFACTORING_CHANGELOG.md for feature details
- Database logs for errors
- System health dashboard for status
- Support documentation

Enjoy your enhanced DKAI2 system!
