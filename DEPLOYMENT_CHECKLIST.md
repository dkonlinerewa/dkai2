# DKAI2 v2.0 Deployment Checklist

## Pre-Deployment

### 1. Backup Current System
- [ ] Backup database: `mysqldump -u user -p database > backup_$(date +%Y%m%d).sql`
- [ ] Backup files: `tar -czf backup_$(date +%Y%m%d).tar.gz public_html/`
- [ ] Store backups in safe location
- [ ] Test backup restoration on staging

### 2. Verify Requirements
- [ ] PHP version: `php -v` (7.4+ required)
- [ ] MySQL version: `mysql -V` (5.7+ required)
- [ ] Required PHP extensions:
  ```bash
  php -m | grep -E 'mysqli|json|mbstring|zip|gd|fileinfo|session|hash'
  ```
- [ ] Web server: Apache 2.4+ or Nginx 1.18+
- [ ] Minimum 256MB PHP memory_limit
- [ ] At least 500MB free disk space

### 3. Prepare Files
- [ ] Upload `.env.php` (from .env.php.example)
- [ ] Upload `database_migration.sql`
- [ ] Upload `public_html/default.php`
- [ ] Upload documentation (README.md, INSTALLATION_GUIDE.md)

---

## Configuration

### 4. Environment Setup (.env.php)
- [ ] Copy example: `cp .env.php.example .env.php`
- [ ] Set database host: `define('DB_HOST', 'localhost');`
- [ ] Set database name: `define('DB_NAME', 'target2030');`
- [ ] Set database user: `define('DB_USER', 'your_user');`
- [ ] Set database password: `define('DB_PASS', 'your_password');`
- [ ] Generate APP_SECRET_KEY: `php -r "echo bin2hex(random_bytes(32));"`
- [ ] Generate CSRF_TOKEN_SECRET: `php -r "echo bin2hex(random_bytes(32));"`
- [ ] Set ENVIRONMENT: `define('ENVIRONMENT', 'production');`
- [ ] Configure SMTP settings (if email needed)
- [ ] Set admin email: `define('ADMIN_EMAIL', 'admin@domain.com');`
- [ ] Secure permissions: `chmod 600 .env.php`

### 5. Database Setup
- [ ] Create database: `CREATE DATABASE target2030 CHARACTER SET utf8mb4;`
- [ ] Create user: `CREATE USER 'user'@'localhost' IDENTIFIED BY 'password';`
- [ ] Grant privileges: `GRANT ALL ON target2030.* TO 'user'@'localhost';`
- [ ] Flush privileges: `FLUSH PRIVILEGES;`
- [ ] Run migration: `mysql -u user -p target2030 < database_migration.sql`
- [ ] Verify tables: `mysql -u user -p target2030 -e "SHOW TABLES;"`
- [ ] Check table count (should be 20+)

### 6. Directory Structure
- [ ] Create directories:
  ```bash
  mkdir -p backups logs cache uploads/documents uploads/profiles uploads/temp
  ```
- [ ] Set permissions:
  ```bash
  chmod 755 backups logs cache uploads
  chmod 755 uploads/documents uploads/profiles uploads/temp
  ```
- [ ] Set ownership (replace www-data with your web server user):
  ```bash
  chown -R www-data:www-data uploads logs cache backups
  ```
- [ ] Create security index files:
  ```bash
  echo "<?php http_response_code(403); ?>" > uploads/index.php
  echo "<?php http_response_code(403); ?>" > logs/index.php
  echo "<?php http_response_code(403); ?>" > cache/index.php
  echo "<?php http_response_code(403); ?>" > backups/index.php
  ```

---

## Security Hardening

### 7. File Permissions
- [ ] .env.php: `chmod 600 .env.php`
- [ ] All PHP files: `chmod 644 public_html/*.php`
- [ ] Directories: `chmod 755` on all directories
- [ ] Uploads writable: `chmod 755 uploads`
- [ ] Logs writable: `chmod 755 logs`
- [ ] Cache writable: `chmod 755 cache`
- [ ] Verify: `ls -la .env.php uploads/ logs/`

### 8. Web Server Configuration

#### Apache (.htaccess)
- [ ] Create `public_html/.htaccess`:
  ```apache
  RewriteEngine On
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteRule ^(.*)$ default.php [QSA,L]
  
  Options -Indexes
  
  Header set X-Content-Type-Options "nosniff"
  Header set X-Frame-Options "SAMEORIGIN"
  Header set X-XSS-Protection "1; mode=block"
  
  <FilesMatch "\.(env|log|sql|bak|backup)$">
      Deny from all
  </FilesMatch>
  ```
- [ ] Create root `.htaccess` to protect .env.php
- [ ] Test .htaccess syntax

#### Nginx (config file)
- [ ] Add security headers
- [ ] Configure PHP-FPM
- [ ] Protect sensitive files
- [ ] Test configuration: `nginx -t`
- [ ] Reload: `systemctl reload nginx`

### 9. SSL/HTTPS (Production)
- [ ] Install SSL certificate (Let's Encrypt or commercial)
- [ ] Configure HTTPS in web server
- [ ] Force HTTPS redirect
- [ ] Test SSL: https://www.ssllabs.com/ssltest/
- [ ] Verify certificate auto-renewal

### 10. PHP Security
- [ ] Edit php.ini:
  - [ ] `expose_php = Off`
  - [ ] `display_errors = Off` (production)
  - [ ] `log_errors = On`
  - [ ] `error_log = /path/to/logs/php_errors.log`
  - [ ] `upload_max_filesize = 10M`
  - [ ] `post_max_size = 10M`
  - [ ] `max_execution_time = 30`
  - [ ] `memory_limit = 256M`
  - [ ] `session.cookie_httponly = On`
  - [ ] `session.cookie_secure = On` (if HTTPS)
  - [ ] `session.use_strict_mode = On`
- [ ] Restart PHP-FPM: `systemctl restart php7.4-fpm`

---

## Testing

### 11. Basic Functionality Tests
- [ ] Access homepage: http://yourdomain.com/public_html/default.php
- [ ] Page loads without errors
- [ ] No PHP errors displayed
- [ ] Check error log: `tail -f logs/php_errors.log`
- [ ] Login with default credentials (admin/Admin@123)
- [ ] Dashboard loads correctly
- [ ] Check "System Information" for green status
- [ ] Test logout

### 12. Database Tests
- [ ] Test database connection from application
- [ ] Verify all tables created:
  ```sql
  SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='target2030';
  ```
- [ ] Check default admin settings:
  ```sql
  SELECT * FROM admin_settings;
  ```
  (Should show 15 settings)
- [ ] Verify default admin user:
  ```sql
  SELECT * FROM users WHERE username='admin';
  ```

### 13. Feature Tests
- [ ] Upload document (Admin panel)
- [ ] Ask question to AI
- [ ] Get response from chatbot
- [ ] Test response rating
- [ ] Submit test report (public user)
- [ ] View reports (staff/admin dashboard)
- [ ] Suggest correction (staff)
- [ ] Approve correction (admin)
- [ ] Check response versioning
- [ ] Test cache (ask same question twice, check cache table)
- [ ] Create new user (staff/admin)
- [ ] Delete document
- [ ] View statistics

### 14. Security Tests
- [ ] CSRF protection active:
  - [ ] Try POST without CSRF token (should fail)
  - [ ] Get CSRF token via `POST action=get_csrf_token`
  - [ ] Submit with valid token (should succeed)
- [ ] Rate limiting working:
  - [ ] Make 101+ requests rapidly
  - [ ] Verify blocked after limit
  - [ ] Check `rate_limits` table
- [ ] Login security:
  - [ ] Try 6 failed logins
  - [ ] Verify account lockout
  - [ ] Check lockout duration
- [ ] Session security:
  - [ ] Verify session cookie has httpOnly flag
  - [ ] Check SameSite attribute
  - [ ] Test session timeout
- [ ] SQL injection prevention:
  - [ ] Try `' OR '1'='1` in login
  - [ ] Verify sanitization working
- [ ] XSS prevention:
  - [ ] Try `<script>alert('XSS')</script>` in input
  - [ ] Verify HTML encoding

### 15. Performance Tests
- [ ] Check page load time (< 2 seconds)
- [ ] Test response caching:
  ```sql
  SELECT cache_key, hit_count FROM response_cache ORDER BY hit_count DESC LIMIT 10;
  ```
- [ ] Monitor cache hit rate (should be > 0)
- [ ] Check database query performance
- [ ] Test with concurrent users (10+ simultaneous)
- [ ] Monitor memory usage
- [ ] Check CPU usage

---

## Post-Deployment

### 16. Change Default Credentials
- [ ] Login as admin (admin/Admin@123)
- [ ] Navigate to Profile/Settings
- [ ] Change admin password to strong password
- [ ] Use password with:
  - [ ] At least 8 characters
  - [ ] Uppercase letter
  - [ ] Lowercase letter
  - [ ] Number
  - [ ] Special character
- [ ] Logout and re-login with new password
- [ ] Store password securely

### 17. Configure Admin Settings
- [ ] Login as admin
- [ ] Go to Settings/Admin Settings
- [ ] Review and adjust:
  - [ ] `reporting_enabled` (true/false)
  - [ ] `approval_type` (manual/auto)
  - [ ] `max_reports_per_user_per_day` (10 recommended)
  - [ ] `response_cache_enabled` (true recommended)
  - [ ] `response_cache_ttl` (3600 recommended)
  - [ ] `rate_limit_enabled` (true recommended)
  - [ ] `rate_limit_requests` (100 recommended)
  - [ ] `rate_limit_window` (3600 recommended)
  - [ ] `csrf_protection_enabled` (true REQUIRED)
  - [ ] `content_filtering_enabled` (true recommended)
- [ ] Save changes
- [ ] Verify settings updated in database

### 18. Setup Monitoring
- [ ] Configure log monitoring:
  ```bash
  tail -f /path/to/logs/php_errors.log
  ```
- [ ] Set up log rotation:
  ```bash
  # /etc/logrotate.d/dkai2
  /path/to/logs/*.log {
      daily
      rotate 30
      compress
      delaycompress
      notifempty
  }
  ```
- [ ] Setup database monitoring queries (save as bookmarks):
  ```sql
  -- Recent errors
  SELECT * FROM system_logs WHERE severity='error' ORDER BY created_at DESC LIMIT 50;
  
  -- Active sessions
  SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW();
  
  -- Cache performance
  SELECT cache_key, hit_count FROM response_cache ORDER BY hit_count DESC LIMIT 20;
  
  -- Report statistics
  SELECT status, COUNT(*) FROM ai_response_reports GROUP BY status;
  ```
- [ ] Configure email alerts for critical errors (optional)

### 19. Setup Automated Backups
- [ ] Database backup cron:
  ```bash
  crontab -e
  # Add:
  0 2 * * * mysqldump -u user -p'password' target2030 > /path/to/backups/db_$(date +\%Y\%m\%d).sql
  ```
- [ ] File backup cron:
  ```bash
  # Add to crontab:
  0 3 * * * tar -czf /path/to/backups/files_$(date +\%Y\%m\%d).tar.gz /path/to/uploads
  ```
- [ ] Test backup script manually
- [ ] Verify backup files created
- [ ] Test restoration process
- [ ] Setup backup rotation (keep 30 days):
  ```bash
  # Add to crontab:
  0 4 * * * find /path/to/backups -name "*.sql" -mtime +30 -delete
  0 4 * * * find /path/to/backups -name "*.tar.gz" -mtime +30 -delete
  ```

### 20. Setup Firewall
- [ ] Configure UFW (Ubuntu) or firewalld (CentOS):
  ```bash
  ufw allow 22/tcp    # SSH
  ufw allow 80/tcp    # HTTP
  ufw allow 443/tcp   # HTTPS
  ufw enable
  ```
- [ ] Restrict MySQL to localhost only
- [ ] Block suspicious IPs (if applicable)
- [ ] Test firewall rules

---

## Documentation

### 21. Create User Documentation
- [ ] Document admin login process
- [ ] Create staff user guide for reporting
- [ ] Write public user guide for chatbot
- [ ] Document report submission process
- [ ] Create correction workflow guide
- [ ] Document admin settings

### 22. Technical Documentation
- [ ] Document server configuration
- [ ] Record database credentials (securely)
- [ ] Note custom configurations
- [ ] Document backup procedures
- [ ] Create disaster recovery plan
- [ ] Document monitoring setup

---

## Maintenance Setup

### 23. Regular Maintenance Tasks
- [ ] Daily: Monitor error logs
- [ ] Daily: Check system health dashboard
- [ ] Weekly: Review reported responses
- [ ] Weekly: Approve pending corrections
- [ ] Weekly: Check backup integrity
- [ ] Monthly: Review user accounts
- [ ] Monthly: Clean old cache entries:
  ```sql
  DELETE FROM response_cache WHERE expires_at < NOW();
  ```
- [ ] Monthly: Clean old rate limit records:
  ```sql
  DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 7 DAY);
  ```
- [ ] Monthly: Optimize database:
  ```sql
  OPTIMIZE TABLE ai_responses, response_cache, rate_limits, system_logs;
  ```

### 24. Create Runbook
- [ ] Document restart procedures
- [ ] Document rollback procedures
- [ ] Create troubleshooting guide
- [ ] Document escalation procedures
- [ ] Create incident response plan

---

## Final Verification

### 25. Complete System Check
- [ ] All files uploaded and configured
- [ ] Database migrated successfully
- [ ] .env.php configured correctly
- [ ] Default admin password changed
- [ ] All directories have correct permissions
- [ ] HTTPS/SSL enabled and working
- [ ] Automated backups configured
- [ ] Monitoring in place
- [ ] Firewall configured
- [ ] Error logging working
- [ ] Rate limiting active
- [ ] CSRF protection enabled
- [ ] Session security configured
- [ ] Content filtering active
- [ ] Response caching working
- [ ] All features tested
- [ ] Documentation complete
- [ ] Staff trained on new features

### 26. Performance Baseline
- [ ] Record current metrics:
  - [ ] Page load time: _______
  - [ ] Cache hit rate: _______
  - [ ] Average response time: _______
  - [ ] Database size: _______
  - [ ] Disk usage: _______
  - [ ] Memory usage: _______
  - [ ] CPU usage: _______
- [ ] Setup performance monitoring
- [ ] Configure alerts for degradation

---

## Go-Live

### 27. Pre-Launch
- [ ] Schedule maintenance window
- [ ] Notify users of potential downtime
- [ ] Final backup of old system
- [ ] Double-check all configurations
- [ ] Review rollback plan
- [ ] Prepare team for launch

### 28. Launch
- [ ] Switch DNS (if applicable)
- [ ] Monitor error logs continuously
- [ ] Watch system metrics
- [ ] Test critical features
- [ ] Verify user access
- [ ] Monitor for issues

### 29. Post-Launch
- [ ] Monitor for first 24 hours
- [ ] Review error logs
- [ ] Check user feedback
- [ ] Verify backups running
- [ ] Document any issues
- [ ] Collect performance data

---

## Success Criteria

✅ All tests passed  
✅ No critical errors in logs  
✅ Admin can login and manage system  
✅ Public users can chat with AI  
✅ Reporting system functional  
✅ Staff can review and correct  
✅ Admin can approve corrections  
✅ Security features active  
✅ Performance acceptable  
✅ Backups running  
✅ Monitoring in place  
✅ Documentation complete  

---

## Emergency Rollback Plan

If critical issues occur:

1. **Stop web server:**
   ```bash
   systemctl stop apache2  # or nginx
   ```

2. **Restore database:**
   ```bash
   mysql -u user -p target2030 < backup_YYYYMMDD.sql
   ```

3. **Restore files:**
   ```bash
   tar -xzf backup_YYYYMMDD.tar.gz
   ```

4. **Switch back to old code:**
   ```bash
   mv default.php default.php.new
   mv default.php.backup default.php
   ```

5. **Restart web server:**
   ```bash
   systemctl start apache2  # or nginx
   ```

6. **Verify old system working**

7. **Document issues for post-mortem**

---

## Contact Information

**Technical Lead:** _______________  
**Database Admin:** _______________  
**Escalation:** _______________  
**Emergency:** _______________  

---

## Notes

Date deployed: _______________  
Deployed by: _______________  
Version: 2.0  
Build: DKAI2-Consolidated  

Issues encountered:
_________________________________
_________________________________
_________________________________

Resolutions:
_________________________________
_________________________________
_________________________________

---

**Deployment Complete!** ✅
