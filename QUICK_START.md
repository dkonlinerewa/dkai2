# DKAI2 v2.0 - Quick Start Guide

## Get Started in 5 Minutes ⚡

### Step 1: Configure Environment (2 minutes)
```bash
cd /home/engine/project
cp .env.php.example .env.php
nano .env.php
```

**Edit these lines:**
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'target2030');
define('DB_USER', 'your_database_user');
define('DB_PASS', 'your_database_password');
```

**Generate secret keys:**
```bash
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
# Copy output to APP_SECRET_KEY

php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
# Copy output to CSRF_TOKEN_SECRET
```

**Save and secure:**
```bash
chmod 600 .env.php
```

---

### Step 2: Setup Database (2 minutes)
```bash
# Create database
mysql -u root -p -e "CREATE DATABASE target2030 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"

# Create user and grant privileges
mysql -u root -p -e "CREATE USER 'djyoti2030'@'localhost' IDENTIFIED BY 'your_password'"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON target2030.* TO 'djyoti2030'@'localhost'"
mysql -u root -p -e "FLUSH PRIVILEGES"

# Run migration
mysql -u djyoti2030 -p target2030 < database_migration.sql

# Verify (should show 21+ tables)
mysql -u djyoti2030 -p target2030 -e "SHOW TABLES"
```

---

### Step 3: Set Permissions (30 seconds)
```bash
chmod 755 backups logs cache uploads
chmod 755 uploads/documents uploads/profiles uploads/temp
chown -R www-data:www-data uploads logs cache backups
```

---

### Step 4: Access Application (30 seconds)
Open browser:
```
http://yourdomain.com/public_html/default.php
```

**Login:**
- Username: `admin`
- Password: `Admin@123`

---

### Step 5: Secure Admin Account (30 seconds)
1. Click on your profile
2. Change password to strong password
3. Logout and login with new password

---

## Done! ✅

You now have a fully functional DKAI2 system with:
- ✅ AI-powered chatbot
- ✅ Response reporting system
- ✅ Security features (CSRF, rate limiting)
- ✅ Performance caching
- ✅ Admin dashboard

---

## Next Steps

### Customize Settings
Go to Admin Panel → Settings:
- Enable/disable reporting
- Adjust rate limits
- Configure caching
- Set approval workflow

### Upload Documents
Admin Panel → Documents → Upload:
- Supported: PDF, DOCX, Excel, PPT, TXT, CSV
- Max size: 10MB
- Auto-processed into knowledge base

### Test Chat
Public page → Chat:
- Ask questions
- Get AI responses
- Rate responses
- Report incorrect answers

### Review Reports (Staff/Admin)
Staff Dashboard → Reports:
- View submitted reports
- Verify and suggest corrections
- Admin approves corrections

---

## Troubleshooting

### "Configuration file not found"
```bash
cp .env.php.example .env.php
nano .env.php  # Edit credentials
```

### "Database connection failed"
```bash
mysql -u djyoti2030 -p  # Test connection
# Check credentials in .env.php
```

### "Permission denied"
```bash
chmod 755 uploads logs cache
chown -R www-data:www-data uploads logs cache
```

### "Can't login"
Default credentials:
- Username: `admin`
- Password: `Admin@123`

If forgotten, reset via database:
```sql
UPDATE users 
SET password_hash = '$2y$10$example_hash_here' 
WHERE username = 'admin';
```

---

## Important Files

| File | Purpose |
|------|---------|
| `.env.php` | Database credentials & secrets |
| `public_html/default.php` | Main application (6,481 lines) |
| `database_migration.sql` | Database schema |
| `logs/php_errors.log` | Application errors |
| `README.md` | Project overview |
| `INSTALLATION_GUIDE.md` | Complete setup guide |

---

## Quick Commands

```bash
# Check error logs
tail -f logs/php_errors.log

# Backup database
mysqldump -u djyoti2030 -p target2030 > backup_$(date +%Y%m%d).sql

# Backup files
tar -czf backup_$(date +%Y%m%d).tar.gz uploads/

# Check database tables
mysql -u djyoti2030 -p target2030 -e "SHOW TABLES"

# Check admin settings
mysql -u djyoti2030 -p target2030 -e "SELECT * FROM admin_settings"

# Generate secret key
php -r "echo bin2hex(random_bytes(32));"
```

---

## Feature Highlights

### For Public Users
- Chat with AI assistant
- Get intelligent responses
- Rate helpful/not helpful
- Report incorrect responses

### For Staff
- Review user reports
- Suggest corrections
- Verify report validity
- Track resolution status

### For Admins
- Approve corrections
- Configure system settings
- View analytics
- Manage users
- Monitor system health

---

## Security Notes

✅ Change default admin password immediately  
✅ Use strong passwords (8+ chars, mixed case, numbers, symbols)  
✅ Enable HTTPS in production  
✅ Keep `.env.php` secure (chmod 600)  
✅ Regular backups (database + files)  
✅ Monitor logs daily  

---

## Getting Help

1. **Documentation:**
   - [README.md](README.md) - Overview
   - [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) - Detailed setup
   - [REFACTORING_CHANGELOG.md](REFACTORING_CHANGELOG.md) - Features
   - [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) - Production

2. **Database:**
   - Check `system_logs` table for errors
   - Review `admin_settings` for configuration

3. **Logs:**
   - Application: `/logs/php_errors.log`
   - Web server: Apache/Nginx logs

---

## Performance Tips

1. **Enable Caching:**
   ```sql
   UPDATE admin_settings 
   SET setting_value = '1' 
   WHERE setting_key = 'response_cache_enabled';
   ```

2. **Optimize Database:**
   ```sql
   OPTIMIZE TABLE ai_responses, response_cache, rate_limits;
   ```

3. **Clean Old Cache:**
   ```sql
   DELETE FROM response_cache WHERE expires_at < NOW();
   ```

4. **Monitor Cache Hits:**
   ```sql
   SELECT cache_key, hit_count 
   FROM response_cache 
   ORDER BY hit_count DESC 
   LIMIT 10;
   ```

---

## Production Checklist

Before going live:
- [ ] `.env.php` has production credentials
- [ ] `ENVIRONMENT` set to `'production'`
- [ ] Admin password changed
- [ ] HTTPS enabled
- [ ] Backups automated
- [ ] Monitoring configured
- [ ] All features tested
- [ ] Firewall configured

---

## Support

**System Status:** Check Admin Dashboard → System Information

**Error Tracking:**
```bash
tail -f logs/php_errors.log
```

**Database Health:**
```sql
SELECT severity, COUNT(*) 
FROM system_logs 
WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) 
GROUP BY severity;
```

---

**You're all set!** 🚀

For detailed information, see the complete documentation files.

Enjoy your enhanced DKAI2 system!
