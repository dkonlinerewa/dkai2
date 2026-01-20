# DKAI2 - AI Knowledge-Base Chatbot System

## Version 2.0 - Comprehensive Refactoring

A monolithic PHP/MySQL knowledge-base chatbot with advanced AI response reporting, security enhancements, and performance optimizations.

---

## Quick Start

### Prerequisites
- PHP 7.4+
- MySQL 5.7+ or MariaDB 10.2+
- Apache 2.4+ or Nginx 1.18+
- 256MB+ PHP memory

### Installation (5 minutes)

1. **Configure environment:**
   ```bash
   cp .env.php.example .env.php
   nano .env.php  # Edit database credentials
   ```

2. **Create database:**
   ```bash
   mysql -u root -p -e "CREATE DATABASE target2030"
   ```

3. **Run migration:**
   ```bash
   mysql -u your_user -p target2030 < database_migration.sql
   ```

4. **Access application:**
   ```
   http://yourdomain.com/public_html/default.php
   ```

5. **Login (default):**
   - Username: `admin`
   - Password: `Admin@123`
   - **⚠️ Change immediately!**

---

## Documentation

- **[Installation Guide](INSTALLATION_GUIDE.md)** - Complete setup instructions
- **[Changelog](REFACTORING_CHANGELOG.md)** - All changes and features
- **[Database Migration](database_migration.sql)** - SQL schema

---

## Key Features

### Core Functionality
✅ Knowledge-base building from uploaded documents (PDF, DOCX, Excel, PPT, TXT, CSV)  
✅ AI-powered chat assistant with training and rating loops  
✅ Multi-role dashboards (public, staff, admin)  
✅ API access with key-based rate limiting  
✅ Built-in operational tooling (logging, backups, system health)

### NEW in v2.0

#### AI Response Reporting System
- Public users can report incorrect/inappropriate responses
- Staff verify reports and suggest corrections
- Admin approval workflow with versioning
- False report handling and analytics

#### Security Enhancements
- CSRF token protection
- Rate limiting (per IP/user)
- Device fingerprinting
- Content filtering (spam/NSFW)
- Enhanced input validation
- SQL injection prevention
- XSS protection

#### Performance Optimizations
- Response caching with hit tracking
- Database query optimization
- Response versioning/history
- Graceful degradation

#### Admin Features
- Configurable system settings (no code changes)
- Comprehensive analytics dashboard
- Audit logging with granular events
- Automated backups
- Health checks

---

## Architecture

### File Structure
```
project/
├── .env.php                    # Secure configuration (REQUIRED)
├── .env.php.example            # Configuration template
├── database_migration.sql      # Database schema
├── README.md                   # This file
├── INSTALLATION_GUIDE.md       # Complete setup guide
├── REFACTORING_CHANGELOG.md    # Detailed changes
├── .gitignore                  # Git ignore rules
├── backups/                    # Database backups
├── cache/                      # Response cache
├── logs/                       # Application logs
├── uploads/                    # Uploaded files
│   ├── documents/
│   ├── profiles/
│   └── temp/
└── public_html/
    ├── default.php             # Main application (6,481 lines)
    ├── backup.php              # Standalone backup script
    └── download.php            # File download handler
```

### Database Schema (20+ tables)
- **Core:** users, documents, knowledge_base, chat_sessions, chat_messages
- **AI Training:** ai_training, ai_responses, response_versions
- **Reporting:** ai_response_reports, response_corrections
- **Security:** csrf_tokens, device_fingerprints, ip_blocks, rate_limits
- **System:** admin_settings, system_logs, audit_logs, response_cache

---

## Technology Stack

- **Backend:** PHP 7.4+ (single-file monolith)
- **Database:** MySQL 5.7+ / MariaDB 10.2+
- **Frontend:** Vanilla JavaScript, HTML5, CSS3
- **Security:** CSRF tokens, rate limiting, device fingerprinting
- **Architecture:** Monolithic (all code in one file)

---

## Admin Settings

Configure via database or admin panel:

| Setting | Default | Description |
|---------|---------|-------------|
| `reporting_enabled` | true | Enable reporting system |
| `approval_type` | manual | Auto/manual correction approval |
| `max_reports_per_user_per_day` | 10 | Daily report limit |
| `response_cache_enabled` | true | Enable response caching |
| `rate_limit_enabled` | true | Enable rate limiting |
| `csrf_protection_enabled` | true | Enable CSRF protection |
| `content_filtering_enabled` | true | Enable spam filtering |

---

## API Endpoints

### Public Endpoints
- `POST /default.php?action=chat` - Chat with AI
- `POST /default.php?action=submit_report` - Report response
- `POST /default.php?action=get_csrf_token` - Get CSRF token

### Staff Endpoints (Authentication Required)
- `POST /default.php?action=suggest_correction` - Suggest correction
- `POST /default.php?action=get_reports` - View reports
- `POST /default.php?action=mark_report_false` - Mark as false

### Admin Endpoints (Admin Only)
- `POST /default.php?action=approve_correction` - Approve correction
- `POST /default.php?action=update_setting` - Update settings
- `POST /default.php?action=get_report_stats` - Get statistics

---

## Security Features

- **Authentication:** Password hashing (bcrypt), failed login protection
- **Sessions:** Secure cookies, httpOnly, SameSite, periodic regeneration
- **CSRF:** Token-based protection with expiry
- **Rate Limiting:** IP and user-based with automatic blocking
- **Input Validation:** Type-specific sanitization, XSS prevention
- **SQL Injection:** 100% prepared statements
- **Content Filtering:** Spam and inappropriate content detection
- **Device Fingerprinting:** Login security and anomaly detection
- **Audit Logging:** Complete trail of all actions

---

## Performance

### Optimizations
- Response caching (1-hour TTL default)
- Database indexing on all queries
- Prepared statement reuse
- Lazy loading of components
- Efficient chunking algorithm

### Expected Metrics
- Response time: < 200ms (cached)
- Response time: < 500ms (uncached)
- Cache hit rate: > 70%
- Concurrent users: 100+
- Database queries: Optimized with indexes

---

## Deployment

### Development
```bash
# Set in .env.php
define('ENVIRONMENT', 'development');
```
- Error display: ON
- Debug info: Visible
- Logging: Verbose

### Production
```bash
# Set in .env.php
define('ENVIRONMENT', 'production');
```
- Error display: OFF
- Debug info: Hidden
- Logging: Errors only
- **HTTPS required**
- **Change default admin password!**

---

## Monitoring

### Log Files
- **Application:** `/logs/php_errors.log`
- **System Events:** `system_logs` table
- **Audit Trail:** `audit_logs` table

### Key Metrics
```sql
-- Recent errors
SELECT * FROM system_logs WHERE severity='error' ORDER BY created_at DESC LIMIT 10;

-- Cache performance
SELECT cache_key, hit_count FROM response_cache ORDER BY hit_count DESC LIMIT 10;

-- Report statistics
SELECT status, COUNT(*) FROM ai_response_reports GROUP BY status;

-- Active users
SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW();
```

---

## Backup & Recovery

### Automated Backups
```bash
# Database (cron: daily at 2 AM)
mysqldump -u user -p database > backups/db_$(date +%Y%m%d).sql

# Files (cron: daily at 3 AM)
tar -czf backups/files_$(date +%Y%m%d).tar.gz uploads/
```

### Manual Backup
Via admin panel or:
```bash
cd /your-web-root
./public_html/backup.php
```

### Recovery
```bash
mysql -u user -p database < backups/db_YYYYMMDD.sql
tar -xzf backups/files_YYYYMMDD.tar.gz
```

---

## Troubleshooting

### Common Issues

**"Configuration file not found"**
```bash
cp .env.php.example .env.php
nano .env.php  # Edit credentials
```

**"Database connection failed"**
```bash
# Check MySQL running
systemctl status mysql

# Test connection
mysql -u username -p

# Verify credentials in .env.php
```

**"Permission denied"**
```bash
chmod 755 uploads logs cache backups
chown -R www-data:www-data uploads logs cache
```

**"CSRF token invalid"**
- Clear browser cache
- Verify session.save_path writable
- Check CSRF_TOKEN_SECRET in .env.php

---

## Contributing

This is a monolithic refactoring. Future enhancements:
- Implement reporting UI components
- Add email notifications
- Create mobile app API
- Multi-language support
- Advanced analytics dashboard

---

## License

As per original project license.

---

## Credits

**Version:** 2.0  
**Original:** DKAI chatbot system  
**Refactoring:** Complete consolidation and enhancement  
**Date:** 2024

---

## Support

For detailed information:
- Read [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)
- Review [REFACTORING_CHANGELOG.md](REFACTORING_CHANGELOG.md)
- Check database schema in [database_migration.sql](database_migration.sql)
- Monitor system logs for errors
- Use admin dashboard for health checks

---

## Quick Reference

### Default Login
- **URL:** `http://yourdomain.com/public_html/default.php`
- **Username:** `admin`
- **Password:** `Admin@123` ⚠️ **CHANGE IMMEDIATELY**

### File Locations
- **Main App:** `public_html/default.php` (6,481 lines)
- **Config:** `.env.php` (secured)
- **Database:** MySQL `target2030`
- **Logs:** `/logs/php_errors.log`
- **Uploads:** `/uploads/documents/`
- **Backups:** `/backups/`

### Key Commands
```bash
# Check system status
tail -f logs/php_errors.log

# Database backup
mysqldump -u user -p target2030 > backup.sql

# File backup
tar -czf backup.tar.gz uploads/

# Check permissions
ls -la .env.php uploads/ logs/

# Test database
mysql -u user -p target2030 -e "SELECT COUNT(*) FROM users;"
```

---

**Enjoy your enhanced DKAI2 system!** 🚀
