# TriTerm Production Scripts

This directory contains operational scripts for managing TriTerm in production.

## Scripts Overview

### `deploy.sh`

Production deployment script with zero-downtime deployment support.

**Usage:**

```bash
./scripts/deploy.sh
```

**What it does:**

- Checks prerequisites (Docker, docker-compose, .env file)
- Creates automatic database backup before deployment
- Pulls latest Docker images
- Deploys services with zero downtime
- Verifies service health
- Cleans up old Docker images

### `backup.sh`

Manual database backup script with compression and retention management.

**Usage:**

```bash
./scripts/backup.sh
```

**What it does:**

- Creates timestamped PostgreSQL backup
- Compresses backup with gzip
- Manages backup retention (deletes old backups)
- Lists recent backups with sizes

**Environment Variables:**

- `BACKUP_DIR` - Backup directory (default: `/backups`)
- `BACKUP_RETENTION_DAYS` - Days to keep backups (default: `7`)
- `POSTGRES_USER` - Database user (default: `triterm_prod`)
- `POSTGRES_DB` - Database name (default: `triterm_production`)
- `DB_HOST` - Database host (default: `db`)

### `restore.sh`

Interactive database restore script with safety checks.

**Usage:**

```bash
# Interactive mode (lists available backups)
./scripts/restore.sh

# Restore specific backup
./scripts/restore.sh ./backups/backup_20240101_120000.sql.gz
```

**What it does:**

- Lists available backups (if no file specified)
- Prompts for confirmation before restore
- Creates backup of current database before restore
- Terminates existing connections
- Drops and recreates database
- Restores data from backup file
- Supports both compressed (.gz) and uncompressed (.sql) backups

**Safety Features:**

- Confirmation prompt before destructive operations
- Automatic pre-restore backup
- Detailed error messages

### `healthcheck.sh`

Comprehensive health check script for monitoring system status.

**Usage:**

```bash
./scripts/healthcheck.sh
```

**What it checks:**

- Docker and Docker Compose installation
- Service status and health
- Database connectivity
- HTTP endpoint availability
- Resource usage (disk, memory)
- Recent log errors
- Backup status and age

**Exit Codes:**

- `0` - All checks passed
- `1` - Some checks failed

**Environment Variables:**

- `COMPOSE_FILE` - Compose file to use (default: `docker-compose.prod.yml`)
- `CLIENT_URL` - Client URL to check (default: `http://localhost`)
- `SERVER_URL` - Server URL to check (default: `http://localhost:3000`)

## Common Workflows

### Initial Production Deployment

```bash
# 1. Configure environment
cp .env.production .env
nano .env

# 2. Deploy
./scripts/deploy.sh

# 3. Verify
./scripts/healthcheck.sh
```

### Regular Maintenance

```bash
# Check system health
./scripts/healthcheck.sh

# Create manual backup
./scripts/backup.sh

# View recent backups
ls -lh backups/
```

### Update Deployment

```bash
# 1. Update .env with new image versions
nano .env

# 2. Deploy update
./scripts/deploy.sh

# 3. Verify
./scripts/healthcheck.sh
```

### Disaster Recovery

```bash
# 1. List available backups
./scripts/restore.sh

# 2. Select and restore backup
# Follow interactive prompts

# 3. Verify restoration
./scripts/healthcheck.sh
```

### Automated Monitoring

Add to crontab for regular health checks:

```bash
# Edit crontab
crontab -e

# Add health check every 5 minutes
*/5 * * * * /path/to/triterm/scripts/healthcheck.sh >> /var/log/triterm-health.log 2>&1

# Add daily backup at 2 AM
0 2 * * * /path/to/triterm/scripts/backup.sh >> /var/log/triterm-backup.log 2>&1
```

### Email Alerts

Wrap healthcheck.sh with email notifications:

```bash
#!/bin/bash
if ! /path/to/triterm/scripts/healthcheck.sh; then
    echo "TriTerm health check failed" | mail -s "TriTerm Alert" admin@example.com
fi
```

## Troubleshooting

### Script Permission Denied

```bash
chmod +x scripts/*.sh
```

### Database Connection Failed

```bash
# Check database is running
docker-compose -f docker-compose.prod.yml ps db

# Check logs
docker-compose -f docker-compose.prod.yml logs db

# Verify credentials in .env
grep POSTGRES .env
```

### Backup Failed

```bash
# Check disk space
df -h

# Check backup directory permissions
ls -ld backups/

# Run manually with verbose output
bash -x ./scripts/backup.sh
```

### Restore Failed

```bash
# Verify backup file exists and is readable
ls -lh ./backups/backup_*.sql.gz

# Check database is running
docker-compose -f docker-compose.prod.yml ps db

# Try manual restore
gunzip -c backup.sql.gz | docker-compose -f docker-compose.prod.yml exec -T db \
  psql -U triterm_prod triterm_production
```

## Best Practices

1. **Test scripts in staging** before using in production
2. **Review logs** after running scripts
3. **Keep backups off-site** for disaster recovery
4. **Monitor script execution** with cron or systemd timers
5. **Document custom modifications** to scripts
6. **Use version control** for script changes
7. **Test restore procedures** regularly

## Security Notes

- Scripts contain sensitive operations (database access, etc.)
- Ensure proper file permissions (readable by authorized users only)
- Never commit .env files or backups to version control
- Use secure channels when transferring backups
- Rotate database passwords regularly and update scripts accordingly

## Support

For issues with scripts:

1. Check script output for error messages
2. Review Docker logs: `docker-compose -f docker-compose.prod.yml logs`
3. Verify environment configuration in `.env`
4. See PRODUCTION.md for detailed troubleshooting guide
