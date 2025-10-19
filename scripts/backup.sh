#!/bin/bash

# TriTerm Database Backup Script
# This script creates timestamped backups of the PostgreSQL database

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
POSTGRES_USER="${POSTGRES_USER:-triterm_prod}"
POSTGRES_DB="${POSTGRES_DB:-triterm_production}"
DB_HOST="${DB_HOST:-db}"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

create_backup() {
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.sql"

    log_info "Creating database backup..."
    log_info "Database: $POSTGRES_DB"
    log_info "Backup file: $BACKUP_FILE"

    # Create backup
    if PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h "$DB_HOST" -U "$POSTGRES_USER" "$POSTGRES_DB" > "$BACKUP_FILE"; then
        # Compress backup
        gzip "$BACKUP_FILE"
        log_info "Backup created successfully: ${BACKUP_FILE}.gz"

        # Get file size
        SIZE=$(du -h "${BACKUP_FILE}.gz" | cut -f1)
        log_info "Backup size: $SIZE"
    else
        log_error "Failed to create backup"
        exit 1
    fi
}

cleanup_old_backups() {
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."

    DELETED=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete -print | wc -l)

    if [ "$DELETED" -gt 0 ]; then
        log_info "Deleted $DELETED old backup(s)"
    else
        log_info "No old backups to delete"
    fi
}

list_backups() {
    log_info "Available backups:"
    find "$BACKUP_DIR" -name "backup_*.sql.gz" -type f -printf "%T@ %Tc %s %p\n" | \
        sort -rn | \
        head -n 10 | \
        awk '{
            size=$3;
            if (size >= 1073741824) {
                printf "  %s - %.2f GB - %s\n", substr($0, index($0,$7)), size/1073741824, substr($0, index($0,$4), index($0,$7)-index($0,$4)-1)
            } else if (size >= 1048576) {
                printf "  %s - %.2f MB - %s\n", substr($0, index($0,$7)), size/1048576, substr($0, index($0,$4), index($0,$7)-index($0,$4)-1)
            } else if (size >= 1024) {
                printf "  %s - %.2f KB - %s\n", substr($0, index($0,$7)), size/1024, substr($0, index($0,$4), index($0,$7)-index($0,$4)-1)
            } else {
                printf "  %s - %d bytes - %s\n", substr($0, index($0,$7)), size, substr($0, index($0,$4), index($0,$7)-index($0,$4)-1)
            }
        }'
}

# Main
main() {
    echo "======================================"
    echo "   TriTerm Database Backup"
    echo "======================================"
    echo ""

    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR"

    # Create backup
    create_backup

    # Cleanup old backups
    cleanup_old_backups

    # List recent backups
    echo ""
    list_backups

    echo ""
    log_info "Backup completed successfully"
}

# Run main function
main
