#!/bin/bash

# TriTerm Database Restore Script
# This script restores the PostgreSQL database from a backup file

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
POSTGRES_USER="${POSTGRES_USER:-triterm_prod}"
POSTGRES_DB="${POSTGRES_DB:-triterm_production}"
DB_HOST="${DB_HOST:-db}"
COMPOSE_FILE="docker-compose.prod.yml"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

list_backups() {
    echo "Available backups:"
    echo ""

    BACKUPS=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -o -name "backup_*.sql" 2>/dev/null | sort -r)

    if [ -z "$BACKUPS" ]; then
        log_error "No backups found in $BACKUP_DIR"
        exit 1
    fi

    INDEX=1
    while IFS= read -r backup; do
        SIZE=$(du -h "$backup" | cut -f1)
        TIMESTAMP=$(basename "$backup" | sed 's/backup_//;s/\.sql.*$//')
        echo "  [$INDEX] $backup ($SIZE) - $TIMESTAMP"
        INDEX=$((INDEX + 1))
    done <<< "$BACKUPS"
}

select_backup() {
    if [ -n "$1" ]; then
        BACKUP_FILE="$1"
        if [ ! -f "$BACKUP_FILE" ]; then
            log_error "Backup file not found: $BACKUP_FILE"
            exit 1
        fi
    else
        list_backups
        echo ""
        read -p "Enter backup number to restore (or full path): " SELECTION

        if [[ "$SELECTION" =~ ^[0-9]+$ ]]; then
            BACKUP_FILE=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -o -name "backup_*.sql" 2>/dev/null | sort -r | sed -n "${SELECTION}p")
            if [ -z "$BACKUP_FILE" ]; then
                log_error "Invalid selection"
                exit 1
            fi
        else
            BACKUP_FILE="$SELECTION"
            if [ ! -f "$BACKUP_FILE" ]; then
                log_error "Backup file not found: $BACKUP_FILE"
                exit 1
            fi
        fi
    fi

    log_info "Selected backup: $BACKUP_FILE"
}

confirm_restore() {
    log_warn "⚠️  WARNING: This will REPLACE all data in the database!"
    log_warn "Database: $POSTGRES_DB on $DB_HOST"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        log_info "Restore cancelled"
        exit 0
    fi
}

create_pre_restore_backup() {
    log_info "Creating backup of current database before restore..."

    PRE_RESTORE_BACKUP="$BACKUP_DIR/pre_restore_$(date +%Y%m%d_%H%M%S).sql"

    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" exec -T db \
            pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "$PRE_RESTORE_BACKUP" 2>/dev/null || true
    else
        PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h "$DB_HOST" -U "$POSTGRES_USER" "$POSTGRES_DB" \
            > "$PRE_RESTORE_BACKUP" 2>/dev/null || true
    fi

    if [ -f "$PRE_RESTORE_BACKUP" ] && [ -s "$PRE_RESTORE_BACKUP" ]; then
        gzip "$PRE_RESTORE_BACKUP"
        log_info "Pre-restore backup created: ${PRE_RESTORE_BACKUP}.gz"
    else
        log_warn "Could not create pre-restore backup (database may be empty)"
        rm -f "$PRE_RESTORE_BACKUP"
    fi
}

restore_database() {
    log_info "Restoring database..."

    # Decompress if needed
    if [[ "$BACKUP_FILE" == *.gz ]]; then
        log_info "Decompressing backup..."
        TEMP_FILE=$(mktemp)
        gunzip -c "$BACKUP_FILE" > "$TEMP_FILE"
        RESTORE_FILE="$TEMP_FILE"
    else
        RESTORE_FILE="$BACKUP_FILE"
    fi

    # Drop existing connections
    log_info "Terminating existing database connections..."
    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" exec -T db psql -U "$POSTGRES_USER" -d postgres -c \
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$POSTGRES_DB' AND pid <> pg_backend_pid();" \
            2>/dev/null || true
    fi

    # Drop and recreate database
    log_info "Recreating database..."
    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" exec -T db psql -U "$POSTGRES_USER" -d postgres <<-EOSQL
            DROP DATABASE IF EXISTS $POSTGRES_DB;
            CREATE DATABASE $POSTGRES_DB;
EOSQL
    else
        PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$DB_HOST" -U "$POSTGRES_USER" -d postgres <<-EOSQL
            DROP DATABASE IF EXISTS $POSTGRES_DB;
            CREATE DATABASE $POSTGRES_DB;
EOSQL
    fi

    # Restore database
    log_info "Importing data..."
    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
            < "$RESTORE_FILE"
    else
        PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$DB_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
            < "$RESTORE_FILE"
    fi

    # Cleanup temp file
    if [ -n "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi

    log_info "Database restore completed successfully"
}

# Main
main() {
    echo "======================================"
    echo "   TriTerm Database Restore"
    echo "======================================"
    echo ""

    select_backup "$1"
    confirm_restore
    create_pre_restore_backup
    restore_database

    echo ""
    log_info "✓ Restore completed successfully"
    log_info "The application should automatically reconnect to the database"
}

# Run main function
main "$@"
