#!/bin/bash

# TriTerm Health Check Script
# This script checks the health of all services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
CLIENT_URL="${CLIENT_URL:-http://localhost}"
SERVER_URL="${SERVER_URL:-http://localhost:3000}"

# Counters
PASSED=0
FAILED=0
WARNING=0

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNING=$((WARNING + 1))
}

check_docker() {
    if command -v docker &> /dev/null; then
        log_pass "Docker is installed"
    else
        log_fail "Docker is not installed"
        return 1
    fi

    if docker info &> /dev/null; then
        log_pass "Docker daemon is running"
    else
        log_fail "Docker daemon is not running"
        return 1
    fi
}

check_compose() {
    if command -v docker-compose &> /dev/null; then
        log_pass "Docker Compose is installed"
    else
        log_fail "Docker Compose is not installed"
        return 1
    fi

    if [ -f "$COMPOSE_FILE" ]; then
        log_pass "Compose file exists: $COMPOSE_FILE"
    else
        log_fail "Compose file not found: $COMPOSE_FILE"
        return 1
    fi
}

check_services() {
    log_info "Checking service status..."

    SERVICES=$(docker-compose -f "$COMPOSE_FILE" ps --services 2>/dev/null)

    if [ -z "$SERVICES" ]; then
        log_warn "No services are running"
        return 0
    fi

    for service in $SERVICES; do
        STATUS=$(docker-compose -f "$COMPOSE_FILE" ps "$service" 2>/dev/null | grep -v "^NAME" | awk '{print $5}')

        if echo "$STATUS" | grep -q "Up"; then
            log_pass "Service '$service' is running"
        else
            log_fail "Service '$service' is not running: $STATUS"
        fi

        # Check health status
        HEALTH=$(docker-compose -f "$COMPOSE_FILE" ps "$service" 2>/dev/null | grep -v "^NAME" | grep -o "(healthy)" || echo "")

        if [ "$service" != "db-backup" ]; then
            if [ -n "$HEALTH" ]; then
                log_pass "Service '$service' is healthy"
            else
                if echo "$STATUS" | grep -q "Up"; then
                    log_warn "Service '$service' health check not available or starting"
                fi
            fi
        fi
    done
}

check_database() {
    log_info "Checking database connection..."

    if docker-compose -f "$COMPOSE_FILE" exec -T db pg_isready -U triterm_prod &> /dev/null; then
        log_pass "Database is accepting connections"
    else
        log_fail "Database is not accepting connections"
        return 1
    fi

    # Check database size
    DB_SIZE=$(docker-compose -f "$COMPOSE_FILE" exec -T db psql -U triterm_prod -d triterm_production -t -c "SELECT pg_size_pretty(pg_database_size('triterm_production'));" 2>/dev/null | xargs)

    if [ -n "$DB_SIZE" ]; then
        log_info "Database size: $DB_SIZE"
    fi
}

check_endpoints() {
    log_info "Checking HTTP endpoints..."

    # Check client health
    if curl -sf "$CLIENT_URL/health" > /dev/null 2>&1; then
        log_pass "Client endpoint is responding: $CLIENT_URL/health"
    else
        log_warn "Client endpoint not responding: $CLIENT_URL/health"
    fi

    # Check server health (if accessible)
    if curl -sf "$SERVER_URL/health" > /dev/null 2>&1; then
        log_pass "Server endpoint is responding: $SERVER_URL/health"
    else
        log_warn "Server endpoint not responding: $SERVER_URL/health (may be internal only)"
    fi
}

check_resources() {
    log_info "Checking resource usage..."

    # Disk space
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -lt 80 ]; then
        log_pass "Disk usage: ${DISK_USAGE}%"
    elif [ "$DISK_USAGE" -lt 90 ]; then
        log_warn "Disk usage is high: ${DISK_USAGE}%"
    else
        log_fail "Disk usage is critical: ${DISK_USAGE}%"
    fi

    # Memory usage
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    if [ "$MEM_USAGE" -lt 80 ]; then
        log_pass "Memory usage: ${MEM_USAGE}%"
    elif [ "$MEM_USAGE" -lt 90 ]; then
        log_warn "Memory usage is high: ${MEM_USAGE}%"
    else
        log_fail "Memory usage is critical: ${MEM_USAGE}%"
    fi
}

check_logs() {
    log_info "Checking for errors in logs..."

    # Check for errors in last 100 lines of logs
    ERROR_COUNT=$(docker-compose -f "$COMPOSE_FILE" logs --tail=100 2>/dev/null | grep -i "error" | grep -v "0 error" | wc -l)

    if [ "$ERROR_COUNT" -eq 0 ]; then
        log_pass "No errors in recent logs"
    else
        log_warn "Found $ERROR_COUNT error(s) in recent logs"
    fi
}

check_backups() {
    log_info "Checking backups..."

    BACKUP_DIR="./backups"

    if [ -d "$BACKUP_DIR" ]; then
        BACKUP_COUNT=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -o -name "backup_*.sql" 2>/dev/null | wc -l)

        if [ "$BACKUP_COUNT" -gt 0 ]; then
            LATEST_BACKUP=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -o -name "backup_*.sql" 2>/dev/null | sort -r | head -n 1)
            BACKUP_AGE=$(( ($(date +%s) - $(stat -c %Y "$LATEST_BACKUP")) / 86400 ))

            log_info "Total backups: $BACKUP_COUNT"
            log_info "Latest backup: $(basename "$LATEST_BACKUP")"

            if [ "$BACKUP_AGE" -eq 0 ]; then
                log_pass "Latest backup is from today"
            elif [ "$BACKUP_AGE" -le 1 ]; then
                log_pass "Latest backup is $BACKUP_AGE day(s) old"
            elif [ "$BACKUP_AGE" -le 7 ]; then
                log_warn "Latest backup is $BACKUP_AGE day(s) old"
            else
                log_fail "Latest backup is $BACKUP_AGE day(s) old - backups may not be running"
            fi
        else
            log_warn "No backups found in $BACKUP_DIR"
        fi
    else
        log_warn "Backup directory not found: $BACKUP_DIR"
    fi
}

print_summary() {
    echo ""
    echo "======================================"
    echo "   Health Check Summary"
    echo "======================================"
    echo -e "${GREEN}Passed:${NC}  $PASSED"
    echo -e "${YELLOW}Warnings:${NC} $WARNING"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo "======================================"
    echo ""

    if [ "$FAILED" -eq 0 ] && [ "$WARNING" -eq 0 ]; then
        echo -e "${GREEN}✓ All checks passed!${NC}"
        return 0
    elif [ "$FAILED" -eq 0 ]; then
        echo -e "${YELLOW}⚠ All checks passed with warnings${NC}"
        return 0
    else
        echo -e "${RED}✗ Some checks failed${NC}"
        return 1
    fi
}

# Main
main() {
    echo "======================================"
    echo "   TriTerm Health Check"
    echo "======================================"
    echo ""

    check_docker
    check_compose
    check_services
    check_database
    check_endpoints
    check_resources
    check_logs
    check_backups

    print_summary
}

# Run main function
main
