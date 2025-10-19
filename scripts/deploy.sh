#!/bin/bash

# TriTerm Production Deployment Script
# This script handles zero-downtime deployment of TriTerm

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env"
BACKUP_DIR="./backups"

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

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # Check if docker-compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi

    # Check if .env file exists
    if [ ! -f "$ENV_FILE" ]; then
        log_error ".env file not found. Copy .env.production to .env and configure it."
        exit 1
    fi

    # Check if compose file exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "$COMPOSE_FILE not found"
        exit 1
    fi

    log_info "Prerequisites check passed"
}

create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        log_info "Creating backup directory..."
        mkdir -p "$BACKUP_DIR"
    fi
}

backup_database() {
    log_info "Creating database backup before deployment..."

    # Check if database is running
    if docker-compose -f "$COMPOSE_FILE" ps db | grep -q "Up"; then
        BACKUP_FILE="$BACKUP_DIR/pre_deploy_$(date +%Y%m%d_%H%M%S).sql"
        docker-compose -f "$COMPOSE_FILE" exec -T db pg_dump -U triterm_prod triterm_production > "$BACKUP_FILE"

        if [ -f "$BACKUP_FILE" ]; then
            log_info "Database backup created: $BACKUP_FILE"
        else
            log_error "Failed to create database backup"
            exit 1
        fi
    else
        log_warn "Database is not running, skipping backup"
    fi
}

pull_images() {
    log_info "Pulling latest Docker images..."
    docker-compose -f "$COMPOSE_FILE" pull
}

deploy() {
    log_info "Starting deployment..."

    # Start services with zero downtime
    docker-compose -f "$COMPOSE_FILE" up -d --no-deps --build

    log_info "Waiting for services to be healthy..."
    sleep 10

    # Check service health
    if docker-compose -f "$COMPOSE_FILE" ps | grep -q "unhealthy"; then
        log_error "Some services are unhealthy. Check logs with: docker-compose -f $COMPOSE_FILE logs"
        exit 1
    fi

    log_info "Deployment completed successfully"
}

cleanup_old_images() {
    log_info "Cleaning up old Docker images..."
    docker image prune -f
}

show_status() {
    log_info "Current service status:"
    docker-compose -f "$COMPOSE_FILE" ps
}

show_logs() {
    log_info "Recent logs (last 50 lines):"
    docker-compose -f "$COMPOSE_FILE" logs --tail=50
}

# Main deployment flow
main() {
    echo "======================================"
    echo "   TriTerm Production Deployment"
    echo "======================================"
    echo ""

    check_prerequisites
    create_backup_dir
    backup_database
    pull_images
    deploy
    cleanup_old_images
    show_status

    echo ""
    log_info "Deployment completed successfully!"
    echo ""
    log_info "Useful commands:"
    echo "  - View logs: docker-compose -f $COMPOSE_FILE logs -f"
    echo "  - View status: docker-compose -f $COMPOSE_FILE ps"
    echo "  - Stop services: docker-compose -f $COMPOSE_FILE down"
    echo "  - Restart service: docker-compose -f $COMPOSE_FILE restart <service>"
    echo ""
}

# Run main function
main
