.PHONY: help docker-up docker-down docker-build docker-logs docker-clean docker-ps docker-backup docker-restore

# Default target
help:
	@echo "TriTerm Docker Commands:"
	@echo ""
	@echo "  make docker-up       - Start all services (build if needed)"
	@echo "  make docker-down     - Stop all services"
	@echo "  make docker-build    - Build all images"
	@echo "  make docker-logs     - Follow logs from all services"
	@echo "  make docker-ps       - Show service status"
	@echo "  make docker-clean    - Stop and remove all containers, networks, volumes"
	@echo "  make docker-backup   - Backup database to backup.sql"
	@echo "  make docker-restore  - Restore database from backup.sql"
	@echo ""

# Start all services
docker-up:
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.docker..."; \
		cp .env.docker .env; \
	fi
	docker-compose up -d --build

# Stop all services
docker-down:
	docker-compose down

# Build all images
docker-build:
	docker-compose build

# Follow logs
docker-logs:
	docker-compose logs -f

# Show service status
docker-ps:
	docker-compose ps

# Clean everything (WARNING: deletes volumes)
docker-clean:
	docker-compose down -v --rmi all

# Backup database
docker-backup:
	@echo "Backing up database to backup.sql..."
	@docker-compose exec -T db pg_dump -U triterm triterm > backup.sql
	@echo "Backup complete: backup.sql"

# Restore database
docker-restore:
	@if [ ! -f backup.sql ]; then \
		echo "Error: backup.sql not found"; \
		exit 1; \
	fi
	@echo "Restoring database from backup.sql..."
	@docker-compose exec -T db psql -U triterm triterm < backup.sql
	@echo "Restore complete"
