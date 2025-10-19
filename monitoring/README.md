# Monitoring Configuration

This directory contains configuration files for the TriTerm monitoring stack.

## Directory Structure

```
monitoring/
├── prometheus/
│   ├── prometheus.yml    # Prometheus main configuration
│   └── alerts.yml        # Alert rules
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── prometheus.yml   # Auto-configure Prometheus datasource
│   │   └── dashboards/
│   │       └── default.yml      # Dashboard provisioning config
│   └── dashboards/
│       └── triterm-overview.json # Pre-built TriTerm dashboard
└── alertmanager/
    └── config.yml        # Alertmanager configuration
```

## Configuration Files

### Prometheus (`prometheus/prometheus.yml`)

Defines:

- Scrape targets (what to monitor)
- Scrape intervals
- Alert rule files
- Alertmanager connection

**Scrape Targets:**

- TriTerm Server (port 3000)
- TriTerm Client (port 80)
- PostgreSQL (via exporter on port 9187)
- System metrics (via node-exporter on port 9100)
- Container metrics (via cAdvisor on port 8080)

### Alert Rules (`prometheus/alerts.yml`)

Defines alert conditions:

- Service availability
- Resource usage (CPU, memory, disk)
- Database health
- Container health

**Alert Severity Levels:**

- `critical` - Immediate action required
- `warning` - Attention needed

### Alertmanager (`alertmanager/config.yml`)

Configures alert routing and notifications:

- Email notifications
- Slack integration
- PagerDuty integration
- Alert grouping and deduplication

### Grafana Datasources (`grafana/provisioning/datasources/`)

Auto-configures Prometheus as data source on Grafana startup.

### Grafana Dashboards (`grafana/dashboards/`)

Pre-built dashboards:

- `triterm-overview.json` - Main TriTerm monitoring dashboard

## Customization

### Adding Custom Alerts

Edit `prometheus/alerts.yml`:

```yaml
groups:
  - name: custom_alerts
    rules:
      - alert: CustomAlert
        expr: your_metric > threshold
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'Custom alert description'
          description: 'Detailed description'
```

### Adding Scrape Targets

Edit `prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'my-service'
    static_configs:
      - targets: ['my-service:9090']
        labels:
          service: 'my-service'
```

### Configuring Email Alerts

Edit `alertmanager/config.yml`:

```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@example.com'
  smtp_auth_username: 'user@gmail.com'
  smtp_auth_password: 'app-password'

receivers:
  - name: 'email'
    email_configs:
      - to: 'admin@example.com'
```

### Configuring Slack Alerts

Edit `alertmanager/config.yml`:

```yaml
receivers:
  - name: 'slack'
    slack_configs:
      - api_url: 'YOUR_WEBHOOK_URL'
        channel: '#alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ .CommonAnnotations.description }}'
```

### Creating Custom Grafana Dashboards

1. **Via UI:**
   - Log into Grafana (http://localhost:3001)
   - Create dashboard
   - Export as JSON
   - Save to `grafana/dashboards/`

2. **Import Public Dashboards:**
   ```bash
   # Popular dashboard IDs:
   # - Node Exporter Full: 1860
   # - PostgreSQL: 9628
   # - Docker: 179
   ```

## Reloading Configuration

### Prometheus

```bash
# Reload configuration without restart
docker-compose -f docker-compose.monitoring.yml exec prometheus \
  kill -HUP 1
```

### Alertmanager

```bash
# Reload configuration without restart
docker-compose -f docker-compose.monitoring.yml exec alertmanager \
  kill -HUP 1
```

### Grafana

```bash
# Restart to load new dashboards
docker-compose -f docker-compose.monitoring.yml restart grafana
```

## Testing

### Test Prometheus Queries

```bash
# Query Prometheus API
curl 'http://localhost:9090/api/v1/query?query=up'

# Check all targets
curl 'http://localhost:9090/api/v1/targets' | jq
```

### Test Alerts

```bash
# View active alerts
curl 'http://localhost:9090/api/v1/alerts' | jq

# View alert rules
curl 'http://localhost:9090/api/v1/rules' | jq
```

### Test Alertmanager

```bash
# View active alerts in Alertmanager
curl 'http://localhost:9093/api/v1/alerts' | jq

# Test webhook (if configured)
curl -X POST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{"labels":{"alertname":"test"}}]'
```

## Backup

### Backup Prometheus Data

```bash
# Data is stored in Docker volume
docker run --rm -v triterm_prometheus_data:/data \
  -v $(pwd)/backup:/backup alpine \
  tar czf /backup/prometheus-$(date +%Y%m%d).tar.gz /data
```

### Backup Grafana Dashboards

```bash
# Export all dashboards via API
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3001/api/search?type=dash-db | \
  jq -r '.[].uri' | \
  xargs -I {} curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3001/api/{} > dashboard-backup.json
```

### Backup Grafana Data

```bash
# Data is stored in Docker volume
docker run --rm -v triterm_grafana_data:/data \
  -v $(pwd)/backup:/backup alpine \
  tar czf /backup/grafana-$(date +%Y%m%d).tar.gz /data
```

## Security

### Change Default Passwords

Edit `.env.monitoring`:

```env
GRAFANA_ADMIN_PASSWORD=strong_password
```

### Restrict Access

**Firewall Rules:**

```bash
# Block external access to monitoring ports
sudo ufw deny 9090  # Prometheus
sudo ufw deny 3001  # Grafana
sudo ufw deny 9093  # Alertmanager
```

**Use Reverse Proxy:**
Configure nginx/Traefik with authentication.

### Secure Credentials

- Don't commit `.env.monitoring` to git
- Use secrets management in production
- Rotate Grafana admin password regularly

## Troubleshooting

### Metrics Not Appearing

1. Check Prometheus targets: http://localhost:9090/targets
2. Verify services are running: `docker-compose ps`
3. Check network connectivity between containers
4. Review Prometheus logs: `docker-compose logs prometheus`

### Alerts Not Firing

1. Check alert rules are loaded: http://localhost:9090/rules
2. Verify Alertmanager connection: http://localhost:9090/config
3. Review Alertmanager logs: `docker-compose logs alertmanager`
4. Check alert conditions with PromQL queries

### Grafana Can't Connect to Prometheus

1. Test datasource in Grafana UI
2. Verify Prometheus is running: `docker-compose ps prometheus`
3. Check network: `docker network inspect triterm_monitoring`
4. Review Grafana logs: `docker-compose logs grafana`

## Additional Resources

- [Prometheus Configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- [Alert Rule Examples](https://awesome-prometheus-alerts.grep.to/)
- [Grafana Dashboard Gallery](https://grafana.com/grafana/dashboards/)
- [PromQL Basics](https://prometheus.io/docs/prometheus/latest/querying/basics/)
