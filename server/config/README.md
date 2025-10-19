# TriTerm Logging Configuration

This directory contains the Winston logger configuration for the TriTerm server.

## Features

### 📝 Log Levels

- **error**: Error messages (always logged)
- **warn**: Warning messages
- **info**: Informational messages
- **debug**: Debug messages (development only)

### 🎨 Development Mode

- Colorized console output
- Pretty formatting for easy reading
- Debug level enabled
- Timestamps in `HH:mm:ss` format

### 🏭 Production Mode

- Structured JSON logging
- File-based log rotation (daily)
- Separate error logs
- Info level and above
- Full timestamps in `YYYY-MM-DD HH:mm:ss` format

## Log Files (Production)

When `NODE_ENV=production` or `LOG_TO_FILE=true`:

```
logs/
  ├── combined-2025-10-19.log    # All logs
  ├── error-2025-10-19.log       # Errors only
  └── ...
```

### Rotation Policy

- **Max File Size**: 20MB
- **Retention**: 14 days
- **Pattern**: Daily rotation with date suffix

## Usage

### In Server Code

```typescript
import logger from './config/logger.js';

// Basic logging
logger.info('Server started');
logger.error('Connection failed');
logger.warn('High memory usage');
logger.debug('Request details', { userId: 123 });

// With metadata
logger.info('Terminal created', {
  terminalId: 'abc123',
  socketId: 'xyz789',
  shell: '/bin/bash',
});
```

### HTTP Request Logging

HTTP requests are automatically logged via `express-winston`:

```
02:15:45 [info]: GET /health 200 2ms
```

Health check endpoint (`/health`) is excluded from logs to reduce noise.

## Environment Variables

### `LOG_LEVEL`

Set the minimum log level (default: `debug` in dev, `info` in prod)

```bash
LOG_LEVEL=warn npm run dev
```

### `LOG_TO_FILE`

Force file logging in development

```bash
LOG_TO_FILE=true npm run dev
```

### `NODE_ENV`

Determines logging behavior

- `development`: Console only, pretty format, debug level
- `production`: Files + console, JSON format, info level
- `test`: Logs suppressed

## Log Format

### Development Console

```
02:15:45 [info]: Client connected {
  "socketId": "q7XPQzCgU0vGHdWDAAAB"
}
```

### Production JSON

```json
{
  "timestamp": "2025-10-19 02:15:45",
  "level": "info",
  "message": "Client connected",
  "socketId": "q7XPQzCgU0vGHdWDAAAB"
}
```

## Log Analysis

### View Logs

```bash
# All logs
tail -f logs/combined-*.log

# Errors only
tail -f logs/error-*.log

# Pretty print JSON
tail -f logs/combined-*.log | jq
```

### Search Logs

```bash
# Find specific socket
grep "socketId.*xyz789" logs/combined-*.log

# Find errors
jq 'select(.level == "error")' logs/combined-*.log
```

## Integration with Monitoring

The JSON format makes it easy to integrate with monitoring tools:

- **Elasticsearch**: Ingest JSON logs with Filebeat/Logstash
- **Splunk**: Forward logs with universal forwarder
- **Datadog**: Use Datadog agent to collect logs
- **CloudWatch**: Use CloudWatch agent

## Best Practices

1. **Use appropriate log levels**
   - `error`: Failures that require attention
   - `warn`: Potential issues
   - `info`: Important state changes
   - `debug`: Detailed diagnostic info

2. **Include metadata**

   ```typescript
   // Good
   logger.info('Terminal created', { terminalId, userId });

   // Less useful
   logger.info(`Terminal ${terminalId} created`);
   ```

3. **Don't log sensitive data**
   - Avoid logging passwords, tokens, or PII
   - Sanitize user input before logging

4. **Use structured logging**
   - Pass objects as metadata instead of string concatenation
   - Makes logs searchable and parseable

## Troubleshooting

### Logs not appearing

- Check `NODE_ENV` setting
- Verify log directory permissions
- Check `LOG_LEVEL` setting

### Too many logs

- Increase `LOG_LEVEL` to `warn` or `error`
- Adjust `ignoreRoute` in HTTP logger middleware

### Disk space issues

- Reduce `maxFiles` in `winston-daily-rotate-file` config
- Reduce `maxSize` per file
- Implement log archival/deletion strategy
