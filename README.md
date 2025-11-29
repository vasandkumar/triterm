# TriTerm

> **Modern, secure web-based terminal manager with multi-user support**

A powerful enterprise-level terminal application that runs in your browser. Manage multiple terminal sessions, collaborate with team members, and monitor system activities—all from a beautiful, responsive web interface.

![License](https://img.shields.io/badge/license-MIT-green)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

## 🎯 What is TriTerm?

TriTerm brings the power of your terminal to the browser with enterprise features like user authentication, role-based access control, audit logging, and real-time collaboration. Perfect for:

- **Remote server management** - Access your servers from anywhere
- **Team collaboration** - Multiple users can manage terminals
- **System monitoring** - Admin dashboard with real-time stats
- **Secure access** - Authentication, RBAC, and audit trails
- **Development teams** - Share terminal sessions safely

## ✨ Features

### Core Terminal Features

- ✅ **Multiple concurrent terminals** (up to 10 per user)
- ✅ **Side-by-side layouts** with automatic arrangement
- ✅ **Resizable terminal panes** with drag handles
- ✅ **Full terminal emulation** powered by xterm.js
- ✅ **Command history** with local storage
- ✅ **Copy/paste support** with keyboard shortcuts

### Authentication & Security

#### Core Authentication

- ✅ **JWT-based authentication** with httpOnly cookies (XSS protection)
- ✅ **OAuth 2.0 support** (GitHub, Google, GitLab)
- ✅ **Role-based access control** (Admin, User, Viewer roles)
- ✅ **Password hashing** with bcrypt (12 rounds)
- ✅ **User approval system** (admin-controlled registration)
- ✅ **Session management** with database persistence

#### Security Hardening

- ✅ **Enhanced security headers** (CSP, HSTS, X-Frame-Options, Permissions-Policy)
- ✅ **Request size limits** (DoS protection)
- ✅ **Password complexity enforcement** (12+ chars, uppercase, lowercase, numbers, special characters)
- ✅ **Common password blocking** (weak password prevention)
- ✅ **Account lockout** (5 failed attempts = 15 min lockout)
- ✅ **JWT token revocation** (immediate logout support)
- ✅ **Session timeout enforcement** (15min access token, 7 day refresh, 30 day absolute)
- ✅ **CSRF protection** (double-submit cookie pattern)
- ✅ **Rate limiting** (endpoint-specific throttling)
- ✅ **User enumeration prevention** (generic error messages)
- ✅ **Audit logging** (comprehensive security event tracking)

### Admin Dashboard

- ✅ **System overview** with real-time statistics
- ✅ **User management** (create users directly, update roles, activate/deactivate, delete)
- ✅ **User approval system** - Approve or reject pending registrations
- ✅ **Session monitoring** - Track active terminal sessions
- ✅ **Audit log viewer** - Security event tracking
- ✅ **System metrics** - CPU, memory, uptime monitoring
- ✅ **System settings** - Toggle public signup on/off

### Developer Experience

- ✅ **TypeScript** - Full type safety
- ✅ **Hot reload** in development
- ✅ **Docker support** - One-command deployment
- ✅ **CI/CD pipelines** - GitHub Actions ready
- ✅ **Automated testing** - Unit, integration, and E2E tests
- ✅ **Code formatting** - ESLint + Prettier configured

### Production Ready

- ✅ **Monitoring stack** - Prometheus + Grafana
- ✅ **Health checks** - Automated system monitoring
- ✅ **Backup scripts** - Database backup/restore
- ✅ **Load balancing** ready
- ✅ **SSL/TLS** support via reverse proxy
- ✅ **Environment-based config** for different deployments

## 🖥️ Platform Support

| Operating System  | Terminal        | Status             | Notes                             |
| ----------------- | --------------- | ------------------ | --------------------------------- |
| **Linux**         | bash, zsh, sh   | ✅ Fully Supported | Recommended platform              |
| **macOS**         | bash, zsh       | ✅ Fully Supported | All features working              |
| **Windows 10/11** | PowerShell, WSL | ⚠️ Partial Support | PowerShell works, WSL recommended |
| **Docker**        | Any             | ✅ Fully Supported | Best for production               |

## 📋 Requirements

| Component    | Minimum Version | Recommended           | Notes                               |
| ------------ | --------------- | --------------------- | ----------------------------------- |
| **Node.js**  | 18.x            | 20.x LTS              | Required for server                 |
| **npm**      | 8.x             | 10.x                  | Package manager                     |
| **Database** | SQLite          | PostgreSQL            | SQLite for dev, PostgreSQL for prod |
| **Browser**  | Chrome 90+      | Latest Chrome/Firefox | Safari 14+ also supported           |
| **RAM**      | 512MB           | 2GB+                  | For running multiple terminals      |

### Browser Support

| Browser        | Version           | Status          | Notes                   |
| -------------- | ----------------- | --------------- | ----------------------- |
| Chrome/Edge    | Latest 2 versions | ✅ Full Support | Recommended             |
| Firefox        | Latest 2 versions | ✅ Full Support | All features working    |
| Safari         | 14+               | ✅ Full Support | macOS/iOS               |
| Mobile Safari  | iOS 14+           | ⚠️ Limited      | Touch interactions vary |
| Android Chrome | Latest            | ⚠️ Limited      | Better on tablets       |

## 🚀 Quick Start

### Option 1: Local Development (Recommended)

**For local development or cloned repositories:**

```bash
# 1. Install dependencies first
npm install

# 2. Run interactive setup wizard
npx triterm setup

# 3. Start the server
npx triterm start
```

The setup wizard will:

- Create `.env` configuration file
- Set up the database with Prisma
- Generate Prisma client
- Run database migrations

After setup, the app will be available at:

- **Frontend**: http://localhost:5173 (or next available port)
- **Backend**: http://localhost:3000

**CLI Commands:**

```bash
npx triterm setup              # Interactive setup wizard
npx triterm start              # Start server (development mode)
npx triterm start -p 8080      # Start on custom port
npx triterm start --prod       # Start in production mode
npx triterm start --auth       # Require authentication
npx triterm migrate            # Run database migrations
npx triterm migrate --reset    # Reset database (WARNING: deletes data)
npx triterm build              # Build client for production
npx triterm info               # Display system information

# System Service Management (Run as background service)
npx triterm service install    # Install as system service
npx triterm service uninstall  # Remove system service
npx triterm service start      # Start the service
npx triterm service stop       # Stop the service
npx triterm service restart    # Restart the service
npx triterm service status     # Check service status

npx triterm --help             # Show all commands
```

### Option 2: From Published Package (When Available)

**Once published to npm, you can try without cloning:**

```bash
# This will work when package is published
npx triterm@latest setup
npx triterm@latest start
```

### Option 3: Manual Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/triterm.git
cd triterm

# 2. Install dependencies
npm install

# 3. Set up the database
cd server
npx prisma generate
npx prisma migrate deploy
cd ..

# 4. Start development servers
npm run dev
```

The app will be available at:

- **Frontend**: http://localhost:5173
- **Backend**: http://localhost:3000

### Option 3: Docker (Recommended for Production)

```bash
# Start all services with Docker Compose
docker-compose up -d

# Access the application
# http://localhost:3000
```

### First User Setup

The **first user to register automatically becomes an admin**. After starting the app:

1. Navigate to http://localhost:5173
2. Click "Register" and create your account
3. You'll be automatically logged in with admin privileges
4. Access the admin dashboard via the shield icon in the header

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the `server/` directory:

```bash
# Server Configuration
PORT=3000
NODE_ENV=development
HOST=0.0.0.0

# Database (SQLite for development)
DATABASE_URL="file:./dev.db"

# For production with PostgreSQL:
# DATABASE_URL="postgresql://user:password@localhost:5432/triterm"

# Authentication
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Encryption for OAuth tokens (REQUIRED if using OAuth)
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
ENCRYPTION_KEY=your-64-character-hex-encryption-key

# Security (Optional - for restricted access)
REQUIRE_AUTH=false
AUTH_TOKEN=  # Set this to enable token-based API access

# Limits
MAX_TERMINALS=10
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# OAuth Providers (Optional - Enable social login)
# Supports: GitHub, Google, Microsoft Azure AD
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=

# Frontend URL (for OAuth callbacks)
CLIENT_URL=http://localhost:5173

# Redis (Optional - for horizontal scaling and performance)
# If not configured, falls back to in-memory storage
REDIS_HOST=localhost
REDIS_PORT=6379
# REDIS_PASSWORD=your-redis-password
REDIS_DB=0
# SERVER_ID=server-1  # Unique ID for multi-instance deployments
```

Copy from the example:

```bash
cp server/.env.example server/.env
# Edit server/.env with your values
```

### Database Setup

**Development (SQLite)**:

```bash
cd server
npx prisma generate
npx prisma migrate dev --name init
```

**Production (PostgreSQL)**:

```bash
# Update DATABASE_URL in .env to PostgreSQL connection string
cd server
npx prisma generate
npx prisma migrate deploy
```

### Redis Configuration (Optional)

Redis provides significant performance improvements and enables horizontal scaling across multiple server instances.

**Quick Start**:

```bash
# Using Docker (recommended)
docker run -d -p 6379:6379 --name triterm-redis redis:7-alpine

# Or using package manager
# Ubuntu/Debian
sudo apt install redis-server

# macOS
brew install redis
brew services start redis
```

**Configure in `.env`**:

```bash
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password  # Optional, for secured Redis
REDIS_DB=0
SERVER_ID=server-1  # Required for multi-instance deployments
```

**Benefits**:

- **10x faster session reads** - Cached sessions respond in 1-2ms vs 5-10ms from database
- **Horizontal scaling** - Run multiple TriTerm servers sharing the same session state
- **Cross-server socket tracking** - Users can connect to the same terminal from multiple devices across servers
- **Graceful degradation** - If Redis is unavailable, automatically falls back to in-memory + database mode

**Testing Redis Connection**:

```bash
# Check if Redis is running
redis-cli ping
# Should return: PONG

# View cached sessions
redis-cli KEYS "triterm:*"
```

**Multi-Server Deployment**:

```bash
# Server 1
SERVER_ID=server-1 PORT=3000 npm run start

# Server 2
SERVER_ID=server-2 PORT=3001 npm run start

# Both servers share session state via Redis
# Load balance with nginx/haproxy
```

## 🚦 Running as a System Service

TriTerm can be installed as a system service for production deployment, allowing it to run in the background and start automatically on system boot.

### Supported Platforms

- **Linux** (systemd) - Ubuntu, Debian, RHEL, CentOS, etc.
- **macOS** (launchd) - macOS 10.10+
- **Windows** (Windows Service) - Windows 7+

### Installing the Service

```bash
# Interactive installation
npx triterm service install
```

This will prompt you for:

- Port number (default: 3000)
- User to run as (Linux/macOS)
- Data directory location
- Log directory location

### Service Management Commands

```bash
# Start the service
npx triterm service start

# Stop the service
npx triterm service stop

# Restart the service
npx triterm service restart

# Check service status
npx triterm service status

# Uninstall the service
npx triterm service uninstall
```

### Platform-Specific Notes

#### Linux (systemd)

- Service runs as specified user (default: current user)
- Logs are stored in `~/.triterm/logs/`
- Service file: `/etc/systemd/system/triterm.service`
- Requires sudo privileges for installation

#### macOS (launchd)

- Service runs as current user
- Auto-starts on login
- Plist file: `~/Library/LaunchAgents/com.triterm.server.plist`
- No sudo required for user-level service

#### Windows

- Runs as Windows Service
- Requires Administrator privileges
- Uses node-windows for service management
- Logs in Event Viewer and `~/.triterm/logs/`

### Service Configuration

When installing as a service, TriTerm will:

1. Build the server for production
2. Create necessary directories for data and logs
3. Configure the service to start on boot
4. Set up proper logging and error handling

The service uses the same `.env` configuration as development, but runs in production mode.

## 📖 Usage Guide

### For Regular Users

1. **Create an account** or log in
2. **Create terminals** using the "+" button
3. **Use multiple terminals** side-by-side
4. **Resize terminals** by dragging the separator
5. **Maximize/minimize** terminals as needed
6. **Command history** is saved automatically

### For Administrators

Access the admin dashboard (shield icon) to:

- **Monitor users** - View all registered users
- **Manage roles** - Promote users to admin or demote to regular users
- **Track sessions** - See all active terminal sessions in real-time
- **View audit logs** - Security events and user actions
- **System stats** - Server health, memory usage, active users

## 🏗️ Project Structure

```
triterm/
├── client/              # React frontend
│   ├── src/
│   │   ├── components/  # UI components
│   │   │   ├── Auth/    # Login/Register
│   │   │   ├── ui/      # shadcn/ui components
│   │   │   └── *.tsx    # Terminal components
│   │   ├── contexts/    # React contexts
│   │   ├── hooks/       # Custom React hooks
│   │   ├── lib/         # Utilities & API clients
│   │   ├── pages/       # Admin dashboard pages
│   │   └── App.tsx      # Main application
│   └── package.json
│
├── server/              # Express + Socket.io backend
│   ├── lib/             # Core libraries
│   │   ├── auditLogger.ts
│   │   ├── jwt.ts
│   │   ├── password.ts
│   │   └── terminalSession.ts
│   ├── middleware/      # Express middleware
│   ├── routes/          # API routes
│   │   ├── auth.ts      # Authentication
│   │   ├── admin.ts     # Admin endpoints
│   │   └── terminals.ts # Terminal management
│   ├── prisma/          # Database schema
│   ├── index.ts         # Server entry point
│   └── package.json
│
├── monitoring/          # Prometheus + Grafana
├── scripts/             # Deployment & backup scripts
├── e2e/                 # End-to-end tests
├── docker-compose.yml   # Docker orchestration
└── package.json         # Root package
```

## 🐳 Deployment

### Docker Deployment (Recommended)

```bash
# Production deployment
docker-compose -f docker-compose.prod.yml up -d

# With monitoring
docker-compose -f docker-compose.monitoring.yml up -d
```

### Manual Deployment

```bash
# 1. Build the client
npm run build

# 2. Set up database
cd server
npx prisma migrate deploy

# 3. Start the server
npm start
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Proxy to TriTerm
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # WebSocket support
    location /socket.io/ {
        proxy_pass http://localhost:3000/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 🔒 Security Features & Best Practices

TriTerm implements enterprise-grade security measures aligned with OWASP Top 10 2021 security standards.

### Built-in Security Features

#### 🛡️ Authentication Security

**JWT Token Security**

- ✅ httpOnly cookies (immune to XSS attacks)
- ✅ Secure flag (HTTPS-only in production)
- ✅ SameSite=Strict (CSRF protection)
- ✅ Token revocation system (immediate logout)
- ✅ 15-minute access token expiration
- ✅ 7-day refresh token expiration
- ✅ 30-day absolute session timeout
- ✅ Unique JWT IDs for tracking

**Password Security**

- ✅ Minimum 12 characters required
- ✅ Complexity requirements (uppercase, lowercase, numbers, special chars)
- ✅ Common password blocking
- ✅ Bcrypt hashing (12 rounds)
- ✅ Maximum 128 characters (DoS prevention)
- ✅ No sequential identical characters

**Account Protection**

- ✅ Account lockout: 5 failed attempts = 15 min lockout
- ✅ User approval system (admin-controlled registration)
- ✅ Admin user creation (admins can create users directly)
- ✅ Generic error messages (prevents user enumeration)
- ✅ Comprehensive audit logging

#### 🔐 Application Security

**Security Headers**

```
Content-Security-Policy: Restrictive CSP policy
Strict-Transport-Security: 1 year with preload
X-Frame-Options: DENY (clickjacking protection)
X-Content-Type-Options: nosniff
X-XSS-Protection: enabled
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: Restricts dangerous browser features
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
```

**Request Protection**

- ✅ 1MB request size limit (DoS protection)
- ✅ 100 parameter limit
- ✅ Strict JSON parsing
- ✅ CSRF double-submit cookie pattern

**Rate Limiting**

- ✅ Global: 100 req/min per IP
- ✅ Login: 10 attempts/15min per email
- ✅ Registration: 3 accounts/hour per IP
- ✅ Token refresh: 10 req/min per IP
- ✅ Socket.io: 100 msg/min per socket

#### 📊 Monitoring & Auditing

**Audit Events Tracked**

- User registration & login attempts
- Account lockouts & unlocks
- Password changes
- Token refresh & revocation
- Admin actions (user creation/activation/deactivation)
- Role changes
- Failed authentication attempts

All events include: timestamp, user ID, IP address, user agent, and metadata.

### Production Deployment Checklist

#### Required: Before Going Live

- [ ] **Generate strong JWT_SECRET** (64+ characters)

  ```bash
  openssl rand -base64 64
  ```

- [ ] **Enable HTTPS** with valid SSL/TLS certificate

  ```nginx
  # Nginx with Let's Encrypt recommended
  listen 443 ssl http2;
  ssl_certificate /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;
  ```

- [ ] **Configure CORS** with specific origins

  ```env
  ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
  ```

- [ ] **Use PostgreSQL** (SQLite is development-only)

  ```env
  DATABASE_URL="postgresql://user:password@localhost:5432/triterm"
  ```

- [ ] **Set strong session timeouts**

  ```env
  JWT_EXPIRES_IN=15m
  JWT_REFRESH_EXPIRES_IN=7d
  ABSOLUTE_SESSION_TIMEOUT=30d
  ```

- [ ] **Configure rate limiting**
  ```env
  RATE_LIMIT_MAX=50
  RATE_LIMIT_WINDOW=60000
  ```

#### Recommended: Enhanced Security

- [ ] **Enable OAuth providers** (reduce password reliance)

  ```env
  GITHUB_CLIENT_ID=your_github_client_id
  GITHUB_CLIENT_SECRET=your_github_client_secret
  ```

- [ ] **Set up automated backups**

  ```bash
  # Daily backups with 30-day retention
  0 2 * * * /path/to/triterm/scripts/backup.sh
  ```

- [ ] **Configure monitoring & alerts**

  ```bash
  # Prometheus + Grafana stack included
  docker-compose -f docker-compose.monitoring.yml up -d
  ```

- [ ] **Review audit logs regularly**

  ```bash
  # Admin dashboard → Audit Logs
  # Look for: failed logins, account lockouts, unusual patterns
  ```

- [ ] **Keep dependencies updated**

  ```bash
  npm audit
  npm audit fix
  npm update
  ```

- [ ] **Enable user approval for new signups**
  ```bash
  # Admin dashboard → System Settings → Disable signup
  # Manually approve each new user
  ```

#### Optional: Advanced Hardening

- [ ] **Enable Redis for horizontal scaling**

  ```bash
  # Install Redis
  docker run -d -p 6379:6379 --name triterm-redis redis:7-alpine

  # Configure in .env
  REDIS_HOST=localhost
  REDIS_PORT=6379
  ```

  **Benefits**:

  - ✅ **10x faster reads** (1-2ms vs 5-10ms from database)
  - ✅ **Horizontal scaling** (run multiple server instances)
  - ✅ **Shared session cache** across servers
  - ✅ **Graceful fallback** (works without Redis)

  See [Redis Configuration](#redis-configuration) for details.

- [ ] **Implement IP whitelisting** for admin access
- [ ] **Set up Web Application Firewall (WAF)**
- [ ] **Enable intrusion detection (fail2ban)**
- [ ] **Configure security event notifications**

### Security Environment Variables

```env
# Authentication Security
JWT_SECRET=<64-character-random-string>
JWT_EXPIRES_IN=15m                    # Access token lifetime
JWT_REFRESH_EXPIRES_IN=7d             # Refresh token lifetime
ABSOLUTE_SESSION_TIMEOUT=30d          # Maximum session duration

# CORS & Network Security
ALLOWED_ORIGINS=https://yourdomain.com
CLIENT_URL=https://yourdomain.com
NODE_ENV=production

# Rate Limiting
RATE_LIMIT_MAX=50                     # Global rate limit
RATE_LIMIT_WINDOW=60000               # 1 minute window

# Database
DATABASE_URL=postgresql://...         # Use PostgreSQL in production
```

### OWASP Top 10 2021 Compliance

| Risk                                          | Status       | Implementation                                   |
| --------------------------------------------- | ------------ | ------------------------------------------------ |
| **A01:2021 – Broken Access Control**          | ✅ Mitigated | RBAC, user approval, token revocation            |
| **A02:2021 – Cryptographic Failures**         | ✅ Mitigated | httpOnly cookies, bcrypt, secure tokens          |
| **A03:2021 – Injection**                      | ✅ Mitigated | Parameterized queries (Prisma), input validation |
| **A04:2021 – Insecure Design**                | ✅ Mitigated | Security by design, defense in depth             |
| **A05:2021 – Security Misconfiguration**      | ✅ Mitigated | Secure defaults, security headers                |
| **A06:2021 – Vulnerable Components**          | ⚠️ Monitor   | Regular `npm audit`, dependency updates          |
| **A07:2021 – Identification & Auth Failures** | ✅ Mitigated | Account lockout, strong passwords, MFA-ready     |
| **A08:2021 – Software & Data Integrity**      | ✅ Mitigated | Audit logging, JWT signatures                    |
| **A09:2021 – Security Logging Failures**      | ✅ Mitigated | Comprehensive audit logs, monitoring             |
| **A10:2021 – Server-Side Request Forgery**    | N/A          | No server-side requests to user-controlled URLs  |

### Security Incident Response

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Email security details privately to the maintainers
3. Include: vulnerability description, reproduction steps, potential impact
4. Allow reasonable time for patching before public disclosure

### Security Updates

Security patches are released as needed with changelog entries marked `[SECURITY]`. Update immediately when security releases are published:

```bash
git pull
npm install
npx triterm migrate
npx triterm service restart
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Unit tests only
npm run test:unit

# E2E tests
npm run test:e2e

# Coverage report
npm run test:coverage

# Watch mode
npm run test:watch
```

## 🐛 Troubleshooting

### Common Issues

**Issue**: `npx triterm setup` fails with "Cannot find package 'commander'"
**Solution**:

For local development, you must install dependencies first:

```bash
npm install
npx triterm setup
```

This is only needed for local/cloned repositories. The published npm package would handle this automatically.

**Issue**: Server crashes with "does not provide an export named 'UserRole'"
**Solution**:

The Prisma client needs to be generated:

```bash
cd server
npx prisma generate
cd ..
npx triterm start
```

Or run the setup wizard which does this automatically:

```bash
npx triterm setup
```

**Issue**: Cannot connect to server
**Solution**:

- Ensure server is running on port 3000
- Check firewall settings
- Verify `CLIENT_URL` in server `.env` matches your frontend URL

**Issue**: Terminal not spawning
**Solution**:

- Check shell path for your OS
- Verify node-pty installation: `npm rebuild node-pty`
- Check server logs for errors

**Issue**: Authentication not working
**Solution**:

- Verify JWT_SECRET is set in `.env`
- Check database connection
- Clear browser localStorage and retry

**Issue**: Database errors
**Solution**:

```bash
cd server
npx prisma generate
npx prisma migrate reset  # WARNING: Deletes all data
npx prisma migrate deploy
```

**Issue**: Permission denied errors
**Solution**:

```bash
# Make scripts executable
chmod +x scripts/*.sh
```

## 📊 Monitoring

TriTerm includes a complete monitoring stack:

```bash
# Start with monitoring
docker-compose -f docker-compose.monitoring.yml up -d

# Access Grafana: http://localhost:3001
# Default login: admin/admin

# Access Prometheus: http://localhost:9090
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow existing code style (ESLint + Prettier configured)
- Write tests for new features
- Update documentation as needed
- Use conventional commit messages

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built with these amazing technologies:

- [xterm.js](https://xtermjs.org/) - Terminal emulation
- [Socket.io](https://socket.io/) - Real-time communication
- [Prisma](https://www.prisma.io/) - Database ORM
- [React](https://react.dev/) - UI framework
- [shadcn/ui](https://ui.shadcn.com/) - UI components
- [Node-pty](https://github.com/microsoft/node-pty) - Terminal process management

## 📮 Support

- **Issues**: Open an issue on GitHub
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

---

**Made with ❤️ for the terminal enthusiast community**
