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

- ✅ **User registration and login** with JWT tokens
- ✅ **OAuth support** (GitHub, Google, GitLab ready)
- ✅ **Role-based access control** (Admin, User roles)
- ✅ **Password hashing** with bcrypt
- ✅ **Session management** with database persistence
- ✅ **Audit logging** for all authentication events
- ✅ **CORS and rate limiting** protection

### Admin Dashboard

- ✅ **System overview** with real-time statistics
- ✅ **User management** (create, update, delete, role assignment)
- ✅ **Session monitoring** - Track active terminal sessions
- ✅ **Audit log viewer** - Security event tracking
- ✅ **System metrics** - CPU, memory, uptime monitoring

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

# Security (Optional - for restricted access)
REQUIRE_AUTH=false
AUTH_TOKEN=  # Set this to enable token-based API access

# Limits
MAX_TERMINALS=10
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# OAuth (Optional)
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Frontend URL (for OAuth callbacks)
CLIENT_URL=http://localhost:5173
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

## 🔒 Security Best Practices

### For Production Deployment

1. **Change JWT_SECRET** - Use a strong random string

   ```bash
   # Generate a secure secret
   openssl rand -base64 64
   ```

2. **Use HTTPS** - Always use SSL/TLS in production

3. **Set strong passwords** - Enforce password complexity

4. **Configure CORS** - Limit allowed origins

   ```env
   ALLOWED_ORIGINS=https://yourdomain.com
   ```

5. **Enable rate limiting** - Prevent abuse

   ```env
   RATE_LIMIT_MAX=50
   RATE_LIMIT_WINDOW=60000
   ```

6. **Use PostgreSQL** - SQLite is for development only

7. **Regular backups** - Use provided backup scripts

   ```bash
   ./scripts/backup.sh
   ```

8. **Keep dependencies updated**
   ```bash
   npm audit fix
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
