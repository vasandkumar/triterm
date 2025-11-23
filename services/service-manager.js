#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import readline from 'readline';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class ServiceManager {
  constructor() {
    this.platform = os.platform();
    this.homeDir = os.homedir();
    this.installDir = process.cwd();
    this.serviceName = 'triterm';

    // Default configuration
    this.config = {
      port: 3000,
      user: process.env.USER || process.env.USERNAME,
      group: process.env.USER || process.env.USERNAME,
      nodeExecutable: process.execPath,
      dataDir: path.join(this.homeDir, '.triterm'),
      logDir: path.join(this.homeDir, '.triterm', 'logs'),
      databaseUrl: `file:${path.join(this.homeDir, '.triterm', 'triterm.db')}`,
    };
  }

  async install() {
    console.log('🚀 Installing TriTerm as a system service...\n');

    // Create necessary directories
    this.createDirectories();

    // Install based on platform
    switch (this.platform) {
      case 'linux':
        await this.installLinuxService();
        break;
      case 'darwin':
        await this.installMacOSService();
        break;
      case 'win32':
        await this.installWindowsService();
        break;
      default:
        throw new Error(`Unsupported platform: ${this.platform}`);
    }
  }

  async uninstall() {
    console.log('🗑️  Uninstalling TriTerm service...\n');

    switch (this.platform) {
      case 'linux':
        await this.uninstallLinuxService();
        break;
      case 'darwin':
        await this.uninstallMacOSService();
        break;
      case 'win32':
        await this.uninstallWindowsService();
        break;
      default:
        throw new Error(`Unsupported platform: ${this.platform}`);
    }
  }

  async start() {
    console.log('▶️  Starting TriTerm service...\n');

    switch (this.platform) {
      case 'linux':
        this.runCommand('sudo systemctl start triterm');
        console.log('✅ Service started successfully');
        break;
      case 'darwin':
        this.runCommand('launchctl load ~/Library/LaunchAgents/com.triterm.server.plist');
        console.log('✅ Service started successfully');
        break;
      case 'win32':
        this.runCommand('net start "TriTerm Server"');
        console.log('✅ Service started successfully');
        break;
    }
  }

  async stop() {
    console.log('⏹️  Stopping TriTerm service...\n');

    switch (this.platform) {
      case 'linux':
        this.runCommand('sudo systemctl stop triterm');
        console.log('✅ Service stopped successfully');
        break;
      case 'darwin':
        this.runCommand('launchctl unload ~/Library/LaunchAgents/com.triterm.server.plist');
        console.log('✅ Service stopped successfully');
        break;
      case 'win32':
        this.runCommand('net stop "TriTerm Server"');
        console.log('✅ Service stopped successfully');
        break;
    }
  }

  async status() {
    console.log('📊 Checking TriTerm service status...\n');

    try {
      switch (this.platform) {
        case 'linux': {
          const linuxStatus = this.runCommand('systemctl is-active triterm', true);
          console.log(`Service status: ${linuxStatus.trim()}`);
          if (linuxStatus.trim() === 'active') {
            const details = this.runCommand('systemctl status triterm --no-pager', true);
            console.log('\nService details:\n', details);
          }
          break;
        }
        case 'darwin': {
          const macStatus = this.runCommand('launchctl list | grep com.triterm.server', true);
          if (macStatus) {
            console.log('Service is running');
            console.log('Details:', macStatus);
          } else {
            console.log('Service is not running');
          }
          break;
        }
        case 'win32': {
          const winStatus = this.runCommand('sc query "TriTerm Server"', true);
          console.log(winStatus);
          break;
        }
      }
    } catch (error) {
      console.log('Service is not installed or not running');
    }
  }

  createDirectories() {
    const dirs = [this.config.dataDir, this.config.logDir];

    dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`✅ Created directory: ${dir}`);
      }
    });
  }

  async installLinuxService() {
    console.log('Installing systemd service for Linux...\n');

    // Check if systemd is available
    try {
      this.runCommand('which systemctl', true);
    } catch {
      throw new Error('systemd is not available on this system');
    }

    // Build the server first
    console.log('Building server...');
    try {
      this.runCommand('npm run build:server');
    } catch (error) {
      // If build fails, we'll use tsx to run TypeScript directly
      console.log('Note: Server will run with tsx for TypeScript support');
    }

    // Read the service template
    const templatePath = path.join(__dirname, 'templates', 'triterm.service');
    let serviceContent = fs.readFileSync(templatePath, 'utf8');

    // Replace placeholders - use tsx to run TypeScript directly
    serviceContent = this.replacePlaceholders(serviceContent);

    // Update the ExecStart to use tsx for TypeScript
    const serverScript = path.join(this.installDir, 'server', 'index.ts');
    const tsxPath = path.join(this.installDir, 'node_modules', '.bin', 'tsx');

    if (fs.existsSync(serverScript)) {
      serviceContent = serviceContent.replace(
        /ExecStart=.*$/m,
        `ExecStart=${tsxPath} ${serverScript}`
      );
    }

    // Write service file
    const servicePath = `/tmp/triterm.service`;
    fs.writeFileSync(servicePath, serviceContent);

    // Install service
    try {
      this.runCommand(`sudo cp ${servicePath} /etc/systemd/system/triterm.service`);
      this.runCommand('sudo systemctl daemon-reload');
      this.runCommand('sudo systemctl enable triterm');

      console.log('✅ Service installed successfully!');
      console.log('\nTo start the service, run:');
      console.log('  npx triterm service start');
      console.log('\nTo check status:');
      console.log('  npx triterm service status');
    } catch (error) {
      throw new Error(`Failed to install service: ${error.message}`);
    }
  }

  async installMacOSService() {
    console.log('Installing launchd service for macOS...\n');

    // Build the server first
    console.log('Building server...');
    try {
      this.runCommand('npm run build:server');
    } catch (error) {
      // If build fails, we'll use tsx to run TypeScript directly
      console.log('Note: Server will run with tsx for TypeScript support');
    }

    // Read the plist template
    const templatePath = path.join(__dirname, 'templates', 'com.triterm.server.plist');
    let plistContent = fs.readFileSync(templatePath, 'utf8');

    // Replace placeholders
    plistContent = this.replacePlaceholders(plistContent);

    // Update to use tsx for TypeScript if needed
    const serverScript = path.join(this.installDir, 'server', 'index.ts');
    const tsxPath = path.join(this.installDir, 'node_modules', '.bin', 'tsx');

    if (fs.existsSync(serverScript)) {
      // Update the ProgramArguments to use tsx
      plistContent = plistContent.replace(
        /<string>{{NODE_PATH}}<\/string>\s*<string>{{INSTALL_DIR}}\/server\/index.js<\/string>/,
        `<string>${tsxPath}</string>\n        <string>${serverScript}</string>`
      );
    }

    // Write plist file
    const plistDir = path.join(this.homeDir, 'Library', 'LaunchAgents');
    if (!fs.existsSync(plistDir)) {
      fs.mkdirSync(plistDir, { recursive: true });
    }

    const plistPath = path.join(plistDir, 'com.triterm.server.plist');
    fs.writeFileSync(plistPath, plistContent);

    // Load the service
    try {
      this.runCommand(`launchctl load ${plistPath}`);

      console.log('✅ Service installed successfully!');
      console.log('\nThe service will start automatically.');
      console.log('\nTo check status:');
      console.log('  npx triterm service status');
    } catch (error) {
      // Service might already be loaded
      console.log('Service might already be loaded. Trying to reload...');
      try {
        this.runCommand(`launchctl unload ${plistPath}`);
        this.runCommand(`launchctl load ${plistPath}`);
        console.log('✅ Service reloaded successfully!');
      } catch (err) {
        throw new Error(`Failed to install service: ${err.message}`);
      }
    }
  }

  async installWindowsService() {
    console.log('Installing Windows service...\n');

    // Check if running as administrator
    try {
      this.runCommand('net session', true);
    } catch {
      throw new Error('Please run this command as Administrator');
    }

    // Build the server first
    console.log('Building server...');
    try {
      this.runCommand('npm run build:server');
    } catch (error) {
      // If build fails, we'll use tsx to run TypeScript directly
      console.log('Note: Server will run with tsx for TypeScript support');
    }

    // Install node-windows if not present
    console.log('Installing node-windows...');
    this.runCommand('npm install --save-dev node-windows');

    // Determine server script path (TypeScript or JavaScript)
    const serverTsPath = path.join(this.installDir, 'server', 'index.ts');
    const serverJsPath = path.join(this.installDir, 'server', 'dist', 'index.js');
    const tsxPath = path.join(this.installDir, 'node_modules', '.bin', 'tsx.cmd');

    let scriptPath = serverJsPath; // Default to built version
    let execPath = process.execPath;

    if (!fs.existsSync(serverJsPath) && fs.existsSync(serverTsPath)) {
      // Use tsx if TypeScript file exists but no build
      scriptPath = serverTsPath;
      execPath = tsxPath;
    }

    // Create service installer script
    const serviceScript = `
const Service = require('node-windows').Service;
const path = require('path');

const svc = new Service({
  name: 'TriTerm Server',
  description: 'TriTerm Multi-Terminal Server Service',
  script: '${scriptPath.replace(/\\/g, '\\\\')}',
  execPath: '${execPath.replace(/\\/g, '\\\\')}',
  env: [
    {
      name: 'NODE_ENV',
      value: 'production'
    },
    {
      name: 'PORT',
      value: '${this.config.port}'
    },
    {
      name: 'DATABASE_URL',
      value: '${this.config.databaseUrl.replace(/\\/g, '\\\\')}'
    }
  ],
  workingDirectory: '${this.installDir.replace(/\\/g, '\\\\')}',
  logpath: '${this.config.logDir.replace(/\\/g, '\\\\')}',
  nodeOptions: [
    '--max-old-space-size=4096'
  ]
});

svc.on('install', function() {
  console.log('✅ Service installed successfully!');
  svc.start();
});

svc.on('alreadyinstalled', function() {
  console.log('Service is already installed.');
});

svc.on('start', function() {
  console.log('✅ Service started successfully!');
});

svc.install();
`;

    const installerPath = path.join(this.installDir, 'install-windows-service.js');
    fs.writeFileSync(installerPath, serviceScript);

    // Run the installer
    try {
      this.runCommand(`node ${installerPath}`);

      // Clean up installer script
      fs.unlinkSync(installerPath);

      console.log('\nTo check status:');
      console.log('  npx triterm service status');
    } catch (error) {
      throw new Error(`Failed to install service: ${error.message}`);
    }
  }

  async uninstallLinuxService() {
    try {
      this.runCommand('sudo systemctl stop triterm');
      this.runCommand('sudo systemctl disable triterm');
      this.runCommand('sudo rm /etc/systemd/system/triterm.service');
      this.runCommand('sudo systemctl daemon-reload');

      console.log('✅ Service uninstalled successfully!');
    } catch (error) {
      console.log('Service might not be installed or already removed.');
    }
  }

  async uninstallMacOSService() {
    try {
      const plistPath = path.join(
        this.homeDir,
        'Library',
        'LaunchAgents',
        'com.triterm.server.plist'
      );

      this.runCommand(`launchctl unload ${plistPath}`);
      fs.unlinkSync(plistPath);

      console.log('✅ Service uninstalled successfully!');
    } catch (error) {
      console.log('Service might not be installed or already removed.');
    }
  }

  async uninstallWindowsService() {
    // Create service uninstaller script
    const uninstallerScript = `
const Service = require('node-windows').Service;
const path = require('path');

const svc = new Service({
  name: 'TriTerm Server',
  script: path.join('${this.installDir.replace(/\\/g, '\\\\')}', 'server', 'dist', 'index.js')
});

svc.on('uninstall', function() {
  console.log('✅ Service uninstalled successfully!');
});

svc.uninstall();
`;

    const uninstallerPath = path.join(this.installDir, 'uninstall-windows-service.js');
    fs.writeFileSync(uninstallerPath, uninstallerScript);

    try {
      this.runCommand(`node ${uninstallerPath}`);

      // Clean up uninstaller script
      fs.unlinkSync(uninstallerPath);
    } catch (error) {
      console.log('Service might not be installed or already removed.');
    }
  }

  replacePlaceholders(content) {
    return content
      .replace(/{{USER}}/g, this.config.user)
      .replace(/{{GROUP}}/g, this.config.group)
      .replace(/{{INSTALL_DIR}}/g, this.installDir)
      .replace(/{{NODE_PATH}}/g, this.config.nodeExecutable)
      .replace(/{{PORT}}/g, this.config.port)
      .replace(/{{DATABASE_URL}}/g, this.config.databaseUrl)
      .replace(/{{DATA_DIR}}/g, this.config.dataDir)
      .replace(/{{LOG_DIR}}/g, this.config.logDir);
  }

  runCommand(command, returnOutput = false) {
    try {
      const result = execSync(command, {
        encoding: 'utf8',
        stdio: returnOutput ? 'pipe' : 'inherit',
      });
      return returnOutput ? result : null;
    } catch (error) {
      if (returnOutput) {
        throw error;
      }
      throw new Error(`Command failed: ${command}\n${error.message}`);
    }
  }

  async promptConfig() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const question = (query) =>
      new Promise((resolve) => {
        rl.question(query, resolve);
      });

    console.log('📝 Service Configuration\n');

    const port = await question(`Port (default: ${this.config.port}): `);
    if (port) this.config.port = parseInt(port);

    if (this.platform !== 'win32') {
      const user = await question(`User (default: ${this.config.user}): `);
      if (user) this.config.user = user;
    }

    const dataDir = await question(`Data directory (default: ${this.config.dataDir}): `);
    if (dataDir) {
      this.config.dataDir = dataDir;
      this.config.logDir = path.join(dataDir, 'logs');
      this.config.databaseUrl = `file:${path.join(dataDir, 'triterm.db')}`;
    }

    rl.close();
    console.log('\n');
  }
}

export default ServiceManager;
