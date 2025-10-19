#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { spawn } from 'child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');
const serverDir = join(rootDir, 'server');

const program = new Command();

// Read package.json for version
const packageJson = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf-8'));

program
  .name('triterm')
  .description('TriTerm - Modern web-based terminal manager')
  .version(packageJson.version);

/**
 * Start command - Start the TriTerm server
 */
program
  .command('start')
  .description('Start the TriTerm server')
  .option('-p, --port <port>', 'Port to run the server on', '3000')
  .option('-H, --host <host>', 'Host to bind to', '0.0.0.0')
  .option('--auth', 'Require authentication', false)
  .option('--prod', 'Run in production mode', false)
  .action(async (options) => {
    console.log(chalk.cyan.bold('\n🚀 Starting TriTerm...\n'));

    // Check if .env exists
    const envPath = join(serverDir, '.env');
    if (!existsSync(envPath)) {
      console.log(chalk.yellow('⚠️  No .env file found. Creating from template...'));
      await createEnvFile(options);
    }

    // Update environment variables based on options
    updateEnvVariables(envPath, {
      PORT: options.port,
      HOST: options.host,
      NODE_ENV: options.prod ? 'production' : 'development',
      REQUIRE_AUTH: options.auth ? 'true' : 'false',
    });

    // Check if database exists, if not run setup
    const dbPath = join(serverDir, 'prisma', 'dev.db');
    if (!existsSync(dbPath)) {
      console.log(chalk.yellow('\n⚠️  Database not found. Running setup first...\n'));
      await runSetup();
    }

    // Start the server
    console.log(chalk.green(`\n✓ Starting server on http://${options.host}:${options.port}\n`));

    const serverProcess = spawn('npm', ['run', options.prod ? 'start' : 'dev:server'], {
      cwd: rootDir,
      stdio: 'inherit',
      shell: true,
    });

    // Start client in development mode
    if (!options.prod) {
      console.log(chalk.green('✓ Starting development client...\n'));
      setTimeout(() => {
        spawn('npm', ['run', 'dev:client'], {
          cwd: rootDir,
          stdio: 'inherit',
          shell: true,
        });
      }, 2000);
    }

    // Handle graceful shutdown
    process.on('SIGINT', () => {
      console.log(chalk.yellow('\n\n👋 Shutting down TriTerm...\n'));
      serverProcess.kill();
      process.exit(0);
    });
  });

/**
 * Setup command - Interactive setup wizard
 */
program
  .command('setup')
  .description('Run the interactive setup wizard')
  .option('--skip-install', 'Skip dependency installation', false)
  .action(async (options) => {
    console.log(chalk.cyan.bold('\n🔧 TriTerm Setup Wizard\n'));

    if (!options.skipInstall) {
      // Install dependencies
      const installSpinner = ora('Installing dependencies...').start();
      await runCommand('npm', ['install'], rootDir);
      installSpinner.succeed('Dependencies installed');
    }

    // Interactive configuration
    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'port',
        message: 'Server port:',
        default: '3000',
      },
      {
        type: 'input',
        name: 'host',
        message: 'Host to bind to:',
        default: '0.0.0.0',
      },
      {
        type: 'confirm',
        name: 'requireAuth',
        message: 'Require authentication?',
        default: false,
      },
      {
        type: 'password',
        name: 'jwtSecret',
        message: 'JWT secret (leave empty to auto-generate):',
        default: '',
      },
      {
        type: 'list',
        name: 'database',
        message: 'Database:',
        choices: ['SQLite (recommended for development)', 'PostgreSQL (production)'],
        default: 'SQLite (recommended for development)',
      },
    ]);

    // Generate JWT secret if not provided
    const jwtSecret = answers.jwtSecret || generateRandomSecret();

    // Create .env file
    const envContent = `# Server Configuration
PORT=${answers.port}
NODE_ENV=development
HOST=${answers.host}

# Database
DATABASE_URL="${answers.database.startsWith('SQLite') ? 'file:./dev.db' : 'postgresql://user:password@localhost:5432/triterm'}"

# Authentication
JWT_SECRET=${jwtSecret}
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Security
REQUIRE_AUTH=${answers.requireAuth ? 'true' : 'false'}
AUTH_TOKEN=

# Limits
MAX_TERMINALS=10
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# Frontend URL
CLIENT_URL=http://localhost:5173
`;

    const envPath = join(serverDir, '.env');
    writeFileSync(envPath, envContent);
    console.log(chalk.green('\n✓ Environment configuration created'));

    // Run database migrations
    const migrateSpinner = ora('Setting up database...').start();
    try {
      await runCommand('npx', ['prisma', 'generate'], serverDir);
      await runCommand('npx', ['prisma', 'migrate', 'deploy'], serverDir);
      migrateSpinner.succeed('Database setup complete');
    } catch (error) {
      migrateSpinner.fail('Database setup failed');
      console.error(chalk.red(error.message));
      process.exit(1);
    }

    console.log(chalk.green.bold('\n✅ Setup complete!\n'));
    console.log(chalk.cyan('Run ' + chalk.bold('npx triterm start') + ' to start the server\n'));
  });

/**
 * Migrate command - Run database migrations
 */
program
  .command('migrate')
  .description('Run database migrations')
  .option('--reset', 'Reset the database (WARNING: deletes all data)', false)
  .action(async (options) => {
    console.log(chalk.cyan.bold('\n📦 Running database migrations...\n'));

    const spinner = ora('Generating Prisma client...').start();

    try {
      await runCommand('npx', ['prisma', 'generate'], serverDir);
      spinner.succeed('Prisma client generated');

      if (options.reset) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: chalk.red.bold('⚠️  This will delete all data. Are you sure?'),
            default: false,
          },
        ]);

        if (!confirm) {
          console.log(chalk.yellow('\nMigration cancelled\n'));
          return;
        }

        spinner.start('Resetting database...');
        await runCommand('npx', ['prisma', 'migrate', 'reset', '--force'], serverDir);
        spinner.succeed('Database reset complete');
      } else {
        spinner.start('Running migrations...');
        await runCommand('npx', ['prisma', 'migrate', 'deploy'], serverDir);
        spinner.succeed('Migrations complete');
      }

      console.log(chalk.green.bold('\n✅ Database is up to date!\n'));
    } catch (error) {
      spinner.fail('Migration failed');
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  });

/**
 * Build command - Build the client for production
 */
program
  .command('build')
  .description('Build the client for production')
  .action(async () => {
    console.log(chalk.cyan.bold('\n🔨 Building client...\n'));

    const spinner = ora('Building client application...').start();

    try {
      await runCommand('npm', ['run', 'build'], rootDir);
      spinner.succeed('Client built successfully');
      console.log(chalk.green.bold('\n✅ Build complete!\n'));
      console.log(
        chalk.cyan(
          'Run ' + chalk.bold('npx triterm start --prod') + ' to start in production mode\n'
        )
      );
    } catch (error) {
      spinner.fail('Build failed');
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  });

/**
 * Info command - Display system information
 */
program
  .command('info')
  .description('Display system and configuration information')
  .action(() => {
    console.log(chalk.cyan.bold('\n📊 TriTerm Information\n'));

    const envPath = join(serverDir, '.env');
    const dbPath = join(serverDir, 'prisma', 'dev.db');

    console.log(chalk.white('Version:       ') + chalk.green(packageJson.version));
    console.log(chalk.white('Node.js:       ') + chalk.green(process.version));
    console.log(chalk.white('Platform:      ') + chalk.green(process.platform));
    console.log(chalk.white('Architecture:  ') + chalk.green(process.arch));
    console.log(chalk.white('Root Directory:') + chalk.gray(rootDir));
    console.log(
      chalk.white('Config File:   ') +
        (existsSync(envPath) ? chalk.green('✓ Found') : chalk.red('✗ Missing'))
    );
    console.log(
      chalk.white('Database:      ') +
        (existsSync(dbPath) ? chalk.green('✓ Found') : chalk.yellow('⚠ Not initialized'))
    );

    if (existsSync(envPath)) {
      const envContent = readFileSync(envPath, 'utf-8');
      const port = envContent.match(/PORT=(\d+)/)?.[1] || 'Not set';
      const host = envContent.match(/HOST=([\d.]+|localhost)/)?.[1] || 'Not set';
      const nodeEnv = envContent.match(/NODE_ENV=(\w+)/)?.[1] || 'Not set';

      console.log(chalk.white('\nConfiguration:'));
      console.log(chalk.white('  Port:        ') + chalk.green(port));
      console.log(chalk.white('  Host:        ') + chalk.green(host));
      console.log(chalk.white('  Environment: ') + chalk.green(nodeEnv));
    }

    console.log('');
  });

// Helper functions

function generateRandomSecret() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: 'pipe',
      shell: true,
    });

    let output = '';
    let errorOutput = '';

    child.stdout?.on('data', (data) => {
      output += data.toString();
    });

    child.stderr?.on('data', (data) => {
      errorOutput += data.toString();
    });

    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(errorOutput || output));
      } else {
        resolve(output);
      }
    });

    child.on('error', (error) => {
      reject(error);
    });
  });
}

async function runSetup() {
  // Run setup without installing dependencies
  const setupProcess = spawn('node', [join(__dirname, 'triterm.js'), 'setup', '--skip-install'], {
    cwd: rootDir,
    stdio: 'inherit',
  });

  return new Promise((resolve, reject) => {
    setupProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error('Setup failed'));
      } else {
        resolve();
      }
    });
  });
}

async function createEnvFile(options) {
  const envContent = `# Server Configuration
PORT=${options.port || 3000}
NODE_ENV=development
HOST=${options.host || '0.0.0.0'}

# Database (SQLite for development)
DATABASE_URL="file:./dev.db"

# Authentication
JWT_SECRET=${generateRandomSecret()}
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Security (Optional - for restricted access)
REQUIRE_AUTH=${options.auth ? 'true' : 'false'}
AUTH_TOKEN=

# Limits
MAX_TERMINALS=10
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# Frontend URL (for OAuth callbacks)
CLIENT_URL=http://localhost:5173
`;

  const envPath = join(serverDir, '.env');
  writeFileSync(envPath, envContent);
  console.log(chalk.green('✓ Created .env file'));
}

function updateEnvVariables(envPath, updates) {
  let envContent = readFileSync(envPath, 'utf-8');

  Object.entries(updates).forEach(([key, value]) => {
    const regex = new RegExp(`^${key}=.*$`, 'm');
    if (regex.test(envContent)) {
      envContent = envContent.replace(regex, `${key}=${value}`);
    } else {
      envContent += `\n${key}=${value}`;
    }
  });

  writeFileSync(envPath, envContent);
}

program.parse();
