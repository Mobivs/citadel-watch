#!/usr/bin/env node

/**
 * Remote Shield Agent - Main Entry Point
 * VPS threat detection and reporting system
 *
 * Usage:
 *   node index.js init <backend-url> <hostname>  - Initialize agent
 *   node index.js scan                              - Run threat detection scan
 *   node index.js daemon                            - Run as background service
 *   node index.js status                            - Check agent status
 */

const path = require('path');
const fs = require('fs-extra');
const chalk = require('chalk');

const Logger = require('./lib/logger');
const Storage = require('./lib/storage');
const BackendClient = require('./lib/backend');
const Detector = require('./lib/detector');

// Setup
const storageDir = process.env.AGENT_HOME || './data';
const logger = new Logger({
  logDir: path.join(storageDir, 'logs'),
  console: true,
  file: true,
  logLevel: process.env.LOG_LEVEL || 'info',
});

const storage = new Storage({ storageDir });

// Main agent class
class RemoteShieldAgent {
  constructor() {
    this.backend = null;
    this.detector = null;
    this.scanInterval = 300000; // 5 minutes
    this.heartbeatInterval = 60000; // 1 minute
    this.scanTimer = null;
    this.heartbeatTimer = null;
  }

  /**
   * Initialize agent (register with backend)
   */
  async init(backendUrl, hostname) {
    console.log(chalk.blue('\n🛡️  Remote Shield Agent - Initialization\n'));

    try {
      const config = {
        backend_url: backendUrl,
        hostname,
        scan_interval_seconds: 300,
        heartbeat_interval_seconds: 60,
        modules: {
          port_scanner: true,
          process_monitor: true,
          file_integrity: true,
          log_analyzer: true,
          cve_scanner: true,
        },
        min_severity: 5,
      };

      storage.saveConfig(config);

      this.backend = new BackendClient({
        backendUrl,
        hostname: hostname,
        storage: { storageDir },
        logger: { console: true, file: false },
      });

      // Get local IP
      const os = require('os');
      const ip = Object.values(os.networkInterfaces())
        .flat()
        .find(iface => iface.family === 'IPv4' && !iface.internal)?.address || '127.0.0.1';

      // Register with backend
      const { agentId, apiToken } = await this.backend.registerAgent(hostname, ip);

      console.log(chalk.green('✓ Agent registered successfully!\n'));
      console.log(chalk.cyan('Agent ID:'), agentId);
      console.log(chalk.cyan('Backend URL:'), backendUrl);
      console.log(chalk.cyan('Hostname:'), hostname);
      console.log(chalk.cyan('IP Address:'), ip);

      // Initialize file baseline
      console.log(chalk.yellow('\nInitializing file integrity baseline...'));
      this.detector = new Detector({
        config,
        hostname,
        storage: { storageDir },
        logger: { console: false, file: true },
      });
      await this.detector.initializeBaseline();
      console.log(chalk.green('✓ Baseline initialized\n'));

      console.log(chalk.green('Ready to run scans!'));
      console.log(chalk.gray('Run "node index.js daemon" to start monitoring\n'));

    } catch (error) {
      console.error(chalk.red('✗ Initialization failed:'), error.message);
      process.exit(1);
    }
  }

  /**
   * Run single threat detection scan
   */
  async runScan() {
    try {
      const config = storage.loadConfig();
      const creds = storage.loadCredentials();

      if (!config || !creds) {
        console.error(chalk.red('✗ Agent not initialized. Run "init" first.'));
        process.exit(1);
      }

      this.backend = new BackendClient({
        backendUrl: config.backend_url,
        agentId: creds.agentId,
        apiToken: creds.apiToken,
        storage: { storageDir },
        logger: { console: true, file: true },
      });

      this.detector = new Detector({
        config: config.modules,
        hostname: config.hostname,
        storage: { storageDir },
        logger: { console: true, file: true },
      });

      console.log(chalk.blue('\n🛡️  Remote Shield Agent - Single Scan\n'));
      console.log(chalk.gray(`Hostname: ${config.hostname}`));
      console.log(chalk.gray(`Timestamp: ${new Date().toISOString()}\n`));

      // Run detection
      const threats = await this.detector.scan();

      if (threats.length === 0) {
        console.log(chalk.green('✓ No threats detected\n'));
      } else {
        console.log(chalk.yellow(`\n⚠️  ${threats.length} threat(s) detected:\n`));
        for (const threat of threats) {
          const severityColor = threat.severity >= 8 ? chalk.red : chalk.yellow;
          console.log(`  ${severityColor(`[S${threat.severity}]`)} ${threat.title}`);
          if (threat.details) {
            console.log(chalk.gray(`      ${JSON.stringify(threat.details).substring(0, 100)}...`));
          }
        }

        // Submit threats
        console.log(chalk.gray(`\nSubmitting ${threats.length} threat(s) to backend...`));
        for (const threat of threats) {
          await this.backend.submitThreat(threat);
        }
        console.log(chalk.green('✓ Threats submitted\n'));
      }

      // Show queue status
      const queueSize = storage.getQueueSize();
      if (queueSize > 0) {
        console.log(chalk.yellow(`⚠️  ${queueSize} threat(s) in offline queue\n`));
      }

    } catch (error) {
      console.error(chalk.red('✗ Scan failed:'), error.message);
      process.exit(1);
    }
  }

  /**
   * Run as background daemon
   */
  async runDaemon() {
    try {
      const config = storage.loadConfig();
      const creds = storage.loadCredentials();

      if (!config || !creds) {
        console.error(chalk.red('✗ Agent not initialized. Run "init" first.'));
        process.exit(1);
      }

      this.backend = new BackendClient({
        backendUrl: config.backend_url,
        agentId: creds.agentId,
        apiToken: creds.apiToken,
        storage: { storageDir },
        logger: { console: false, file: true },
      });

      this.detector = new Detector({
        config: config.modules,
        hostname: config.hostname,
        storage: { storageDir },
        logger: { console: false, file: true },
      });

      logger.info('Remote Shield Agent starting in daemon mode');
      console.log(chalk.blue('\n🛡️  Remote Shield Agent - Daemon Mode\n'));
      console.log(chalk.green('Agent running. Monitor logs in ./data/logs/\n'));

      this.scanInterval = (config.scan_interval_seconds || 300) * 1000;
      this.heartbeatInterval = (config.heartbeat_interval_seconds || 60) * 1000;

      // Start heartbeat loop
      this.startHeartbeat();

      // Start scan loop
      this.startScans();

      // Handle signals
      process.on('SIGTERM', () => this.shutdown());
      process.on('SIGINT', () => this.shutdown());

    } catch (error) {
      logger.error('Failed to start daemon', { error: error.message });
      process.exit(1);
    }
  }

  /**
   * Show agent status
   */
  showStatus() {
    try {
      const config = storage.loadConfig();
      const creds = storage.loadCredentials();

      if (!config) {
        console.log(chalk.yellow('⚠️  Agent not initialized\n'));
        return;
      }

      console.log(chalk.blue('\n🛡️  Remote Shield Agent - Status\n'));
      console.log(chalk.cyan('Configuration:'));
      console.log(`  Backend URL:  ${config.backend_url}`);
      console.log(`  Hostname:     ${config.hostname}`);
      console.log(`  Agent ID:     ${creds?.agentId || 'NOT SET'}`);
      console.log(`  Scan Interval: ${config.scan_interval_seconds}s`);
      console.log(`  Heartbeat:    ${config.heartbeat_interval_seconds}s\n`);

      console.log(chalk.cyan('Modules:'));
      for (const [name, enabled] of Object.entries(config.modules || {})) {
        const status = enabled ? chalk.green('✓') : chalk.red('✗');
        console.log(`  ${status} ${name}`);
      }

      const queueSize = storage.getQueueSize();
      console.log(chalk.cyan(`\nOffline Queue: ${queueSize} threat(s)\n`));

    } catch (error) {
      console.error(chalk.red('Error reading status:'), error.message);
    }
  }

  // Private methods

  startScans() {
    // Run first scan immediately
    this.performScan();

    // Schedule periodic scans
    this.scanTimer = setInterval(() => this.performScan(), this.scanInterval);
  }

  async performScan() {
    try {
      const threats = await this.detector.scan();

      // Submit detected threats
      for (const threat of threats) {
        await this.backend.submitThreat(threat);
      }

      // Try to sync queued threats
      await this.backend.syncQueue();

    } catch (error) {
      logger.error('Scan error', { error: error.message });
    }
  }

  startHeartbeat() {
    // Send first heartbeat immediately
    this.sendHeartbeat();

    // Schedule periodic heartbeats
    this.heartbeatTimer = setInterval(() => this.sendHeartbeat(), this.heartbeatInterval);
  }

  async sendHeartbeat() {
    const success = await this.backend.sendHeartbeat();
    if (!success) {
      logger.warn('Heartbeat failed - backend may be unreachable');
    }
  }

  shutdown() {
    logger.info('Shutting down agent');
    clearInterval(this.scanTimer);
    clearInterval(this.heartbeatTimer);
    process.exit(0);
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  const agent = new RemoteShieldAgent();

  switch (command) {
    case 'init':
      if (args.length < 3) {
        console.error(chalk.red('Usage: node index.js init <backend-url> <hostname>'));
        process.exit(1);
      }
      await agent.init(args[1], args[2]);
      break;

    case 'scan':
      await agent.runScan();
      break;

    case 'daemon':
      await agent.runDaemon();
      break;

    case 'status':
      agent.showStatus();
      break;

    default:
      console.log(chalk.blue('\n🛡️  Remote Shield Agent\n'));
      console.log('Commands:');
      console.log('  init <url> <hostname>  - Initialize agent');
      console.log('  scan                    - Run threat detection scan');
      console.log('  daemon                  - Run as background service');
      console.log('  status                  - Show agent status\n');
      break;
  }
}

main().catch(error => {
  console.error(chalk.red('Fatal error:'), error.message);
  process.exit(1);
});
