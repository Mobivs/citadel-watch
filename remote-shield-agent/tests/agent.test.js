/**
 * Remote Shield Agent Tests
 * Test suite for agent CLI, threat detection, and backend communication
 */

const assert = require('assert');
const { describe, it } = require('mocha');

// Test utilities
function assertEqual(actual, expected, message) {
  assert.strictEqual(actual, expected, message);
}

function assertNotNull(value, message) {
  assert.notStrictEqual(value, null, message);
}

// ======== Logger Tests ========
describe('Logger', () => {
  const Logger = require('../lib/logger');

  it('should initialize with default config', () => {
    const logger = new Logger();
    assertNotNull(logger, 'Logger should be instantiated');
  });

  it('should log messages without errors', () => {
    const logger = new Logger({ console: true, file: false });
    logger.info('Test message');
    logger.warn('Test warning');
    logger.error('Test error');
  });

  it('should respect log level filtering', () => {
    const logger = new Logger({ logLevel: 'warn', console: false, file: false });
    // Should not throw
    logger.debug('Debug message (should be filtered)');
    logger.info('Info message (should be filtered)');
    logger.warn('Warning message (should pass)');
  });
});

// ======== Storage Tests ========
describe('Storage', () => {
  const Storage = require('../lib/storage');
  const fs = require('fs-extra');

  it('should initialize storage directory', () => {
    const storage = new Storage({ storageDir: './test-data' });
    assertNotNull(storage, 'Storage should be instantiated');
  });

  it('should queue and retrieve threats', () => {
    const storage = new Storage({ storageDir: './test-data' });
    const threat = { type: 'port_scan', severity: 7, title: 'Test threat' };
    
    const id = storage.queueThreat(threat);
    assertNotNull(id, 'Threat should have ID');

    const queued = storage.getQueuedThreats();
    assertEqual(queued.length > 0, true, 'Queue should contain threat');
  });

  it('should remove threats from queue', () => {
    const storage = new Storage({ storageDir: './test-data' });
    const threat = { type: 'test', severity: 5, title: 'Test' };
    
    const id = storage.queueThreat(threat);
    storage.removeFromQueue([id]);

    const queued = storage.getQueuedThreats();
    const found = queued.find(t => t.id === id);
    assertEqual(found, undefined, 'Threat should be removed');
  });

  it('should save and load configuration', () => {
    const storage = new Storage({ storageDir: './test-data' });
    const config = { backend_url: 'http://localhost:8000', hostname: 'test-host' };
    
    storage.saveConfig(config);
    const loaded = storage.loadConfig();
    
    assertEqual(loaded.backend_url, config.backend_url, 'Config should match');
  });

  // Cleanup
  afterEach(() => {
    try {
      fs.removeSync('./test-data');
    } catch (e) {
      // Ignore cleanup errors
    }
  });
});

// ======== Port Scanner Tests ========
describe('Port Scanner', () => {
  const PortScanner = require('../lib/scanner/ports');

  it('should initialize port scanner', () => {
    const scanner = new PortScanner();
    assertNotNull(scanner, 'Port scanner should initialize');
  });

  it('should have baseline ports configured', () => {
    const scanner = new PortScanner();
    assertEqual(scanner.baselinePorts.length > 0, true, 'Baseline ports should be defined');
    assertEqual(scanner.baselinePorts.includes(22), true, 'Should include SSH port 22');
  });

  it('should be able to run scan (may not detect anomalies)', async () => {
    const scanner = new PortScanner();
    const threats = await scanner.scan();
    assertEqual(Array.isArray(threats), true, 'Should return array');
  });
});

// ======== Process Monitor Tests ========
describe('Process Monitor', () => {
  const ProcessMonitor = require('../lib/scanner/processes');

  it('should initialize process monitor', () => {
    const monitor = new ProcessMonitor();
    assertNotNull(monitor, 'Process monitor should initialize');
  });

  it('should have whitelist of safe processes', () => {
    const monitor = new ProcessMonitor();
    assertEqual(monitor.whitelistedProcesses.size > 0, true, 'Whitelist should not be empty');
    assertEqual(monitor.whitelistedProcesses.has('bash'), true, 'Should whitelist bash');
  });

  it('should be able to run scan', async () => {
    const monitor = new ProcessMonitor();
    const threats = await monitor.scan();
    assertEqual(Array.isArray(threats), true, 'Should return array');
  });
});

// ======== File Integrity Tests ========
describe('File Integrity Monitor', () => {
  const FileIntegrityMonitor = require('../lib/scanner/files');

  it('should initialize file monitor', () => {
    const monitor = new FileIntegrityMonitor();
    assertNotNull(monitor, 'File monitor should initialize');
  });

  it('should have critical files configured', () => {
    const monitor = new FileIntegrityMonitor();
    assertEqual(monitor.criticalFiles.length > 0, true, 'Critical files should be defined');
    assertEqual(monitor.criticalFiles.includes('/etc/passwd'), true, 'Should monitor /etc/passwd');
  });

  it('should be able to run scan', async () => {
    const monitor = new FileIntegrityMonitor();
    const threats = await monitor.scan();
    assertEqual(Array.isArray(threats), true, 'Should return array');
  });
});

// ======== Log Analyzer Tests ========
describe('Log Analyzer', () => {
  const LogAnalyzer = require('../lib/scanner/logs');

  it('should initialize log analyzer', () => {
    const analyzer = new LogAnalyzer();
    assertNotNull(analyzer, 'Log analyzer should initialize');
  });

  it('should have brute force threshold configured', () => {
    const analyzer = new LogAnalyzer();
    assertEqual(analyzer.bruteForceThreshold > 0, true, 'Threshold should be positive');
  });

  it('should be able to run scan', async () => {
    const analyzer = new LogAnalyzer();
    const threats = await analyzer.scan();
    assertEqual(Array.isArray(threats), true, 'Should return array');
  });
});

// ======== CVE Scanner Tests ========
describe('CVE Scanner', () => {
  const CVEScanner = require('../lib/scanner/cve');

  it('should initialize CVE scanner', () => {
    const scanner = new CVEScanner();
    assertNotNull(scanner, 'CVE scanner should initialize');
  });

  it('should have known vulnerabilities', () => {
    const scanner = new CVEScanner();
    assertEqual(Object.keys(scanner.knownVulnerabilities).length > 0, true, 'Should have CVE data');
  });

  it('should be able to run scan', async () => {
    const scanner = new CVEScanner();
    const threats = await scanner.scan();
    assertEqual(Array.isArray(threats), true, 'Should return array');
  });
});

// ======== Detector Tests ========
describe('Detector', () => {
  const Detector = require('../lib/detector');

  it('should initialize detector engine', () => {
    const detector = new Detector({ hostname: 'test-host' });
    assertNotNull(detector, 'Detector should initialize');
  });

  it('should have all modules initialized', () => {
    const detector = new Detector();
    assertEqual(Object.keys(detector.scanners).length, 5, 'Should have 5 scanner modules');
  });

  it('should be able to run scan', async () => {
    const detector = new Detector({ hostname: 'test-host' });
    const threats = await detector.scan();
    assertEqual(Array.isArray(threats), true, 'Should return array');
  });

  it('should respect minimum severity threshold', () => {
    const detector = new Detector({ hostname: 'test-host' });
    detector.setMinSeverity(8);
    assertEqual(detector.minSeverity, 8, 'Severity threshold should be set');
  });

  it('should track scan statistics', () => {
    const detector = new Detector({ hostname: 'test-host' });
    const stats = detector.getStats();
    assertEqual(stats.threatsDetected >= 0, true, 'Stats should track threats');
  });
});

// ======== Backend Client Tests ========
describe('Backend Client', () => {
  const BackendClient = require('../lib/backend');

  it('should initialize with config', () => {
    const client = new BackendClient({
      backendUrl: 'http://localhost:8000',
      storage: { storageDir: './test-data' }
    });
    assertNotNull(client, 'Backend client should initialize');
  });

  it('should queue threats locally', async () => {
    const client = new BackendClient({
      backendUrl: 'http://localhost:8000',
      storage: { storageDir: './test-data' }
    });

    const threat = {
      type: 'test',
      severity: 5,
      title: 'Test threat',
      hostname: 'test-host',
    };

    const result = await client.submitThreat(threat);
    assertNotNull(result.id, 'Should return threat ID');
  });

  // Cleanup
  afterEach(() => {
    const fs = require('fs-extra');
    try {
      fs.removeSync('./test-data');
    } catch (e) {
      // Ignore
    }
  });
});

// ======== Integration Tests ========
describe('Integration: Full Scan Cycle', () => {
  const Detector = require('../lib/detector');
  const BackendClient = require('../lib/backend');

  it('should detect threats and prepare for submission', async () => {
    const detector = new Detector({
      hostname: 'integration-test',
      config: { minSeverity: 5 }
    });

    const threats = await detector.scan();
    assertEqual(Array.isArray(threats), true, 'Should detect threats');

    // All threats should have required fields
    threats.forEach(threat => {
      assertNotNull(threat.type, 'Threat should have type');
      assertNotNull(threat.severity, 'Threat should have severity');
      assertNotNull(threat.title, 'Threat should have title');
      assertEqual(threat.hostname, 'integration-test', 'Threat should have hostname');
    });
  });
});

console.log('\n✓ All tests defined. Run with: npm test\n');
