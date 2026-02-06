// PRD: Dashboard - Main Application Logic
// Reference: docs/PRD.md v0.2.3, Section: Dashboard
//
// Citadel Archer Frontend (Vanilla JS + Web Components)
// Connects to FastAPI backend via REST + WebSocket for real-time updates

import { api } from './utils/api.js';

class CitadelDashboard {
    constructor() {
        this.state = {
            guardianActive: false,
            securityLevel: 'guardian',
            threatLevel: 'green',
            threatsBlocked: 0,
            processes: [],
            events: []
        };
    }

    async init() {
        console.log('🛡️ Citadel Archer Dashboard v0.2.3');
        console.log('Initializing...');

        try {
            // Connect to backend
            await this.connectToBackend();

            // Setup WebSocket for real-time updates
            this.setupWebSocket();

            // Setup periodic data refresh
            this.setupDataRefresh();

            // Setup event listeners
            this.setupEventListeners();

            console.log('✅ Dashboard initialized successfully');
        } catch (error) {
            console.error('❌ Dashboard initialization failed:', error);
            this.showError('Failed to connect to Citadel Archer backend. Is the server running?');
        }
    }

    async connectToBackend() {
        // Load initial system status
        const status = await api.getSystemStatus();
        this.updateState({
            guardianActive: status.guardian_active,
            securityLevel: status.security_level,
            threatLevel: status.threat_level
        });

        // Load initial processes
        const processes = await api.getProcesses();
        this.updateState({ processes });

        console.log('✅ Connected to backend:', status);
    }

    setupWebSocket() {
        // Connect WebSocket for real-time updates
        api.connectWebSocket();

        // Listen for connection events
        api.on('connected', () => {
            console.log('🔗 Real-time updates enabled');
        });

        api.on('disconnected', () => {
            console.warn('⚠️ Real-time updates disconnected');
        });

        // Listen for Guardian status changes
        api.on('guardian_started', () => {
            this.updateState({ guardianActive: true });
            this.addEvent({
                severity: 'info',
                message: 'Guardian protection started',
                timestamp: new Date().toISOString()
            });
        });

        api.on('guardian_stopped', () => {
            this.updateState({ guardianActive: false });
            this.addEvent({
                severity: 'alert',
                message: 'Guardian protection stopped',
                timestamp: new Date().toISOString()
            });
        });

        // Listen for security level changes
        api.on('security_level_changed', (data) => {
            this.updateState({ securityLevel: data.new_level });
            this.addEvent({
                severity: 'info',
                message: `Security level changed to ${data.new_level}`,
                timestamp: data.timestamp
            });
        });

        // Listen for process kills
        api.on('process_killed', (data) => {
            this.addEvent({
                severity: 'alert',
                message: `Process ${data.pid} terminated: ${data.reason}`,
                timestamp: data.timestamp
            });
            this.refreshProcesses(); // Refresh process list
        });
    }

    setupDataRefresh() {
        // Refresh processes every 5 seconds
        setInterval(async () => {
            await this.refreshProcesses();
        }, 5000);

        // Refresh system status every 10 seconds
        setInterval(async () => {
            await this.refreshSystemStatus();
        }, 10000);
    }

    async refreshProcesses() {
        try {
            const processes = await api.getProcesses();
            this.updateState({ processes });
        } catch (error) {
            console.error('Failed to refresh processes:', error);
        }
    }

    async refreshSystemStatus() {
        try {
            const status = await api.getSystemStatus();
            this.updateState({
                guardianActive: status.guardian_active,
                securityLevel: status.security_level,
                threatLevel: status.threat_level
            });
        } catch (error) {
            console.error('Failed to refresh system status:', error);
        }
    }

    setupEventListeners() {
        // Settings button
        const settingsBtn = document.getElementById('settings-btn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => {
                this.openSettings();
            });
        }
    }

    updateState(updates) {
        Object.assign(this.state, updates);
        this.broadcastStateUpdates();
    }

    broadcastStateUpdates() {
        // Dispatch custom events to Web Components

        // Guardian status
        window.dispatchEvent(new CustomEvent('guardian-status-changed', {
            detail: {
                isActive: this.state.guardianActive,
                securityLevel: this.state.securityLevel
            }
        }));

        // Threat level
        window.dispatchEvent(new CustomEvent('threat-level-changed', {
            detail: {
                level: this.state.threatLevel,
                threatsBlocked: this.state.threatsBlocked
            }
        }));

        // Processes
        window.dispatchEvent(new CustomEvent('processes-updated', {
            detail: this.state.processes
        }));
    }

    addEvent(event) {
        this.state.events.unshift(event);
        if (this.state.events.length > 100) {
            this.state.events = this.state.events.slice(0, 100); // Keep last 100
        }

        // Broadcast to event log component
        window.dispatchEvent(new CustomEvent('new-event', {
            detail: event
        }));

        // Update threat count if it's a blocked threat
        if (event.severity === 'alert' || event.severity === 'critical') {
            this.state.threatsBlocked++;
            this.broadcastStateUpdates();
        }
    }

    openSettings() {
        // TODO: Phase 1 - Implement settings modal
        alert('Settings coming soon! (Phase 1)');
    }

    showError(message) {
        // Simple error display (TODO: Better UI for Phase 1)
        const errorDiv = document.createElement('div');
        errorDiv.className = 'fixed top-4 right-4 bg-red-500 text-white px-6 py-4 rounded-lg shadow-lg z-50';
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);

        setTimeout(() => errorDiv.remove(), 5000);
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
    const dashboard = new CitadelDashboard();
    await dashboard.init();

    // Make dashboard accessible globally for debugging
    window.citadel = dashboard;

    // Simulate some events for demo (remove in production)
    setTimeout(() => {
        dashboard.addEvent({
            severity: 'info',
            message: 'System scan completed. No threats found.',
            timestamp: new Date().toISOString()
        });
    }, 2000);

    setTimeout(() => {
        dashboard.addEvent({
            severity: 'investigate',
            message: 'Checking suspicious file: update.exe',
            timestamp: new Date().toISOString()
        });
    }, 4000);

    setTimeout(() => {
        dashboard.addEvent({
            severity: 'alert',
            message: 'Quarantined suspicious file: update.exe (double extension detected)',
            timestamp: new Date().toISOString()
        });
    }, 6000);
});

console.log('🛡️ Citadel Archer Dashboard loaded');
