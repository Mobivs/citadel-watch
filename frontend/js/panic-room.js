// Panic Room JavaScript Implementation
class PanicRoom {
    constructor() {
        this.apiBase = '/api/panic';
        this.activeResponse = null;
        this.wsConnection = null;
        this.config = {
            ipWhitelist: ['127.0.0.1', '::1'],
            processWhitelist: ['ssh', 'nginx', 'mysql'],
            isolationMode: 'strict'
        };
        this.initializeEventListeners();
        this.loadConfig();
        this.loadHistory();
    }

    initializeEventListeners() {
        // Panic button
        document.getElementById('panicButton').addEventListener('click', () => this.showPlaybookSelection());
        
        // Confirmation modal
        document.getElementById('confirmPanic').addEventListener('click', () => this.activatePanicMode());
        document.getElementById('cancelPanic').addEventListener('click', () => this.hideConfirmationModal());
        
        // Active session controls
        document.getElementById('cancelActive').addEventListener('click', () => this.cancelPanicMode());
        document.getElementById('rollbackButton').addEventListener('click', () => this.rollbackChanges());
        
        // Configuration
        document.getElementById('saveConfig').addEventListener('click', () => this.saveConfiguration());
        
        // Playbook checkboxes
        document.querySelectorAll('.playbook-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateSelectedPlaybooks());
        });
    }

    showPlaybookSelection() {
        document.getElementById('playbookSection').classList.remove('hidden');
        document.getElementById('panicButton').disabled = true;
        
        // Pre-select critical playbooks
        document.querySelector('input[value="IsolateNetwork"]').checked = true;
        document.querySelector('input[value="RotateCredentials"]').checked = true;
        
        // Show confirmation after selection
        setTimeout(() => this.showConfirmationModal(), 500);
    }

    showConfirmationModal() {
        const selectedPlaybooks = this.getSelectedPlaybooks();
        if (selectedPlaybooks.length === 0) {
            alert('Please select at least one playbook');
            return;
        }
        
        const list = document.getElementById('selectedPlaybooks');
        list.innerHTML = selectedPlaybooks.map(p => `<li>${this.getPlaybookDescription(p)}</li>`).join('');
        document.getElementById('confirmModal').classList.remove('hidden');
    }

    hideConfirmationModal() {
        document.getElementById('confirmModal').classList.add('hidden');
        document.getElementById('playbookSection').classList.add('hidden');
        document.getElementById('panicButton').disabled = false;
        
        // Clear selections
        document.querySelectorAll('.playbook-checkbox').forEach(cb => cb.checked = false);
    }

    getSelectedPlaybooks() {
        return Array.from(document.querySelectorAll('.playbook-checkbox:checked'))
            .map(cb => cb.value);
    }

    getPlaybookDescription(playbook) {
        const descriptions = {
            'IsolateNetwork': '🔒 Network Isolation',
            'RotateCredentials': '🔑 Credential Rotation',
            'SnapshotSystem': '📸 System Snapshot',
            'SecureBackup': '💾 Secure Backup'
        };
        return descriptions[playbook] || playbook;
    }

    async activatePanicMode() {
        const playbooks = this.getSelectedPlaybooks();
        
        try {
            // Mock API call
            const response = await this.mockApiCall('POST', '/activate', {
                playbooks: playbooks,
                config: this.config,
                timestamp: new Date().toISOString()
            });
            
            this.activeResponse = response;
            this.hideConfirmationModal();
            this.showActiveSession(response.response_id);
            this.startStatusPolling(response.response_id);
            this.connectWebSocket(response.response_id);
            
        } catch (error) {
            console.error('Failed to activate panic mode:', error);
            alert('Failed to activate panic mode: ' + error.message);
        }
    }

    showActiveSession(responseId) {
        document.getElementById('activeSession').classList.remove('hidden');
        document.getElementById('panicButton').classList.add('hidden');
        this.addLogEntry(`Panic mode activated - Response ID: ${responseId}`, 'info');
    }

    startStatusPolling(responseId) {
        let progress = 0;
        const interval = setInterval(async () => {
            try {
                const status = await this.mockApiCall('GET', `/status/${responseId}`);
                this.updateProgress(status.progress);
                this.updateActionLog(status.actions);
                
                if (status.status === 'completed') {
                    clearInterval(interval);
                    this.onPanicCompleted();
                } else if (status.status === 'failed') {
                    clearInterval(interval);
                    this.onPanicFailed(status.error);
                }
            } catch (error) {
                console.error('Status polling error:', error);
            }
        }, 2000);
    }

    connectWebSocket(responseId) {
        // Mock WebSocket connection
        console.log(`WebSocket would connect to: ws://localhost:8080/panic/${responseId}`);
        
        // Simulate real-time updates
        setTimeout(() => this.addLogEntry('🔒 Isolating network...', 'executing'), 1000);
        setTimeout(() => this.addLogEntry('✅ Network isolated', 'success'), 3000);
        setTimeout(() => this.addLogEntry('🔑 Rotating credentials...', 'executing'), 4000);
        setTimeout(() => this.addLogEntry('✅ Credentials rotated', 'success'), 7000);
        setTimeout(() => this.updateProgress(100), 8000);
    }

    updateProgress(percent) {
        document.getElementById('progressBar').style.width = `${percent}%`;
        document.getElementById('progressText').textContent = `${percent}%`;
    }

    updateActionLog(actions) {
        const log = document.getElementById('actionLog');
        log.innerHTML = '<p class="text-gray-400 mb-2">Action log:</p>';
        
        if (actions && actions.length > 0) {
            actions.forEach(action => {
                this.addLogEntry(action.message, action.status);
            });
        }
    }

    addLogEntry(message, status = 'info') {
        const log = document.getElementById('actionLog');
        const entry = document.createElement('div');
        entry.className = 'mb-1';
        
        const statusColors = {
            'info': 'text-gray-300',
            'executing': 'text-yellow-400',
            'success': 'text-green-400',
            'failed': 'text-red-400'
        };
        
        entry.innerHTML = `<span class="${statusColors[status] || 'text-gray-300'}">${new Date().toLocaleTimeString()}: ${message}</span>`;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    async cancelPanicMode() {
        if (!confirm('Are you sure you want to cancel the active panic response?')) {
            return;
        }
        
        try {
            await this.mockApiCall('POST', `/cancel/${this.activeResponse.response_id}`);
            this.addLogEntry('⚠️ Panic mode cancelled by user', 'failed');
            this.resetUI();
        } catch (error) {
            alert('Failed to cancel panic mode: ' + error.message);
        }
    }

    onPanicCompleted() {
        this.addLogEntry('✅ Panic response completed successfully', 'success');
        document.getElementById('rollbackButton').classList.remove('hidden');
        document.getElementById('cancelActive').classList.add('hidden');
    }

    onPanicFailed(error) {
        this.addLogEntry(`❌ Panic response failed: ${error}`, 'failed');
        document.getElementById('rollbackButton').classList.remove('hidden');
        document.getElementById('cancelActive').classList.add('hidden');
    }

    async rollbackChanges() {
        if (!confirm('This will rollback all changes made during panic mode. Continue?')) {
            return;
        }
        
        try {
            this.addLogEntry('🔄 Starting rollback...', 'executing');
            const result = await this.mockApiCall('POST', `/rollback/${this.activeResponse.response_id}`);
            
            // Simulate rollback progress
            setTimeout(() => this.addLogEntry('🔄 Restoring network configuration...', 'executing'), 1000);
            setTimeout(() => this.addLogEntry('🔄 Restoring original credentials...', 'executing'), 2000);
            setTimeout(() => this.addLogEntry('✅ Rollback completed', 'success'), 3000);
            setTimeout(() => this.resetUI(), 4000);
            
        } catch (error) {
            this.addLogEntry(`❌ Rollback failed: ${error.message}`, 'failed');
        }
    }

    resetUI() {
        document.getElementById('activeSession').classList.add('hidden');
        document.getElementById('panicButton').classList.remove('hidden');
        document.getElementById('panicButton').disabled = false;
        document.getElementById('rollbackButton').classList.add('hidden');
        document.getElementById('cancelActive').classList.remove('hidden');
        this.updateProgress(0);
        this.activeResponse = null;
        this.loadHistory();
    }

    async saveConfiguration() {
        const ipWhitelist = document.getElementById('ipWhitelist').value.split('\n').filter(ip => ip.trim());
        const processWhitelist = document.getElementById('processWhitelist').value.split('\n').filter(p => p.trim());
        
        this.config = {
            ipWhitelist: ipWhitelist.length > 0 ? ipWhitelist : ['127.0.0.1'],
            processWhitelist: processWhitelist.length > 0 ? processWhitelist : ['ssh'],
            isolationMode: 'strict',
            savedAt: new Date().toISOString()
        };
        
        try {
            await this.mockApiCall('POST', '/config', this.config);
            this.showNotification('✅ Configuration saved successfully');
        } catch (error) {
            this.showNotification('❌ Failed to save configuration', 'error');
        }
    }

    async loadConfig() {
        try {
            const config = await this.mockApiCall('GET', '/config');
            this.config = config;
            
            if (config.ipWhitelist) {
                document.getElementById('ipWhitelist').value = config.ipWhitelist.join('\n');
            }
            if (config.processWhitelist) {
                document.getElementById('processWhitelist').value = config.processWhitelist.join('\n');
            }
        } catch (error) {
            console.log('Using default configuration');
        }
    }

    async loadHistory() {
        try {
            const history = await this.mockApiCall('GET', '/history');
            this.displayHistory(history);
        } catch (error) {
            console.log('No history available');
        }
    }

    displayHistory(history) {
        const historyList = document.getElementById('historyList');
        
        if (!history || history.length === 0) {
            historyList.innerHTML = '<p class="text-gray-400">No panic responses recorded</p>';
            return;
        }
        
        historyList.innerHTML = history.map(item => `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-400">${new Date(item.timestamp).toLocaleString()}</span>
                    <span class="text-sm ${item.status === 'completed' ? 'text-green-400' : 'text-yellow-400'}">${item.status}</span>
                </div>
                <div class="mt-1">
                    <span class="text-xs">Response ID: ${item.response_id}</span>
                    <span class="ml-4 text-xs">Playbooks: ${item.playbooks.join(', ')}</span>
                </div>
            </div>
        `).join('');
    }

    showNotification(message, type = 'success') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded ${type === 'error' ? 'bg-red-600' : 'bg-green-600'} text-white z-50`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => notification.remove(), 3000);
    }

    // Mock API implementation for testing
    async mockApiCall(method, endpoint, data = null) {
        console.log(`Mock API Call: ${method} ${this.apiBase}${endpoint}`, data);
        
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Mock responses
        if (endpoint === '/activate') {
            return {
                response_id: 'panic_' + Date.now(),
                status: 'active',
                playbooks: data.playbooks,
                started_at: new Date().toISOString()
            };
        }
        
        if (endpoint.startsWith('/status/')) {
            const progress = Math.min(100, (Date.now() % 10000) / 100);
            return {
                status: progress === 100 ? 'completed' : 'active',
                progress: progress,
                actions: [
                    { message: 'Initializing panic response', status: 'success' },
                    { message: 'Executing playbooks', status: 'executing' }
                ]
            };
        }
        
        if (endpoint === '/history') {
            return [
                {
                    response_id: 'panic_1707123456',
                    timestamp: new Date(Date.now() - 86400000).toISOString(),
                    status: 'completed',
                    playbooks: ['IsolateNetwork', 'RotateCredentials']
                },
                {
                    response_id: 'panic_1707037056',
                    timestamp: new Date(Date.now() - 172800000).toISOString(),
                    status: 'completed',
                    playbooks: ['SnapshotSystem']
                }
            ];
        }
        
        if (endpoint === '/config') {
            if (method === 'GET') {
                return this.config;
            }
            return { success: true };
        }
        
        return { success: true };
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    window.panicRoom = new PanicRoom();
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PanicRoom;
}