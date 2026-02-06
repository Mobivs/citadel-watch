// PRD: Dashboard - API Client
// FastAPI backend client (REST + WebSocket)
// Reference: docs/PRD.md v0.2.3, Section: Technical Architecture

class CitadelAPI {
    constructor(baseURL = 'http://127.0.0.1:8000') {
        this.baseURL = baseURL;
        this.ws = null;
        this.eventHandlers = new Map();
    }

    // REST API Methods
    async get(endpoint) {
        const response = await fetch(`${this.baseURL}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        return response.json();
    }

    async post(endpoint, data) {
        const response = await fetch(`${this.baseURL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        return response.json();
    }

    // System Status
    async getSystemStatus() {
        return this.get('/api/status');
    }

    // Security Level
    async getSecurityLevel() {
        return this.get('/api/security-level');
    }

    async setSecurityLevel(level) {
        return this.post('/api/security-level', { level });
    }

    // Processes
    async getProcesses() {
        return this.get('/api/processes');
    }

    async killProcess(pid, reason = 'User requested') {
        return this.post(`/api/processes/${pid}/kill`, { reason });
    }

    // Guardian Control
    async startGuardian() {
        return this.get('/api/guardian/start');
    }

    async stopGuardian() {
        return this.get('/api/guardian/stop');
    }

    // Events
    async getRecentEvents(limit = 50) {
        return this.get(`/api/events?limit=${limit}`);
    }

    // WebSocket Methods
    connectWebSocket() {
        const wsURL = this.baseURL.replace('http', 'ws') + '/ws';
        this.ws = new WebSocket(wsURL);

        this.ws.onopen = () => {
            console.log('✅ WebSocket connected to Citadel Archer backend');
            this.emit('connected');
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.emit('message', data);

                // Dispatch specific event types
                if (data.type) {
                    this.emit(data.type, data);
                }
            } catch (error) {
                console.error('WebSocket message parse error:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('❌ WebSocket error:', error);
            this.emit('error', error);
        };

        this.ws.onclose = () => {
            console.log('🔌 WebSocket disconnected. Attempting to reconnect in 5s...');
            this.emit('disconnected');
            setTimeout(() => this.connectWebSocket(), 5000); // Auto-reconnect
        };
    }

    // Event Emitter Pattern
    on(eventName, handler) {
        if (!this.eventHandlers.has(eventName)) {
            this.eventHandlers.set(eventName, []);
        }
        this.eventHandlers.get(eventName).push(handler);
    }

    emit(eventName, data) {
        const handlers = this.eventHandlers.get(eventName);
        if (handlers) {
            handlers.forEach(handler => handler(data));
        }
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Export singleton instance
export const api = new CitadelAPI();
