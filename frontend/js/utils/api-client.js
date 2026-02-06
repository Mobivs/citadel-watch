// PRD: API Client - Authenticated API requests
// Reference: docs/PRD.md v0.2.3, Section: Security
//
// Handles session token management and authenticated API requests
// All vault API calls must include X-Session-Token header

class APIClient {
    constructor() {
        this.sessionToken = null;
        this.initialized = false;
    }

    /**
     * Initialize API client by fetching session token
     * Must be called before making any authenticated requests
     */
    async initialize() {
        if (this.initialized) {
            return; // Already initialized
        }

        try {
            const response = await fetch('/api/session');
            if (response.ok) {
                const data = await response.json();
                this.sessionToken = data.session_token;
                this.initialized = true;
                console.log('✅ API client initialized with session token');
            } else {
                console.error('Failed to fetch session token:', response.status);
                throw new Error('Failed to initialize API client');
            }
        } catch (error) {
            console.error('API client initialization error:', error);
            throw error;
        }
    }

    /**
     * Make an authenticated API request
     * Automatically includes X-Session-Token header
     *
     * @param {string} url - API endpoint URL
     * @param {object} options - Fetch options (method, body, headers, etc.)
     * @returns {Promise<Response>} Fetch response
     */
    async request(url, options = {}) {
        if (!this.initialized) {
            await this.initialize();
        }

        // Add session token header
        const headers = {
            ...options.headers,
            'X-Session-Token': this.sessionToken
        };

        return fetch(url, {
            ...options,
            headers
        });
    }

    /**
     * GET request with authentication
     */
    async get(url) {
        return this.request(url, { method: 'GET' });
    }

    /**
     * POST request with authentication
     */
    async post(url, data) {
        return this.request(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
    }

    /**
     * DELETE request with authentication
     */
    async delete(url) {
        return this.request(url, { method: 'DELETE' });
    }
}

// Export singleton instance
export const apiClient = new APIClient();
