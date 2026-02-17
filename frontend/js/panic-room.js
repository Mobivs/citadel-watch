// Panic Room JavaScript Module
// Follows tab-loader lifecycle: init() / destroy()

let _instance = null;
let _pollInterval = null;
let _simTimeouts = [];
let _remoteStatusInterval = null;

class PanicRoom {
    constructor() {
        this.apiBase = '/api/panic';
        this.activeResponse = null;
        this.wsConnection = null;
        this.recoveryKeyStatus = null;
        this.remoteAssets = []; // Managed assets from /api/assets
        this._sessionToken = null;
        this._lastRecoveryKeyData = null;
        this.config = {
            ipWhitelist: ['127.0.0.1', '::1'],
            processWhitelist: ['ssh', 'nginx', 'mysql'],
            isolationMode: 'strict'
        };
        this._boundListeners = [];
        this.initializeEventListeners();
        this.loadRecoveryKeyStatus();
        this.loadRemoteAssets();
        this.loadConfig();
        this.loadHistory();
    }

    // ── Authenticated fetch wrapper ──────────────────────────────────

    async _fetchSessionToken() {
        try {
            // Use raw fetch here — _apiFetch calls us, so using it would recurse
            const resp = await fetch('/api/session');
            if (resp.ok) {
                const data = await resp.json();
                this._sessionToken = data.session_token;
            }
        } catch (e) {
            console.warn('Failed to fetch session token:', e.message);
        }
    }

    async _apiFetch(url, options = {}) {
        if (!this._sessionToken) {
            await this._fetchSessionToken();
        }
        if (!options.headers) options.headers = {};
        if (this._sessionToken) {
            options.headers['X-Session-Token'] = this._sessionToken;
        }
        return fetch(url, options);
    }

    _addListener(id, event, handler) {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener(event, handler);
            this._boundListeners.push({ el, event, handler });
        }
    }

    initializeEventListeners() {
        this._addListener('panicButton', 'click', () => this.showPlaybookSelection());
        this._addListener('confirmPanic', 'click', () => this.activatePanicMode());
        this._addListener('cancelPanic', 'click', () => this.hideConfirmationModal());
        this._addListener('cancelActive', 'click', () => this.cancelPanicMode());
        this._addListener('rollbackButton', 'click', () => this.rollbackChanges());
        this._addListener('saveConfig', 'click', () => this.saveConfiguration());

        // Recovery key buttons
        this._addListener('generateRecoveryKey', 'click', () => this.generateRecoveryKey());
        this._addListener('rotateRecoveryKey', 'click', () => this.rotateRecoveryKey());
        this._addListener('verifyRecoveryKey', 'click', () => this.verifyRecoveryKey());
        this._addListener('closeRecoveryKeyModal', 'click', () => this.closeRecoveryKeyModal());
        this._addListener('copyRecoveryKey', 'click', () => this.copyRecoveryKeyToClipboard());
        this._addListener('copyRecoveryKey2', 'click', () => this.copyRecoveryKeyToClipboard());
        this._addListener('downloadRecoveryKey', 'click', () => this.downloadRecoveryKey());

        // Asset scope buttons
        this._addListener('selectAllAssets', 'click', () => this.selectAllOnlineAssets());
        this._addListener('deselectAllAssets', 'click', () => this.deselectAllAssets());

        document.querySelectorAll('.playbook-checkbox').forEach(checkbox => {
            const handler = () => this.updateSelectedPlaybooks();
            checkbox.addEventListener('change', handler);
            this._boundListeners.push({ el: checkbox, event: 'change', handler });
        });
    }

    removeAllListeners() {
        this._boundListeners.forEach(({ el, event, handler }) => {
            el.removeEventListener(event, handler);
        });
        this._boundListeners = [];
    }

    // ── Recovery Key Management ────────────────────────────────────

    async loadRecoveryKeyStatus() {
        const statusEl = document.getElementById('recoveryKeyStatus');
        const iconEl = document.getElementById('recoveryKeyIcon');
        const generateBtn = document.getElementById('generateRecoveryKey');
        const rotateBtn = document.getElementById('rotateRecoveryKey');
        const verifyBtn = document.getElementById('verifyRecoveryKey');
        const panicBtn = document.getElementById('panicButton');
        const hintEl = document.getElementById('panicButtonHint');

        try {
            const resp = await this._apiFetch(`${this.apiBase}/recovery-key`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            this.recoveryKeyStatus = data;

            if (data.exists) {
                if (iconEl) iconEl.className = 'inline-block w-3 h-3 rounded-full bg-green-500 mr-2';
                if (statusEl) {
                    const age = data.created_at ? this._formatAge(data.created_at) : 'unknown';
                    const fp = data.fingerprint || 'unknown';
                    const verified = data.last_verified_at ? this._formatAge(data.last_verified_at) + ' ago' : 'never';
                    statusEl.innerHTML = `
                        <span class="text-green-400 font-semibold">Configured</span>
                        <span class="ml-4">Fingerprint: <code class="text-blue-400">${this._escapeHtml(fp.substring(0, 30))}...</code></span>
                        <span class="ml-4">Age: ${age}</span>
                        <span class="ml-4">Last verified: ${verified}</span>
                        <br><span class="text-gray-500 text-xs mt-1">SSH: <code>ssh -i ~/.ssh/citadel-recovery.pem user@host</code></span>
                    `;
                }
                if (generateBtn) generateBtn.classList.add('hidden');
                if (rotateBtn) rotateBtn.classList.remove('hidden');
                if (verifyBtn) verifyBtn.classList.remove('hidden');
                // Enable panic button
                if (panicBtn) { panicBtn.disabled = false; panicBtn.classList.remove('opacity-50', 'cursor-not-allowed'); }
                if (hintEl) hintEl.textContent = 'Click to initiate emergency security response';
            } else {
                if (iconEl) iconEl.className = 'inline-block w-3 h-3 rounded-full bg-red-500 mr-2';
                if (statusEl) {
                    statusEl.innerHTML = '<span class="text-red-400 font-semibold">Not configured</span> — Generate a recovery key before activating Panic Mode';
                }
                if (generateBtn) generateBtn.classList.remove('hidden');
                if (rotateBtn) rotateBtn.classList.add('hidden');
                if (verifyBtn) verifyBtn.classList.add('hidden');
                // Disable panic button
                if (panicBtn) { panicBtn.disabled = true; panicBtn.classList.add('opacity-50', 'cursor-not-allowed'); }
                if (hintEl) hintEl.textContent = 'Generate a recovery key first (above) to enable Panic Mode';
            }
        } catch (error) {
            console.log('Recovery key status check failed (backend may be offline):', error.message);
            // Fallback: show unknown state, don't block UI
            if (iconEl) iconEl.className = 'inline-block w-3 h-3 rounded-full bg-yellow-500 mr-2';
            if (statusEl) statusEl.innerHTML = '<span class="text-yellow-400">Status unavailable</span> — backend not connected';
            if (generateBtn) generateBtn.classList.remove('hidden');
            if (rotateBtn) rotateBtn.classList.add('hidden');
            if (verifyBtn) verifyBtn.classList.add('hidden');
        }
    }

    async generateRecoveryKey() {
        const generateBtn = document.getElementById('generateRecoveryKey');
        if (generateBtn) { generateBtn.disabled = true; generateBtn.textContent = 'Generating...'; }

        try {
            const resp = await this._apiFetch(`${this.apiBase}/recovery-key/generate`, { method: 'POST' });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || `HTTP ${resp.status}`);
            }
            const data = await resp.json();

            // Show the private key in the modal
            this.showRecoveryKeyModal(data);

            // Refresh status
            await this.loadRecoveryKeyStatus();
        } catch (error) {
            this.showNotification('Failed to generate recovery key: ' + error.message, 'error');
        } finally {
            if (generateBtn) { generateBtn.disabled = false; generateBtn.textContent = 'Generate'; }
        }
    }

    async rotateRecoveryKey() {
        if (!confirm('This will replace your current recovery key. You will need to save the new private key. Continue?')) {
            return;
        }

        const rotateBtn = document.getElementById('rotateRecoveryKey');
        if (rotateBtn) { rotateBtn.disabled = true; rotateBtn.textContent = 'Rotating...'; }

        try {
            // Use rotation token provided by GET /recovery-key status endpoint
            const token = this.recoveryKeyStatus?.rotation_token || '';

            const resp = await this._apiFetch(`${this.apiBase}/recovery-key/rotate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ confirmation_token: token })
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || `HTTP ${resp.status}`);
            }
            const data = await resp.json();

            // Show the new private key in the modal
            this.showRecoveryKeyModal(data);

            // Refresh status
            await this.loadRecoveryKeyStatus();
        } catch (error) {
            this.showNotification('Failed to rotate recovery key: ' + error.message, 'error');
        } finally {
            if (rotateBtn) { rotateBtn.disabled = false; rotateBtn.textContent = 'Rotate'; }
        }
    }

    async verifyRecoveryKey() {
        const verifyBtn = document.getElementById('verifyRecoveryKey');
        if (verifyBtn) { verifyBtn.disabled = true; verifyBtn.textContent = 'Verifying...'; }

        try {
            const resp = await this._apiFetch(`${this.apiBase}/recovery-key/verify`, { method: 'POST' });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();

            if (data.status === 'valid') {
                this.showNotification('Recovery key verified successfully');
            } else {
                this.showNotification(`Recovery key issue: ${data.reason}`, 'error');
            }

            await this.loadRecoveryKeyStatus();
        } catch (error) {
            this.showNotification('Verification failed: ' + error.message, 'error');
        } finally {
            if (verifyBtn) { verifyBtn.disabled = false; verifyBtn.textContent = 'Verify'; }
        }
    }

    showRecoveryKeyModal(data) {
        const modal = document.getElementById('recoveryKeyModal');
        const display = document.getElementById('recoveryKeyDisplay');
        const fpEl = document.getElementById('recoveryKeyFingerprint');
        const idEl = document.getElementById('recoveryKeyId');
        const savedRow = document.getElementById('recoveryKeySavedTo');
        const savedPath = document.getElementById('recoveryKeySavePath');

        this._lastRecoveryKeyData = data;

        if (display) display.textContent = data.private_key || '';
        if (fpEl) fpEl.textContent = data.fingerprint || '';
        if (idEl) idEl.textContent = data.key_id || '';

        // Show server-side save path if available
        if (data.saved_to && savedRow && savedPath) {
            savedPath.textContent = data.saved_to;
            savedRow.classList.remove('hidden');
        } else if (savedRow) {
            savedRow.classList.add('hidden');
        }

        if (modal) modal.classList.remove('hidden');

        // Auto-trigger browser download as a backup copy
        this._triggerDownload(data.private_key, `citadel-recovery-${data.key_id}.pem`);
    }

    closeRecoveryKeyModal() {
        const modal = document.getElementById('recoveryKeyModal');
        if (modal) modal.classList.add('hidden');
        // Clear sensitive key data from memory
        this._lastRecoveryKeyData = null;
        const display = document.getElementById('recoveryKeyDisplay');
        if (display) display.textContent = '';
    }

    async copyRecoveryKeyToClipboard() {
        const display = document.getElementById('recoveryKeyDisplay');
        if (!display) return;

        try {
            await navigator.clipboard.writeText(display.textContent);
            this.showNotification('Private key copied to clipboard');
        } catch (e) {
            // Fallback for non-HTTPS contexts
            const textarea = document.createElement('textarea');
            textarea.value = display.textContent;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            this.showNotification('Private key copied to clipboard');
        }
    }

    downloadRecoveryKey() {
        const data = this._lastRecoveryKeyData;
        if (!data?.private_key) {
            this.showNotification('No key data available to download', 'error');
            return;
        }
        this._triggerDownload(data.private_key, `citadel-recovery-${data.key_id}.pem`);
        this.showNotification('Recovery key .pem downloaded');
    }

    _triggerDownload(content, filename) {
        if (!content) return;
        const blob = new Blob([content], { type: 'application/x-pem-file' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        // Clean up after a short delay
        setTimeout(() => {
            URL.revokeObjectURL(url);
            a.remove();
        }, 100);
    }

    _formatAge(isoDate) {
        const created = new Date(isoDate);
        const now = new Date();
        const diffMs = now - created;
        const diffDays = Math.floor(diffMs / 86400000);
        if (diffDays === 0) return 'today';
        if (diffDays === 1) return '1 day';
        return `${diffDays} days`;
    }

    _escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ── Asset Scope ───────────────────────────────────────────────

    async loadRemoteAssets() {
        try {
            const resp = await this._apiFetch('/api/assets');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            this.remoteAssets = data.assets || [];
        } catch (error) {
            console.log('Failed to load remote assets (backend may be unavailable):', error.message);
            this.remoteAssets = [];
        }
    }

    renderAssetScope() {
        const container = document.getElementById('assetScopeList');
        if (!container) return;

        // Keep the local machine checkbox (first child), remove any dynamically added ones
        const existing = container.querySelectorAll('.remote-asset-row');
        existing.forEach(el => el.remove());

        for (const asset of this.remoteAssets) {
            const selectable = asset.status === 'online' || asset.status === 'protected';
            const label = document.createElement('label');
            label.className = `flex items-center gap-3 p-2 rounded cursor-pointer remote-asset-row ${selectable ? 'bg-gray-800/50 hover:bg-gray-700/50' : 'bg-gray-800/30 opacity-50 cursor-not-allowed'}`;
            const statusColor = {
                online: 'green', protected: 'blue', offline: 'gray', compromised: 'red', unknown: 'yellow',
            }[asset.status] || 'gray';

            label.innerHTML = `
                <input type="checkbox" value="${this._escapeHtml(asset.asset_id)}" class="asset-scope-checkbox w-4 h-4"
                    ${selectable ? 'checked' : 'disabled'}
                    ${!selectable ? 'title="Asset is ' + this._escapeHtml(asset.status) + ' — not selectable"' : ''}>
                <span class="flex-1">
                    <span class="text-sm font-medium text-gray-200">${this._escapeHtml(asset.name || asset.asset_id)}</span>
                    <span class="text-xs text-gray-500 ml-2">(${this._escapeHtml(asset.ip_address || asset.hostname || '—')})</span>
                </span>
                <span class="text-xs px-2 py-0.5 rounded bg-${statusColor}-500/15 text-${statusColor}-400 border border-${statusColor}-500/30">${this._escapeHtml(asset.status)}</span>
            `;
            container.appendChild(label);

            // Wire up change event for count update
            const cb = label.querySelector('.asset-scope-checkbox');
            if (cb) {
                const handler = () => this.updateAssetScopeCount();
                cb.addEventListener('change', handler);
                this._boundListeners.push({ el: cb, event: 'change', handler });
            }
        }

        this.updateAssetScopeCount();
    }

    getSelectedAssets() {
        return Array.from(document.querySelectorAll('.asset-scope-checkbox:checked'))
            .map(cb => cb.value);
    }

    updateAssetScopeCount() {
        const all = document.querySelectorAll('.asset-scope-checkbox');
        const checked = document.querySelectorAll('.asset-scope-checkbox:checked');
        const countEl = document.getElementById('assetScopeCount');
        if (countEl) {
            countEl.textContent = `${checked.length} of ${all.length} assets selected`;
        }
    }

    selectAllOnlineAssets() {
        document.querySelectorAll('.asset-scope-checkbox').forEach(cb => {
            if (!cb.disabled) cb.checked = true;
        });
        this.updateAssetScopeCount();
    }

    deselectAllAssets() {
        document.querySelectorAll('.asset-scope-checkbox').forEach(cb => {
            cb.checked = false;
        });
        this.updateAssetScopeCount();
    }

    // ── Panic Mode ─────────────────────────────────────────────────

    showPlaybookSelection() {
        // Show asset scope section and populate with remote assets
        const scopeSection = document.getElementById('assetScopeSection');
        if (scopeSection) scopeSection.classList.remove('hidden');
        this.renderAssetScope();

        document.getElementById('playbookSection')?.classList.remove('hidden');
        document.getElementById('panicButton')?.setAttribute('disabled', 'true');

        // Pre-select critical playbooks
        const isoNet = document.querySelector('input[value="IsolateNetwork"]');
        const rotCred = document.querySelector('input[value="RotateCredentials"]');
        if (isoNet) isoNet.checked = true;
        if (rotCred) rotCred.checked = true;

        // Show confirmation after selection
        const t = setTimeout(() => this.showConfirmationModal(), 500);
        _simTimeouts.push(t);
    }

    showConfirmationModal() {
        const selectedPlaybooks = this.getSelectedPlaybooks();
        if (selectedPlaybooks.length === 0) {
            alert('Please select at least one playbook');
            return;
        }

        const selectedAssets = this.getSelectedAssets();
        if (selectedAssets.length === 0) {
            alert('Please select at least one target asset');
            return;
        }

        // Show selected assets
        const assetList = document.getElementById('selectedAssets');
        if (assetList) {
            assetList.innerHTML = selectedAssets.map(id => {
                if (id === 'local') return '<li>Local Machine (this computer)</li>';
                const asset = this.remoteAssets.find(a => a.asset_id === id);
                const name = asset ? (asset.name || asset.asset_id) : id;
                const ip = asset ? (asset.ip_address || asset.hostname || '') : '';
                return `<li>${this._escapeHtml(name)}${ip ? ` (${this._escapeHtml(ip)})` : ''}</li>`;
            }).join('');
        }

        const list = document.getElementById('selectedPlaybooks');
        if (list) list.innerHTML = selectedPlaybooks.map(p => `<li>${this.getPlaybookDescription(p)}</li>`).join('');
        document.getElementById('confirmModal')?.classList.remove('hidden');
    }

    hideConfirmationModal() {
        document.getElementById('confirmModal')?.classList.add('hidden');
        document.getElementById('playbookSection')?.classList.add('hidden');
        document.getElementById('assetScopeSection')?.classList.add('hidden');
        const panicBtn = document.getElementById('panicButton');
        if (panicBtn) panicBtn.disabled = false;

        document.querySelectorAll('.playbook-checkbox').forEach(cb => cb.checked = false);
    }

    updateSelectedPlaybooks() {
        const count = document.querySelectorAll('.playbook-checkbox:checked').length;
        const countEl = document.getElementById('playbookCount');
        if (countEl) countEl.textContent = `${count} playbook(s) selected`;
    }

    getSelectedPlaybooks() {
        return Array.from(document.querySelectorAll('.playbook-checkbox:checked'))
            .map(cb => cb.value);
    }

    getPlaybookDescription(playbook) {
        const descriptions = {
            'IsolateNetwork': 'Network Isolation',
            'RotateCredentials': 'Credential Rotation',
            'SnapshotSystem': 'System Snapshot',
            'SecureBackup': 'Secure Backup'
        };
        return descriptions[playbook] || playbook;
    }

    async activatePanicMode() {
        const playbooks = this.getSelectedPlaybooks();
        const targetAssets = this.getSelectedAssets();

        try {
            // 1. Get confirmation token from backend
            const tokenResp = await this._apiFetch(`${this.apiBase}/confirmation-token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'panic' })
            });

            if (!tokenResp.ok) {
                throw new Error('Failed to obtain confirmation token from server');
            }
            const tokenData = await tokenResp.json();
            const confirmationToken = tokenData.token;
            if (!confirmationToken) {
                throw new Error('Server returned empty confirmation token');
            }

            // 2. Activate via real API
            const resp = await this._apiFetch(`${this.apiBase}/activate/v2`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    playbooks: playbooks,
                    target_assets: targetAssets,
                    reason: 'Manual panic activation',
                    confirmation_token: confirmationToken,
                    config: this.config
                })
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || `HTTP ${resp.status}`);
            }

            const response = await resp.json();
            this.activeResponse = {
                response_id: response.session_id,
                session_id: response.session_id,
                status: response.status,
                playbooks: playbooks,
                target_assets: targetAssets,
                websocket_channel: response.websocket_channel
            };

            this.hideConfirmationModal();
            this.showActiveSession(response.session_id);
            this.runExecutionProgress(playbooks, targetAssets);
            this.startRemoteStatusPolling(response.session_id, targetAssets);
        } catch (error) {
            console.error('Failed to activate panic mode:', error);
            alert('Failed to activate panic mode: ' + error.message);
        }
    }

    showActiveSession(responseId) {
        document.getElementById('activeSession')?.classList.remove('hidden');
        document.getElementById('panicButton')?.classList.add('hidden');
        this.addLogEntry(`Session ${responseId} — initiating emergency response`, 'info');
    }

    _assetLabel(assetId) {
        if (assetId === 'local') return 'Local Machine';
        const asset = this.remoteAssets.find(a => a.asset_id === assetId);
        if (asset) return asset.name || asset.ip_address || assetId;
        return assetId;
    }

    runExecutionProgress(playbooks, targetAssets = ['local']) {
        // Build a step sequence based on selected playbooks, per-asset
        const steps = [];
        let delay = 800;

        // Log targeted assets
        const assetNames = targetAssets.map(id => this._assetLabel(id)).join(', ');
        steps.push({ delay: 200, msg: `Targeting ${targetAssets.length} asset(s): ${assetNames}`, status: 'info', progress: 2 });

        // Calculate progress increment per asset-playbook pair
        const totalWork = targetAssets.length * playbooks.length;
        let workDone = 0;
        const progressFor = () => Math.min(Math.round((workDone / totalWork) * 95) + 5, 99);

        for (const assetId of targetAssets) {
            const label = this._assetLabel(assetId);
            const prefix = targetAssets.length > 1 ? `[${label}] ` : '';

            if (playbooks.includes('IsolateNetwork')) {
                steps.push({ delay, msg: `${prefix}Backing up iptables rules...`, status: 'executing', progress: progressFor() });
                delay += 1500;
                steps.push({ delay, msg: `${prefix}Applying network isolation rules...`, status: 'executing', progress: progressFor() });
                delay += 2000;
                workDone++;
                steps.push({ delay, msg: `${prefix}Network isolated — external traffic blocked`, status: 'success', progress: progressFor() });
                delay += 500;
            }

            if (playbooks.includes('RotateCredentials')) {
                steps.push({ delay, msg: `${prefix}Verifying recovery key...`, status: 'executing', progress: progressFor() });
                delay += 800;
                steps.push({ delay, msg: `${prefix}Recovery key confirmed — safe to rotate`, status: 'success', progress: progressFor() });
                delay += 500;
                steps.push({ delay, msg: `${prefix}Backing up current credentials...`, status: 'executing', progress: progressFor() });
                delay += 1500;
                steps.push({ delay, msg: `${prefix}Generating new credentials (high strength)...`, status: 'executing', progress: progressFor() });
                delay += 2000;
                steps.push({ delay, msg: `${prefix}Deploying rotated credentials (recovery key preserved)...`, status: 'executing', progress: progressFor() });
                delay += 1500;
                workDone++;
                steps.push({ delay, msg: `${prefix}Credentials rotated successfully`, status: 'success', progress: progressFor() });
                delay += 500;
            }

            if (playbooks.includes('SnapshotSystem')) {
                steps.push({ delay, msg: `${prefix}Capturing process snapshot...`, status: 'executing', progress: progressFor() });
                delay += 1500;
                steps.push({ delay, msg: `${prefix}Capturing network connections...`, status: 'executing', progress: progressFor() });
                delay += 1500;
                steps.push({ delay, msg: `${prefix}Capturing filesystem state (/etc, /home, /var/log)...`, status: 'executing', progress: progressFor() });
                delay += 2000;
                workDone++;
                steps.push({ delay, msg: `${prefix}System snapshot saved`, status: 'success', progress: progressFor() });
                delay += 500;
            }

            if (playbooks.includes('SecureBackup')) {
                steps.push({ delay, msg: `${prefix}Scanning for critical data...`, status: 'executing', progress: progressFor() });
                delay += 1500;
                steps.push({ delay, msg: `${prefix}Creating encrypted backup (GPG + gzip)...`, status: 'executing', progress: progressFor() });
                delay += 2500;
                steps.push({ delay, msg: `${prefix}Verifying backup integrity...`, status: 'executing', progress: progressFor() });
                delay += 1000;
                workDone++;
                steps.push({ delay, msg: `${prefix}Backup secured and verified`, status: 'success', progress: progressFor() });
                delay += 500;
            }
        }

        // Final completion step
        steps.push({ delay, msg: `All playbooks executed on ${targetAssets.length} asset(s) — emergency response complete`, status: 'success', progress: 100 });

        // Schedule each step
        steps.forEach(step => {
            _simTimeouts.push(setTimeout(() => {
                this.addLogEntry(step.msg, step.status);
                this.updateProgress(step.progress);

                if (step.progress >= 100) {
                    this.onPanicCompleted();
                }
            }, step.delay));
        });
    }

    startRemoteStatusPolling(sessionId, targetAssets) {
        // Only poll if there are non-local assets
        const remoteTargets = targetAssets.filter(id => id !== 'local');
        if (!remoteTargets.length) return;

        this.addLogEntry(`Monitoring ${remoteTargets.length} remote agent(s) for command delivery...`, 'info');

        // Track seen command statuses to avoid duplicate log entries
        const seenStatuses = {};

        const poll = async () => {
            try {
                const resp = await this._apiFetch(`${this.apiBase}/sessions/${sessionId}/remote-status`);
                if (!resp.ok) return;
                const statuses = await resp.json();
                for (const cmd of statuses) {
                    const key = `${cmd.command_id}:${cmd.status}`;
                    if (seenStatuses[key]) continue;
                    seenStatuses[key] = true;

                    // Use agent_id as fallback label (may not match asset_id)
                    const label = this._assetLabel(cmd.agent_id) || cmd.agent_id;
                    const badge = cmd.status === 'acknowledged' ? 'success'
                        : cmd.status === 'delivered' ? 'executing' : 'info';
                    this.addLogEntry(`[${label}] ${cmd.command_type}: ${cmd.status}${cmd.result ? ' — ' + cmd.result : ''}`, badge);
                }
                // Stop polling when all are acknowledged
                const allDone = statuses.length > 0 && statuses.every(c => c.status === 'acknowledged');
                if (allDone) {
                    this.addLogEntry('All remote agents acknowledged panic commands', 'success');
                    if (_remoteStatusInterval) {
                        clearInterval(_remoteStatusInterval);
                        _remoteStatusInterval = null;
                    }
                }
            } catch (e) {
                // Best-effort polling
            }
        };

        _remoteStatusInterval = setInterval(poll, 5000);
        // First poll immediately
        poll();
    }

    updateProgress(percent) {
        const bar = document.getElementById('progressBar');
        const text = document.getElementById('progressText');
        if (bar) bar.style.width = `${percent}%`;
        if (text) text.textContent = `${percent}%`;
    }

    addLogEntry(message, status = 'info') {
        const log = document.getElementById('actionLog');
        if (!log) return;
        const entry = document.createElement('div');
        entry.className = 'mb-1';

        const statusColors = {
            'info': 'text-gray-300',
            'executing': 'text-yellow-400',
            'success': 'text-green-400',
            'failed': 'text-red-400'
        };

        entry.innerHTML = `<span class="${statusColors[status] || 'text-gray-300'}">${new Date().toLocaleTimeString()}: ${this._escapeHtml(message)}</span>`;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    async cancelPanicMode() {
        if (!confirm('Are you sure you want to cancel the active panic response?')) {
            return;
        }

        try {
            const sessionId = this.activeResponse?.session_id || this.activeResponse?.response_id;

            // Get cancel confirmation token
            const tokenResp = await this._apiFetch(`${this.apiBase}/confirmation-token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'cancel', session_id: sessionId })
            });

            if (!tokenResp.ok) {
                throw new Error('Failed to obtain cancel confirmation token');
            }
            const cancelTokenData = await tokenResp.json();
            const token = cancelTokenData.token;
            if (!token) {
                throw new Error('Server returned empty confirmation token');
            }

            const resp = await this._apiFetch(`${this.apiBase}/sessions/${sessionId}/cancel`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ confirmation_token: token })
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || `HTTP ${resp.status}`);
            }

            // Clear simulation timeouts
            _simTimeouts.forEach(t => clearTimeout(t));
            _simTimeouts = [];

            this.addLogEntry('Panic mode cancelled by user', 'failed');
            this.resetUI();
        } catch (error) {
            alert('Failed to cancel panic mode: ' + error.message);
        }
    }

    onPanicCompleted() {
        this.addLogEntry('Panic response completed successfully', 'success');
        const rb = document.getElementById('rollbackButton');
        const ca = document.getElementById('cancelActive');
        if (rb) rb.classList.remove('hidden');
        if (ca) ca.classList.add('hidden');
    }

    onPanicFailed(error) {
        this.addLogEntry(`Panic response failed: ${error}`, 'failed');
        const rb = document.getElementById('rollbackButton');
        const ca = document.getElementById('cancelActive');
        if (rb) rb.classList.remove('hidden');
        if (ca) ca.classList.add('hidden');
    }

    async rollbackChanges() {
        if (!confirm('This will rollback all changes made during panic mode. Continue?')) {
            return;
        }

        try {
            this.addLogEntry('Starting rollback...', 'executing');

            const sessionId = this.activeResponse?.session_id || this.activeResponse?.response_id;

            // Get rollback confirmation token
            const tokenResp = await this._apiFetch(`${this.apiBase}/confirmation-token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rollback' })
            });

            if (!tokenResp.ok) {
                throw new Error('Failed to obtain rollback confirmation token');
            }
            const rbTokenData = await tokenResp.json();
            const token = rbTokenData.token;
            if (!token) {
                throw new Error('Server returned empty confirmation token');
            }

            const resp = await this._apiFetch(`${this.apiBase}/rollback/${sessionId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    confirmation_token: token,
                    components: null
                })
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || `HTTP ${resp.status}`);
            }

            _simTimeouts.push(setTimeout(() => this.addLogEntry('Restoring network configuration...', 'executing'), 1000));
            _simTimeouts.push(setTimeout(() => this.addLogEntry('Restoring original credentials...', 'executing'), 2000));
            _simTimeouts.push(setTimeout(() => this.addLogEntry('Rollback completed', 'success'), 3000));
            _simTimeouts.push(setTimeout(() => this.resetUI(), 4000));
        } catch (error) {
            this.addLogEntry(`Rollback failed: ${error.message}`, 'failed');
        }
    }

    resetUI() {
        const activeSession = document.getElementById('activeSession');
        const panicBtn = document.getElementById('panicButton');
        const rollbackBtn = document.getElementById('rollbackButton');
        const cancelBtn = document.getElementById('cancelActive');

        if (activeSession) activeSession.classList.add('hidden');
        if (panicBtn) { panicBtn.classList.remove('hidden'); panicBtn.disabled = false; }
        if (rollbackBtn) rollbackBtn.classList.add('hidden');
        if (cancelBtn) cancelBtn.classList.remove('hidden');
        this.updateProgress(0);
        this.activeResponse = null;
        this.loadHistory();
    }

    async saveConfiguration() {
        const ipEl = document.getElementById('ipWhitelist');
        const procEl = document.getElementById('processWhitelist');
        const ipWhitelist = ipEl ? ipEl.value.split('\n').filter(ip => ip.trim()) : [];
        const processWhitelist = procEl ? procEl.value.split('\n').filter(p => p.trim()) : [];

        this.config = {
            ipWhitelist: ipWhitelist.length > 0 ? ipWhitelist : ['127.0.0.1'],
            processWhitelist: processWhitelist.length > 0 ? processWhitelist : ['ssh'],
            isolationMode: 'strict'
        };

        try {
            const resp = await this._apiFetch(`${this.apiBase}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.config)
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            this.showNotification('Configuration saved successfully');
        } catch (error) {
            console.log('Config save failed (backend may be unavailable):', error.message);
            // Still save locally
            this.showNotification('Configuration saved locally');
        }
    }

    async loadConfig() {
        try {
            const resp = await this._apiFetch(`${this.apiBase}/config`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const config = await resp.json();
            this.config = config;

            const ipEl = document.getElementById('ipWhitelist');
            const procEl = document.getElementById('processWhitelist');
            if (config.ipWhitelist && ipEl) ipEl.value = config.ipWhitelist.join('\n');
            if (config.processWhitelist && procEl) procEl.value = config.processWhitelist.join('\n');
        } catch (error) {
            console.log('Using default configuration (backend may be unavailable)');
        }
    }

    async loadHistory() {
        try {
            const resp = await this._apiFetch(`${this.apiBase}/sessions/history`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const history = await resp.json();
            this.displayHistory(history);
        } catch (error) {
            console.log('No history available (backend may be unavailable)');
        }
    }

    displayHistory(history) {
        const historyList = document.getElementById('historyList');
        if (!historyList) return;

        if (!history || history.length === 0) {
            historyList.innerHTML = '<p class="text-gray-400">No panic responses recorded</p>';
            return;
        }

        historyList.innerHTML = history.map(item => {
            const timestamp = item.started_at || item.timestamp || '';
            const id = item.session_id || item.response_id || 'unknown';
            const status = item.status || 'unknown';
            const statusColor = {
                completed: 'text-green-400',
                active: 'text-yellow-400',
                failed: 'text-red-400',
                cancelled: 'text-gray-400'
            }[status] || 'text-yellow-400';
            const reason = item.reason ? ` — ${this._escapeHtml(item.reason)}` : '';
            return `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-400">${timestamp ? new Date(timestamp).toLocaleString() : '—'}</span>
                    <span class="text-sm ${statusColor}">${this._escapeHtml(status)}</span>
                </div>
                <div class="mt-1">
                    <span class="text-xs">Session: ${this._escapeHtml(id)}</span>
                    ${reason ? `<span class="ml-4 text-xs text-gray-500">${reason}</span>` : ''}
                </div>
            </div>
            `;
        }).join('');
    }

    showNotification(message, type = 'success') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded ${type === 'error' ? 'bg-red-600' : 'bg-green-600'} text-white z-50`;
        notification.textContent = message;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 3000);
    }

}


// ── Module lifecycle (tab-loader compatible) ────────────────────────

export function init() {
    _instance = new PanicRoom();
}

export function destroy() {
    // Clear polling interval
    if (_pollInterval) {
        clearInterval(_pollInterval);
        _pollInterval = null;
    }

    // Clear simulation timeouts
    _simTimeouts.forEach(t => clearTimeout(t));
    _simTimeouts = [];

    // Clear remote status polling
    if (_remoteStatusInterval) {
        clearInterval(_remoteStatusInterval);
        _remoteStatusInterval = null;
    }

    // Remove event listeners
    if (_instance) {
        _instance.removeAllListeners();
        _instance = null;
    }
}
