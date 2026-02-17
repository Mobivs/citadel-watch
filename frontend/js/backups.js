/**
 * Backups module — create, list, restore, and delete encrypted backups.
 * v0.3.33: Local backup + restore. Off-site push deferred.
 *
 * Lifecycle: init() on tab load, destroy() on tab switch.
 */

import { apiClient } from './utils/api-client.js';

let _backups = [];
let _refreshInterval = null;

// ── Init / Destroy ──────────────────────────────────────────────────

export function init() {
    wireButtons();
    loadBackups();
}

export function destroy() {
    if (_refreshInterval) {
        clearInterval(_refreshInterval);
        _refreshInterval = null;
    }
    _backups = [];
}

// ── Data Loading ────────────────────────────────────────────────────

async function loadBackups() {
    try {
        const resp = await apiClient.get('/api/backups');
        _backups = resp.backups || [];
        renderBackups();
        updateStats();
    } catch (e) {
        console.error('Failed to load backups:', e);
    }
}

// ── Rendering ───────────────────────────────────────────────────────

function renderBackups() {
    const tbody = document.getElementById('backup-table-body');
    const table = document.getElementById('backup-table');
    const empty = document.getElementById('backup-empty');
    if (!tbody || !table || !empty) return;

    if (_backups.length === 0) {
        table.style.display = 'none';
        empty.style.display = 'block';
        return;
    }

    table.style.display = 'table';
    empty.style.display = 'none';

    tbody.innerHTML = _backups.map(b => {
        const statusClass = b.status === 'complete' ? 'status-complete'
            : b.status === 'deleted' ? 'status-deleted' : 'status-corrupt';
        const safeId = (b.backup_id || '').replace(/[^a-zA-Z0-9_-]/g, '');
        const safeLabel = escapeHtml(b.label || 'Untitled');
        const actions = b.status === 'complete'
            ? `<button class="action-btn" onclick="window._backupRestore('${safeId}')">Restore</button>`
              + `<button class="action-btn danger" onclick="window._backupDelete('${safeId}')">Delete</button>`
            : '';

        return `<tr>
            <td>${safeLabel}</td>
            <td>${formatDate(b.created_at)}</td>
            <td>${formatBytes(b.size_bytes || 0)}</td>
            <td>${b.db_count || 0}</td>
            <td><span class="status-chip ${statusClass}">${escapeHtml(b.status)}</span></td>
            <td>${actions}</td>
        </tr>`;
    }).join('');
}

function updateStats() {
    const totalEl = document.getElementById('backup-stat-total');
    const lastEl = document.getElementById('backup-stat-last');
    const sizeEl = document.getElementById('backup-stat-size');

    const active = _backups.filter(b => b.status === 'complete');
    if (totalEl) totalEl.textContent = active.length;

    if (lastEl) {
        if (active.length > 0) {
            lastEl.textContent = formatDate(active[0].created_at);
        } else {
            lastEl.textContent = 'Never';
        }
    }

    if (sizeEl) {
        const total = active.reduce((s, b) => s + (b.size_bytes || 0), 0);
        sizeEl.textContent = formatBytes(total);
    }
}

// ── Button Wiring ───────────────────────────────────────────────────

function wireButtons() {
    const createBtn = document.getElementById('backup-create-btn');
    if (createBtn) createBtn.addEventListener('click', openCreateModal);

    const cancelCreate = document.getElementById('backup-create-cancel');
    if (cancelCreate) cancelCreate.addEventListener('click', closeCreateModal);

    const submitCreate = document.getElementById('backup-create-submit');
    if (submitCreate) submitCreate.addEventListener('click', handleCreateBackup);

    const cancelRestore = document.getElementById('backup-restore-cancel');
    if (cancelRestore) cancelRestore.addEventListener('click', closeRestoreModal);

    const submitRestore = document.getElementById('backup-restore-submit');
    if (submitRestore) submitRestore.addEventListener('click', handleRestoreBackup);

    // Global handlers for table action buttons
    window._backupRestore = openRestoreModal;
    window._backupDelete = handleDeleteBackup;
}

// ── Create Backup ───────────────────────────────────────────────────

function openCreateModal() {
    const modal = document.getElementById('backup-create-modal');
    const passEl = document.getElementById('backup-passphrase');
    const labelEl = document.getElementById('backup-label');
    const errEl = document.getElementById('backup-create-error');
    if (modal) modal.classList.add('active');
    if (passEl) passEl.value = '';
    if (labelEl) labelEl.value = '';
    if (errEl) errEl.style.display = 'none';
}

function closeCreateModal() {
    const modal = document.getElementById('backup-create-modal');
    if (modal) modal.classList.remove('active');
}

async function handleCreateBackup() {
    const passEl = document.getElementById('backup-passphrase');
    const labelEl = document.getElementById('backup-label');
    const errEl = document.getElementById('backup-create-error');
    const submitBtn = document.getElementById('backup-create-submit');

    const passphrase = passEl ? passEl.value : '';
    const label = labelEl ? labelEl.value.trim() : '';

    if (passphrase.length < 12) {
        showError(errEl, 'Passphrase must be at least 12 characters.');
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner"></span> Creating...';
    }

    try {
        await apiClient.post('/api/backups', { passphrase, label });
        closeCreateModal();
        await loadBackups();
    } catch (e) {
        const msg = e.detail || e.message || 'Backup creation failed.';
        showError(errEl, msg);
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Backup';
        }
    }
}

// ── Restore Backup ──────────────────────────────────────────────────

function openRestoreModal(backupId) {
    const modal = document.getElementById('backup-restore-modal');
    const passEl = document.getElementById('backup-restore-passphrase');
    const idEl = document.getElementById('backup-restore-id');
    const errEl = document.getElementById('backup-restore-error');
    if (modal) modal.classList.add('active');
    if (passEl) passEl.value = '';
    if (idEl) idEl.value = backupId;
    if (errEl) errEl.style.display = 'none';
}

function closeRestoreModal() {
    const modal = document.getElementById('backup-restore-modal');
    if (modal) modal.classList.remove('active');
}

async function handleRestoreBackup() {
    const passEl = document.getElementById('backup-restore-passphrase');
    const idEl = document.getElementById('backup-restore-id');
    const errEl = document.getElementById('backup-restore-error');
    const submitBtn = document.getElementById('backup-restore-submit');

    const passphrase = passEl ? passEl.value : '';
    const backupId = idEl ? idEl.value : '';

    if (passphrase.length < 12) {
        showError(errEl, 'Passphrase must be at least 12 characters.');
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner"></span> Restoring...';
    }

    try {
        const result = await apiClient.post(`/api/backups/${backupId}/restore`, { passphrase });
        closeRestoreModal();
        const dbs = (result.restored_dbs || []).join(', ');
        alert(`Restore complete. Databases restored: ${dbs}\nPre-restore backup ID: ${result.pre_restore_backup_id || 'N/A'}`);
        await loadBackups();
    } catch (e) {
        const msg = e.detail || e.message || 'Restore failed. Check passphrase.';
        showError(errEl, msg);
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Restore';
        }
    }
}

// ── Delete Backup ───────────────────────────────────────────────────

async function handleDeleteBackup(backupId) {
    if (!confirm('Delete this backup permanently?')) return;

    try {
        await apiClient.delete(`/api/backups/${backupId}`);
        await loadBackups();
    } catch (e) {
        alert('Failed to delete backup: ' + (e.detail || e.message));
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const val = bytes / Math.pow(1024, i);
    return val.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function formatDate(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_e) {
        return iso;
    }
}

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function showError(el, msg) {
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
}
