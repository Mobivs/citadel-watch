// PRD: Vault - Main Vault Manager
// Reference: docs/PRD.md v0.2.3, Section: Vault
//
// Coordinates vault unlock, password list, and password viewer

import { apiClient } from './utils/api-client.js';

class VaultManager {
    constructor() {
        this.isUnlocked = false;
        this.vaultExists = false;

        // Auto-lock timeout (15 minutes of inactivity)
        this.autoLockTimeout = null;
        this.autoLockDelay = 15 * 60 * 1000; // 15 minutes in milliseconds
    }

    async init() {
        console.log('🔐 Initializing Vault...');

        // Initialize API client (fetch session token)
        await apiClient.initialize();

        // Check vault status
        await this.checkStatus();

        // Setup components
        this.setupComponents();

        // Setup event listeners
        this.setupEventListeners();
    }

    async checkStatus() {
        try {
            const response = await apiClient.get('/api/vault/status');
            if (response.ok) {
                const status = await response.json();
                this.isUnlocked = status.is_unlocked;
                this.vaultExists = status.vault_exists;

                console.log(`Vault status: exists=${this.vaultExists}, unlocked=${this.isUnlocked}`);
            }
        } catch (error) {
            console.error('Failed to check vault status:', error);
        }
    }

    setupComponents() {
        // Get component references
        this.unlockModal = document.querySelector('vault-unlock');
        this.passwordList = document.querySelector('vault-password-list');
        this.passwordViewer = document.querySelector('vault-password-viewer');

        // Show appropriate UI
        this.updateUI();
    }

    setupEventListeners() {
        // Vault unlocked
        window.addEventListener('vault-unlocked', () => {
            console.log('✅ Vault unlocked!');
            this.isUnlocked = true;
            this.startAutoLock();  // Start auto-lock timer
            this.updateUI();
        });

        // Reset auto-lock timer on user activity
        const resetTimer = () => this.resetAutoLock();
        document.addEventListener('click', resetTimer);
        document.addEventListener('keydown', resetTimer);
        document.addEventListener('mousemove', resetTimer);

        // Password selected (view)
        window.addEventListener('password-selected', (e) => {
            if (this.passwordViewer) {
                this.passwordViewer.showView(e.detail.id);
            }
        });

        // Password added
        window.addEventListener('password-added', () => {
            console.log('✅ Password added to vault');
        });

        // Password deleted
        window.addEventListener('password-deleted', () => {
            console.log('🗑️ Password deleted from vault');
        });

        // Add password button
        const addBtn = document.getElementById('add-password-btn');
        if (addBtn) {
            addBtn.addEventListener('click', () => {
                if (this.isUnlocked && this.passwordViewer) {
                    this.passwordViewer.showAdd();
                } else {
                    this.showUnlock();
                }
            });
        }

        // Unlock vault button
        const unlockBtn = document.getElementById('unlock-vault-btn');
        if (unlockBtn) {
            unlockBtn.addEventListener('click', () => {
                this.showUnlock();
            });
        }

        // Lock vault button
        const lockBtn = document.getElementById('lock-vault-btn');
        if (lockBtn) {
            lockBtn.addEventListener('click', async () => {
                await this.lockVault();
            });
        }
    }

    updateUI() {
        const vaultSection = document.getElementById('vault-section');
        const lockedState = document.getElementById('vault-locked-state');
        const unlockedState = document.getElementById('vault-unlocked-state');

        if (!vaultSection) return;

        if (this.isUnlocked) {
            // Show unlocked UI
            if (lockedState) lockedState.classList.add('hidden');
            if (unlockedState) unlockedState.classList.remove('hidden');

            // Load passwords
            if (this.passwordList) {
                this.passwordList.loadPasswords();
            }
        } else {
            // Show locked UI
            if (lockedState) lockedState.classList.remove('hidden');
            if (unlockedState) unlockedState.classList.add('hidden');
        }
    }

    showUnlock() {
        if (this.unlockModal) {
            this.unlockModal.show();
        }
    }

    async lockVault() {
        try {
            const response = await apiClient.post('/api/vault/lock', {});
            if (response.ok) {
                this.isUnlocked = false;
                this.stopAutoLock();  // Clear timeout when manually locked
                this.updateUI();
                console.log('🔒 Vault locked');
            }
        } catch (error) {
            console.error('Failed to lock vault:', error);
        }
    }

    /**
     * Security: Auto-lock timeout
     * Automatically locks vault after 15 minutes of inactivity
     */
    startAutoLock() {
        this.stopAutoLock();  // Clear any existing timeout

        this.autoLockTimeout = setTimeout(async () => {
            if (this.isUnlocked) {
                console.log('⏰ Auto-locking vault after inactivity...');
                await this.lockVault();
                alert('Vault auto-locked after 15 minutes of inactivity');
            }
        }, this.autoLockDelay);
    }

    resetAutoLock() {
        if (this.isUnlocked) {
            this.startAutoLock();  // Reset the timer
        }
    }

    stopAutoLock() {
        if (this.autoLockTimeout) {
            clearTimeout(this.autoLockTimeout);
            this.autoLockTimeout = null;
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
    const vaultManager = new VaultManager();
    await vaultManager.init();

    // Make accessible globally for debugging
    window.vault = vaultManager;
});

console.log('🔐 Vault module loaded');
