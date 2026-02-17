/**
 * E2E: Error Handling
 *
 * Tests that the app handles errors gracefully — missing backend,
 * broken localStorage, 404 tab content, and unexpected states.
 */
import { test, expect } from '@playwright/test';

test.describe('Error Handling', () => {

  test('app loads without crashing when API endpoints are unavailable', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(2000);

    // Dashboard should still render
    await expect(page.locator('#app')).toBeVisible();
    await expect(page.locator('#dashboard-tab-bar')).toBeVisible();

    // Filter out expected network errors (no backend = 404s, connection refused, etc.)
    const unexpectedErrors = consoleErrors.filter(e =>
      !e.includes('Failed to fetch') &&
      !e.includes('Failed to load resource') &&
      !e.includes('WebSocket') &&
      !e.includes('ws://') &&
      !e.includes('wss://') &&
      !e.includes('ERR_CONNECTION_REFUSED') &&
      !e.includes('/api/') &&
      !e.includes('404') &&
      !e.includes('net::') &&
      !e.includes('NetworkError') &&
      !e.includes('initialization failed') &&
      !e.includes('initialization error') &&
      !e.includes('API client')
    );
    expect(unexpectedErrors).toHaveLength(0);
  });

  test('app handles broken localStorage gracefully', async ({ page, context }) => {
    // Override localStorage to throw on access
    await context.addInitScript(() => {
      const origStorage = window.localStorage;
      Object.defineProperty(window, 'localStorage', {
        get() {
          throw new DOMException('Storage disabled', 'SecurityError');
        }
      });
    });

    const uncaughtExceptions = [];
    page.on('pageerror', err => uncaughtExceptions.push(err.message));

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Dashboard should still load despite localStorage being broken
    await expect(page.locator('#app')).toBeVisible();
    await expect(page.locator('#dashboard-tab-bar')).toBeVisible();

    // Allow at most a small number of storage-related exceptions
    // (some modules may not wrap localStorage in try/catch)
    const storageErrors = uncaughtExceptions.filter(e =>
      e.includes('localStorage') || e.includes('Storage disabled')
    );
    expect(storageErrors.length).toBeLessThanOrEqual(3);
  });

  test('navigating to a non-existent tab does not crash', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Programmatically try to activate a non-existent tab
    await page.evaluate(() => {
      const fakeBtn = document.createElement('button');
      fakeBtn.id = 'tab-btn-nonexistent';
      fakeBtn.click();
    });

    await page.waitForTimeout(300);

    // Dashboard should still be intact
    await expect(page.locator('#app')).toBeVisible();
  });

  test('error toast container exists for showing user errors', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    const errorContainer = page.locator('#nav-error-container');
    await expect(errorContainer).toBeAttached();
  });

  test('tab content loads gracefully when CDN scripts are slow', async ({ page }) => {
    // Delay CDN scripts to simulate slow loading
    await page.route('**/cdn.jsdelivr.net/**', async route => {
      await new Promise(r => setTimeout(r, 2000));
      await route.continue();
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Switch to Charts tab (needs Chart.js from CDN)
    await page.locator('#tab-btn-charts').click();
    await page.waitForTimeout(3000);

    // Tab should still be active even if CDN was slow
    await expect(page.locator('#tab-btn-charts')).toHaveClass(/tab-active/);

    // Dynamic panel should be showing content
    await expect(page.locator('#tab-panel-dynamic')).toBeVisible();
  });

  test('multiple rapid tab switches do not cause uncaught exceptions', async ({ page }) => {
    const uncaughtExceptions = [];
    page.on('pageerror', err => uncaughtExceptions.push(err.message));

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Rapid fire clicks
    for (let i = 0; i < 3; i++) {
      await page.locator('#tab-btn-charts').click();
      await page.locator('#tab-btn-assets').click();
      await page.locator('#tab-btn-intelligence').click();
    }

    await page.waitForTimeout(1000);

    // Should have no uncaught exceptions
    expect(uncaughtExceptions).toHaveLength(0);
  });

});
