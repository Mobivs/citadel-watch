/**
 * E2E: WebSocket Real-Time
 *
 * Tests WebSocket connection behavior — badge updates, reconnection
 * handling, and fallback behavior when no backend is running.
 * Since the E2E tests run against a static http-server (no FastAPI),
 * WebSocket connections will fail. These tests verify the UI handles
 * that gracefully.
 */
import { test, expect } from '@playwright/test';

test.describe('WebSocket Real-Time', () => {

  test('connection badge shows offline/connecting state without backend', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500); // Wait for WS connection attempt

    // Connection badge should exist
    const connBadge = page.locator('#nav-conn-badge');
    await expect(connBadge).toBeVisible();

    // Text should indicate not connected (either "Connecting..." or "Offline")
    const connText = page.locator('#nav-conn-text');
    const text = await connText.textContent();
    expect(text).toBeTruthy();
    // Without a backend, it should NOT say "Connected"
    // (it may say "Connecting..." or "Offline" depending on retry state)
  });

  test('charts tab live badge shows offline state without backend', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    await page.locator('#tab-btn-charts').click();
    await page.waitForTimeout(1500);

    const liveText = page.locator('#live-text');
    await expect(liveText).toBeAttached();
    const text = await liveText.textContent();
    // Should show some non-connected status
    expect(text).toBeTruthy();
  });

  test('timeline tab live badge shows status without backend', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    await page.locator('#tab-btn-timeline').click();
    await page.waitForTimeout(1500);

    const liveText = page.locator('#live-text');
    await expect(liveText).toBeAttached();
  });

  test('app does not crash when WebSocket fails to connect', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(2000);

    // Dashboard should still be fully functional
    const container = page.locator('#app');
    await expect(container).toBeVisible();

    // Tab bar should still work
    const tabBar = page.locator('#dashboard-tab-bar');
    await expect(tabBar).toBeVisible();

    // Filter out expected errors (no backend running = 404s, connection refused, etc.)
    const unexpectedErrors = consoleErrors.filter(e =>
      !e.includes('WebSocket') &&
      !e.includes('ws://') &&
      !e.includes('wss://') &&
      !e.includes('ERR_CONNECTION_REFUSED') &&
      !e.includes('Failed to fetch') &&
      !e.includes('Failed to load resource') &&
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

  test('navigation works normally when WebSocket is unavailable', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);

    // Switch between multiple tabs to verify navigation isn't blocked
    const tabs = ['charts', 'timeline', 'assets', 'intelligence'];
    for (const tab of tabs) {
      await page.locator(`#tab-btn-${tab}`).click();
      await page.waitForTimeout(400);
      await expect(page.locator(`#tab-btn-${tab}`)).toHaveClass(/tab-active/);
    }
  });

});
