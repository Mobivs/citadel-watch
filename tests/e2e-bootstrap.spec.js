/**
 * E2E: App Bootstrap & Session
 *
 * Tests that the dashboard loads correctly, core DOM structure is present,
 * and the app initializes without fatal errors.
 */
import { test, expect } from '@playwright/test';

test.describe('App Bootstrap & Session', () => {

  test('index.html loads and dashboard container renders', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    // Title contains Citadel Archer
    await expect(page).toHaveTitle(/Citadel Archer/);

    // Main app container is visible
    const container = page.locator('#app');
    await expect(container).toBeVisible();

    // Tab bar is rendered
    const tabBar = page.locator('#dashboard-tab-bar');
    await expect(tabBar).toBeVisible();
  });

  test('header contains branding, security badge, and connection indicator', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    // Branding text (use heading role to avoid strict mode violation)
    await expect(page.getByRole('heading', { name: 'Citadel Archer' })).toBeVisible();

    // Security level badge exists
    const secBadge = page.locator('#security-level-badge');
    await expect(secBadge).toBeVisible();

    // Connection badge
    const connBadge = page.locator('#nav-conn-badge');
    await expect(connBadge).toBeVisible();
    await expect(page.locator('#nav-conn-dot')).toBeVisible();
    await expect(page.locator('#nav-conn-text')).toBeVisible();
  });

  test('all tab buttons are present in the tab bar', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    const expectedTabs = [
      'intelligence', 'charts', 'timeline', 'risk-metrics',
      'assets', 'remote-shield', 'backup', 'performance',
      'panic-room',
    ];

    for (const tabId of expectedTabs) {
      const btn = page.locator(`#tab-btn-${tabId}`);
      await expect(btn).toBeAttached();
    }
  });

  test('intelligence tab is the default active tab', async ({ page }) => {
    // Clear any saved tab preference
    await page.addInitScript(() => {
      try { localStorage.removeItem('citadel_active_tab'); } catch {}
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Intelligence tab button should have active class
    const intelBtn = page.locator('#tab-btn-intelligence');
    await expect(intelBtn).toHaveClass(/tab-active/);

    // Intelligence panel should be visible
    const intelPanel = page.locator('#tab-panel-intelligence');
    await expect(intelPanel).toBeVisible();
  });

  test('dark theme is applied to body', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    const body = page.locator('body');
    const classes = await body.getAttribute('class');
    expect(classes).toContain('dark');
    expect(classes).toContain('bg-dark-bg');
  });

  test('vault shortcut button exists in header', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    const vaultBtn = page.locator('#vault-shortcut-btn');
    await expect(vaultBtn).toBeAttached();
  });

  test('settings button exists in header', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    const settingsBtn = page.locator('#settings-btn');
    await expect(settingsBtn).toBeVisible();
  });

  test('chat sidebar elements exist', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    // Chat toggle button
    await expect(page.locator('#chat-toggle-btn')).toBeAttached();

    // Chat sidebar container
    await expect(page.locator('#chat-sidebar')).toBeAttached();

    // Chat input and send button
    await expect(page.locator('#chat-input')).toBeAttached();
    await expect(page.locator('#chat-send-btn')).toBeAttached();
  });

});
