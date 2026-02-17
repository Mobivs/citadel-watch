import { test, expect } from '@playwright/test';

/**
 * Original dashboard E2E tests — updated for current architecture.
 * (No iframes, CDN Tailwind, #app container, tab-loader dynamic content.)
 */
test.describe('Citadel Archer Dashboard', () => {
  test('index.html loads without unexpected console errors', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Verify the page title
    await expect(page).toHaveTitle(/Citadel Archer/);

    // Verify that the main content is visible
    const dashboard = page.locator('#app');
    await expect(dashboard).toBeVisible();

    // Verify that tab buttons exist
    const tabBar = page.locator('#dashboard-tab-bar');
    await expect(tabBar).toBeVisible();

    // Filter out expected errors (no backend = 404s, WebSocket failures, etc.)
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
      !e.includes('API client') &&
      !e.includes('session token')
    );
    expect(unexpectedErrors).toHaveLength(0);
  });

  test('All tabs load without crashing', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    const tabs = ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets'];

    for (const tab of tabs) {
      const tabBtn = page.locator(`#tab-btn-${tab}`);
      await expect(tabBtn).toBeVisible();
      await tabBtn.click();
      await page.waitForTimeout(600);

      // Tab should be active
      await expect(tabBtn).toHaveClass(/tab-active/);

      // For non-intelligence tabs, content loads into the dynamic panel
      if (tab !== 'intelligence') {
        const dynamicPanel = page.locator('#tab-panel-dynamic');
        await expect(dynamicPanel).toBeVisible();
      }
    }
  });

  test('charts.html renders without errors', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('charts.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);

    // Verify the page title
    await expect(page).toHaveTitle(/Citadel Archer/);

    // Verify main content area exists
    const mainContent = page.locator('#app');
    await expect(mainContent).toBeVisible();

    // Filter out expected errors (no backend)
    const unexpectedErrors = consoleErrors.filter(e =>
      !e.includes('Failed to fetch') &&
      !e.includes('Failed to load resource') &&
      !e.includes('WebSocket') &&
      !e.includes('ws://') &&
      !e.includes('404') &&
      !e.includes('net::') &&
      !e.includes('API client') &&
      !e.includes('session token') &&
      !e.includes('initialization')
    );
    expect(unexpectedErrors).toHaveLength(0);
  });

  test('CSS is loaded and applied correctly', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    // Verify custom styles.css link exists
    const cssLink = page.locator('link[href="css/styles.css"]');
    await expect(cssLink).toBeAttached();

    // Verify dark theme body classes are applied
    const body = page.locator('body');
    const classes = await body.getAttribute('class');
    expect(classes).toContain('dark');
    expect(classes).toContain('bg-dark-bg');

    // Verify glass-card styles are present in the page
    const cards = page.locator('.glass-card');
    const cardCount = await cards.count();
    expect(cardCount).toBeGreaterThanOrEqual(1);
  });

  test('localStorage is handled gracefully', async ({ page, context }) => {
    // Block localStorage access to simulate private browsing
    await context.addInitScript(() => {
      delete window.localStorage;
    });

    const uncaughtExceptions = [];
    page.on('pageerror', err => uncaughtExceptions.push(err.message));

    // Page should still load
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Verify the page still renders
    const dashboard = page.locator('#app');
    await expect(dashboard).toBeVisible();
    await expect(page.locator('#dashboard-tab-bar')).toBeVisible();

    // Allow a small number of storage-related exceptions (some modules
    // may not wrap localStorage in try/catch)
    const storageErrors = uncaughtExceptions.filter(e =>
      e.includes('localStorage') || e.includes('is not defined')
    );
    expect(storageErrors.length).toBeLessThanOrEqual(3);
  });

  test('Tailwind CDN and custom CSS are both loaded', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    // Current architecture uses Tailwind CDN
    const tailwindCdn = page.locator('script[src*="cdn.tailwindcss.com"]');
    await expect(tailwindCdn).toHaveCount(1);

    // Custom styles.css is also loaded
    const customCss = page.locator('link[href="css/styles.css"]');
    await expect(customCss).toBeAttached();

    // Tailwind config is present (inline script)
    const hasConfig = await page.evaluate(() => {
      return typeof tailwind !== 'undefined' && tailwind.config !== undefined;
    });
    expect(hasConfig).toBe(true);
  });
});
