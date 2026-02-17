/**
 * E2E: Tab Navigation
 *
 * Tests tab switching, active-tab highlighting, panel toggling,
 * localStorage persistence, and dynamic content loading via tab-loader.
 */
import { test, expect } from '@playwright/test';

test.describe('Tab Navigation', () => {

  test.beforeEach(async ({ page }) => {
    // Clear saved tab preference so tests start from a clean state
    await page.addInitScript(() => {
      try { localStorage.removeItem('citadel_active_tab'); } catch {}
    });
  });

  test('clicking a tab activates it and deactivates others', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Intelligence should be active by default
    await expect(page.locator('#tab-btn-intelligence')).toHaveClass(/tab-active/);

    // Click Charts tab
    await page.locator('#tab-btn-charts').click();
    await page.waitForTimeout(500);

    // Charts should now be active
    await expect(page.locator('#tab-btn-charts')).toHaveClass(/tab-active/);

    // Intelligence should no longer be active
    const intelClasses = await page.locator('#tab-btn-intelligence').getAttribute('class');
    expect(intelClasses).not.toContain('tab-active');
  });

  test('switching to a non-intelligence tab shows dynamic panel and hides intelligence panel', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Intelligence panel visible initially
    await expect(page.locator('#tab-panel-intelligence')).toBeVisible();

    // Click Timeline tab
    await page.locator('#tab-btn-timeline').click();
    await page.waitForTimeout(800);

    // Dynamic panel should now be visible
    const dynamicPanel = page.locator('#tab-panel-dynamic');
    await expect(dynamicPanel).toBeVisible();

    // Intelligence panel should be hidden
    await expect(page.locator('#tab-panel-intelligence')).toBeHidden();
  });

  test('switching back to intelligence tab shows intelligence panel', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Switch to Charts
    await page.locator('#tab-btn-charts').click();
    await page.waitForTimeout(500);
    await expect(page.locator('#tab-panel-intelligence')).toBeHidden();

    // Switch back to Intelligence
    await page.locator('#tab-btn-intelligence').click();
    await page.waitForTimeout(300);

    // Intelligence panel should be visible again
    await expect(page.locator('#tab-panel-intelligence')).toBeVisible();
  });

  test('tab selection persists to localStorage', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Click Assets tab
    await page.locator('#tab-btn-assets').click();
    await page.waitForTimeout(500);

    // Check localStorage was updated
    const savedTab = await page.evaluate(() => {
      try { return localStorage.getItem('citadel_active_tab'); } catch { return null; }
    });
    expect(savedTab).toBe('assets');
  });

  test('saved tab is restored on page reload', async ({ page, context }) => {
    // Use a fresh context without the beforeEach addInitScript clearing localStorage
    const freshPage = await context.newPage();
    await freshPage.goto('index.html');
    await freshPage.waitForLoadState('domcontentloaded');
    await freshPage.waitForTimeout(300);

    // Click Risk Metrics tab
    await freshPage.locator('#tab-btn-risk-metrics').click();
    await freshPage.waitForTimeout(500);

    // Verify localStorage was set
    const savedTab = await freshPage.evaluate(() => {
      try { return localStorage.getItem('citadel_active_tab'); } catch { return null; }
    });
    expect(savedTab).toBe('risk-metrics');

    // Reload the page (no addInitScript to clear localStorage)
    await freshPage.reload();
    await freshPage.waitForLoadState('domcontentloaded');
    await freshPage.waitForTimeout(800);

    // Risk Metrics should still be active
    await expect(freshPage.locator('#tab-btn-risk-metrics')).toHaveClass(/tab-active/);
    await freshPage.close();
  });

  test('each tab loads its HTML content into the dynamic panel', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Test a selection of tabs that load HTML content
    const tabTests = [
      { tab: 'charts', selector: '#threat-trend-chart' },
      { tab: 'timeline', selector: '#timeline-table' },
      { tab: 'risk-metrics', selector: '#threat-gauge' },
      { tab: 'assets', selector: '#asset-table' },
    ];

    for (const { tab, selector } of tabTests) {
      await page.locator(`#tab-btn-${tab}`).click();
      await page.waitForTimeout(800);

      // Check the dynamic panel has the expected element from that tab's HTML
      const el = page.locator(selector);
      await expect(el).toBeAttached({ timeout: 5000 });
    }
  });

  test('rapidly clicking multiple tabs does not break UI', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // Rapid tab switching
    await page.locator('#tab-btn-charts').click();
    await page.locator('#tab-btn-timeline').click();
    await page.locator('#tab-btn-assets').click();
    await page.locator('#tab-btn-intelligence').click();
    await page.waitForTimeout(500);

    // Should end on intelligence without errors
    await expect(page.locator('#tab-btn-intelligence')).toHaveClass(/tab-active/);
    await expect(page.locator('#tab-panel-intelligence')).toBeVisible();
  });

});
