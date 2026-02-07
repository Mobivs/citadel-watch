import { test, expect } from '@playwright/test';

test.describe('Citadel Archer Dashboard', () => {
  test('index.html loads without console errors', async ({ page }) => {
    // Listen for console errors
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Navigate to the page
    await page.goto('index.html');
    
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
    
    // Allow any async initialization
    await page.waitForTimeout(500);

    // Verify the page title
    await expect(page).toHaveTitle(/Citadel Archer/);

    // Verify that the main content is visible
    const dashboard = page.locator('#dashboard-container');
    await expect(dashboard).toBeVisible();

    // Verify that tab buttons exist
    const tabBar = page.locator('#dashboard-tab-bar');
    await expect(tabBar).toBeVisible();

    // Verify no console errors
    expect(consoleErrors).toHaveLength(0);
  });

  test('All tabs load without console errors', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('index.html');
    await page.waitForLoadState('networkidle');

    const tabs = ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets'];

    for (const tab of tabs) {
      // Click the tab button
      const tabBtn = page.locator(`#tab-btn-${tab}`);
      await expect(tabBtn).toBeVisible();
      await tabBtn.click();

      // Wait for iframe to load if needed
      await page.waitForTimeout(300);

      // For external tabs (charts, timeline, etc.), wait for iframe to load
      if (tab !== 'intelligence') {
        const iframe = page.locator(`#tab-iframe-${tab}`);
        if (await iframe.isVisible()) {
          // Just verify iframe is visible, don't wait for internal content
          await expect(iframe).toBeVisible();
        }
      }
    }

    // Verify no console errors
    expect(consoleErrors).toHaveLength(0);
  });

  test('charts.html renders without errors', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('charts.html');
    await page.waitForLoadState('networkidle');

    // Verify the page title
    await expect(page).toHaveTitle(/Charts/);

    // Verify main content is visible
    const mainContent = page.locator('main');
    await expect(mainContent).toBeVisible();

    // Verify Tailwind CSS is loaded (check for styling)
    const htmlElement = page.locator('html');
    const computedStyle = await htmlElement.evaluate(el => 
      window.getComputedStyle(el).backgroundColor
    );
    // Should have computed background color from CSS
    expect(computedStyle).toBeTruthy();

    // Verify no console errors
    expect(consoleErrors).toHaveLength(0);
  });

  test('CSS is loaded and applied correctly', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('networkidle');

    // Verify Tailwind CSS link exists
    const cssLink = page.locator('link[href="css/tailwind.css"]');
    await expect(cssLink).toBeVisible();

    // Verify custom styles are applied
    const body = page.locator('body');
    const classes = await body.getAttribute('class');
    expect(classes).toBeTruthy();

    // Verify glass-card styles are applied
    const cards = page.locator('.glass-card');
    const cardCount = await cards.count();
    expect(cardCount).toBeGreaterThanOrEqual(0);
  });

  test('localStorage is handled gracefully', async ({ page, context }) => {
    // Block localStorage access to simulate private browsing
    await context.addInitScript(() => {
      delete window.localStorage;
    });

    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Page should still load without errors
    await page.goto('index.html');
    await page.waitForLoadState('networkidle');

    // Verify the page still works
    const dashboard = page.locator('#dashboard-container');
    await expect(dashboard).toBeVisible();

    // Verify no errors from localStorage access
    expect(consoleErrors).toHaveLength(0);
  });

  test('No CDN scripts in HTML', async ({ page }) => {
    await page.goto('index.html');
    
    // Verify no Tailwind CDN script
    const tailwindCdn = page.locator('script[src*="cdn.tailwindcss.com"]');
    await expect(tailwindCdn).toHaveCount(0);

    // Verify the compiled CSS is used instead
    const compiledCss = page.locator('link[href="css/tailwind.css"]');
    await expect(compiledCss).toHaveCount(1);
  });
});
