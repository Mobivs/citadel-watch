/**
 * E2E: Charts Tab
 *
 * Tests chart rendering, time range controls, summary stats cards,
 * and live-status badge behavior.
 */
import { test, expect } from '@playwright/test';

test.describe('Charts Tab', () => {

  test.beforeEach(async ({ page }) => {
    // Navigate to index and switch to Charts tab
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);
    await page.locator('#tab-btn-charts').click();
    await page.waitForTimeout(1000);
  });

  test('all four chart canvases are rendered', async ({ page }) => {
    const canvasIds = [
      'threat-trend-chart',
      'severity-distribution-chart',
      'timeline-scatter-chart',
      'category-breakdown-chart',
    ];

    for (const id of canvasIds) {
      const canvas = page.locator(`#${id}`);
      await expect(canvas).toBeAttached();
    }
  });

  test('time range buttons are visible and one is active', async ({ page }) => {
    const timeSelector = page.locator('#time-range-selector');
    await expect(timeSelector).toBeAttached();

    // At least one time button should have the active class
    const activeBtn = page.locator('#time-range-selector .time-btn.active');
    await expect(activeBtn).toBeAttached();

    // Default active should be 24h
    const activeText = await activeBtn.textContent();
    expect(activeText).toBe('24h');
  });

  test('clicking a time range button switches the active state', async ({ page }) => {
    // Click the 7d button
    const btn7d = page.locator('#time-range-selector .time-btn[data-hours="168"]');
    await btn7d.click();
    await page.waitForTimeout(300);

    // 7d should be active
    await expect(btn7d).toHaveClass(/active/);

    // 24h should no longer be active
    const btn24h = page.locator('#time-range-selector .time-btn[data-hours="24"]');
    const classes = await btn24h.getAttribute('class');
    expect(classes).not.toContain('active');
  });

  test('summary stat cards are present', async ({ page }) => {
    const statIds = ['stat-total', 'stat-critical', 'stat-high', 'stat-medium'];
    for (const id of statIds) {
      const stat = page.locator(`#${id}`);
      await expect(stat).toBeAttached();
    }
  });

  test('live badge is visible with status text', async ({ page }) => {
    const liveBadge = page.locator('#live-badge');
    await expect(liveBadge).toBeAttached();

    const liveText = page.locator('#live-text');
    await expect(liveText).toBeAttached();
    const text = await liveText.textContent();
    expect(text).toBeTruthy();
  });

  test('chart canvases have accessible aria labels', async ({ page }) => {
    const chartConfigs = [
      { id: 'threat-trend-chart', label: /[Tt]hreat/ },
      { id: 'severity-distribution-chart', label: /[Ss]everity/ },
      { id: 'timeline-scatter-chart', label: /[Tt]imeline|[Ee]vent/ },
      { id: 'category-breakdown-chart', label: /[Cc]ategory/ },
    ];

    for (const { id, label } of chartConfigs) {
      const canvas = page.locator(`#${id}`);
      const ariaLabel = await canvas.getAttribute('aria-label');
      expect(ariaLabel).toMatch(label);
    }
  });

});
