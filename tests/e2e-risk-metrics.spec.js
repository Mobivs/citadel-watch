/**
 * E2E: Risk Metrics Tab
 *
 * Tests threat counter cards, gauge, trend chart, asset risk chart,
 * sensitivity controls, and sparkline containers.
 */
import { test, expect } from '@playwright/test';

test.describe('Risk Metrics Tab', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);
    await page.locator('#tab-btn-risk-metrics').click();
    await page.waitForTimeout(1000);
  });

  test('threat counter cards display all four severity levels', async ({ page }) => {
    const counters = [
      { id: 'count-critical', label: 'Critical' },
      { id: 'count-high', label: 'High' },
      { id: 'count-medium', label: 'Medium' },
      { id: 'count-low', label: 'Low' },
    ];

    for (const { id } of counters) {
      const counter = page.locator(`#${id}`);
      await expect(counter).toBeAttached();
      const text = await counter.textContent();
      expect(text).toBeTruthy();
    }
  });

  test('threat gauge canvas is rendered', async ({ page }) => {
    const gauge = page.locator('#threat-gauge');
    await expect(gauge).toBeAttached();

    // Gauge value text shows a percentage
    const valueText = page.locator('#gauge-value-text');
    await expect(valueText).toBeAttached();
    const text = await valueText.textContent();
    expect(text).toMatch(/%/);

    // Zone text
    const zoneText = page.locator('#gauge-zone-text');
    await expect(zoneText).toBeAttached();
  });

  test('sensitivity selector buttons are present and one is active', async ({ page }) => {
    const selector = page.locator('#sensitivity-selector');
    await expect(selector).toBeAttached();

    // All three buttons
    const buttons = page.locator('#sensitivity-selector .sens-btn');
    const count = await buttons.count();
    expect(count).toBe(3);

    // Moderate is active by default
    const activeBtn = page.locator('#sensitivity-selector .sens-btn.active');
    const text = await activeBtn.textContent();
    expect(text.toLowerCase()).toContain('moderate');
  });

  test('clicking a sensitivity button changes the active state', async ({ page }) => {
    const highBtn = page.locator('#sensitivity-selector .sens-btn[data-sensitivity="high"]');
    await highBtn.click();
    await page.waitForTimeout(300);

    await expect(highBtn).toHaveClass(/active/);

    // Moderate should no longer be active
    const modBtn = page.locator('#sensitivity-selector .sens-btn[data-sensitivity="moderate"]');
    const classes = await modBtn.getAttribute('class');
    expect(classes).not.toContain('active');
  });

  test('trend chart and asset risk chart canvases are rendered', async ({ page }) => {
    const trendChart = page.locator('#trend-chart');
    await expect(trendChart).toBeAttached();

    const assetChart = page.locator('#asset-risk-chart');
    await expect(assetChart).toBeAttached();
  });

  test('sparkline containers exist for each severity level', async ({ page }) => {
    const sparklines = [
      'sparkline-critical',
      'sparkline-high',
      'sparkline-medium',
      'sparkline-low',
    ];

    for (const id of sparklines) {
      const container = page.locator(`#${id}`);
      await expect(container).toBeAttached();
    }
  });

  test('live badge is present', async ({ page }) => {
    const liveBadge = page.locator('#live-badge');
    await expect(liveBadge).toBeAttached();
  });

});
