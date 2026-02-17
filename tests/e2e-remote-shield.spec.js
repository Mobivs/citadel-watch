/**
 * E2E: Remote Shield Tab
 *
 * Tests remote shield rendering — agent stats bar, agent panels,
 * heatmap grid, patch status, policy groups, threat timeline,
 * and simplified view.
 */
import { test, expect } from '@playwright/test';

test.describe('Remote Shield Tab', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);
    await page.locator('#tab-btn-remote-shield').click();
    await page.waitForTimeout(1000);
  });

  test('technical view renders with stats bar', async ({ page }) => {
    // Technical view should be visible by default
    const techView = page.locator('#rs-technical-view');
    await expect(techView).toBeAttached();

    // Stats values
    const stats = ['total-agents', 'active-agents', 'total-threats', 'critical-threats'];
    for (const id of stats) {
      const el = page.locator(`#${id}`);
      await expect(el).toBeAttached();
    }
  });

  test('agent panels container exists', async ({ page }) => {
    const container = page.locator('#agents-container');
    await expect(container).toBeAttached();
  });

  test('heatmap grid is rendered', async ({ page }) => {
    const heatmap = page.locator('#heatmap-grid');
    await expect(heatmap).toBeAttached();
  });

  test('patch status section exists', async ({ page }) => {
    const patchContainer = page.locator('#patch-status-container');
    await expect(patchContainer).toBeAttached();
  });

  test('threat timeline section exists', async ({ page }) => {
    const timeline = page.locator('#threat-timeline-container');
    await expect(timeline).toBeAttached();
  });

  test('policy groups section with add button exists', async ({ page }) => {
    const policyContainer = page.locator('#policy-groups-container');
    await expect(policyContainer).toBeAttached();

    const addBtn = page.locator('#add-policy-btn');
    await expect(addBtn).toBeAttached();
  });

  test('simplified view exists but is hidden initially', async ({ page }) => {
    const simplifiedView = page.locator('#rs-simplified-view');
    await expect(simplifiedView).toBeAttached();

    // Should be hidden (display: none)
    await expect(simplifiedView).toBeHidden();
  });

});
