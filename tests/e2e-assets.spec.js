/**
 * E2E: Assets Tab
 *
 * Tests asset table rendering, filter controls, pagination,
 * add-asset modal, detail panel, invite modal, and stat pills.
 */
import { test, expect } from '@playwright/test';

test.describe('Assets Tab', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);
    await page.locator('#tab-btn-assets').click();
    await page.waitForTimeout(1000);
  });

  test('asset table and headers are rendered', async ({ page }) => {
    const table = page.locator('#asset-table');
    await expect(table).toBeAttached();

    // Check sortable columns
    const sortableHeaders = page.locator('#asset-table thead th[data-sort]');
    const count = await sortableHeaders.count();
    expect(count).toBeGreaterThanOrEqual(4); // name, status, threat_level, last_event, event_count
  });

  test('filter controls are present', async ({ page }) => {
    // Search input
    const search = page.locator('#search-input');
    await expect(search).toBeAttached();

    // Status filter
    const statusFilter = page.locator('#filter-status');
    await expect(statusFilter).toBeAttached();

    // Threat level filter
    const threatFilter = page.locator('#filter-threat');
    await expect(threatFilter).toBeAttached();
  });

  test('stat pills show online, protected, and total counts', async ({ page }) => {
    const stats = ['stat-online', 'stat-protected', 'stat-total'];
    for (const id of stats) {
      const el = page.locator(`#${id}`);
      await expect(el).toBeAttached();
    }
  });

  test('add asset button is visible', async ({ page }) => {
    const addBtn = page.locator('#add-asset-btn');
    await expect(addBtn).toBeAttached();
  });

  test('clicking add-asset opens the invite modal', async ({ page }) => {
    const addBtn = page.locator('#add-asset-btn');
    await addBtn.click();
    await page.waitForTimeout(500);

    // Invite modal overlay should be visible (add-asset opens invite flow)
    const modal = page.locator('#invite-modal-overlay');
    await expect(modal).toHaveClass(/open/);
  });

  test('invite modal cancel button closes the modal', async ({ page }) => {
    // Open invite modal via add-asset button
    await page.locator('#add-asset-btn').click();
    await page.waitForTimeout(500);
    await expect(page.locator('#invite-modal-overlay')).toHaveClass(/open/);

    // Cancel
    await page.locator('#invite-cancel').click();
    await page.waitForTimeout(300);

    // Modal should be closed
    const classes = await page.locator('#invite-modal-overlay').getAttribute('class');
    expect(classes).not.toContain('open');
  });

  test('pagination controls are present', async ({ page }) => {
    await expect(page.locator('#page-prev')).toBeAttached();
    await expect(page.locator('#page-next')).toBeAttached();
    await expect(page.locator('#page-indicator')).toBeAttached();
    await expect(page.locator('#page-size-select')).toBeAttached();
  });

  test('detail panel is hidden by default', async ({ page }) => {
    const panel = page.locator('#detail-panel');
    await expect(panel).toBeAttached();
    const classes = await panel.getAttribute('class');
    expect(classes).not.toContain('open');
  });

  test('live badge is present', async ({ page }) => {
    const liveBadge = page.locator('#live-badge');
    await expect(liveBadge).toBeAttached();
  });

  test('invite modal has generate button and agent name field', async ({ page }) => {
    // Open invite modal
    await page.locator('#add-asset-btn').click();
    await page.waitForTimeout(500);

    // Generate button should exist
    const genBtn = page.locator('#invite-generate-btn');
    await expect(genBtn).toBeAttached();

    // Agent name input should exist
    const nameInput = page.locator('#invite-agent-name');
    await expect(nameInput).toBeAttached();
  });

});
