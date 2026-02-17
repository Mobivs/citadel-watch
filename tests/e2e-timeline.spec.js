/**
 * E2E: Timeline Tab
 *
 * Tests the alert timeline table, D3 visualization, filters,
 * pagination, drill-down panel, and stat pills.
 */
import { test, expect } from '@playwright/test';

test.describe('Timeline Tab', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);
    await page.locator('#tab-btn-timeline').click();
    await page.waitForTimeout(1000);
  });

  test('timeline table and D3 visualization are rendered', async ({ page }) => {
    // Table
    const table = page.locator('#timeline-table');
    await expect(table).toBeAttached();

    // Table headers are present
    const headers = page.locator('#timeline-table thead th');
    const count = await headers.count();
    expect(count).toBeGreaterThanOrEqual(5); // time, severity, asset, event_type, category, source, description

    // D3 timeline visualization container
    const d3Viz = page.locator('#d3-timeline-viz');
    await expect(d3Viz).toBeAttached();
  });

  test('filter controls are present and functional', async ({ page }) => {
    // Search input
    const search = page.locator('#search-input');
    await expect(search).toBeAttached();

    // Severity filter
    const sevFilter = page.locator('#filter-severity');
    await expect(sevFilter).toBeAttached();

    // Asset filter
    const assetFilter = page.locator('#filter-asset');
    await expect(assetFilter).toBeAttached();

    // Event type filter
    const typeFilter = page.locator('#filter-event-type');
    await expect(typeFilter).toBeAttached();

    // Source filter
    const sourceFilter = page.locator('#filter-source');
    await expect(sourceFilter).toBeAttached();

    // Typing in search input works
    await search.fill('test query');
    const val = await search.inputValue();
    expect(val).toBe('test query');
  });

  test('pagination controls are present', async ({ page }) => {
    const prevBtn = page.locator('#page-prev');
    await expect(prevBtn).toBeAttached();

    const nextBtn = page.locator('#page-next');
    await expect(nextBtn).toBeAttached();

    const indicator = page.locator('#page-indicator');
    await expect(indicator).toBeAttached();
  });

  test('stat pills show counts', async ({ page }) => {
    const pills = [
      { id: '#stat-critical-count', label: 'critical' },
      { id: '#stat-high-count', label: 'high' },
      { id: '#stat-total-count', label: 'total' },
    ];

    for (const { id } of pills) {
      const pill = page.locator(id);
      await expect(pill).toBeAttached();
      const text = await pill.textContent();
      expect(text).toBeTruthy();
    }
  });

  test('live badge shows connection status', async ({ page }) => {
    const liveBadge = page.locator('#live-badge');
    await expect(liveBadge).toBeAttached();

    const liveText = page.locator('#live-text');
    const text = await liveText.textContent();
    expect(text).toBeTruthy();
  });

  test('detail panel is hidden by default', async ({ page }) => {
    const detailPanel = page.locator('#detail-panel');
    await expect(detailPanel).toBeAttached();

    // Panel should not have the 'open' class
    const classes = await detailPanel.getAttribute('class');
    expect(classes).not.toContain('open');
  });

  test('table headers are sortable (have data-sort attributes)', async ({ page }) => {
    const sortableHeaders = page.locator('#timeline-table thead th[data-sort]');
    const count = await sortableHeaders.count();
    expect(count).toBeGreaterThanOrEqual(5);

    // First sortable header (time) should be sorted by default
    const timeHeader = page.locator('#timeline-table thead th[data-sort="time"]');
    await expect(timeHeader).toHaveClass(/sorted/);
  });

});
