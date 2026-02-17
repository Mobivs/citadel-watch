/**
 * E2E: Settings & Dashboard Mode
 *
 * Tests the settings button behavior, dashboard mode switching
 * (technical vs simplified), and mode persistence.
 */
import { test, expect } from '@playwright/test';

test.describe('Settings & Dashboard Mode', () => {

  test.beforeEach(async ({ page }) => {
    // Clear mode preference
    await page.addInitScript(() => {
      try {
        localStorage.removeItem('citadel_dashboard_mode');
        localStorage.removeItem('citadel_active_tab');
      } catch {}
    });
  });

  test('settings button is clickable', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');

    const settingsBtn = page.locator('#settings-btn');
    await expect(settingsBtn).toBeVisible();

    // Click it and verify no crash
    await settingsBtn.click();
    await page.waitForTimeout(300);

    // Dashboard should still be intact
    await expect(page.locator('#app')).toBeVisible();
  });

  test('default mode shows all tabs (technical mode)', async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);

    // All major tabs should be visible in technical mode
    const technicalTabs = ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets'];
    for (const tab of technicalTabs) {
      const btn = page.locator(`#tab-btn-${tab}`);
      await expect(btn).toBeVisible();
    }
  });

  test('simplified mode hides non-essential tabs', async ({ page }) => {
    // Set simplified mode before loading
    await page.addInitScript(() => {
      try { localStorage.setItem('citadel_dashboard_mode', 'simplified'); } catch {}
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);

    // Simplified tabs should be visible
    const simplifiedTabs = ['intelligence', 'assets', 'remote-shield'];
    for (const tab of simplifiedTabs) {
      const btn = page.locator(`#tab-btn-${tab}`);
      await expect(btn).toBeVisible();
    }

    // Technical-only tabs should be hidden
    const hiddenTabs = ['charts', 'timeline', 'risk-metrics', 'backup', 'performance'];
    for (const tab of hiddenTabs) {
      const btn = page.locator(`#tab-btn-${tab}`);
      await expect(btn).toBeHidden();
    }
  });

  test('mode preference persists across page reload', async ({ page }) => {
    // Set simplified mode
    await page.addInitScript(() => {
      try { localStorage.setItem('citadel_dashboard_mode', 'simplified'); } catch {}
    });

    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);

    // Verify charts tab is hidden
    await expect(page.locator('#tab-btn-charts')).toBeHidden();

    // Reload and check it persists
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);

    await expect(page.locator('#tab-btn-charts')).toBeHidden();
  });

});
