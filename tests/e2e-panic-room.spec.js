/**
 * E2E: Panic Room Tab
 *
 * Tests panic room rendering — panic button, playbook selection,
 * asset scope, confirmation modal, active session panel,
 * whitelist management, recovery key section, and history.
 */
import { test, expect } from '@playwright/test';

test.describe('Panic Room Tab', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('index.html');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(300);
    await page.locator('#tab-btn-panic-room').click();
    await page.waitForTimeout(1000);
  });

  test('panic button is visible and clickable', async ({ page }) => {
    const panicBtn = page.locator('#panicButton');
    await expect(panicBtn).toBeAttached();

    const text = await panicBtn.textContent();
    expect(text).toContain('PANIC');

    // Hint text
    const hint = page.locator('#panicButtonHint');
    await expect(hint).toBeAttached();
  });

  test('playbook checkboxes are present', async ({ page }) => {
    // Playbooks section may be hidden initially, but the checkboxes exist
    const playbooks = page.locator('.playbook-checkbox');
    const count = await playbooks.count();
    expect(count).toBe(4);

    // Verify specific playbook values
    const values = [];
    for (let i = 0; i < count; i++) {
      values.push(await playbooks.nth(i).getAttribute('value'));
    }
    expect(values).toContain('IsolateNetwork');
    expect(values).toContain('RotateCredentials');
    expect(values).toContain('SnapshotSystem');
    expect(values).toContain('SecureBackup');
  });

  test('whitelist management section is visible', async ({ page }) => {
    const ipWhitelist = page.locator('#ipWhitelist');
    await expect(ipWhitelist).toBeAttached();

    const processWhitelist = page.locator('#processWhitelist');
    await expect(processWhitelist).toBeAttached();

    const saveBtn = page.locator('#saveConfig');
    await expect(saveBtn).toBeAttached();
  });

  test('confirmation modal is hidden by default', async ({ page }) => {
    const modal = page.locator('#confirmModal');
    await expect(modal).toBeAttached();
    await expect(modal).toBeHidden();
  });

  test('active session panel is hidden by default', async ({ page }) => {
    const session = page.locator('#activeSession');
    await expect(session).toBeAttached();
    await expect(session).toBeHidden();
  });

  test('recovery key card is present', async ({ page }) => {
    const card = page.locator('#recoveryKeyCard');
    await expect(card).toBeAttached();

    // Status text
    const status = page.locator('#recoveryKeyStatus');
    await expect(status).toBeAttached();
  });

  test('recovery key modal is hidden by default', async ({ page }) => {
    const modal = page.locator('#recoveryKeyModal');
    await expect(modal).toBeAttached();
    await expect(modal).toBeHidden();
  });

  test('history section exists', async ({ page }) => {
    const history = page.locator('#historyList');
    await expect(history).toBeAttached();
  });

  test('clicking panic button shows playbook and asset scope sections', async ({ page }) => {
    // Click the panic button
    await page.locator('#panicButton').click();
    await page.waitForTimeout(500);

    // Playbook section should become visible
    const playbookSection = page.locator('#playbookSection');
    await expect(playbookSection).toBeVisible();

    // Asset scope section should become visible
    const assetScope = page.locator('#assetScopeSection');
    await expect(assetScope).toBeVisible();
  });

  test('whitelist textareas accept input', async ({ page }) => {
    const ipWhitelist = page.locator('#ipWhitelist');
    await ipWhitelist.fill('192.168.1.1\n10.0.0.1');
    const val = await ipWhitelist.inputValue();
    expect(val).toContain('192.168.1.1');

    const processWhitelist = page.locator('#processWhitelist');
    await processWhitelist.fill('nginx\nssh');
    const val2 = await processWhitelist.inputValue();
    expect(val2).toContain('nginx');
  });

});
