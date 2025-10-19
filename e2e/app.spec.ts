import { test, expect } from '@playwright/test';

test.describe('TriTerm Application', () => {
  test('should load the application', async ({ page }) => {
    await page.goto('/');

    // Check for the app title
    await expect(page).toHaveTitle(/TriTerm/);
  });

  test('should display the header with logo', async ({ page }) => {
    await page.goto('/');

    // Check for TriTerm branding
    const header = page.locator('header');
    await expect(header).toBeVisible();
    await expect(header.getByText('TriTerm')).toBeVisible();
  });

  test('should show connection status', async ({ page }) => {
    await page.goto('/');

    // Wait for socket connection
    await page.waitForTimeout(2000);

    // Look for connection indicator (wifi icon or text)
    const connectionIndicator = page.locator('[data-testid="connection-status"], .lucide-wifi, .lucide-wifi-off').first();
    await expect(connectionIndicator).toBeVisible();
  });

  test('should have settings and info buttons', async ({ page }) => {
    await page.goto('/');

    // Check for Settings button
    const settingsButton = page.getByRole('button', { name: /settings/i });
    await expect(settingsButton).toBeVisible();

    // Check for Info button
    const infoButton = page.getByRole('button', { name: /about|info/i });
    await expect(infoButton).toBeVisible();
  });

  test('should open settings dialog when settings button is clicked', async ({ page }) => {
    await page.goto('/');

    // Click settings button
    const settingsButton = page.getByRole('button', { name: /settings/i });
    await settingsButton.click();

    // Wait for dialog to appear
    await page.waitForTimeout(500);

    // Check if settings dialog is visible
    const dialog = page.getByRole('dialog').or(page.locator('[role="dialog"]'));
    await expect(dialog).toBeVisible();
  });
});
