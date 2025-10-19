import { test, expect } from '@playwright/test';

// Helper function to generate unique test user credentials
function getTestUser() {
  const timestamp = Date.now();
  return {
    email: `test-${timestamp}@example.com`,
    username: `testuser${timestamp}`,
    password: 'TestPass123!',
  };
}

// Helper to switch to register form
async function switchToRegister(page) {
  await page.getByRole('button', { name: /create account/i }).click();
  await page.waitForTimeout(300);
}

// Helper to switch to login form
async function switchToLogin(page) {
  await page.getByText(/already have an account/i).click();
  await page.waitForTimeout(300);
}

test.describe('Authentication', () => {
  test.describe('Auth Page', () => {
    test('should display auth page with TriTerm branding', async ({ page }) => {
      await page.goto('/');

      // Should show TriTerm branding
      await expect(page.getByRole('heading', { name: 'TriTerm', exact: true })).toBeVisible();

      // Login form should be shown by default
      await expect(page.getByRole('button', { name: /sign in/i }).last()).toBeVisible();
    });

    test('should switch between login and register forms', async ({ page }) => {
      await page.goto('/');

      // Start on login form
      await expect(page.getByRole('button', { name: /sign in/i }).last()).toBeVisible();

      // Switch to register
      await switchToRegister(page);

      // Should now show register form with confirm password
      const passwordInputs = page.getByPlaceholder(/password/i);
      expect(await passwordInputs.count()).toBe(2);

      // Switch back to login
      await switchToLogin(page);

      // Should be back on login form
      await expect(page.getByRole('button', { name: /sign in/i }).last()).toBeVisible();
    });
  });

  test.describe('Registration', () => {
    test('should register a new user successfully', async ({ page }) => {
      const user = getTestUser();

      await page.goto('/');
      await switchToRegister(page);

      // Fill registration form
      await page.getByPlaceholder(/email/i).fill(user.email);
      await page.getByPlaceholder(/username/i).fill(user.username);

      const passwordInputs = page.getByPlaceholder(/password/i);
      await passwordInputs.first().fill(user.password);
      await passwordInputs.nth(1).fill(user.password);

      // Submit
      await page.getByRole('button', { name: /sign up/i }).last().click();

      // Should be logged in - check for username in user menu
      await expect(page.getByText(user.username)).toBeVisible({ timeout: 10000 });
    });

    test('should show validation error for weak password', async ({ page }) => {
      const user = getTestUser();

      await page.goto('/');
      await switchToRegister(page);

      await page.getByPlaceholder(/email/i).fill(user.email);
      await page.getByPlaceholder(/username/i).fill(user.username);

      const passwordInputs = page.getByPlaceholder(/password/i);
      await passwordInputs.first().fill('weak');
      await passwordInputs.nth(1).fill('weak');

      await page.getByRole('button', { name: /sign up/i }).last().click();

      // Should show validation error
      await expect(page.getByText(/password must/i)).toBeVisible({ timeout: 3000 });
    });

    test('should show error for mismatched passwords', async ({ page }) => {
      const user = getTestUser();

      await page.goto('/');
      await switchToRegister(page);

      await page.getByPlaceholder(/email/i).fill(user.email);
      await page.getByPlaceholder(/username/i).fill(user.username);

      const passwordInputs = page.getByPlaceholder(/password/i);
      await passwordInputs.first().fill(user.password);
      await passwordInputs.nth(1).fill('DifferentPass123!');

      await page.getByRole('button', { name: /sign up/i}).last().click();

      // Should show mismatch error
      await expect(page.getByText(/passwords do not match/i)).toBeVisible({ timeout: 3000 });
    });
  });

  test.describe('Login', () => {
    test('should login with valid credentials', async ({ page }) => {
      const user = getTestUser();

      // First register
      await page.goto('/');
      await switchToRegister(page);

      await page.getByPlaceholder(/email/i).fill(user.email);
      await page.getByPlaceholder(/username/i).fill(user.username);
      const registerPasswordInputs = page.getByPlaceholder(/password/i);
      await registerPasswordInputs.first().fill(user.password);
      await registerPasswordInputs.nth(1).fill(user.password);
      await page.getByRole('button', { name: /sign up/i }).last().click();

      await page.waitForTimeout(1000);

      // Logout
      await page.getByText(user.username).click();
      await page.getByRole('button', { name: /logout/i }).click();
      await page.waitForTimeout(500);

      // Now login
      await page.getByPlaceholder(/email/i).fill(user.email);
      const loginPasswordInput = page.getByPlaceholder(/password/i);
      await loginPasswordInput.fill(user.password);
      await page.getByRole('button', { name: /sign in/i }).last().click();

      // Should be logged in
      await expect(page.getByText(user.username)).toBeVisible({ timeout: 5000 });
    });

    test('should show error for invalid credentials', async ({ page }) => {
      await page.goto('/');

      // Login form is default
      await page.getByPlaceholder(/email/i).fill('nonexistent@example.com');
      const passwordInput = page.getByPlaceholder(/password/i);
      await passwordInput.fill('WrongPassword123!');
      await page.getByRole('button', { name: /sign in/i }).last().click();

      // Should show error
      await expect(page.getByText(/invalid credentials|incorrect/i)).toBeVisible({ timeout: 3000 });
    });
  });

  test.describe('Protected Routes', () => {
    test('should redirect to auth page when not logged in', async ({ page }) => {
      await page.goto('/');
      await page.evaluate(() => localStorage.clear());
      await page.reload();

      // Should show auth page (TriTerm branding)
      await expect(page.getByRole('heading', { name: 'TriTerm', exact: true })).toBeVisible();
    });

    test('should persist authentication across page reloads', async ({ page }) => {
      const user = getTestUser();

      // Register
      await page.goto('/');
      await switchToRegister(page);

      await page.getByPlaceholder(/email/i).fill(user.email);
      await page.getByPlaceholder(/username/i).fill(user.username);
      const passwordInputs = page.getByPlaceholder(/password/i);
      await passwordInputs.first().fill(user.password);
      await passwordInputs.nth(1).fill(user.password);
      await page.getByRole('button', { name: /sign up/i }).last().click();

      await page.waitForTimeout(1000);

      // Verify logged in
      await expect(page.getByText(user.username)).toBeVisible();

      // Reload page
      await page.reload();

      // Should still be logged in
      await expect(page.getByText(user.username)).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Logout', () => {
    test('should logout and return to auth page', async ({ page }) => {
      const user = getTestUser();

      // Register
      await page.goto('/');
      await switchToRegister(page);

      await page.getByPlaceholder(/email/i).fill(user.email);
      await page.getByPlaceholder(/username/i).fill(user.username);
      const passwordInputs = page.getByPlaceholder(/password/i);
      await passwordInputs.first().fill(user.password);
      await passwordInputs.nth(1).fill(user.password);
      await page.getByRole('button', { name: /sign up/i }).last().click();

      await page.waitForTimeout(1000);

      // Logout
      await page.getByText(user.username).click();
      await page.getByRole('button', { name: /logout/i }).click();

      // Should be back on auth page
      await expect(page.getByRole('heading', { name: 'TriTerm', exact: true })).toBeVisible({ timeout: 3000 });

      // Tokens should be cleared
      const hasToken = await page.evaluate(() => {
        return localStorage.getItem('triterm_access_token') !== null;
      });
      expect(hasToken).toBe(false);
    });
  });
});
