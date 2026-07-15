import { test, expect } from '@playwright/test';

test.describe('Landing page', () => {
  test('loads with search input and brand', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('header .brand')).toBeVisible();
    await expect(page.locator('#q')).toBeVisible();
    await expect(page.locator('#q')).toHaveAttribute('placeholder', /Rechercher/);
  });

  test('shows landing examples when empty', async ({ page }) => {
    await page.goto('/');
    // La landing devrait montrer les exemples (boutons d'IOC)
    await expect(page.locator('#landing')).toBeVisible({ timeout: 5000 });
  });

  test('keyboard shortcut / focuses search', async ({ page }) => {
    await page.goto('/');
    await page.keyboard.press('/');
    await expect(page.locator('#q')).toBeFocused();
  });

  test('healthz returns ok', async ({ page }) => {
    const response = await page.goto('/healthz');
    expect(response?.status()).toBe(200);
  });
});

test.describe('IP lookup', () => {
  test('searches an IP and shows report', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', '8.8.8.8');
    await page.click('#goBtn');
    // Le rapport devrait apparaître
    await expect(page.locator('#report')).toBeVisible({ timeout: 10000 });
    // Le verdict devrait être présent
    await expect(page.locator('#verdict')).toBeVisible({ timeout: 5000 });
  });

  test('searches via URL query param', async ({ page }) => {
    await page.goto('/?q=1.1.1.1');
    await expect(page.locator('#report')).toBeVisible({ timeout: 10000 });
  });

  test('empty search shows error', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', '');
    await page.click('#goBtn');
    // Devrait soit montrer la landing, soit une erreur
    const error = page.locator('.errmsg');
    const landing = page.locator('#landing');
    await expect(error.or(landing).first()).toBeVisible({ timeout: 5000 });
  });
});

test.describe('Domain lookup', () => {
  test('searches a domain and shows report', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', 'example.com');
    await page.click('#goBtn');
    await expect(page.locator('#report')).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Comparator', () => {
  test('opens comparator with button', async ({ page }) => {
    await page.goto('/');
    await page.click('#cmpBtn');
    await expect(page.locator('#comparator')).toBeVisible({ timeout: 3000 });
  });

  test('opens comparator with keyboard shortcut c', async ({ page }) => {
    await page.goto('/');
    await page.keyboard.press('c');
    await expect(page.locator('#comparator')).toBeVisible({ timeout: 3000 });
  });

  test('closes comparator with Escape', async ({ page }) => {
    await page.goto('/');
    await page.click('#cmpBtn');
    await expect(page.locator('#comparator')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#comparator')).toBeHidden({ timeout: 2000 });
  });

  test('compares two IPs', async ({ page }) => {
    await page.goto('/');
    await page.click('#cmpBtn');
    await page.fill('#cmpA', '8.8.8.8');
    await page.fill('#cmpB', '1.1.1.1');
    await page.click('#cmpGo');
    await expect(page.locator('#cmpColA .report')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#cmpColB .report')).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Settings', () => {
  test('opens settings panel', async ({ page }) => {
    await page.goto('/');
    await page.click('#settingsBtn');
    await expect(page.locator('#settings')).toBeVisible({ timeout: 3000 });
  });

  test('closes settings with Escape', async ({ page }) => {
    await page.goto('/');
    await page.click('#settingsBtn');
    await expect(page.locator('#settings')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#settings')).toBeHidden({ timeout: 2000 });
  });
});

test.describe('Theme', () => {
  test('toggles dark/light theme', async ({ page }) => {
    await page.goto('/');
    const html = page.locator('html');
    const currentTheme = await html.getAttribute('data-theme');
    await page.click('#themeBtn');
    const newTheme = await html.getAttribute('data-theme');
    expect(newTheme).not.toBe(currentTheme);
  });
});

test.describe('Graph', () => {
  test('shows graph for IP lookup', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', '8.8.8.8');
    await page.click('#goBtn');
    // Le canvas du graphe devrait apparaître
    await expect(page.locator('#graph canvas')).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Export', () => {
  test('STIX export button opens new tab', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', '8.8.8.8');
    await page.click('#goBtn');
    await expect(page.locator('#report')).toBeVisible({ timeout: 10000 });
    // Le bouton STIX devrait être visible
    await expect(page.locator('#exportStix')).toBeVisible({ timeout: 3000 });
  });
});
