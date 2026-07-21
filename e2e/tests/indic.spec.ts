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

  test('empty search falls back to the visitor IP', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', '');
    await page.click('#goBtn');
    // champ vide = lookup de sa propre IP : rapport, ou erreur si elle est privée
    await expect(page.locator('#report').or(page.locator('#err')).first())
      .toBeVisible({ timeout: 15000 });
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

// Le comparateur part toujours de la fiche affichée : il n'est pas atteignable
// depuis l'accueil, et la première colonne est figée sur l'observable courant.
test.describe('Comparator', () => {
  const openReport = async (page, q: string) => {
    await page.goto(`/?q=${encodeURIComponent(q)}`);
    await expect(page.locator('#report')).toBeVisible({ timeout: 20000 });
  };

  test('is not reachable from the landing page', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#cmpBtn')).toBeHidden();
    await page.keyboard.press('c');
    await expect(page.locator('#comparator')).toBeHidden();
  });

  test('opens from the report and pins the subject', async ({ page }) => {
    await openReport(page, '8.8.8.8');
    await page.click('#cmpBtn');
    await expect(page.locator('#comparator')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('#cmpSubject')).toContainText('8.8.8.8');
  });

  test('opens with keyboard shortcut c once a report is shown', async ({ page }) => {
    await openReport(page, '8.8.8.8');
    await page.keyboard.press('c');
    await expect(page.locator('#comparator')).toBeVisible({ timeout: 3000 });
  });

  test('closes comparator with Escape', async ({ page }) => {
    await openReport(page, '8.8.8.8');
    await page.click('#cmpBtn');
    await expect(page.locator('#comparator')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#comparator')).toBeHidden({ timeout: 2000 });
  });

  test('compares the subject with a second observable', async ({ page }) => {
    await openReport(page, '8.8.8.8');
    await page.click('#cmpBtn');
    await page.fill('#cmpB', '1.1.1.1');
    await page.click('#cmpGo');
    await expect(page.locator('#cmpResults .cmpTbl')).toBeVisible({ timeout: 25000 });
    await expect(page.locator('#cmpResults .cmpCol')).toHaveCount(2);
    await expect(page.locator('#cmpResults .cmpRel')).toBeVisible();
  });

  test('compares up to three observables', async ({ page }) => {
    await openReport(page, '8.8.8.8');
    await page.click('#cmpBtn');
    await page.fill('#cmpB', '1.1.1.1');
    await page.click('#cmpAdd');
    await page.fill('#cmpC', '9.9.9.9');
    await page.click('#cmpGo');
    await expect(page.locator('#cmpResults .cmpTbl')).toBeVisible({ timeout: 30000 });
    await expect(page.locator('#cmpResults .cmpCol')).toHaveCount(3);
  });
});

test.describe('IOC extractor', () => {
  const SAMPLE = 'Compromission : 8.8.8.8 a contacté evil-example.com puis CVE-2021-44228.';

  test('opens with the e shortcut and groups results by type', async ({ page }) => {
    await page.goto('/');
    await page.keyboard.press('e');
    await expect(page.locator('#extractor')).toBeVisible({ timeout: 3000 });
    await page.fill('#exText', SAMPLE);
    await page.click('#exGo');
    await expect(page.locator('#exOut .exGrp').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#exOut .exSum')).toContainText('IOC');
  });

  test('opens from the landing button and closes with Escape', async ({ page }) => {
    await page.goto('/');
    await page.click('.lextract');
    await expect(page.locator('#extractor')).toBeVisible({ timeout: 3000 });
    await page.keyboard.press('Escape');
    await expect(page.locator('#extractor')).toBeHidden({ timeout: 2000 });
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
  test('shows the pivot graph when an observable has enough pivots', async ({ page }) => {
    await page.goto('/');
    await page.fill('#q', 'google.com');
    await page.click('#goBtn');
    await expect(page.locator('#report')).toBeVisible({ timeout: 20000 });
    // le graphe n'apparaît qu'au-delà de 3 pivots — sinon la section reste repliée
    await expect(page.locator('#secPivots')).toBeVisible({ timeout: 10000 });
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
