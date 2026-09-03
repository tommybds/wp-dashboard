/* Captures d'écran de référence — docs/captures/.
 *
 * Elles servent à comparer d'une phase à l'autre : deux thèmes × deux largeurs
 * × les six destinations + la page site. Rien n'est produit à la main, donc
 * rien ne dérive.
 *
 *   python3 tools/preview.py &            # page bouchonnée, port 8787
 *   npx --yes playwright@1.62 exec node tools/captures.mjs
 *   # ou, si playwright est installé globalement :  node tools/captures.mjs
 *
 * Le thème est forcé AVANT le chargement (localStorage.dashTheme), et non par
 * le bouton : sinon la première image serait prise dans le thème précédent.
 */
import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';

const BASE = process.env.WPDASH_PREVIEW || 'http://127.0.0.1:8787';
const SORTIE = new URL('../docs/captures/', import.meta.url).pathname;

const ECRANS = [
  ['parc', '#parc'],
  ['incidents', '#incidents'],
  ['securite', '#securite'],
  ['changements', '#changements'],
  ['gestion', '#gestion'],
  ['reglages', '#reglages'],
  ['site', '#site/site-01.exemple.fr'],
];
const LARGEURS = [['1440', 1440, 900], ['390', 390, 844]];
const THEMES = ['light', 'dark'];

await mkdir(SORTIE, { recursive: true });
const nav = await chromium.launch();

for (const theme of THEMES) {
  for (const [nomL, w, hh] of LARGEURS) {
    const ctx = await nav.newContext({
      viewport: { width: w, height: hh },
      deviceScaleFactor: 1,
      isMobile: w < 720,
      hasTouch: w < 720,
      colorScheme: theme,
      locale: 'fr-FR',
    });
    await ctx.addInitScript(t => {
      try { localStorage.dashTheme = t; } catch (e) { /* stockage refusé */ }
    }, theme);
    const page = await ctx.newPage();
    for (const [nom, frag] of ECRANS) {
      await page.goto(BASE + '/' + frag, { waitUntil: 'load' });
      // La flotte, la file d'incidents et les sections arrivent en plusieurs
      // requêtes : on laisse la page se remplir avant de la photographier.
      await page.waitForTimeout(2500);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.waitForTimeout(200);
      const f = `${SORTIE}${nom}-${nomL}-${theme}.png`;
      await page.screenshot({ path: f });
      console.log('   ' + f.replace(/^.*\/docs\//, 'docs/'));
    }
    await ctx.close();
  }
}
await nav.close();
console.log('Captures à jour.');
