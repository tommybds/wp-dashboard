/* Démarrage de l'application : sprite d'icônes, coque, routeur par fragment,
   chargement de la flotte.

   Phase 1 : la coque et le routage sont neufs, les écrans sont ceux d'avant,
   montés tels quels. Les anciens fragments (#dash, #sec/…, #hist/…, #mgmt/…)
   redirigent vers les nouveaux : des liens et des habitudes existent. */

import { esc as H } from './lib/dom.js';
import { initIcons } from './lib/icons.js';
import { stopPoll } from './lib/poll.js';
import { store, subscribe, loadFleet, loadStatus } from './lib/state.js';
import { V } from './version.js';

import { initModals, askInfo, registerModalCloser } from './components/confirm.js';
import { initTips } from './components/tip.js';
import { initJob, setSecRefresh, reouvrirBulk } from './components/job.js';
import { setOuvreurs } from './components/toast.js';
import { initShell, loadSched, updMeta, setScreenTitle, majCompteurs, pollCollect } from './components/shell.js';

import { openDrawer, onFleetChange, loadViews } from './screens/parc.js';
import { loadMgmt, wpauthBanner } from './screens/gestion.js';
import { loadSec, majCompteurSec } from './screens/securite.js';
import { loadHist } from './screens/historique.js';
import { ouvrirReglages } from './screens/reglages.js';
import { renderIncidents } from './screens/incidents.js';

/* ---- destinations ---------------------------------------------------------
   `page` est l'identifiant DOM historique du volet (page-dash, page-sec…) :
   les écrans repris en phase 1 le connaissent, on ne le renomme pas ici.
   `legacy` est l'ancien fragment, conservé en redirection. */
const DESTINATIONS = [
  { route: 'parc',        page: 'dash',      titre: 'Parc',        legacy: 'dash' },
  { route: 'incidents',   page: 'incidents', titre: 'Incidents' },
  { route: 'securite',    page: 'sec',       titre: 'Sécurité',    legacy: 'sec' },
  { route: 'changements', page: 'hist',      titre: 'Changements', legacy: 'hist' },
  { route: 'gestion',     page: 'mgmt',      titre: 'Gestion',     legacy: 'mgmt' },
];
const PAR_ROUTE = Object.fromEntries(DESTINATIONS.map(d => [d.route, d]));
const PAR_LEGACY = Object.fromEntries(DESTINATIONS.filter(d => d.legacy).map(d => [d.legacy, d]));
const ROUTE_DE_PAGE = Object.fromEntries(DESTINATIONS.map(d => [d.page, d.route]));

/* Fil d'Ariane dans l'URL : #destination/sous-section — partageable et
   rechargeable. Les slugs de sous-section sont inchangés : les liens déjà
   partagés (#sec/vulnerabilites) continuent de tomber au bon endroit. */
const SUBSLUG = {
  gestion: ['sites-non-geres', 'installs', 'mode-rest', 'moniteurs', 'docroots', 'serveurs'],
  changements: ['tendance', 'changements'],
  securite: ['vulnerabilites', 'erreurs-php', 'administrateurs', 'recherche-plugin',
    'php-obsolete', 'certificats', 'plugins-a-risque', 'integrite-core'],
};

let NAVLOCK = false;   // évite que l'écriture de l'URL relance la navigation
let ROUTE = 'parc';    // destination affichée

function currentSub(route) {
  const d = PAR_ROUTE[route];
  const nav = d && document.querySelector(`#page-${d.page}> .subtabs`);
  if (!nav) return -1;
  return [...nav.querySelectorAll('.subtab')].findIndex(b => b.classList.contains('active'));
}

/* `push` : seule une navigation VOULUE par l'utilisateur (clic de destination
   ou de sous-onglet) empile une entrée d'historique. Sans elle, `replaceState`
   seul faisait sortir de l'application au premier clic sur « Précédent ». */
function writeHash(route, sub, push) {
  if (NAVLOCK) return;
  const i = (sub === undefined) ? currentSub(route) : sub;
  const slugs = SUBSLUG[route] || [];
  const h = '#' + route + (i >= 0 && slugs[i] ? '/' + slugs[i] : '');
  if (location.hash === h) return;
  NAVLOCK = true;                    // pushState ne déclenche pas hashchange, ceinture et bretelles
  try { history[push ? 'pushState' : 'replaceState'](null, '', h); } catch (e) { /* historique verrouillé */ }
  NAVLOCK = false;
}

function showDest(route, { ecrire = true, push = false } = {}) {
  const d = PAR_ROUTE[route];
  if (!d) return false;
  ROUTE = route;
  document.querySelectorAll('.nav-i[data-dest]').forEach(x => {
    const on = x.dataset.dest === route;
    x.classList.toggle('active', on);
    if (on) x.setAttribute('aria-current', 'page'); else x.removeAttribute('aria-current');
  });
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
  document.getElementById('page-' + d.page).classList.add('active');
  setScreenTitle(d.titre);
  // Sondages propres à un écran : inutile de les laisser tourner ailleurs.
  if (route !== 'securite') { stopPoll('vulns'); stopPoll('phe'); }
  if (route === 'gestion') loadMgmt();
  if (route === 'securite') loadSec();
  if (route === 'changements') loadHist();
  if (route === 'incidents') renderIncidents();
  if (ecrire) writeHash(route, undefined, push);
  return true;
}

function applyHash() {
  const brut = decodeURIComponent(location.hash.replace(/^#/, ''));
  let [tete, sub] = brut.split('/');

  // Réglages : encore une modale en phase 1. On garde l'écran courant dessous
  // et on rend la main à l'URL précédente à la fermeture.
  if (tete === 'reglages') {
    NAVLOCK = true; showDest(ROUTE, { ecrire: false }); NAVLOCK = false;
    ouvrirReglages();
    return;
  }
  // Compatibilité : #dash, #sec/…, #hist/…, #mgmt/… → nouvelles destinations.
  if (PAR_LEGACY[tete]) {
    const d = PAR_LEGACY[tete];
    const h = '#' + d.route + (sub ? '/' + sub : '');
    NAVLOCK = true;
    try { history.replaceState(null, '', h); } catch (e) { /* historique verrouillé */ }
    NAVLOCK = false;
    tete = d.route;
  }
  NAVLOCK = true;
  const ok = showDest(tete || 'parc', { ecrire: false });
  if (ok && sub && SUBSLUG[tete]) {
    const i = SUBSLUG[tete].indexOf(sub);
    const nav = document.querySelector(`#page-${PAR_ROUTE[tete].page}> .subtabs`);
    if (i >= 0 && nav) { const b = nav.querySelectorAll('.subtab')[i]; if (b) b.click(); }
  }
  NAVLOCK = false;
  // Fragment inconnu : on retombe sur Parc pour de bon (l'URL ET l'écran).
  if (!ok) showDest('parc');
}

/* ---- sous-onglets ---------------------------------------------------------
   Les libellés viennent des <h2> existants — rien à maintenir en double.
   Ils disparaîtront en phase 3 (Sécurité, Changements) et 4 (Gestion). */
function buildSubtabs(pageId, key, shortLabels) {
  const page = document.getElementById(pageId); if (!page) return;
  const secs = [...page.querySelectorAll(':scope> .section')];
  if (secs.length < 2) return;
  let nav = page.querySelector(':scope> .subtabs');
  if (!nav) {
    nav = document.createElement('nav'); nav.className = 'subtabs';
    const anchor = page.querySelector(':scope> .filters');
    if (anchor) anchor.after(nav); else page.prepend(nav);
  }
  nav.innerHTML = secs.map((s, i) => {
    const h = s.querySelector('h2');
    const raw = h ? (h.childNodes[0]?.textContent || h.textContent) : 'Section ' + (i + 1);
    const label = (shortLabels && shortLabels[i]) || raw.trim().replace(/\s*\(.*$/, '');
    return `<button class="subtab" type="button" data-i="${i}">${H(label)}</button>`;
  }).join('');
  // `push` : seul un clic de l'utilisateur empile une entrée d'historique ;
  // la restauration au chargement ou depuis l'URL remplace.
  const sel = (i, push) => {
    secs.forEach((s, j) => { s.hidden = (j !== i); });
    nav.querySelectorAll('.subtab').forEach((b, j) => {
      b.classList.toggle('active', j === i);
      b.setAttribute('aria-current', j === i ? 'true' : 'false');
    });
    try { localStorage[key] = String(i); } catch (e) { /* stockage refusé */ }
    const route = ROUTE_DE_PAGE[pageId.replace('page-', '')];
    if (document.getElementById(pageId).classList.contains('active')) writeHash(route, i, push);
  };
  nav.querySelectorAll('.subtab').forEach((b, i) => { b.onclick = () => sel(i, true); });
  let start = parseInt((() => { try { return localStorage[key]; } catch (e) { return '0'; } })() || '0', 10);
  if (!(start >= 0 && start < secs.length)) start = 0;
  sel(start, false);
}

/* ---- démarrage ------------------------------------------------------------ */
async function boot() {
  // Le sprite est injecté AVANT le premier rendu : aucune icône vide au chargement.
  await initIcons('icons.svg?v=' + V);

  initTips();
  initModals();
  initJob();
  setSecRefresh(loadSec);
  setOuvreurs({ bulk: reouvrirBulk, site: openDrawer });
  initShell({ onCollect: err => askInfo('Collecte impossible', H(err)) });

  // La modale Réglages rend la main à l'URL de l'écran affiché.
  const rendreLaMain = () => { if (location.hash === '#reglages') writeHash(ROUTE); };
  registerModalCloser('setmodal', () => {
    document.getElementById('setmodal').classList.remove('open');
    rendreLaMain();
  });
  document.getElementById('setmodal').addEventListener('click', e => {
    if (e.target.id === 'setmodal') rendreLaMain();
  });

  document.querySelectorAll('.nav-i[data-dest]').forEach(b => {
    b.onclick = e => { e.preventDefault(); showDest(b.dataset.dest, { push: true }); };
  });
  window.addEventListener('hashchange', applyHash);

  buildSubtabs('page-mgmt', 'dashSubMgmt',
    ['Sites non gérés', 'Installs découverts', 'Mode REST', 'Moniteurs Kuma', 'Docroots', 'Serveurs']);
  buildSubtabs('page-hist', 'dashSubHist', ['Tendance', 'Changements']);
  buildSubtabs('page-sec', 'dashSubSec',
    ['Vulnérabilités', 'Erreurs PHP', 'Administrateurs', 'Recherche plugin', 'PHP obsolète',
     'Certificats SSL', 'Plugins à risque', 'Intégrité du core']);

  // Un écran se redessine quand le store change ; plus personne ne l'appelle
  // depuis le chargeur de données.
  subscribe(() => { onFleetChange(); updMeta(); majCompteurs(); majCompteurSec(); });

  // La destination demandée par l'URL n'est appliquée qu'une fois la flotte
  // chargée : Gestion et Sécurité se construisent à partir de ces données.
  loadFleet().then(applyHash).catch(() => applyHash());
  loadSched();
  loadStatus();
  loadViews();
  pollCollect();
  wpauthBanner();
  setInterval(loadStatus, 60000);
  setInterval(() => { if (!store.curjob) loadFleet(); }, 15 * 60000);
}

boot();

export { showDest, writeHash };
