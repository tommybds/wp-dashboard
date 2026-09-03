/* Démarrage de l'application : sprite d'icônes, coque, routeur par fragment,
   chargement de la flotte.

   Phase 2 : le Parc et la page site sont neufs (`#site/<clé>[/<onglet>]`), le
   tiroir a disparu, la recherche globale ⌘K est branchée.

   Phase 3 : Incidents, Sécurité et Changements sont neufs à leur tour. Leurs
   sous-onglets ont disparu au profit d'une page unique par destination ; les
   anciens sous-slugs (#sec/vulnerabilites, #hist/tendance) et ceux des liens
   d'incidents (#securite/vulns) désignent maintenant une ANCRE dans la page.
   Les anciens fragments (#dash, #sec/…, #hist/…, #mgmt/…) redirigent toujours
   vers les nouveaux : des liens et des habitudes existent.

   Phase 4 : Gestion perd ses six sous-onglets et Réglages cesse d'être une
   modale — les deux sont des pages à ancres. Il n'existe donc PLUS un seul
   sous-onglet dans l'application : `buildSubtabs` et `SUBSLUG` ont disparu, et
   tout sous-slug d'URL désigne une ancre. */

import { esc as H } from './lib/dom.js';
import { initIcons } from './lib/icons.js';
import { stopPoll } from './lib/poll.js';
import { store, subscribe, loadFleet, loadStatus } from './lib/state.js';
import { V } from './version.js';

import { initModals, askInfo } from './components/confirm.js';
import { initTips } from './components/tip.js';
import { initJob, setSecRefresh, reouvrirBulk } from './components/job.js';
import { setOuvreurs } from './components/toast.js';
import {
  initShell, loadSched, updMeta, setScreenTitle, majCompteurs, majCompteursServeur, pollCollect,
} from './components/shell.js';
import { initSearch, ouvrirRecherche, raccourciLabel } from './components/search.js';
import { setVizSettings } from './components/viz.js';
import { fermerMenus } from './components/actions-menu.js';
import { wpauthBanner } from './components/wpauth.js';

import { onFleetChange, loadViews, chargerIncidents, filtrerSurExtension } from './screens/parc.js';
import { renderSite, quitterSite, cleDeSite, siteParCle } from './screens/site.js';
import { loadMgmt } from './screens/gestion.js';
import { loadSec, majCompteurSec } from './screens/securite.js';
import { loadHist } from './screens/historique.js';
import { loadReglages, ensureSettings } from './screens/reglages.js';
import { renderIncidents } from './screens/incidents.js';

/* ---- destinations ---------------------------------------------------------
   `page` est l'identifiant DOM du volet (page-dash, page-sec…). `legacy` est
   l'ancien fragment, conservé en redirection. La page site n'est pas une
   destination de la barre latérale : elle a sa propre branche de routage. */
const DESTINATIONS = [
  { route: 'parc',        page: 'dash',      titre: 'Parc',        legacy: 'dash' },
  { route: 'incidents',   page: 'incidents', titre: 'Incidents' },
  { route: 'securite',    page: 'sec',       titre: 'Sécurité',    legacy: 'sec' },
  { route: 'changements', page: 'hist',      titre: 'Changements', legacy: 'hist' },
  { route: 'gestion',     page: 'mgmt',      titre: 'Gestion',     legacy: 'mgmt' },
  { route: 'reglages',    page: 'reglages',  titre: 'Réglages' },
];
const PAR_ROUTE = Object.fromEntries(DESTINATIONS.map(d => [d.route, d]));
const PAR_LEGACY = Object.fromEntries(DESTINATIONS.filter(d => d.legacy).map(d => [d.legacy, d]));

/* Sous-slug → identifiant de section. Deux familles de noms cohabitent, et les
   deux doivent tomber juste : les slugs des anciens sous-onglets (partagés dans
   des liens et des marque-pages) et ceux que le backend pose dans le champ
   `link` des incidents (`{tab:"securite", sub:"vulns"}`). */
const ANCRES = {
  securite: {
    vulnerabilites: 'sec-vulns', vulns: 'sec-vulns',
    administrateurs: 'sec-admins', admins: 'sec-admins',
    'erreurs-php': 'sec-phperr', phperrors: 'sec-phperr',
    'plugins-a-risque': 'sec-risky', risky: 'sec-risky',
    'php-obsolete': 'sec-php', php: 'sec-php',
    certificats: 'sec-certs', certs: 'sec-certs',
    'integrite-core': 'sec-checksums', checksums: 'sec-checksums',
    'recherche-plugin': 'sec-recherche',
  },
  changements: {
    changements: 'hist-chrono', chronologie: 'hist-chrono',
    actions: 'hist-chrono', evenements: 'hist-chrono', tendance: 'hist-tendance',
  },
  // Phase 4 : les six anciens sous-onglets de Gestion sont devenus des ancres.
  gestion: {
    serveurs: 'mgmt-serveurs',
    installs: 'mgmt-installs',
    'mode-rest': 'mgmt-rest', rest: 'mgmt-rest', 'sites-sans-ssh': 'mgmt-rest',
    moniteurs: 'mgmt-moniteurs', kuma: 'mgmt-moniteurs',
    docroots: 'mgmt-docroots',
    'sites-non-geres': 'mgmt-nongeres', 'non-geres': 'mgmt-nongeres',
    candidats: 'mgmt-nongeres',
  },
  reglages: {
    collecte: 'set-collecte', cadence: 'set-collecte',
    alertes: 'set-alertes', telegram: 'set-alertes',
    vizproof: 'set-vizproof',
    'controle-visuel': 'set-visuel', visuel: 'set-visuel', 'maj-sure': 'set-visuel',
    incidents: 'set-incidents', 'regles-incidents': 'set-incidents',
    'cles-ssh': 'set-cles', cles: 'set-cles', sshkeys: 'set-cles',
    apparence: 'set-apparence', theme: 'set-apparence',
    session: 'set-session',
  },
};

/* Défilement jusqu'à la section demandée.

   L'écran vient d'être monté : ses sections sont dans le document, mais leur
   CONTENU arrive ensuite, par plusieurs requêtes, et chaque section qui se
   remplit pousse les suivantes vers le bas. Un défilement fait une seule fois
   raterait donc sa cible de plusieurs centaines de pixels : on re-vise tant que
   la page grandit, pendant 3 s au plus, et jamais après que l'utilisateur a
   repris la main.

   `setTimeout` plutôt que `requestAnimationFrame` : ce dernier ne se déclenche
   pas tant que l'onglet n'est pas visible, et l'ancre d'une page ouverte en
   arrière-plan n'aurait jamais été appliquée. */
function allerAncre(route, sub) {
  const id = (ANCRES[route] || {})[sub];
  if (!id) return;
  const aller = () => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ block: 'start' });
  };
  aller();
  // Re-visée pendant 3 s : chaque section qui se remplit déplace la cible.
  // Un simple minuteur plutôt qu'un ResizeObserver — celui-ci n'est appelé
  // qu'avec la boucle de rendu, donc jamais dans un onglet en arrière-plan.
  let tours = 0;
  const t = setInterval(() => { if (++tours > 12) rendre(); else aller(); }, 250);
  function rendre() {
    clearInterval(t);
    ['wheel', 'touchstart', 'keydown'].forEach(x => window.removeEventListener(x, rendre));
  }
  ['wheel', 'touchstart', 'keydown'].forEach(x => window.addEventListener(x, rendre, { passive: true }));
}

let NAVLOCK = false;   // évite que l'écriture de l'URL relance la navigation
let ROUTE = 'parc';    // destination affichée ('site' pour la page d'un site)

/* `push` : seule une navigation VOULUE par l'utilisateur (clic de destination)
   empile une entrée d'historique. Sans elle, `replaceState` seul faisait sortir
   de l'application au premier clic sur « Précédent ». */
function writeHash(route, push) {
  if (NAVLOCK) return;
  const h = '#' + route;
  if (location.hash === h) return;
  NAVLOCK = true;                    // pushState ne déclenche pas hashchange, ceinture et bretelles
  try { history[push ? 'pushState' : 'replaceState'](null, '', h); } catch (e) { /* historique verrouillé */ }
  NAVLOCK = false;
}

/* Quitter l'écran courant : les sondages qui n'ont de sens que sur cet écran
   s'arrêtent, les menus déployés se referment. Les JOBS, eux, continuent côté
   serveur — c'est tout l'intérêt de la barre de notifications. */
function quitterEcran(suivant) {
  fermerMenus();
  if (ROUTE === 'site' && suivant !== 'site') quitterSite();
  if (suivant !== 'securite') { stopPoll('vulns'); stopPoll('phe'); }
}

function masquerPages() {
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
}

function marquerNav(route) {
  document.querySelectorAll('.nav-i[data-dest]').forEach(x => {
    const on = x.dataset.dest === route;
    x.classList.toggle('active', on);
    if (on) x.setAttribute('aria-current', 'page'); else x.removeAttribute('aria-current');
  });
}

function showDest(route, { ecrire = true, push = false } = {}) {
  const d = PAR_ROUTE[route];
  if (!d) return false;
  quitterEcran(route);
  ROUTE = route;
  marquerNav(route);
  masquerPages();
  document.getElementById('page-' + d.page).classList.add('active');
  setScreenTitle(d.titre);
  if (route === 'gestion') loadMgmt();
  if (route === 'securite') loadSec();
  if (route === 'changements') loadHist();
  if (route === 'incidents') renderIncidents();
  if (route === 'reglages') loadReglages();
  if (ecrire) writeHash(route, push);
  return true;
}

/* ---- page site -------------------------------------------------------------
   Elle n'appartient à aucune destination de la barre latérale, mais « Parc »
   reste surligné : c'est de là qu'on y arrive, et le fil d'Ariane le dit. */
function showSite(cle, onglet) {
  quitterEcran('site');
  ROUTE = 'site';
  marquerNav('parc');
  masquerPages();
  document.getElementById('page-site').classList.add('active');
  setScreenTitle(cle);
  renderSite(cle, onglet);
}

/** Ouvre la page d'un site depuis n'importe où (barre de notifications, ⌘K). */
function ouvrirSite(cle, onglet) {
  location.hash = '#site/' + encodeURIComponent(cle) + (onglet ? '/' + onglet : '');
}

/* La barre de notifications ne connaît qu'un couple (serveur, domaine) ; la
   clé d'URL, elle, est le nom Kuma quand il existe. */
function ouvrirSiteParDomaine(srv, dom) {
  const s = siteParCle(dom);
  ouvrirSite(s ? cleDeSite(s) : dom);
}

function applyHash() {
  // Découpage AVANT décodage : une clé de site pourrait porter un « / » encodé.
  const parts = location.hash.replace(/^#/, '').split('/').map(x => {
    try { return decodeURIComponent(x); } catch (e) { return x; }
  });
  let tete = parts[0], sub = parts[1];

  if (tete === 'site' && parts[1]) { showSite(parts[1], parts[2] || ''); return; }

  // Compatibilité : #dash, #sec/…, #hist/…, #mgmt/… → nouvelles destinations.
  if (PAR_LEGACY[tete]) {
    const d = PAR_LEGACY[tete];
    const cible = '#' + d.route + (sub ? '/' + sub : '');
    NAVLOCK = true;
    try { history.replaceState(null, '', cible); } catch (e) { /* historique verrouillé */ }
    NAVLOCK = false;
    tete = d.route;
  }
  NAVLOCK = true;
  const ok = showDest(tete || 'parc', { ecrire: false });
  if (ok && sub && ANCRES[tete]) allerAncre(tete, sub);
  NAVLOCK = false;
  // Fragment inconnu : on retombe sur Parc pour de bon (l'URL ET l'écran).
  if (!ok) showDest('parc');
}

/* ---- démarrage ------------------------------------------------------------ */
async function boot() {
  // Le sprite est injecté AVANT le premier rendu : aucune icône vide au chargement.
  await initIcons('icons.svg?v=' + V);

  initTips();
  initModals();
  initJob();
  setSecRefresh(loadSec);
  setOuvreurs({ bulk: reouvrirBulk, site: ouvrirSiteParDomaine });
  // Le jeton VizProof enregistré est lu par l'écran Réglages : le composant de
  // connexion le demande sans dépendre de cet écran.
  setVizSettings(ensureSettings);
  initShell({ onCollect: err => askInfo('Collecte impossible', H(err)) });

  initSearch({
    ouvrirSite,
    filtrerExtension: nom => { filtrerSurExtension(nom); location.hash = '#parc'; },
    allerA: f => { location.hash = f; },
  });
  document.getElementById('searchbtn').onclick = ouvrirRecherche;
  document.getElementById('searchkbd').textContent = raccourciLabel();

  document.querySelectorAll('.nav-i[data-dest]').forEach(b => {
    b.onclick = e => { e.preventDefault(); showDest(b.dataset.dest, { push: true }); };
  });
  window.addEventListener('hashchange', applyHash);

  /* Un écran se redessine quand le store change ; plus personne ne l'appelle
     depuis le chargeur de données. La page site, elle, se rafraîchit sur ordre
     (après une action) : la redessiner toutes les 60 s effacerait l'onglet
     ouvert et relancerait ses requêtes pour rien. */
  subscribe(() => { onFleetChange(); updMeta(); majCompteurs(); majCompteurSec(); });

  // La destination demandée par l'URL n'est appliquée qu'une fois la flotte
  // chargée : la page site, Gestion et Sécurité se construisent à partir d'elle.
  loadFleet().then(applyHash).catch(() => applyHash());
  loadSched();
  loadStatus();
  loadViews();
  chargerIncidents();
  // Pastilles de la barre latérale : un seul agrégat côté serveur
  // (/api/mgmt/counts) pour Incidents ET Sécurité, rafraîchi à chaque
  // changement du store (donc après chaque collecte) et après chaque analyse.
  majCompteursServeur(true);
  ensureSettings();
  pollCollect();
  wpauthBanner();
  setInterval(loadStatus, 60000);
  setInterval(() => {
    if (!store.curjob) { loadFleet(); chargerIncidents(); majCompteursServeur(true); }
  }, 15 * 60000);
}

boot();

export { showDest, writeHash, ouvrirSite };
