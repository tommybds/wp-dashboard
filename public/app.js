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

import { initModals, askInfo, registerModalCloser } from './components/confirm.js';
import { fermerFeuille } from './components/sheet.js';
import { initTips } from './components/tip.js';
import { initJob, setSecRefresh, reouvrirBulk } from './components/job.js';
import { setOuvreurs } from './components/toast.js';
import {
  initShell, loadSched, updMeta, setScreenTitle, majCompteurs, majCompteursServeur, pollCollect,
} from './components/shell.js';
import { initSearch, ouvrirRecherche, raccourciLabel } from './components/search.js';
import { setVizSettings } from './components/viz.js';
import { initDebordement } from './components/table.js';
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

/* ---- sommaires d'ancres ----------------------------------------------------

   Une page à ancres (Sécurité, Changements, Gestion, Réglages) est UNE page :
   passer d'une de ses sections à une autre n'est PAS une navigation. Tout ce
   qui suit sert à tenir cette promesse — ne rien reconstruire, ne rien perdre
   d'une saisie en cours, et ne pas confisquer le défilement. */

/** Le mouvement est-il permis ? (`prefers-reduced-motion` coupe tout.) */
function mouvementOk() {
  try { return !window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
  catch (e) { return true; }
}

/** Identifiant de section visé par un lien de sommaire (`#reglages/alertes`). */
function idDeLien(a) {
  const parts = String(a.getAttribute('href') || '').replace(/^#/, '').split('/');
  return (ANCRES[parts[0]] || {})[parts[1]] || '';
}

/* Chip actif = section VISIBLE, pas dernier chip cliqué : au défilement libre
   comme après un saut, le sommaire dit toujours où l'on est.

   `epingler` marque un choix EXPLICITE (clic sur un chip, ancre d'URL). La
   section choisie reste marquée tant qu'elle est à l'écran, puis le suivi
   reprend la main. Sans cela, cliquer sur l'avant-dernière section d'une page
   allumait la dernière : le bas de page est atteint, les deux sont visibles, et
   la règle « la dernière en bas de page » contredisait le clic. */
let SECTIONVUE = '';
let EPINGLE = '';
/* Le défilement doux met une bonne demi-seconde : pendant ce trajet la section
   visée est encore hors de l'écran, et le suivi la déclarerait « pas visible »
   pour aussitôt rallumer le chip d'où l'on part. L'épingle est donc INCONDI-
   TIONNELLE le temps du voyage, puis soumise à la visibilité comme le reste. */
const EPINGLE_TRAJET = 1200;
let EPINGLEFIN = 0;
function marquerSection(id, epingler) {
  SECTIONVUE = id;
  EPINGLE = epingler ? id : '';
  if (epingler) EPINGLEFIN = Date.now() + EPINGLE_TRAJET;
  document.querySelectorAll('.anchors a').forEach(a => {
    const on = !!id && idDeLien(a) === id;
    a.classList.toggle('actif', on);
    if (on) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current');
  });
}

/* Section courante : la dernière dont le haut est passé sous le sommaire
   collant. Deux lectures de `getBoundingClientRect` par section et par tour de
   défilement, étranglées — c'est assez léger pour se passer d'un
   IntersectionObserver, qui demanderait d'être recréé à chaque remontage. */
function majSectionActive() {
  const page = document.querySelector('.page.active');
  const somm = page && page.querySelector('.anchors');
  if (!somm) { if (SECTIONVUE) marquerSection(''); return; }
  const liens = [...somm.querySelectorAll('a')];
  if (!liens.length) return;
  const sections = liens.map(a => document.getElementById(idDeLien(a)));
  const premiere = sections.find(Boolean);
  if (!premiere) return;
  /* Seuil = la ligne où une section VISÉE vient se poser, c'est-à-dire son
     `scroll-margin-top` (screens.css) — un seuil pris au bas du sommaire
     collant serait quelques pixels trop haut, et la section qu'on vient
     d'atteindre ne serait jamais celle qui s'allume. */
  const marge = parseFloat(getComputedStyle(premiere).scrollMarginTop) || 0;
  const seuil = Math.max(somm.getBoundingClientRect().bottom, marge) + 4;

  if (EPINGLE) {
    const e = document.getElementById(EPINGLE), r = e && e.getBoundingClientRect();
    const enRoute = Date.now() < EPINGLEFIN;
    if (r && (enRoute || (r.bottom > seuil && r.top < window.innerHeight))) {
      // Ré-épingler sans REPARTIR le délai de trajet : sinon l'épingle ne
      // tomberait jamais et le sommaire cesserait de suivre le défilement.
      if (SECTIONVUE !== EPINGLE) { const fin = EPINGLEFIN; marquerSection(EPINGLE, true); EPINGLEFIN = fin; }
      return;
    }
    EPINGLE = '';                       // sortie de l'écran : le suivi reprend
  }

  let courant = idDeLien(liens[0]);
  liens.forEach((a, i) => {
    const el = sections[i];
    if (el && el.getBoundingClientRect().top <= seuil) courant = idDeLien(a);
  });
  // Bas de page : la dernière section est active même trop courte pour atteindre
  // le seuil — sinon son chip ne s'allume jamais.
  if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) {
    courant = idDeLien(liens[liens.length - 1]) || courant;
  }
  if (courant !== SECTIONVUE) marquerSection(courant);
}

/* Étranglé par un minuteur et non par `requestAnimationFrame` : celui-ci ne se
   déclenche pas dans un onglet en arrière-plan, et le sommaire d'une page
   rouverte depuis un autre onglet resterait figé sur sa première section. */
let SUIVITICK = null;
function suivreSections() {
  if (SUIVITICK) return;
  SUIVITICK = setTimeout(() => { SUIVITICK = null; majSectionActive(); }, 80);
}

/* Défilement jusqu'à la section demandée.

   `revise` n'est vrai qu'au PREMIER rendu d'une destination : ses sections sont
   dans le document mais leur CONTENU arrive ensuite, par plusieurs requêtes, et
   chaque section qui se remplit pousse les suivantes vers le bas — un
   défilement fait une seule fois raterait sa cible de plusieurs centaines de
   pixels. Une fois la page remplie, il n'y a plus rien à re-viser : re-viser
   quand même revenait à annuler tout défilement de l'utilisateur pendant 3 s.

   La re-visée s'arrête dès que quelqu'un d'AUTRE que nous a défilé. Distinguer
   les deux ne se fait pas sur `scrollY` seul : quand le contenu grandit
   au-dessus de la cible, le navigateur déplace lui-même la page (ancrage du
   défilement), et le comparer à la valeur retenue faisait passer ce réglage
   automatique pour un geste de l'utilisateur — l'ancre n'arrivait alors jamais
   sur sa section. On mesure donc la CIBLE, deux fois :

     `doc`  sa position dans le document — elle change quand le contenu bouge ;
     `haut` sa position à l'écran — elle change quand ON défile.

   Cible qui n'a pas bougé dans le document mais qui n'est plus à l'écran là où
   on l'avait posée : c'est un défilement extérieur, on rend la main. Tout le
   reste (contenu qui se remplit, ancrage du navigateur) est une re-visée.

   `setTimeout` plutôt que `requestAnimationFrame` : ce dernier ne se déclenche
   pas tant que l'onglet n'est pas visible, et l'ancre d'une page ouverte en
   arrière-plan n'aurait jamais été appliquée. */
function mesurerCible(el) {
  const r = el.getBoundingClientRect();
  return { haut: Math.round(r.top), doc: Math.round(r.top + window.scrollY) };
}

/* Une seule re-visée à la fois : la suivante (clic sur un autre chip, autre
   fragment) annule la précédente au lieu de lui disputer le défilement. */
let ARRETANCRE = null;
function arreterRevisee() { if (ARRETANCRE) ARRETANCRE(); }

function allerAncre(route, sub, revise) {
  arreterRevisee();
  const id = (ANCRES[route] || {})[sub];
  if (!id) return;
  let ref = null;
  const aller = doux => {
    const el = document.getElementById(id);
    if (!el) return;
    el.scrollIntoView({ block: 'start', behavior: doux ? 'smooth' : 'auto' });
    ref = mesurerCible(el);
  };
  aller(!revise && mouvementOk());
  marquerSection(id, true);
  if (!revise) return;
  const detourne = () => {
    const el = document.getElementById(id);
    if (!el || !ref) return true;
    const m = mesurerCible(el);
    return Math.abs(m.doc - ref.doc) <= 2 && Math.abs(m.haut - ref.haut) > 2;
  };
  let tours = 0;
  const t = setInterval(() => {
    if (detourne() || ++tours > 12) rendre();
    else aller(false);
  }, 250);
  // L'évènement `scroll` rend la main tout de suite plutôt qu'au tour suivant.
  // Il ne suffit pas à lui seul : un document caché n'en émet aucun (ils sont
  // produits par les étapes de rendu), d'où le contrôle du minuteur ci-dessus,
  // qui, lui, fonctionne partout.
  const auScroll = () => { if (detourne()) rendre(); };
  function rendre() {
    clearInterval(t);
    window.removeEventListener('scroll', auScroll);
    if (ARRETANCRE === rendre) ARRETANCRE = null;
    majSectionActive();
  }
  ARRETANCRE = rendre;
  window.addEventListener('scroll', auScroll, { passive: true });
}

/* Clic sur un chip de sommaire dont la page est DÉJÀ affichée : il ne doit rien
   reconstruire. Sans cette interception, le changement de fragment relançait
   `showDest`, donc `loadReglages()`, donc le remontage de tous les corps de
   section — le champ dans lequel on tapait était remplacé, et la saisie perdue.
   Le lien garde son `href` : clic milieu, « ouvrir dans un onglet » et copie du
   lien continuent de marcher. */
function clicSommaire(e) {
  if (e.defaultPrevented || e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = e.target.closest && e.target.closest('.anchors a[href^="#"]');
  if (!a) return;
  const href = a.getAttribute('href');
  const route = href.replace(/^#/, '').split('/')[0];
  if (route !== ROUTE || !PAR_ROUTE[route]) return;      // vraie navigation : laisser faire
  const id = idDeLien(a);
  const el = id && document.getElementById(id);
  if (!el) return;
  e.preventDefault();
  arreterRevisee();          // une re-visée de chargement encore en cours perdrait ce clic
  el.scrollIntoView({ block: 'start', behavior: mouvementOk() ? 'smooth' : 'auto' });
  marquerSection(id, true);
  // `replaceState` et non `pushState` : sauter de section en section dans une
  // même page ne doit pas remplir l'historique de dix entrées à remonter.
  if (NAVLOCK) return;
  NAVLOCK = true;
  try { history.replaceState(null, '', href); } catch (err) { /* historique verrouillé */ }
  NAVLOCK = false;
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
  fermerFeuille();          // une feuille ouverte n'a plus d'objet sur l'écran suivant
  if (ROUTE === 'site' && suivant !== 'site') quitterSite();
  if (suivant !== 'securite') { stopPoll('vulns'); stopPoll('phe'); }
}

function masquerPages() {
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
}

/* La barre latérale ET la barre d'onglets basse portent `data-dest` : les deux
   suivent la même destination courante, avec le même `aria-current`. */
function marquerNav(route) {
  document.querySelectorAll('[data-dest]').forEach(x => {
    const on = x.dataset.dest === route;
    x.classList.toggle('active', on);
    if (on) x.setAttribute('aria-current', 'page'); else x.removeAttribute('aria-current');
  });
}

/* Destinations déjà affichées au moins une fois : leurs sections ont du
   contenu, donc plus rien à re-viser quand on y revient sur une ancre. */
const RENDUES = new Set();

function showDest(route, { ecrire = true, push = false } = {}) {
  const d = PAR_ROUTE[route];
  if (!d) return false;
  quitterEcran(route);
  ROUTE = route;
  marquerNav(route);
  masquerPages();
  document.getElementById('page-' + d.page).classList.add('active');
  setScreenTitle(d.titre);
  const premier = !RENDUES.has(route);
  RENDUES.add(route);
  if (route === 'gestion') loadMgmt();
  if (route === 'securite') loadSec();
  if (route === 'changements') loadHist();
  if (route === 'incidents') renderIncidents();
  if (route === 'reglages') loadReglages();
  if (ecrire) writeHash(route, push);
  marquerSection('');
  suivreSections();
  return premier ? 'premier' : true;
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
  /* Même destination, seule la section change (chip de sommaire, lien
     `#reglages/vizproof` d'une modale, retour arrière du navigateur) : on
     DÉFILE, on ne remonte rien. Un remontage remplacerait le champ en cours de
     saisie par un champ neuf — c'est exactement ce que Tommy voyait. */
  if (tete && tete === ROUTE && RENDUES.has(tete) && PAR_ROUTE[tete]) {
    if (sub && ANCRES[tete]) allerAncre(tete, sub, false);
    else majSectionActive();
    return;
  }
  NAVLOCK = true;
  const ok = showDest(tete || 'parc', { ecrire: false });
  if (ok && sub && ANCRES[tete]) allerAncre(tete, sub, ok === 'premier');
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
  // La feuille basse est une couche comme les autres pour Échap ; c'est ici
  // qu'on le déclare, pour ne pas créer de cycle sheet ↔ confirm ↔ menu.
  registerModalCloser('sheetmodal', fermerFeuille);
  initJob();
  setSecRefresh(loadSec);
  setOuvreurs({ bulk: reouvrirBulk, site: ouvrirSiteParDomaine });
  // Le jeton VizProof enregistré est lu par l'écran Réglages : le composant de
  // connexion le demande sans dépendre de cet écran.
  setVizSettings(ensureSettings);
  initShell({ onCollect: err => askInfo('Collecte impossible', H(err)) });
  // Ombres de débordement des tableaux, sommaires et onglets : posées une fois
  // pour tout le document, elles suivent ensuite les rendus des écrans.
  initDebordement();

  initSearch({
    ouvrirSite,
    filtrerExtension: nom => { filtrerSurExtension(nom); location.hash = '#parc'; },
    allerA: f => { location.hash = f; },
  });
  document.getElementById('searchbtn').onclick = ouvrirRecherche;
  document.getElementById('searchkbd').textContent = raccourciLabel();

  document.querySelectorAll('[data-dest]').forEach(b => {
    b.onclick = e => { e.preventDefault(); showDest(b.dataset.dest, { push: true }); };
  });
  window.addEventListener('hashchange', applyHash);

  /* Sommaires d'ancres : un seul écouteur pour toute l'application. Les chips
     sont (re)construits par leurs écrans à chaque rafraîchissement — les
     brancher un par un obligerait chaque écran à y penser, et l'un d'eux
     finirait par l'oublier. */
  document.addEventListener('click', clicSommaire);
  window.addEventListener('scroll', suivreSections, { passive: true });
  window.addEventListener('resize', suivreSections);

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

