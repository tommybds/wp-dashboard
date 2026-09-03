/* Coque : barre latérale (destinations, compteurs, pied), barre d'onglets basse
   du mobile, en-tête d'écran (titre, méta, bouton Collecter), thème et
   collecte. Le journal des actions est une modale à part (components/log.js),
   branchée d'ici.

   Sous 720 px, la barre latérale cède la place à la barre d'onglets basse
   (`#tabbar`) : trois destinations et un bouton « Plus » qui ouvre une feuille
   avec le reste. Les pastilles de compteur sont les MÊMES des deux côtés —
   d'où `data-count` plutôt qu'un identifiant.

   Rien ici ne connaît le contenu d'un écran : la coque n'affiche que ce que
   `store` et le backend lui donnent. */

import { api, logout } from '../lib/api.js';
import { esc as H } from '../lib/dom.js';
import { relTime } from '../lib/format.js';
import { icon } from '../lib/icons.js';
import { poll } from '../lib/poll.js';
import { store, allSites, st, loadFleet, loadStatus } from '../lib/state.js';
import { NOTIF } from './toast.js';
import { chip } from './chip.js';
import { initJournal } from './log.js';
import { ouvrirFeuille, boutonFeuille } from './sheet.js';

/* ---- thème : auto / clair / sombre ---------------------------------------
   `auto` retire l'attribut et laisse `prefers-color-scheme` décider ; les deux
   autres l'écrivent. Le choix est mémorisé dans localStorage.dashTheme. */
const THEMES = [
  ['auto', 'Auto', 'sun-moon'],
  ['light', 'Clair', 'sun'],
  ['dark', 'Sombre', 'moon'],
];

export function applyTheme(t) {
  if (t === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  const cur = THEMES.find(x => x[0] === t) || THEMES[0];
  const b = document.getElementById('themebtn');
  if (b) {
    b.innerHTML = icon(cur[2], { size: 20 }) + `<span class="nav-l">Thème : ${H(cur[1].toLowerCase())}</span>`;
    b.title = 'Thème : ' + cur[1].toLowerCase() + ' (cliquer pour changer)';
    b.setAttribute('aria-label', 'Thème : ' + cur[1].toLowerCase() + ', cliquer pour changer');
  }
  try { localStorage.dashTheme = t; } catch (e) { /* stockage refusé : le thème vaut pour la session */ }
}

/** Thème choisi : 'auto', 'light' ou 'dark'. Lu aussi par l'écran Réglages. */
export function themeCourant() {
  try { return localStorage.dashTheme || 'auto'; } catch (e) { return 'auto'; }
}

/* ---- cadence de collecte -------------------------------------------------
   Lue une fois ; Réglages la modifie et rappelle loadSched(). */
let SCHED = null;

function schedLabel() {
  const m = SCHED == null ? null : +SCHED;
  if (m == null) return 'actualisation automatique';
  if (!m) return 'actualisation manuelle';
  if (m === 60) return 'actualisation horaire';
  if (m < 60) return `actualisation toutes les ${m} min`;
  return m % 60 ? `actualisation toutes les ${Math.floor(m / 60)} h ${m % 60}` : `actualisation toutes les ${m / 60} h`;
}

export async function loadSched() {
  try { const s = await api('/api/mgmt/schedule'); SCHED = s.interval_minutes; }
  catch (e) { /* cadence inconnue : la méta le dit en clair */ }
  updMeta();
}

/* ---- méta de l'en-tête d'écran ------------------------------------------- */
export function updMeta() {
  const el = document.getElementById('meta');
  if (!el || !store.fleet) return;
  const rel = relTime(store.fleet.generated_at), n = allSites().length;
  const ko = (store.fleet?.servers || []).filter(x => x && x.stale);
  const koTip = ko.map(x => x.name + (x.last_attempt ? ' (essai du ' + x.last_attempt + ')' : '') + (x.error ? ' : ' + x.error : '')).join(' · ');
  el.innerHTML =
    `<b>${n}</b> site${n > 1 ? 's' : ''} suivi${n > 1 ? 's' : ''}<span class="sep">·</span>`
    + `collecté ${H(rel)}<span class="sep">·</span>${schedLabel()}`
    + (store.hidden ? `<span class="sep">·</span>${store.hidden} masqué${store.hidden > 1 ? 's' : ''}` : '')
    // Un serveur muet fausse la lecture de tout le tableau : il se dit en clair.
    + (ko.length ? `<span class="sep">·</span>` + chip(
        `${ko.length} serveur${ko.length > 1 ? 's' : ''} injoignable${ko.length > 1 ? 's' : ''}`, 'warn',
        { tip: 'Données conservées de la collecte précédente pour : ' + koTip }) : '');
  el.title = 'Dernière collecte : ' + store.fleet.generated_at;
}

/** Titre de l'écran courant. */
export function setScreenTitle(t) {
  const el = document.getElementById('screen-title');
  if (el) el.textContent = t;
  document.title = t + ' — Parc WordPress';
}

/* ---- compteurs de la barre latérale --------------------------------------
   Tant que la file « à traiter » n'a pas répondu, le compteur Incidents vaut
   les sites injoignables (calculable sans requête). Dès que `/api/incidents`
   a parlé, c'est LUI qui fait foi : deux sources qui se contredisent sur la
   même pastille, c'est une pastille qu'on n'ose plus croire. */
let INCIDENTS_CONNUS = false;

export function setIncidentCount(n, level) {
  INCIDENTS_CONNUS = true;
  setCounter('incidents', n, level);
}

/* Une pastille est portée par DEUX barres — la latérale du bureau et celle du
   bas au mobile. Elle est donc visée par `data-count` et non par un
   identifiant : sinon l'une des deux mentirait. */
function setCounter(name, value, level) {
  const n = Number(value) || 0;
  document.querySelectorAll('[data-count="' + name + '"]').forEach(el => {
    const base = el.classList.contains('tab-c') ? 'tab-c' : 'nav-c';
    el.textContent = String(n);
    el.className = base + (n && level ? ' ' + level : '');
    el.hidden = !n;
    el.title = n ? el.dataset.label || '' : '';
  });
}

/** Compteurs déduits de la flotte + du statut Kuma (sites injoignables). */
export function majCompteurs() {
  if (!store.fleet || INCIDENTS_CONNUS) return;
  const down = allSites().filter(s => st(s) === 0).length;
  setCounter('incidents', down, 'err');
}

/* ---- pastilles servies par le backend -------------------------------------
   `/api/mgmt/counts` dérive du MÊME agrégat que `/api/incidents` : c'est la
   seule façon d'être sûr que la pastille Incidents dit exactement ce que montre
   la file, et que la pastille Sécurité dit ce que montre l'écran Sécurité
   (vulnérabilités corrigeables + administrateurs inconnus).

   Étranglement à 20 s : la fonction est appelée à chaque changement du store
   (statut Kuma toutes les 60 s, collecte, action), et l'agrégat relit une
   demi-douzaine de fichiers côté serveur. */
let CNT_AT = 0, CNT_P = null;

export function majCompteursServeur(force) {
  if (!force && CNT_P && Date.now() - CNT_AT < 20000) return CNT_P;
  CNT_AT = Date.now();
  CNT_P = api('/api/mgmt/counts').then(c => {
    const i = (c && c.incidents) || {}, s = (c && c.securite) || {};
    // La pastille ne compte QUE les incidents « à traiter » : y ajouter les
    // chantiers (PHP en fin de support, moniteur en pause) la maintiendrait
    // rouge en permanence, et une pastille qui ne redescend jamais n'est plus
    // lue. `critical`/`warning` restent le repli d'un backend plus ancien.
    const crit = ('now_critical' in i) ? (i.now_critical || 0) : (i.critical || 0);
    const avert = ('now_warning' in i) ? (i.now_warning || 0) : (i.warning || 0);
    setIncidentCount(crit + avert, crit ? 'err' : 'warn');
    setCounter('securite', (s.vulns_fixable || 0) + (s.admins_unknown || 0),
      s.admins_unknown ? 'err' : 'warn');
    return c;
  }).catch(() => null);
  return CNT_P;
}

/* ---- hauteur réelle de l'en-tête ------------------------------------------
   Publiée dans `--shead-h` : les sommaires collants des pages à ancres se
   placent JUSTE dessous, y compris quand l'en-tête passe à la ligne en étroit.
   Une valeur en dur les ferait chevaucher ou flotter. */
function suivreHauteurEntete() {
  const el = document.querySelector('.shead');
  if (!el) return;
  const maj = () => document.documentElement.style.setProperty('--shead-h', el.offsetHeight + 'px');
  maj();
  if (window.ResizeObserver) new ResizeObserver(maj).observe(el);
  else window.addEventListener('resize', maj);
}

/* ---- collecte manuelle ---------------------------------------------------- */
export function pollCollect() {
  poll('collect', async () => {
    const j = await api('/api/actions/collect_status');
    const box = document.getElementById('collectbox'), btn = document.getElementById('collectbtn');
    if (!j.running && j.rc === null) { box.hidden = true; btn.disabled = false; return { fini: true }; }
    box.hidden = false;
    const pct = j.total ? Math.round(100 * Math.min(j.done, j.total) / j.total) : 0;
    document.getElementById('cb-bar').style.width = (j.running ? Math.max(pct, 4) : 100) + '%';
    document.getElementById('cb-lines').textContent = (j.lines || []).join('\n');
    if (j.running) {
      btn.disabled = true;
      box.dataset.w = '1';
      document.getElementById('cb-title').textContent = 'Collecte en cours…';
      document.getElementById('cb-step').textContent = `serveur ${Math.min(j.done + 1, j.total)}/${j.total} · ${j.started || ''}`;
      // La collecte peut aussi avoir été lancée ailleurs (cron, autre onglet) :
      // `start` est idempotent sur un même identifiant tant que la ligne tourne.
      if (!NOTIF.encours('collect')) NOTIF.start({ id: 'collect', kind: 'collect', label: 'Collecte du parc', progress: 0 });
      NOTIF.update('collect', {
        progress: j.total ? Math.min(j.done, j.total) / j.total : null,
        detail: `serveur ${Math.min(j.done + 1, j.total)}/${j.total}`,
      });
      return { fini: false };
    }
    btn.disabled = false;
    NOTIF.done('collect', {
      ok: j.rc === 0,
      message: j.rc === 0 ? (j.total ? j.total + ' serveur' + (j.total > 1 ? 's' : '') + ' relevé' + (j.total > 1 ? 's' : '') : '') : 'échec (rc ' + j.rc + ')',
    });
    if (box.dataset.w !== '1') { box.hidden = true; return { fini: true }; }
    document.getElementById('cb-title').innerHTML = j.rc === 0
      ? icon('circle-check', { cls: 'ic-ok' }) + ' Collecte terminée'
      : icon('circle-x', { cls: 'ic-err' }) + ' échec (rc ' + H(j.rc) + ')';
    document.getElementById('cb-step').textContent = '';
    loadFleet().then(loadStatus).catch(() => {});
    setTimeout(() => { box.hidden = true; }, 6000);
    return { fini: true };
  }, { every: 2500, maxErrors: 5, until: r => !!(r && r.fini) });
}

/* ---- démarrage de la coque ------------------------------------------------ */
export function initShell({ onCollect } = {}) {
  applyTheme(themeCourant());
  suivreHauteurEntete();
  document.getElementById('themebtn').onclick = () => {
    const c = themeCourant();
    applyTheme(THEMES[(THEMES.findIndex(x => x[0] === c) + 1) % THEMES.length][0]);
  };
  document.getElementById('logoutbtn').onclick = logout;
  // Le journal des actions vit dans son propre composant (components/log.js) :
  // c'est une modale transversale, pas un morceau de la coque.
  initJournal();
  document.getElementById('collectbtn').onclick = async () => {
    const r = await api('/api/actions/collect', {}).catch(e => ({ error: String(e) }));
    if (r && r.error && onCollect) onCollect(r.error);
    pollCollect();
  };
  document.getElementById('plusbtn').onclick = ouvrirPlus;
}

/* ---- « Plus » : le pied de la barre latérale, au mobile -------------------
   La barre d'onglets basse ne porte que trois destinations : le reste (deux
   destinations, le journal, le thème, la déconnexion) vit dans cette feuille.
   Elle ne duplique aucune logique — chaque entrée actionne le contrôle déjà
   présent dans la barre latérale, ou navigue. */
function ouvrirPlus() {
  const btn = document.getElementById('plusbtn');
  const aller = f => () => { location.hash = f; };
  const cliquer = id => () => { const b = document.getElementById(id); if (b) b.click(); };
  ouvrirFeuille({
    titre: 'Plus',
    onClose: () => btn.setAttribute('aria-expanded', 'false'),
    contenu: () => [
      boutonFeuille({ label: 'Changements', ic: 'history', onSelect: aller('#changements') }),
      boutonFeuille({ label: 'Gestion', ic: 'server', onSelect: aller('#gestion') }),
      boutonFeuille({ label: 'Réglages', ic: 'settings', onSelect: aller('#reglages') }),
      boutonFeuille({ label: 'Journal des actions', ic: 'scroll-text', onSelect: cliquer('logbtn') }),
      boutonFeuille({
        label: 'Thème : ' + (THEMES.find(x => x[0] === themeCourant()) || THEMES[0])[1].toLowerCase(),
        ic: 'sun-moon', onSelect: cliquer('themebtn'),
      }),
      boutonFeuille({ label: 'Se déconnecter', ic: 'log-out', kind: 'danger', onSelect: logout }),
    ],
  });
  btn.setAttribute('aria-expanded', 'true');
}
