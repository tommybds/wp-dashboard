/* Coque : barre latérale (destinations, compteurs, pied), en-tête d'écran
   (titre, méta, bouton Collecter), thème, journal des actions, collecte.

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

function themeCourant() {
  try { return localStorage.dashTheme || 'auto'; } catch (e) { return 'auto'; }
}

/* ---- cadence de collecte -------------------------------------------------
   Lue une fois ; Réglages la modifie et rappelle loadSched(). */
let SCHED = null;

export function schedLabel() {
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
   Phase 1 : les deux valeurs déjà calculables sans nouvelle route. Les règles
   complètes de la file « à traiter » arrivent en phase 2. */
export function setCounter(name, value, level) {
  const el = document.getElementById('cnt-' + name);
  if (!el) return;
  const n = Number(value) || 0;
  el.textContent = String(n);
  el.className = 'nav-c' + (n && level ? ' ' + level : '');
  el.hidden = !n;
  el.title = n ? el.dataset.label || '' : '';
}

/** Compteurs déduits de la flotte + du statut Kuma (sites injoignables). */
export function majCompteurs() {
  if (!store.fleet) return;
  const down = allSites().filter(s => st(s) === 0).length;
  setCounter('incidents', down, 'err');
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

/* ---- journal des actions -------------------------------------------------- */
async function ouvrirJournal() {
  document.getElementById('logmodal').classList.add('open');
  const j = await api('/api/actions/log');
  document.getElementById('loglist').innerHTML = (j.log || []).map(e => {
    /* rc 2 sur une action vizproof (scan, verdict) = ANOMALIES : l'action a
       tourné, c'est le rendu du site qui a changé — chip orange, pas rouge. */
    const anom = Number(e.rc) === 2 && /^viz_/.test(String(e.action || ''));
    const cls = e.rc === 0 ? 'ok' : (anom ? 'warn' : 'err'), lib = e.rc === 0 ? 'OK' : (anom ? 'anomalies' : 'échec');
    return `<div class="logline"><b>${H(e.domain)}</b> · ${H(e.action)}${e.arg ? ' ' + H(e.arg) : ''} · <span class="pill ${cls}">${lib}</span> <span class="muted small">${H(e.source || '')} ${H(e.ts)} · ${e.duration_s}s</span><br><code>${H((e.output_tail || '').slice(-240))}</code></div>`;
  }).join('') || 'Aucune action.';
}

/* ---- démarrage de la coque ------------------------------------------------ */
export function initShell({ onCollect } = {}) {
  applyTheme(themeCourant());
  document.getElementById('themebtn').onclick = () => {
    const c = themeCourant();
    applyTheme(THEMES[(THEMES.findIndex(x => x[0] === c) + 1) % THEMES.length][0]);
  };
  document.getElementById('logoutbtn').onclick = logout;
  document.getElementById('logbtn').onclick = ouvrirJournal;
  document.getElementById('logmodal').onclick = e => {
    if (e.target.id === 'logmodal') e.target.classList.remove('open');
  };
  document.getElementById('collectbtn').onclick = async () => {
    const r = await api('/api/actions/collect', {}).catch(e => ({ error: String(e) }));
    if (r && r.error && onCollect) onCollect(r.error);
    pollCollect();
  };
  // Menu latéral en étroit : le fond se referme au clic, Échap aussi.
  const nav = document.getElementById('nav'), back = document.getElementById('navback');
  const fermer = () => { nav.classList.remove('open'); back.classList.remove('open'); };
  document.getElementById('menubtn').onclick = () => {
    const ouvert = nav.classList.toggle('open');
    back.classList.toggle('open', ouvert);
  };
  back.onclick = fermer;
  nav.addEventListener('click', e => { if (e.target.closest('.nav-i')) fermer(); });
}
