/* État partagé : la flotte, le statut Kuma, la sélection, les filtres, les
   réglages — et les abonnements qui préviennent les écrans quand ça change.

   Avant la refonte ces valeurs étaient des variables globales (FLEET, STATUS,
   SEL, FILT, CUR…) que n'importe quel bout de code pouvait écrire. Elles vivent
   maintenant dans `store`, et un écran qui veut se redessiner s'abonne plutôt
   que d'être appelé de l'extérieur. Le comportement est identique : `emit()`
   est déclenché exactement là où l'ancien code appelait `render()`. */

import { api, SLUG } from './api.js';

export const store = {
  fleet: null,          // contenu de fleet.json
  status: {},           // {nom de moniteur Kuma: 0|1|2}
  mgmt: null,           // /api/mgmt/state
  baseline: {},         // référence des administrateurs
  settings: {           // réglages serveur, lus paresseusement (voir screens/reglages.js)
    viz_anomaly_rollback: false,
    viz_scan_after_update: true,
    viz_baseline_before_update: true,
    viz_baseline_required: false,
  },
  hidden: 0,            // sites masqués par la visibilité / le filtre Kuma
  curjob: null,         // identifiant du job groupé en cours
  cur: null,            // site affiché par la page site
  sort: { k: 'domain', dir: 1 },
  sel: new Set(),       // clés serveur|domaine cochées
  filt: { q: '', srv: '', grp: '', st: '', todo: false, groupby: false, compact: false, card: '' },
};

/* ---- seuils venus des réglages -------------------------------------------
   Ils pilotent aussi la file « à traiter » côté serveur (`incident_rules`) :
   les colonnes du tableau et le bandeau de la page site doivent dire la MÊME
   chose, sinon un site paraît « ok » ici et en incident là. Tant que
   `/api/mgmt/settings` n'a pas répondu, on retombe sur les valeurs par défaut
   du backend. */
function incidentRules() {
  const r = store.settings && store.settings.incident_rules;
  return (r && typeof r === 'object') ? r : {};
}

/** Version PHP hors support ? (liste des réglages, sinon « < 8.1 »). */
export function phpEol(v) {
  const m = /^(\d+)\.(\d+)/.exec(String(v || ''));
  if (!m) return false;
  const court = m[1] + '.' + m[2];
  const eol = incidentRules().php_eol_versions;
  if (Array.isArray(eol) && eol.length) return eol.map(String).includes(court);
  return parseFloat(court) < 8.1;
}

/** Âge (en heures) au-delà duquel une sauvegarde est jugée en retard. */
export function seuilBackup() {
  const n = Number(incidentRules().backup_max_age_h);
  return isFinite(n) && n > 0 ? n : 48;
}

/* ---- abonnements --------------------------------------------------------- */
const bus = new EventTarget();

/** subscribe(fn) → fonction de désabonnement. */
export function subscribe(fn) {
  const handler = () => fn(store);
  bus.addEventListener('change', handler);
  return () => bus.removeEventListener('change', handler);
}

/** Prévient les abonnés que le store a changé. */
function emit() { bus.dispatchEvent(new Event('change')); }

/* ---- cache court par chargeur --------------------------------------------
   Changer d'écran relançait tout son volet à CHAQUE clic — pour Sécurité,
   5 requêtes dont /api/sec/vulns (~190 Ko, le parc entier). Les boutons
   « Relancer » et les actions passent `force`. */
const CACHE_TTL = 60000, CACHE_AT = {};

export function cacheFrais(k, force) {
  if (!force && CACHE_AT[k] && Date.now() - CACHE_AT[k] < CACHE_TTL) return true;
  CACHE_AT[k] = Date.now();
  return false;
}
export function cacheVider(k) { delete CACHE_AT[k]; }

/* ---- lecture de la flotte ------------------------------------------------- */
export function kName(d) { return ('kuma' in d) ? d.kuma : d.domain; }

/* Chaîne de recherche pré-calculée : le filtre du tableau sérialisait
   `plugins_updates_list` en JSON pour CHAQUE site à CHAQUE frappe. Elle est
   construite une fois par collecte et couvre aussi les extensions déjà à jour
   (`plugins_list`) et les comptes administrateurs. */
function siteHaystack(d) {
  const bouts = [d.domain, d.kuma, d.srv, d.blogname, d.kuma_group, d.php_version, d.core_version];
  (d.plugins_list || []).forEach(p => { bouts.push(p.name); bouts.push(p.version); });
  (d.plugins_updates_list || []).forEach(p => bouts.push(typeof p === 'string' ? p : (p && (p.name || p.slug))));
  (d.admins || []).forEach(a => bouts.push(a && a.login));
  return bouts.filter(Boolean).join(' ').toLowerCase();
}

/* Mémoïsation : `allSites()` était reconstruite 3 fois par rendu (cartes,
   filtre, méta). Le cache est vidé dès que la flotte change. */
let SITECACHE = null;

export function allSites() {
  if (SITECACHE) return SITECACHE;
  const out = [];
  store.hidden = 0;
  (store.fleet?.servers || []).forEach(s => (s.sites || []).forEach(x => {
    const d = { srv: s.name, ...x };
    if (d.visible === false) { store.hidden++; return; }
    // un site ajouté sans SSH (mode REST) est géré explicitement : toujours visible,
    // même tant qu'aucun moniteur Kuma ne lui correspond.
    if (d.visible !== true && d.via !== 'rest' && ('kuma' in d) && !d.kuma) { store.hidden++; return; }
    d._q = siteHaystack(d);
    // État du serveur reporté sur ses sites : `stale` = injoignable à la
    // dernière collecte, les chiffres affichés datent de la précédente.
    d._stale = !!s.stale; d._srvErr = s.error || ''; d._srvAt = s.last_attempt || '';
    out.push(d);
  }));
  SITECACHE = out;
  return out;
}

/* Retrouve le site du parc derrière un nom vu ailleurs (clé Kuma d'un rapport
   de vulnérabilités, alias…) : `find_site()` côté serveur ne connaît que le
   vhost réel, pas l'alias de moniteur. */
export function siteByName(nom, srv) {
  const n = String(nom || '').toLowerCase();
  if (!n) return null;
  const S = allSites();
  return S.find(s => String(s.kuma || '').toLowerCase() === n && (!srv || s.srv === srv))
      || S.find(s => String(s.domain || '').toLowerCase() === n && (!srv || s.srv === srv))
      || S.find(s => String(s.kuma || '').toLowerCase() === n)
      || S.find(s => String(s.domain || '').toLowerCase() === n)
      || null;
}

/** État Kuma d'un site : 1 en ligne, 0 down, 2 en attente, undefined inconnu. */
export function st(d) { const n = kName(d); return n ? store.status[n] : undefined; }

/** Âge de la dernière sauvegarde UpdraftPlus, en heures (null si aucune). */
export function bkAge(s) {
  const ts = s.updraft?.last_backup_ts;
  if (!ts) return null;
  return (Date.now() / 1000 - ts) / 3600;
}

/** « À traiter » : mise à jour en attente, sauvegarde en retard, erreur, down. */
export function attn(s) {
  return !!(s.core_update || s.plugins_updates || Object.keys(s.errors || {}).length
    || (s.updraft && (bkAge(s) === null || bkAge(s) > seuilBackup())) || st(s) === 0);
}

/** Clé stable d'un site dans la sélection. */
export const key = s => s.srv + '|' + s.domain;

/* ---- chargements ---------------------------------------------------------- */
/* Dédoublonnage : plusieurs actions enchaînées (bulk terminé, re-scan, retour
   d'autorisation) déclenchaient trois collectes de fleet.json en parallèle. */
let FLEETP = null;

export function loadFleet() {
  if (FLEETP) return FLEETP;
  FLEETP = chargerFleet().finally(() => { FLEETP = null; });
  return FLEETP;
}

async function chargerFleet() {
  const f = await api('fleet.json?' + Date.now());
  store.fleet = f;
  SITECACHE = null;
  allSites();          // recalcule le cache et le compteur de sites masqués
  emit();
}

export async function loadStatus() {
  try {
    const cfg = await api('/api/status-page/' + SLUG);
    const hb = await api('/api/status-page/heartbeat/' + SLUG);
    const byId = {};
    (cfg.publicGroupList || []).forEach(g => (g.monitorList || []).forEach(m => { byId[m.id] = m.name; }));
    const next = {};
    Object.entries(hb.heartbeatList || {}).forEach(([id, arr]) => {
      const n = byId[id];
      if (n && arr.length) next[n] = arr[arr.length - 1].status;
    });
    store.status = next;
    emit();
  } catch (e) { /* Kuma muet : les sites restent « inconnu », pas « en ligne » */ }
}
