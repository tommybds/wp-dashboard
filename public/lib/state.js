/* État partagé : la flotte, le statut Kuma, la sélection, les filtres, les
   réglages — et les abonnements qui préviennent les écrans quand ça change.

   Avant la refonte ces valeurs étaient des variables globales (FLEET, STATUS,
   SEL, FILT, CUR…) que n'importe quel bout de code pouvait écrire. Elles vivent
   maintenant dans `store`, et un écran qui veut se redessiner s'abonne plutôt
   que d'être appelé de l'extérieur. Le comportement est identique : `emit()`
   est déclenché exactement là où l'ancien code appelait `render()`.

   Uptime Kuma est FACULTATIF. Le dashboard sonde lui-même chaque site
   (`site.probe`) et lit lui-même les certificats (`site.cert`) : il reste
   complet sans Kuma. Quand Kuma est là, son verdict prime — c'est un vrai
   moniteur, avec un historique et des alertes, là où la sonde n'est qu'un
   relevé de collecte. Toute la règle tient dans `etatSite()` : aucun écran ne
   la ré-invente, sinon deux écrans finissent par dire deux choses du même
   site. */

import { api, slugKuma, setSlugKuma } from './api.js';
import { relTime } from './format.js';

export const store = {
  fleet: null,          // contenu de fleet.json
  status: {},           // {nom de moniteur Kuma: 0|1|2}
  kuma: null,           // {enabled, reason, slug, container, db, status_url} — null tant
                        // que /api/mgmt/state n'a pas répondu
  mgmt: null,           // /api/mgmt/state
  baseline: {},         // référence des administrateurs
  settings: {           // réglages serveur, lus paresseusement (voir screens/reglages.js)
    viz_anomaly_rollback: false,
    viz_scan_after_update: true,
    viz_baseline_before_update: true,
    viz_baseline_required: false,
  },
  hidden: 0,            // sites découverts mais non suivis (ou masqués à la main)
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
   (`plugins_list`), les thèmes (`themes_list`) et les comptes administrateurs. */
function siteHaystack(d) {
  const bouts = [d.domain, d.kuma, d.srv, d.blogname, d.kuma_group, d.php_version, d.core_version];
  (d.plugins_list || []).forEach(p => { bouts.push(p.name); bouts.push(p.version); });
  (d.plugins_updates_list || []).forEach(p => bouts.push(typeof p === 'string' ? p : (p && (p.name || p.slug))));
  // Un thème se cherche par son slug de dossier comme par son nom affiché.
  (d.themes_list || []).forEach(t => { bouts.push(t.name); bouts.push(t.title); bouts.push(t.version); });
  (d.admins || []).forEach(a => bouts.push(a && a.login));
  return bouts.filter(Boolean).join(' ').toLowerCase();
}

/* ---- suivi et visibilité ---------------------------------------------------
   Le Parc ne montre plus « ce que Kuma surveille » mais « ce que le dashboard
   suit » : une liste qui lui appartient (`site.followed`, écrite par
   /api/mgmt/follow). Un install découvert au scan reste donc MASQUÉ tant qu'on
   ne l'a pas explicitement pris en charge — c'est ce qui permet de scanner un
   serveur entier sans noyer le tableau.

   `site.visible` reste au-dessus : c'est le forçage manuel (afficher / masquer
   quoi qu'il arrive) de la route d'override. Il n'est presque jamais posé.

   Repli : tant que `followed` n'est pas remonté par la collecte (backend plus
   ancien), on retombe sur l'ancienne règle — sinon le Parc se viderait d'un
   coup au premier déploiement du front. */
export function suivi(d) {
  if (typeof d.followed === 'boolean') return d.followed;
  return d.via === 'rest' || !!kName(d);
}

/** Le site apparaît-il dans le Parc ? (forçage manuel, sinon suivi) */
export function estAffiche(d) {
  if (d.visible === true) return true;
  if (d.visible === false) return false;
  // `primary` est faux sur la copie perdante d'un domaine hébergé à deux
  // endroits (migration en cours) : la suivre afficherait deux fois le même
  // site. Même règle que `site_visible` côté serveur, qui fait autorité.
  return suivi(d) && d.primary !== false;
}

/** L'affichage forcé contredit-il le suivi ? (à dire, sinon il est invisible) */
export function affichageForce(d) {
  return (d.visible === true || d.visible === false) && d.visible !== suivi(d);
}

/* ---- nom, client -----------------------------------------------------------
   Le nom vient de Kuma quand il y a un moniteur, sinon du libellé saisi dans
   Gestion (`label`), sinon du domaine. La CLÉ D'URL, elle, ne bouge pas avec le
   libellé (cf. `cleDeSite` dans screens/site.js) : un renommage ne doit pas
   casser les liens déjà partagés. */
export function nomDeSite(d) {
  return kName(d) || d.label || d.domain || '';
}

/** Client d'un site : groupe Kuma s'il existe, sinon le client saisi. */
export function clientDe(d) {
  return d.kuma_group || d.client || '';
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
    if (!estAffiche(d)) { store.hidden++; return; }
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

/* État Kuma brut d'un site : 1 en ligne, 0 down, 2 en attente, undefined si
   aucun moniteur ne parle de lui. Volontairement NON exporté : un écran qui
   lirait Kuma directement afficherait « inconnu » sur une installation sans
   Kuma, alors que la sonde du dashboard, elle, a la réponse. Tout le monde
   passe par `etatSite()`. */
function st(d) { const n = kName(d); return n ? store.status[n] : undefined; }

/* ---- disponibilité affichée ------------------------------------------------
   UNE fonction pour tout l'écran. Elle rend un objet d'affichage — libellé,
   niveau de chip, phrase de source — et jamais du DOM : les cartes du mobile,
   les lignes du tableau, l'en-tête de la page site et la recherche globale
   passent tous par là, donc ils ne peuvent pas diverger.

     v      1 en ligne · 0 injoignable · 2 en attente · undefined inconnu
     source 'kuma' | 'probe' | ''    (pour un affichage discret, pas pour trier)
     tip    d'où vient ce verdict, et quand — la phrase de l'infobulle

   Kuma prime quand un moniteur répond pour ce site : il a l'historique et les
   alertes. Sinon la sonde du dashboard, faite à la collecte. Si aucune des deux
   n'a parlé : « inconnu », gris — jamais vert par défaut. */
export function etatSite(d) {
  const v = st(d);
  if (v !== undefined) {
    return {
      v,
      txt: v === 1 ? 'en ligne' : v === 0 ? 'down' : v === 2 ? 'en attente' : 'inconnu',
      niv: v === 1 ? 'ok' : v === 0 ? 'err' : v === 2 ? 'warn' : 'mut',
      source: 'kuma',
      tip: "d'après Uptime Kuma",
    };
  }
  const p = d && d.probe;
  if (p && typeof p === 'object' && typeof p.ok === 'boolean') {
    const bouts = [];
    if (p.status) bouts.push('HTTP ' + p.status);
    if (p.ms) bouts.push(Math.round(p.ms) + ' ms');
    if (!p.ok && p.error) bouts.push(String(p.error).slice(0, 120));
    const quand = p.checked_at ? relTime(p.checked_at) : '';
    return {
      v: p.ok ? 1 : 0,
      txt: p.ok ? 'en ligne' : 'injoignable',
      niv: p.ok ? 'ok' : 'err',
      source: 'probe',
      tip: 'sonde du dashboard' + (quand ? ', ' + quand : '')
        + (bouts.length ? ' · ' + bouts.join(' · ') : ''),
    };
  }
  return {
    v: undefined, txt: 'inconnu', niv: 'mut', source: '',
    tip: "aucune sonde n'a encore relevé ce site",
  };
}

/* ---- Uptime Kuma présent ? -------------------------------------------------
   `store.kuma` vient de /api/mgmt/state. Tant qu'il est `null` on considère
   Kuma présent : c'était le comportement avant, et il vaut mieux une seconde
   d'optimisme qu'un écran qui efface ses sections puis les remet. */
export function kumaActif() { return !store.kuma || store.kuma.enabled !== false; }

/* Où lire comment brancher Uptime Kuma. Une seule constante : trois écrans
   renvoient à cette page, et trois liens copiés-collés finissent par diverger. */
export const DOC_KUMA = 'https://github.com/tommybds/wp-dashboard#configjson';

/** Pourquoi Kuma n'est pas là (phrase du backend), pour les écrans qui le disent. */
export function kumaRaison() { return (store.kuma && store.kuma.reason) || ''; }

/* Le drapeau est lu UNE fois au démarrage : Parc, page site, Sécurité et
   Réglages en ont besoin, et aucun d'eux n'ouvre Gestion (seul écran qui
   chargeait /api/mgmt/state jusqu'ici). Un échec laisse `store.kuma` à null,
   donc l'ancien affichage. */
let KUMAP = null;

/** `force` refait l'appel : après un enregistrement du branchement, l'état
    « connecté / non configuré » doit changer sans rechargement de page. */
export function loadKuma(force) {
  if (KUMAP && !force) return KUMAP;
  KUMAP = api('/api/mgmt/state').then(j => {
    setKuma(j && j.kuma);
    return store.kuma;
  }).catch(() => null);
  return KUMAP;
}

/** Enregistre l'état Kuma (appelé aussi par Gestion, qui lit le même état).

    Le bloc porte la présence (`enabled`, `reason`) ET le branchement (slug,
    conteneur, base, url) : Réglages remplit ses champs avec, et le slug fait
    autorité pour les appels à la status page — d'où `setSlugKuma`. */
export function setKuma(k) {
  const avant = store.kuma && store.kuma.enabled;
  const src = (k && typeof k === 'object') ? k : {};
  store.kuma = {
    enabled: src.enabled !== false,
    reason: String(src.reason || ''),
    slug: String(src.slug || ''),
    container: String(src.container || ''),
    db: String(src.db || ''),
    status_url: String(src.status_url || ''),
  };
  setSlugKuma(store.kuma.slug);
  if (store.kuma.enabled !== avant) emit();
}

/** Âge de la dernière sauvegarde UpdraftPlus, en heures (null si aucune). */
export function bkAge(s) {
  const ts = s.updraft?.last_backup_ts;
  if (!ts) return null;
  return (Date.now() / 1000 - ts) / 3600;
}

/** « À traiter » : mise à jour en attente, sauvegarde en retard, erreur, down. */
export function attn(s) {
  return !!(s.core_update || s.plugins_updates || Object.keys(s.errors || {}).length
    || (s.updraft && (bkAge(s) === null || bkAge(s) > seuilBackup())) || etatSite(s).v === 0);
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
  // Sans Kuma il n'y a pas de status page à interroger : aller la chercher
  // quand même remplirait la console d'erreurs réseau à chaque minute.
  if (!kumaActif()) { store.status = {}; return; }
  try {
    const slug = slugKuma();
    const cfg = await api('/api/status-page/' + slug);
    const hb = await api('/api/status-page/heartbeat/' + slug);
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
