/* Page d'un site — `#site/<clé>` et `#site/<clé>/<onglet>`.

   Elle remplace le tiroir de la phase 1 : même contenu, mêmes actions, mêmes
   gardes, mais une adresse partageable, cinq onglets, une action principale
   déduite de l'état et le reste dans un menu groupé par intention.

   Trois points d'attention repris tels quels du tiroir :

   * UN SEUL compteur de séquence (`PAGESEQ`) pour tous les chargeurs. Ouvrir A
     puis vite B affichait sinon les gels, les points de restauration ou les
     vulnérabilités de A dans la fiche de B.
   * La console est identifiée par le domaine qu'elle porte (`data-domain`) :
     la cibler par son seul identifiant faisait écrire la progression du site A
     dans la console du site B.
   * Les suivis de job (MAJ sûre, MAJ sous contrôle visuel) vivent côté
     serveur : rouvrir la page s'y raccroche, la quitter ne les arrête pas. */

import { api } from '../lib/api.js';
import { esc as H, h, mount } from '../lib/dom.js';
import {
  absTime, relTime, safeUrl, stripPhpNoise, tsMs,
  udIntervalFr, udHorizon, udRulesFr,
} from '../lib/format.js';
import { icon, iconEl } from '../lib/icons.js';
import { poll, stopPoll } from '../lib/poll.js';
import { store, allSites, st, bkAge, kName, loadFleet, phpEol, seuilBackup } from '../lib/state.js';

import { setBusy, setIdle } from '../components/button.js';
import { chipEl, libelleKuma, niveauKuma } from '../components/chip.js';
import { askConfirm, askInfo, askOpen } from '../components/confirm.js';
import { menuActions, fermerMenus } from '../components/actions-menu.js';
import { askVersion, pointsListeEl, setRollbackPoints, rollbackPoints } from '../components/rollback.js';
import { NOTIF } from '../components/toast.js';
import {
  openVizConnect, vizBlocEl, vizConnected, vizConsoleLigne, vizDisconnect, vizEtat,
  vizInstall, vizPhrase, vizState, setVizConsole, setVizRefresh,
  VIZ_PHASES, suivreVizLast,
} from '../components/viz.js';
import { loadWpCred } from './gestion.js';
import { ensureSettings } from './reglages.js';
import { sevPill, SEVLABEL, SEVRANK, grouperParExtension } from './securite.js';

/* ---- état de la page ------------------------------------------------------ */
const ONGLETS = [
  ['apercu', 'Aperçu'],
  ['extensions', 'Extensions'],
  ['securite', 'Sécurité'],
  ['sauvegardes', 'Sauvegardes'],
  ['historique', 'Historique'],
];
const ONGLET_SLUGS = ONGLETS.map(o => o[0]);

let PAGESEQ = 0;         // un seul compteur pour tous les chargeurs
let CUR = null;          // site affiché
let ONGLET = 'apercu';
let CLE = '';            // clé d'URL du site affiché
let VULNS = null;        // dernier croisement pour CE site
let FROZEN = [];         // extensions gelées
let INCIDENTS = [];      // incidents de CE site

/** Site du parc derrière une clé d'URL (nom Kuma, sinon vhost). */
export function siteParCle(cle) {
  const n = String(cle || '').toLowerCase();
  const S = allSites();
  return S.find(s => String(kName(s) || '').toLowerCase() === n)
    || S.find(s => String(s.domain || '').toLowerCase() === n) || null;
}
export function cleDeSite(s) { return kName(s) || s.domain; }

/* ---- libellés d'action (barre de notifications) --------------------------- */
const ACT_LIB = {
  core_update: 'MAJ cœur', plugins_update_all: 'MAJ extensions',
  plugins_update_except: 'MAJ extensions', plugin_update: 'MAJ', themes_update_all: 'MAJ thèmes',
  updraft_backup: 'Sauvegarde UpdraftPlus', cache_flush: 'Vidage des caches',
  autoupdate_on: 'Activation des auto-MAJ', autoupdate_off: 'Désactivation des auto-MAJ',
  verify_checksums: 'Intégrité du cœur', vizproof_install: 'Installation VizProof',
  viz_baseline: 'Baseline visuelle', viz_scan: 'Scan visuel', viz_disconnect: 'Dissociation VizProof',
  rescan: 'Re-scan',
};
const ACT_KIND = {
  core_update: 'maj', plugins_update_all: 'maj', plugins_update_except: 'maj',
  plugin_update: 'maj', themes_update_all: 'maj', updraft_backup: 'backup', cache_flush: 'cache',
  verify_checksums: 'check', vizproof_install: 'install', viz_baseline: 'viz', viz_scan: 'viz',
  viz_disconnect: 'connect', rescan: 'rescan',
};
export function actLib(act, arg) { return (ACT_LIB[act] || act) + (arg ? ' ' + arg : ''); }
function notifLabel(act, arg, s) { return actLib(act, arg) + ' · ' + ((s && (kName(s) || s.domain)) || ''); }

/* Seules les actions qui MODIFIENT le site demandent confirmation : tout
   confirmer revient à ne plus rien signaler. */
const ACT_RISQUE = new Set(['core_update', 'plugins_update_all', 'plugin_update',
  'themes_update_all', 'autoupdate_on', 'autoupdate_off', 'vizproof_install']);
const MAJ_ACTS = new Set(['core_update', 'plugins_update_all', 'plugins_update_except',
  'plugin_update', 'themes_update_all']);

/* ---- console -------------------------------------------------------------- */
/* La console est recréée à chaque rendu : la cibler par son seul identifiant
   ferait écrire la progression du site A dans la console du site B. */
function consoleDe(dom) {
  const box = document.getElementById('site-console');
  return (box && box.dataset.domain === dom) ? box : null;
}
setVizConsole(consoleDe);

function consoleVisible() {
  const box = document.getElementById('site-console');
  if (box) box.hidden = false;
  return box;
}

/* ---- rendu ---------------------------------------------------------------- */

/** Ouvre (ou rafraîchit) la page d'un site. Appelé par le routeur. */
export function renderSite(cle, onglet) {
  const s = siteParCle(cle);
  CLE = String(cle || '');
  ONGLET = ONGLET_SLUGS.includes(onglet) ? onglet : 'apercu';
  fermerMenus();
  if (!s) {
    CUR = null;
    store.cur = null;
    mount('page-site', h('div', { class: 'empty' },
      iconEl('triangle-alert', { size: 20 }),
      h('h2', { text: 'Site inconnu' }),
      h('p', {}, 'Aucun site du parc ne correspond à ', h('code', { text: CLE }),
        '. Il a peut-être été masqué, renommé, ou son moniteur supprimé.'),
      h('a', { class: 'btn', href: '#parc' }, iconEl('layout-grid'), 'Retour au parc')));
    return;
  }
  const change = !CUR || CUR.domain !== s.domain || CUR.srv !== s.srv;
  CUR = s;
  store.cur = s;
  if (change) {
    PAGESEQ++;
    stopPoll('safe');
    VULNS = null;
    FROZEN = [];
    setRollbackPoints([], s.srv, s.domain);
  }
  dessiner();
  if (change) chargerTout();
}

/* Rafraîchissement après une action : la flotte a changé, la console et
   l'onglet courant restent. */
export function refreshSite() {
  if (!CUR) return;
  const s = siteParCle(CLE) || siteParCle(cleDeSite(CUR));
  if (!s) return;
  CUR = s;
  store.cur = s;
  const box = document.getElementById('site-console');
  const garde = (box && !box.hidden) ? box.innerHTML : null;
  dessiner();
  if (garde !== null) { const b2 = document.getElementById('site-console'); if (b2) { b2.hidden = false; b2.innerHTML = garde; } }
  renderPolicy();
  renderVulnsSite();
}
setVizRefresh(refreshSite);

function dessiner() {
  const s = CUR;
  mount('page-site',
    entete(s),
    bandeau(s),
    ongletsNav(s),
    h('div', { id: 'site-tab', class: 'sitetab' }),
    h('div', { class: 'console', id: 'site-console', hidden: true, dataset: { domain: s.domain } }));
  renderVulnsSite();
  dessinerOnglet();
}

/* ---- en-tête -------------------------------------------------------------- */
function entete(s) {
  const v = st(s);
  const meta = h('div', { class: 'meta sitemeta' });
  const bout = (txt, cls) => h('span', { class: cls || '', text: txt });
  const sep = () => h('span', { class: 'sep', text: '·' });
  if (s.kuma_group) { meta.append(bout(s.kuma_group)); meta.append(sep()); }
  meta.append(bout(s.srv || '—'));
  if (s.path) { meta.append(sep()); meta.append(h('code', { class: 'small', text: s.path })); }
  meta.append(sep());
  meta.append(h('span', { title: absTime(s.collected_at || store.fleet?.generated_at), text: 'relevé ' + relTime(s.collected_at || store.fleet?.generated_at) }));
  meta.append(sep());
  meta.append(h('span', {
    class: 'pill mut',
    title: s.via === 'rest' ? "inventaire poussé par l'agent, sans accès SSH" : 'inventaire relevé en SSH',
    text: s.via === 'rest' ? 'via REST' : 'via SSH',
  }));

  const fil = h('nav', { class: 'fil', 'aria-label': "Fil d'Ariane" },
    h('a', { href: '#parc', text: 'Parc' }),
    h('span', { class: 'sep', text: '›' }),
    h('span', { 'aria-current': 'page', text: cleDeSite(s) }));

  const titre = h('div', { class: 'sitetitle' },
    h('h1', { text: cleDeSite(s) }),
    chipEl(libelleKuma(v), niveauKuma(v)),
    s._stale ? chipEl('données du ' + (s._srvAt || 'relevé précédent'), 'warn', {
      tip: 'serveur ' + (s.srv || '') + ' injoignable à la dernière collecte'
        + (s._srvErr ? ' : ' + s._srvErr : '') + ' — les chiffres datent du relevé précédent.',
    }) : null);

  return h('header', { class: 'sitehead' },
    fil, titre, meta,
    h('div', { class: 'siteact' }, actionPrincipale(s), menuDuSite(s)));
}

/* Action principale déduite de l'état : mettre à jour s'il y a de quoi, sinon
   re-scanner. Un job en cours la désactive — deux mises à jour de front sur le
   même WordPress, c'est un site cassé sans coupable (le serveur refuse en 409). */
function actionPrincipale(s) {
  const rest = s.via === 'rest';
  const nEx = s.plugins_updates || 0, core = !!s.core_update;
  if (!rest && (core || nEx)) {
    const quoi = core ? ('cœur' + (nEx ? ' + ' + nEx + ' ext.' : '')) : (nEx + ' ext.');
    const b = h('button', {
      type: 'button', class: 'btn primary', id: 'safeup',
      title: 'Archive ce qui va changer (fichiers + base), met à jour, contrôle le site, '
        + 'et remet en arrière automatiquement si quelque chose casse',
    }, iconEl('shield-check'), 'MAJ sûre — ' + quoi);
    b.dataset.core = core ? '1' : '0';
    b.dataset.n = String(nEx);
    b.onclick = () => startSafeUpdate(s.srv, s.domain, b);
    return b;
  }
  const b = h('button', { type: 'button', class: 'btn primary' }, iconEl('refresh-cw'), 'Re-scan');
  b.dataset.act = 'rescan';
  b.onclick = () => confirmRun(b);
  return b;
}

/* Raison d'indisponibilité, dite en clair : une action grisée sans explication
   ne se distingue pas d'un bug. */
function raisons(s) {
  const rest = s.via === 'rest';
  return {
    rest: rest ? "site géré sans SSH : l'agent est en lecture seule, à faire depuis wp-admin" : '',
  };
}

/* Une entrée du menu qui lance une action unitaire. Elle est DÉCLARÉE
   (`{action, label, …}`) plutôt que construite : c'est cette forme que
   tools/check_front.py croise avec la table ACTIONS du backend. */
function itemAct(s, def) {
  const R = raisons(s);
  const act = def.action;
  let raison = def.raison || '';
  if (!raison && R.rest && !def.restOk) raison = R.rest;
  return {
    label: def.label, ic: def.ic,
    attention: def.attention === undefined ? ACT_RISQUE.has(act) : !!def.attention,
    disabled: !!raison, raison,
    onSelect: () => {
      const faux = h('button', { type: 'button', class: 'btn' });
      faux.dataset.act = act;
      if (def.arg) faux.dataset.arg = def.arg;
      confirmRun(faux, def.label);
    },
  };
}

function menuDuSite(s) {
  const rest = s.via === 'rest';
  const R = raisons(s);
  const vs = vizState(s);
  const nEx = s.plugins_updates || 0;
  const total = s.plugins_total || 0;
  const autoOn = (s.plugins_auto_update ?? 0) < total;

  const maj = [
    {
      label: 'MAJ sûre' + (nEx || s.core_update ? '' : ' (rien à mettre à jour)'),
      ic: 'shield-check', attention: true,
      disabled: rest || !(nEx || s.core_update),
      raison: rest ? R.rest : 'aucune mise à jour en attente sur ce site',
      onSelect: () => { const b = document.getElementById('safeup'); if (b) b.click(); },
    },
    itemAct(s, { action: 'plugins_update_all', label: 'Extensions seules (sans filet)', ic: 'arrow-up', raison: rest ? R.rest : (nEx ? '' : 'aucune extension à mettre à jour') }),
    itemAct(s, { action: 'themes_update_all', label: 'Thèmes', ic: 'arrow-up', raison: rest ? R.rest : (s.themes_updates ? '' : 'aucun thème à mettre à jour') }),
    itemAct(s, { action: 'core_update', label: 'Cœur seul (sans filet)', ic: 'arrow-up', raison: rest ? R.rest : (s.core_update ? '' : 'le cœur est à jour') }),
    autoOn
      ? itemAct(s, { action: 'autoupdate_on', label: 'Activer les auto-MAJ' + (total ? ' (' + total + ')' : ''), ic: 'check', raison: rest ? R.rest : (total ? '' : 'aucune extension installée') })
      : itemAct(s, { action: 'autoupdate_off', label: 'Désactiver les auto-MAJ', ic: 'x', raison: rest ? R.rest : (total ? '' : 'aucune extension installée') }),
  ];

  const verif = [
    itemAct(s, { action: 'verify_checksums', label: 'Intégrité du cœur', ic: 'shield-check' }),
    itemAct(s, { action: 'viz_scan', label: 'Scan visuel', ic: 'scan-eye', raison: rest ? R.rest : (vizConnected(s) ? '' : 'site non relié à VizProof') }),
    itemAct(s, { action: 'viz_baseline', label: 'Capturer une baseline', ic: 'scan-eye', raison: rest ? R.rest : (vizConnected(s) ? '' : 'site non relié à VizProof') }),
    itemAct(s, { action: 'rescan', label: 'Re-scan de l’inventaire', ic: 'refresh-cw', restOk: true }),
  ];

  const sauv = [
    itemAct(s, { action: 'updraft_backup', label: 'Lancer une sauvegarde UpdraftPlus', ic: 'download', attention: true, raison: rest ? R.rest : (s.updraft ? '' : 'UpdraftPlus non détecté sur ce site') }),
    itemAct(s, { action: 'cache_flush', label: 'Vider les caches', ic: 'eraser', attention: true }),
  ];

  const conn = [
    {
      action: 'vizproof_install',
      label: 'Installer VizProof', ic: 'plus', attention: true,
      disabled: rest || vs !== 'absent',
      raison: rest ? "site sans SSH : passez par « Autoriser WordPress » puis le bloc VizProof" : (vs === 'absent' ? '' : 'extension déjà présente'),
      onSelect: () => vizInstall(h('button', { type: 'button', class: 'btn' }), s.srv, s.domain),
    },
    {
      label: 'Connecter VizProof', ic: 'link',
      disabled: rest || !['nonconnecte', 'connecte'].includes(vs),
      raison: rest ? R.rest : (vs === 'absent' ? 'extension non installée'
        : vs === 'inactif' ? 'extension désactivée sur le site'
          : vs === 'nocli' ? 'version trop ancienne : la commande wp vizproof est absente' : ''),
      onSelect: () => openVizConnect([s]),
    },
    {
      label: 'Dissocier VizProof', ic: 'x', attention: true,
      disabled: rest || vs !== 'connecte',
      raison: rest ? R.rest : 'site non relié à VizProof',
      onSelect: () => vizDisconnect(h('button', { type: 'button', class: 'btn' }), s),
    },
    {
      label: 'Installer l’agent Dash (alertes temps réel)', ic: 'link', attention: true,
      disabled: rest, raison: rest ? "site sans SSH : l'agent y est déjà, c'est lui qui pousse l'inventaire" : '',
      onSelect: () => dashAgent(s, true),
    },
    {
      label: 'Dissocier l’agent Dash', ic: 'x', attention: true,
      disabled: rest, raison: rest ? "site sans SSH : dissocier l'agent couperait tout inventaire" : '',
      onSelect: () => dashAgent(s, false),
    },
    {
      label: 'Autoriser WordPress (mot de passe d’application)', ic: 'link', attention: true,
      disabled: !rest, raison: rest ? '' : "réservé aux sites gérés sans SSH : en SSH le dashboard agit déjà directement",
      onSelect: () => cliquerWpCred('[data-wpauth]', 'Autoriser'),
    },
    {
      label: 'Révoquer l’autorisation WordPress', ic: 'trash-2', attention: true,
      disabled: !rest, raison: rest ? '' : "réservé aux sites gérés sans SSH",
      onSelect: () => cliquerWpCred('[data-wprevoke]', 'Révoquer'),
    },
  ];

  return menuActions({
    label: 'Actions', ic: 'list', groups: [
      { titre: 'Mettre à jour', items: maj },
      { titre: 'Vérifier', items: verif },
      { titre: 'Sauvegarder', items: sauv },
      { titre: 'Connecter', items: conn },
    ],
  });
}

/* Les boutons d'autorisation WordPress sont posés par gestion.js dans le bloc
   « Identifiants WordPress » : le menu ne fait que les actionner, pour ne pas
   dupliquer le flux d'approbation. */
function cliquerWpCred(sel, quoi) {
  const aller = () => {
    const b = document.querySelector('#site-tab ' + sel);
    if (b) { b.scrollIntoView({ block: 'center' }); b.click(); return true; }
    return false;
  };
  if (ONGLET !== 'apercu') { allerOnglet('apercu'); setTimeout(aller, 400); return; }
  if (!aller()) askInfo(quoi + ' — indisponible', "Le bloc « Identifiants WordPress » n'est pas encore chargé, ou le site est déjà dans l'état demandé.");
}

async function dashAgent(s, connecter) {
  const quoi = connecter ? 'Installer l’agent Dash' : 'Dissocier l’agent Dash';
  const msg = connecter
    ? `Installer et appairer l'agent Dash sur <b>${H(s.domain)}</b> ?<br><br>Le site poussera alors ses événements (nouvel administrateur, activation d'extension) sans attendre la collecte horaire.`
    : `Dissocier l'agent Dash de <b>${H(s.domain)}</b> ?<br><br>Les alertes temps réel s'arrêtent ; l'inventaire par SSH continue.`;
  if (!await askConfirm(msg, { titre: quoi, ok: connecter ? 'Installer' : 'Dissocier', danger: !connecter })) return;
  const nid = NOTIF.start({ kind: 'connect', label: quoi + ' · ' + (kName(s) || s.domain), site: { srv: s.srv, domain: s.domain } });
  let j;
  // Deux routes écrites en toutes lettres : une URL construite par concaténation
  // échappe au croisement front ↔ backend de tools/check_front.py.
  try {
    j = connecter
      ? await api('/api/mgmt/dash_connect', { server: s.srv, domain: s.domain }) || {}
      : await api('/api/mgmt/dash_disconnect', { server: s.srv, domain: s.domain }) || {};
  }
  catch (e) { j = { ok: false, error: String(e) }; }
  const out = stripPhpNoise(String(j.output ?? j.error ?? '')).slice(-200);
  NOTIF.done(nid, { ok: !!j.ok, message: j.ok ? 'agent ' + (connecter ? 'installé' : 'dissocié') : out });
  if (!j.ok) askInfo(quoi + ' — échec', H(out || 'échec'));
}

/* ---- bandeau d'indicateurs ------------------------------------------------ */
function ib(label, valeur, sub, niv, tip) {
  return h('div', { class: 'ib' + (niv ? ' ' + niv : '') },
    h('span', { class: 'ib-l', text: label }),
    h('span', { class: 'ib-v' }, valeur),
    sub ? h('span', { class: 'ib-s', text: sub, 'data-tip': tip || null, tabindex: tip ? '0' : null, role: tip ? 'button' : null }) : null);
}

function bandeau(s) {
  const ud = s.updraft, age = bkAge(s), seuil = seuilBackup();
  const core = s.core_version || '?';
  const nEx = s.plugins_updates || 0;
  const auto = (() => {
    const n = s.plugins_auto_update, t = s.plugins_total;
    if (n == null || t == null) return ['', '?', 'inconnu'];
    if (t === 0) return ['', '—', 'aucune extension'];
    if (n === 0) return ['warn', '0/' + t, 'désactivées'];
    if (n >= t) return ['ok', n + '/' + t, 'toutes'];
    return ['warn', n + '/' + t, 'partielles'];
  })();
  const bk = (!ud) ? ['mut', 'aucune', 'UpdraftPlus non détecté']
    : (age === null) ? ['warn', 'jamais', 'aucune sauvegarde connue']
      : (age >= seuil) ? ['warn', (age / 24).toFixed(1) + ' j', ud.service || 'locale']
        : ['ok', Math.round(age) + ' h', ud.service || 'locale'];
  const tipBk = ud
    ? 'fichiers : ' + udIntervalFr(ud.interval) + ' × ' + (ud.retain || '?') + ' jeux'
    + (udHorizon(ud.retain, ud.interval) ? ' (' + udHorizon(ud.retain, ud.interval) + ')' : '')
    + ' · base : ' + udIntervalFr(ud.interval_db) + ' × ' + (ud.retain_db || '?') + ' jeux'
    + (udHorizon(ud.retain_db, ud.interval_db) ? ' (' + udHorizon(ud.retain_db, ud.interval_db) + ')' : '')
    + (udRulesFr(ud.extrarules && ud.extrarules.files) ? ' · fichiers : ' + udRulesFr(ud.extrarules.files) : '')
    + (udRulesFr(ud.extrarules && ud.extrarules.db) ? ' · base : ' + udRulesFr(ud.extrarules.db) : '')
    : '';
  const eol = phpEol(s.php_version);

  return h('div', { class: 'iband', id: 'site-band' },
    ib('WordPress', h('b', { text: core }), s.core_update ? '→ ' + s.core_update : 'à jour', s.core_update ? 'warn' : (s.core_version ? 'ok' : '')),
    ib('Extensions', h('b', { text: String(nEx) }), 'sur ' + (s.plugins_total ?? '?') + ' installées', nEx ? 'warn' : 'ok'),
    ib('PHP', h('b', { text: s.php_version || '?' }), eol ? 'fin de support' : 'suivie', eol ? 'warn' : ''),
    ib('Sauvegarde', h('b', { text: bk[1] }), bk[2], bk[0], tipBk),
    ib('Auto-MAJ', h('b', { text: auto[1] }), auto[2], auto[0]),
    ib('Vulnérabilités', h('b', { text: '…' }), 'analyse…', '', ''));
}

function renderVulnsSite() {
  const box = document.getElementById('site-band');
  if (!box) return;
  const cell = box.children[5];
  if (!cell) return;
  const v = VULNS;
  const n = v ? v.count : null;
  const worst = v ? v.worst : '';
  cell.className = 'ib' + (n === null ? '' : (worst === 'critical' || worst === 'high' ? ' err' : n ? ' warn' : ' ok'));
  cell.querySelector('.ib-v').textContent = n === null ? '…' : String(n || 0);
  cell.querySelector('.ib-s').textContent = n === null ? 'analyse…' : (n ? (SEVLABEL[worst] || worst || 'connues') : 'aucune');
}

/* ---- onglets -------------------------------------------------------------- */
function ongletsNav(s) {
  const nav = h('nav', { class: 'subtabs', 'aria-label': 'Sections du site' });
  ONGLETS.forEach(([slug, label]) => {
    const b = h('button', {
      type: 'button', class: 'subtab' + (slug === ONGLET ? ' active' : ''),
      'aria-current': slug === ONGLET ? 'true' : 'false',
      text: label,
    });
    b.onclick = () => allerOnglet(slug);
    nav.append(b);
  });
  return nav;
}

/* Le changement d'onglet empile une entrée d'historique : le bouton
   « Précédent » du navigateur revient à l'onglet précédent, pas hors du site. */
function allerOnglet(slug) {
  if (slug === ONGLET) return;
  location.hash = '#site/' + encodeURIComponent(CLE) + (slug === 'apercu' ? '' : '/' + slug);
}

function dessinerOnglet() {
  const s = CUR;
  if (!s) return;
  const cible = document.getElementById('site-tab');
  if (!cible) return;
  if (ONGLET === 'extensions') mount(cible, ongletExtensions(s));
  else if (ONGLET === 'securite') mount(cible, ongletSecurite(s));
  else if (ONGLET === 'sauvegardes') mount(cible, ongletSauvegardes(s));
  else if (ONGLET === 'historique') mount(cible, ongletHistorique(s));
  else mount(cible, ongletApercu(s));
  renderPolicy();
  if (ONGLET === 'securite') renderVulnsListe();
  if (ONGLET === 'apercu' && s.via === 'rest') loadWpCred(s.srv, s.domain);
  if (ONGLET === 'securite') { chargerAdmins(); chargerChecksums(); chargerPhpErrors(); }
  if (ONGLET === 'historique') loadTimeline(s.srv, s.domain);
}

/* ---- onglet Aperçu -------------------------------------------------------- */
function ongletApercu(s) {
  const blocs = [];

  blocs.push(h('section', { class: 'sitesec', id: 'site-incidents' },
    h('h3', { text: 'À traiter sur ce site' }),
    incidentsEl()));

  const viz = vizBlocEl(s);
  if (viz) {
    blocs.push(h('section', { class: 'sitesec' }, viz));
    viz.querySelectorAll('[data-act]').forEach(b => { b.onclick = () => confirmRun(b); });
  }

  if (s.via === 'rest') {
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', { text: 'Identifiants WordPress' }),
      h('div', { id: 'wpcred' }, h('span', { class: 'muted small', text: 'chargement…' })),
      h('div', { class: 'actions mt2', id: 'rest-vizslot' }),
      h('p', { class: 'hint hint-loose', id: 'rest-note' })));
  }

  if (s._stale) {
    blocs.push(h('div', { class: 'warnbox small' }, iconEl('triangle-alert'), ' ',
      h('b', { text: 'Serveur ' + (s.srv || '') + ' injoignable' }),
      ' à la dernière collecte — les chiffres ci-dessus datent du ' + (s._srvAt || 'relevé précédent')
      + ' et peuvent avoir changé depuis.',
      s._srvErr ? h('div', { class: 'mt1' }, h('code', { text: s._srvErr })) : null));
  }

  const u = safeUrl(s.siteurl || 'https://' + s.domain);
  const adm = h('span', {});
  (s.admins || []).forEach(a => adm.append(h('span', { class: 'tag', text: a.login }), ' '));
  if (!(s.admins || []).length) adm.append(h('span', { class: 'muted', text: '—' }));

  blocs.push(h('section', { class: 'sitesec' },
    h('h3', { text: 'Fiche' }),
    h('div', { class: 'kv' },
      h('span', { class: 'k', text: 'Nom' }), h('span', { text: s.blogname || '—' }),
      h('span', { class: 'k', text: 'URL' }),
      h('span', {}, u ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: s.siteurl || u })
        : h('span', { class: 'muted', text: s.siteurl || '—' })),
      h('span', { class: 'k', text: 'Serveur' }), h('span', {}, srvCellEl(s)),
      ...(s.path ? [h('span', { class: 'k', text: 'Chemin' }), h('span', {}, h('code', { class: 'small', text: s.path }))] : []),
      h('span', { class: 'k', text: 'Client (Kuma)' }), h('span', { text: s.kuma_group || '—' }),
      h('span', { class: 'k', text: 'Administrateurs' }), adm,
      h('span', { class: 'k', text: 'Collecté' }),
      h('span', { class: 'muted', text: s.collected_at || store.fleet?.generated_at || '—' }))));

  blocs.push(h('section', { class: 'sitesec' }, h('h3', { text: 'Sauvegardes' }), updraftKv(s)));

  const errs = Object.keys(s.errors || {});
  if (errs.length) {
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', { text: 'Erreurs de collecte' }),
      h('div', { class: 'errbox', text: Object.entries(s.errors).map(([k, v]) => k + ': ' + v).join('\n\n') })));
  }
  return blocs;
}

function srvCellEl(s) {
  return s.via === 'rest'
    ? h('span', { class: 'pill mut', title: "inventaire via l'agent, sans SSH" + (s.srv ? ' · ' + s.srv : ''), text: 'REST' })
    : h('span', { class: 'pill mut', text: s.srv || '—' });
}

function updraftKv(s) {
  const ud = s.updraft;
  if (!ud) return h('span', { class: 'muted', text: 'UpdraftPlus non détecté' });
  const hF = udHorizon(ud.retain, ud.interval), hD = udHorizon(ud.retain_db, ud.interval_db);
  const rF = udRulesFr(ud.extrarules && ud.extrarules.files), rD = udRulesFr(ud.extrarules && ud.extrarules.db);
  const age = bkAge(s);
  return h('div', { class: 'kv' },
    h('span', { class: 'k', text: 'Fichiers' }),
    h('span', {}, udIntervalFr(ud.interval), ' · ', h('b', { text: (ud.retain || '?') + ' jeux' }),
      hF ? h('span', { class: 'muted small', text: ' ≈ ' + hF }) : null,
      rF ? h('div', { class: 'muted small', text: 'puis ' + rF }) : null),
    h('span', { class: 'k', text: 'Base de données' }),
    h('span', {}, udIntervalFr(ud.interval_db), ' · ', h('b', { text: (ud.retain_db || '?') + ' jeux' }),
      hD ? h('span', { class: 'muted small', text: ' ≈ ' + hD }) : null,
      rD ? h('div', { class: 'muted small', text: 'puis ' + rD }) : null),
    h('span', { class: 'k', text: 'Destination' }), h('span', { text: ud.service || '?' }),
    h('span', { class: 'k', text: 'Dernière' }),
    h('span', {}, age === null ? h('span', { class: 'pill warn', text: 'jamais' })
      : h('span', { class: 'pill ' + (age >= seuilBackup() ? 'warn' : 'ok'), text: relTime(ud.last_backup_ts) })));
}

/* ---- incidents de ce site -------------------------------------------------- */
function incidentsEl() {
  if (!INCIDENTS.length) {
    return h('p', { class: 'hint hint-tight', text: 'Rien à traiter sur ce site.' });
  }
  const box = h('div', { class: 'inclist' });
  INCIDENTS.forEach(i => box.append(incidentLigne(i, false)));
  return box;
}

/* Une ligne d'incident, partagée avec l'écran Parc : trait de gravité, site,
   titre, détail court, ancienneté, action en ligne. */
export function incidentLigne(inc, avecSite) {
  const age = Number(inc.age_h) || 0;
  const quand = inc.since ? relTime(inc.since) : (age ? (age < 48 ? 'depuis ' + Math.round(age) + ' h' : 'depuis ' + Math.round(age / 24) + ' j') : '');
  const ligne = h('div', { class: 'inc ' + (inc.severity === 'critical' ? 'err' : 'warn') },
    h('div', { class: 'inc-m' },
      h('div', { class: 'inc-t' },
        avecSite && inc.site ? h('b', { class: 'inc-s', text: inc.site }) : null,
        h('span', { class: 'inc-h', text: inc.title || '' })),
      inc.detail ? h('div', { class: 'muted small inc-d', text: inc.detail }) : null),
    quand ? h('span', { class: 'muted small inc-a', title: inc.since ? absTime(inc.since) : '', text: quand }) : null,
    incidentAction(inc, avecSite));
  return ligne;
}

/* `avecSite` vaut faux sur la page d'un site : « Ouvrir » y renverrait vers la
   page déjà affichée. */
function incidentAction(inc, avecSite) {
  const acts = h('span', { class: 'inc-b' });
  const s = inc.site ? siteParCle(inc.site) : null;
  if (inc.action && inc.action.act && s) {
    const b = h('button', { type: 'button', class: 'btn sm', text: inc.action.label || 'Corriger' });
    b.dataset.act = inc.action.act;
    if (inc.action.arg) b.dataset.arg = inc.action.arg;
    b.onclick = e => { e.stopPropagation(); lancerSur(s, b, inc.action.label); };
    acts.append(b);
  }
  if (s && avecSite) {
    acts.append(h('a', { class: 'btn sm', href: '#site/' + encodeURIComponent(cleDeSite(s)), text: 'Ouvrir' }));
  } else if (!s && inc.link && inc.link.tab) {
    acts.append(h('a', { class: 'btn sm', href: '#' + inc.link.tab + (inc.link.sub ? '/' + inc.link.sub : ''), text: 'Voir' }));
  }
  return acts;
}

/* Action en ligne depuis une file d'incidents : même mécanisme que la page site
   (confirmation pour ce qui modifie, notification, re-scan derrière), mais sur
   un site qui n'est pas forcément celui affiché. */
export async function lancerSur(s, btn, label) {
  const act = btn.dataset.act, arg = btn.dataset.arg || null;
  if (ACT_RISQUE.has(act)) {
    const ok = await askConfirm(
      `${H(label || actLib(act, arg))} sur <b>${H(kName(s) || s.domain)}</b> ?`
      + `<br><br>Cette action <b>modifie le site</b>. Elle n'est pas archivée : pour un retour arrière automatique, passez par « MAJ sûre » depuis la page du site.`,
      { titre: actLib(act, arg), ok: 'Lancer' });
    if (!ok) return;
  }
  setBusy(btn, 'en cours…');
  const nid = NOTIF.start({ label: notifLabel(act, arg, s), site: { srv: s.srv, domain: s.domain }, kind: ACT_KIND[act] || 'action' });
  let j;
  try { j = await api('/api/actions/run', { server: s.srv, domain: s.domain, action: act, arg }) || {}; }
  catch (e) { j = { ok: false, error: String(e) }; }
  setIdle(btn);
  if (j.job === 'viz_update') {
    NOTIF.update(nid, { progress: 0, detail: 'démarrage…' });
    suivreVizUp(s.srv, s.domain, nid);
    return;
  }
  const anom = !j.ok && Number(j.rc) === 2 && /^viz_/.test(act);
  NOTIF.done(nid, {
    ok: !!(j.ok || anom), warn: anom,
    message: anom ? 'anomalies visuelles détectées'
      : (j.ok ? '' : stripPhpNoise(String(j.output || j.error || '')).slice(-160) || ('rc ' + (j.rc ?? '?'))),
  });
  if (j.ok || anom) {
    if (act !== 'rescan' && act !== 'verify_checksums') {
      await api('/api/actions/run', { server: s.srv, domain: s.domain, action: 'rescan' }).catch(() => {});
    }
    await loadFleet().catch(() => {});
  }
}

/* ---- onglet Extensions ----------------------------------------------------- */
function cveChip(nom) {
  if (!VULNS) return null;
  const g = (VULNS.findings || []).filter(v => v.component === nom);
  if (!g.length) return null;
  let worst = '';
  g.forEach(v => { if ((SEVRANK[v.severity] || 0) > (SEVRANK[worst] || 0)) worst = v.severity; });
  const el = h('span', {});
  el.innerHTML = sevPill(worst);
  const p = el.firstElementChild;
  if (p) p.title = g.length + ' vulnérabilité(s) connue(s) : ' + g.map(v => v.cve || v.title).filter(Boolean).slice(0, 4).join(', ');
  return el;
}

function ligneExtension(s, p, maj) {
  const tr = h('tr', { dataset: { plug: p.name } },
    h('td', {}, h('b', { text: p.name }), cveChip(p.name)),
    h('td', {}, maj ? h('span', {}, p.version || '?', ' → ', h('b', { text: p.to || '?' })) : (p.version || '?'),
      p.status !== 'active' ? h('span', { class: 'pill mut', text: 'inactive' }) : null),
    h('td', { class: 'pcell' }));
  const cell = tr.lastElementChild;
  if (maj) {
    const b = h('button', { type: 'button', class: 'btn sm', text: 'MAJ' });
    b.dataset.act = 'plugin_update';
    b.dataset.arg = p.name;
    b.onclick = () => confirmRun(b);
    cell.append(b);
  }
  const gel = h('button', {
    type: 'button', class: 'btn sm pfreeze',
    title: 'Ne plus jamais mettre à jour cette extension sur ce site', text: 'Geler',
  });
  gel.dataset.slug = p.name;
  const reb = h('button', { type: 'button', class: 'btn sm prb', title: 'Revenir à une version antérieure' }, iconEl('rotate-ccw'), 'Rétablir');
  reb.dataset.slug = p.name;
  reb.onclick = () => askVersion(p.name, reb, { srv: s.srv, dom: s.domain }, () => loadFleet().then(refreshSite).catch(() => {}));
  cell.append(gel, reb);
  return tr;
}

function ongletExtensions(s) {
  const tous = (s.plugins_list || []).filter(p => p.name && !/\.php$/.test(p.name));
  const aMaj = tous.filter(p => p.update === 'available');
  const autres = tous.filter(p => p.update !== 'available');
  const blocs = [];

  if (s.via === 'rest') {
    blocs.push(h('p', { class: 'hint' }, h('b', { text: 'Site géré sans SSH' }),
      ' : les mises à jour et le gel ne sont pas disponibles ici, à faire depuis wp-admin.'));
  }

  blocs.push(h('section', { class: 'sitesec' },
    h('h3', { text: 'À mettre à jour (' + aMaj.length + ')' }),
    aMaj.length
      ? h('table', { class: 'ptable' }, h('tbody', {}, aMaj.map(p => ligneExtension(s, p, true))))
      : h('p', { class: 'hint hint-tight', text: 'Toutes les extensions sont à jour.' })));

  if (autres.length) {
    const tbl = h('table', { class: 'ptable', hidden: true }, h('tbody', {}, autres.map(p => ligneExtension(s, p, false))));
    const bt = h('button', { type: 'button', class: 'btn sm fr', text: 'Afficher (' + autres.length + ' à jour)' });
    bt.onclick = () => {
      tbl.hidden = !tbl.hidden;
      bt.textContent = tbl.hidden ? 'Afficher (' + autres.length + ' à jour)' : 'Masquer';
      renderPolicy();
    };
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', {}, 'Toutes les extensions', bt),
      h('p', { class: 'hint' }, 'Repliée par défaut. ',
        h('span', { class: 'info', 'data-tip': "Utile pour retablir une version anterieure d'une extension deja a jour.", text: '?' })),
      tbl));
  }

  blocs.push(h('section', { class: 'sitesec', id: 'site-frozen', hidden: true },
    h('h3', { text: 'Extensions gelées' }),
    h('p', { class: 'hint' }, 'Jamais mises à jour par le dashboard. ',
      h('span', { class: 'info', 'data-tip': 'Ni par un bouton, ni par une action groupee, ni par la MAJ sure. Utile quand une version casse le site, ou quand un client doit valider avant.', text: '?' })),
    h('div', { id: 'site-frozenlist', class: 'small' })));
  return blocs;
}

/* ---- politique par extension (gel) ---------------------------------------- */
function renderPolicy() {
  const sec = document.getElementById('site-frozen'), list = document.getElementById('site-frozenlist');
  if (sec && list) {
    sec.hidden = !FROZEN.length;
    mount(list, FROZEN.map(sl => {
      const b = h('button', { type: 'button', class: 'btn sm pthaw', text: 'Dégeler' });
      b.dataset.slug = sl;
      return h('div', { class: 'vulnrow' }, h('span', { class: 'pill warn', text: 'gelée' }), h('b', { text: sl }), b);
    }));
  }
  document.querySelectorAll('#site-tab [data-plug]').forEach(tr => {
    const sl = tr.dataset.plug, gel = FROZEN.includes(sl);
    const b = tr.querySelector('.pfreeze'), maj = tr.querySelector('[data-act="plugin_update"]');
    if (b) { b.textContent = gel ? 'Dégeler' : 'Geler'; b.classList.toggle('primary', gel); }
    if (maj) maj.disabled = gel;
    tr.classList.toggle('row-frozen', gel);
  });
  document.querySelectorAll('#site-tab .pfreeze,#site-tab .pthaw').forEach(b => {
    b.onclick = async () => {
      const sl = b.dataset.slug, gel = !FROZEN.includes(sl);
      b.disabled = true;
      try {
        const r = await api('/api/actions/policy', { server: CUR.srv, domain: CUR.domain, slug: sl, frozen: gel });
        FROZEN = r.frozen || [];
      } catch (e) { /* le gel reste dans l'état affiché */ }
      b.disabled = false;
      renderPolicy();
    };
  });
}

/* ---- onglet Sécurité ------------------------------------------------------- */
function ongletSecurite(s) {
  return [
    h('section', { class: 'sitesec', id: 'site-vulnsec' },
      h('h3', { text: 'Vulnérabilités connues' }),
      h('div', { id: 'site-vulnlist', class: 'small' }, h('span', { class: 'muted small', text: 'analyse…' }))),
    h('section', { class: 'sitesec' },
      h('h3', { text: 'Comptes administrateurs' }),
      h('p', { class: 'hint', text: "Un compte absent de la référence est signalé : c'est le signal n°1 d'une compromission." }),
      h('div', { id: 'site-admins', class: 'small' }, h('span', { class: 'muted small', text: 'chargement…' }))),
    h('section', { class: 'sitesec' },
      h('h3', { text: 'Intégrité du cœur (checksums)' }),
      h('p', { class: 'hint' }, 'Lance ', h('code', { text: 'wp core verify-checksums' }), ' et compare au cœur officiel.'),
      h('div', { id: 'site-checksums', class: 'small' }, h('span', { class: 'muted small', text: 'chargement…' }))),
    h('section', { class: 'sitesec' },
      h('h3', { text: 'Erreurs PHP' }),
      h('p', { class: 'hint', text: 'Lecture des journaux que le serveur écrit déjà, regroupées par message et par fichier.' }),
      h('div', { id: 'site-phperr', class: 'small' }, h('span', { class: 'muted small', text: 'chargement…' }))),
  ];
}

function renderVulnsListe() {
  const box = document.getElementById('site-vulnlist');
  if (!box) return;
  if (!VULNS || !(VULNS.findings || []).length) {
    mount(box, h('span', { class: 'pill ok', text: 'aucune vulnérabilité connue' }));
    return;
  }
  const groupes = grouperParExtension(VULNS.findings);
  mount(box, groupes.map(g => {
    const sev = h('span', {});
    sev.innerHTML = sevPill(g.worst);
    const cves = h('div', { class: 'vcves small' });
    g.cves.slice(0, 12).forEach(v => {
      const u = safeUrl(v.link);
      cves.append(u
        ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', class: 'muted small', text: v.cve || v.title || 'détail' })
        : h('span', { class: 'muted small', text: (v.cve || v.title || '') + ' ' }));
    });
    return h('div', { class: 'vrow' }, sev,
      h('b', { text: g.component }), h('span', { class: 'muted small', text: g.version || '' }),
      g.update_to ? h('span', { class: 'pill ok', text: 'MAJ ' + g.update_to }) : null,
      g.unfixed ? h('span', { class: 'pill err', text: 'non corrigée' }) : null,
      h('span', { class: 'muted small', text: g.n + ' CVE' }), cves);
  }));
}

async function chargerAdmins() {
  const seq = PAGESEQ, s = CUR;
  const box = document.getElementById('site-admins');
  if (!box) return;
  let base = null, err = '';
  try { const bl = await api('/api/sec/baseline'); store.baseline = (bl && bl.baseline) || {}; }
  catch (e) { err = String(e); }
  if (seq !== PAGESEQ) return;
  const b2 = document.getElementById('site-admins');
  if (!b2) return;
  base = (store.baseline || {})[s.domain]?.logins;
  const tags = h('div', {});
  (s.admins || []).forEach(a => {
    const isNew = base && !base.includes(a.login);
    tags.append(h('span', {
      class: 'tag' + (isNew ? ' new-admin' : ''),
      title: (a.email || '') + ' · inscrit ' + (a.registered || '?'),
    }, isNew ? iconEl('triangle-alert', { size: 14 }) : null, ' ' + a.login), ' ');
  });
  if (!(s.admins || []).length) tags.append(h('span', { class: 'muted', text: '—' }));
  const bt = h('button', { type: 'button', class: 'btn sm', text: 'Marquer comme vu' });
  bt.onclick = async () => {
    setBusy(bt, '…');
    await api('/api/sec/baseline', { domain: s.domain }).catch(() => {});
    setIdle(bt, 'Marquer comme vu');
    chargerAdmins();
  };
  mount(b2,
    err ? h('div', {}, h('span', { class: 'pill err', text: 'référence indisponible' }), ' ', h('span', { class: 'muted small', text: err })) : null,
    tags,
    base ? null : h('div', { class: 'muted small', text: 'aucune référence enregistrée pour ce site' }),
    h('div', { class: 'actions mt2' }, bt));
}

async function chargerChecksums() {
  const seq = PAGESEQ, s = CUR;
  let cks = {};
  try {
    const c = await api('/api/sec/checksums');
    if (c && typeof c === 'object' && !c.error) cks = (c.checksums && typeof c.checksums === 'object') ? c.checksums : c;
  } catch (e) { cks = {}; }
  if (seq !== PAGESEQ) return;
  const box = document.getElementById('site-checksums');
  if (!box) return;
  const ck = cks[s.domain];
  const etat = (ck && typeof ck === 'object')
    ? h('span', {}, h('span', { class: 'pill ' + (ck.ok ? 'ok' : 'err'), title: String(ck.output_tail ?? '').slice(-400), text: ck.ok ? 'intègre' : 'anomalie' }),
      ' ', h('span', { class: 'muted small', title: absTime(ck.ts), text: relTime(ck.ts) }))
    : h('span', { class: 'muted small', text: 'jamais vérifié' });
  const bt = h('button', { type: 'button', class: 'btn sm', text: 'Vérifier maintenant' });
  bt.disabled = s.via === 'rest';
  if (s.via === 'rest') bt.title = "site géré sans SSH : vérification impossible d'ici";
  const res = h('span', { class: 'small' }, etat);
  bt.onclick = async () => {
    setBusy(bt, 'vérification…');
    let j;
    try { j = await api('/api/sec/verify', { server: s.srv, domain: s.domain }); }
    catch (e) { j = { ok: false, output: String(e) }; }
    setIdle(bt, 'Vérifier maintenant');
    mount(res, (j && j.ok)
      ? h('span', { class: 'pill ok', text: 'intègre' })
      : h('span', {}, h('span', { class: 'pill err', text: 'anomalie' }), ' ',
        h('span', { class: 'muted small', text: String((j && (j.output || j.error)) || '').slice(-160) })));
  };
  mount(box, h('div', { class: 'vulnrow' }, res, bt));
}

async function chargerPhpErrors() {
  const seq = PAGESEQ, s = CUR;
  let j = null;
  try { j = await api('/api/sec/phperrors'); } catch (e) { j = null; }
  if (seq !== PAGESEQ) return;
  const box = document.getElementById('site-phperr');
  if (!box) return;
  if (!j || j.error) { mount(box, h('span', { class: 'muted small', text: 'journaux indisponibles' })); return; }
  const rec = (j.sites || []).find(x => x.domain === s.domain || x.domain === kName(s));
  if (!rec || !(rec.groups || []).length) {
    mount(box, h('span', { class: 'pill ok', text: 'aucune erreur relevée sur la fenêtre analysée' }));
    return;
  }
  mount(box, rec.groups.slice(0, 30).map(g => {
    const fatale = /Fatal|Parse/.test(String(g.severity || ''));
    return h('div', { class: 'logline' },
      h('span', { class: 'pill ' + (fatale ? 'err' : 'warn'), text: g.severity || '?' }), ' ',
      h('b', { text: String(g.message || '').slice(0, 160) }),
      h('div', { class: 'muted small' }, (g.short || g.file || '?') + (g.line ? ':' + g.line : ''),
        ' · ×' + (g.count || 1), g.last ? ' · ' + relTime(g.last) : ''));
  }));
}

/* ---- onglet Sauvegardes et restauration ------------------------------------ */
function ongletSauvegardes(s) {
  const bt = h('button', { type: 'button', class: 'btn primary' }, iconEl('download'), 'Lancer une sauvegarde');
  bt.dataset.act = 'updraft_backup';
  bt.disabled = !s.updraft || s.via === 'rest';
  if (bt.disabled) bt.title = s.via === 'rest' ? 'site géré sans SSH' : 'UpdraftPlus non détecté';
  else bt.onclick = () => confirmRun(bt);

  const pts = rollbackPoints();
  return [
    h('section', { class: 'sitesec' },
      h('h3', { text: 'UpdraftPlus' }),
      updraftKv(s),
      h('div', { class: 'actions mt3' }, bt)),
    h('section', { class: 'sitesec', id: 'site-rbsec', hidden: !pts.length },
      h('h3', { text: 'Revenir en arrière' }),
      h('p', { class: 'hint' }, 'Archives laissées par les mises à jour sûres. ',
        h('span', {
          class: 'info', text: '?',
          'data-tip': "Cliquez une pastille pour remettre l'extension dans sa version d'avant, a l'identique — y compris pour les extensions premium. Le bouton Retablir de chaque extension permet en plus de choisir une version publiee sur wordpress.org. Dans les deux cas seuls les fichiers sont remplaces : la base n'est pas touchee.",
        })),
      h('div', { id: 'site-rblist' }, pts.length
        ? pointsListeEl({ srv: s.srv, dom: s.domain }, () => loadFleet().then(refreshSite).catch(() => {}))
        : h('span', { class: 'muted small', text: 'aucune archive locale' }))),
    h('div', { class: 'warnbox small' }, iconEl('triangle-alert'), ' ',
      'Un rétablissement ne remplace que les ', h('b', { text: 'fichiers' }),
      '. Si l’extension ou le cœur a migré ses tables, la ',
      h('b', { text: 'base de données' }), ' reste dans son nouvel état : la sauvegarde UpdraftPlus est le seul recours pour elle.'),
  ];
}

/* ---- onglet Historique ------------------------------------------------------ */
const TLKIND = { action: 'actions', collect: 'collectes', event: 'événements' };
let TLGROUPS = [], TLSHOWN = 0, TLFILTRE = '';
const TLPAGE = 20;
let TLSEQ = 0;

function ongletHistorique() {
  const barre = h('div', { class: 'filters' });
  [['', 'Tout'], ...Object.entries(TLKIND)].forEach(([k, lbl]) => {
    const b = h('button', { type: 'button', class: 'subtab' + (TLFILTRE === k ? ' active' : ''), text: lbl });
    b.onclick = () => { TLFILTRE = k; TLSHOWN = TLPAGE; dessinerOnglet(); };
    barre.append(b);
  });
  return h('section', { class: 'sitesec' },
    h('h3', { text: 'Historique du site' }), barre,
    h('div', { id: 'site-timeline' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

async function loadTimeline(srv, dom) {
  const seq = ++TLSEQ;
  const el = document.getElementById('site-timeline');
  if (!el) return;
  let j;
  try { j = await api('/api/site/timeline?server=' + encodeURIComponent(srv) + '&domain=' + encodeURIComponent(dom)); }
  catch (e) { if (seq === TLSEQ) mount(el, h('span', { class: 'muted small', text: 'historique indisponible' })); return; }
  if (seq !== TLSEQ) return;
  const ev = (j && Array.isArray(j.events)) ? j.events.filter(x => x && typeof x === 'object') : [];
  ev.sort((a, b) => ((tsMs(b.ts) ?? 0) - (tsMs(a.ts) ?? 0)));
  // Regroupement des répétitions : une même mise à jour relancée quatre fois
  // n'a pas à occuper quatre blocs identiques.
  TLGROUPS = [];
  for (const e of ev) {
    const cle = [e.kind, e.label, e.status, tlDetail(e)].join('|');
    const last = TLGROUPS[TLGROUPS.length - 1];
    if (last && last.cle === cle) { last.n++; continue; }
    TLGROUPS.push({ cle, e, n: 1 });
  }
  TLSHOWN = TLPAGE;
  renderTimeline();
}

function renderTimeline() {
  const el = document.getElementById('site-timeline');
  if (!el) return;
  const tous = TLFILTRE ? TLGROUPS.filter(g => g.e.kind === TLFILTRE) : TLGROUPS;
  if (!tous.length) { mount(el, h('span', { class: 'muted small', text: 'aucun événement enregistré.' })); return; }
  const vus = tous.slice(0, TLSHOWN);
  const reste = tous.length - vus.length;
  const noeuds = vus.map(tlRow);
  if (reste > 0) {
    const b = h('button', { type: 'button', class: 'btn sm mt3', text: 'Voir plus (' + reste + ')' });
    b.onclick = () => { TLSHOWN += TLPAGE; renderTimeline(); };
    noeuds.push(b);
  } else if (tous.length > TLPAGE) {
    noeuds.push(h('div', { class: 'muted small mt2', text: "fin de l'historique" }));
  }
  mount(el, noeuds);
}

function tlRow({ e, n }) {
  const kind = String(e.kind ?? ''), lab = String(e.label ?? ''), stt = String(e.status ?? '').toLowerCase();
  const det = tlDetail(e);
  const brut = String(e.detail ?? '');
  const depliable = brut && brut.trim() !== det.trim();
  let c = 'mut';
  if (kind === 'action') c = stt.includes('ok') ? 'ok' : (stt.includes('anomal') ? 'warn' : 'err');
  else if (kind === 'event') c = TLCRIT.test(lab) ? 'err' : 'mut';
  else if (kind === 'collect') c = (stt === 'alerte') ? 'err' : 'mut';
  const titre = (kind === 'event' ? (EVLABEL[lab] || lab) : lab) || '—';
  const ic = h('span', { class: 'tlic ' + c });
  ic.append(iconEl(TLICON[kind] || 'diamond', { size: 14 }));
  const pre = depliable ? h('pre', { class: 'tldet', hidden: true, text: brut.slice(0, 4000) }) : null;
  const row = h('div', { class: 'tlrow' + (depliable ? ' tlopenable' : '') }, ic,
    h('div', { class: 'tlmain' },
      h('div', { class: 'tltop' }, h('b', { text: titre }),
        n > 1 ? h('span', { class: 'pill mut', text: '×' + n }) : null,
        depliable ? h('span', { class: 'tlchev' }, iconEl('chevron-right', { size: 14 })) : null,
        h('span', { class: 'muted small tlwhen', title: absTime(e.ts), text: relTime(e.ts) })),
      det ? h('div', { class: 'muted small tlsub', text: det }) : null,
      pre));
  if (pre) row.onclick = () => { pre.hidden = !pre.hidden; row.classList.toggle('open', !pre.hidden); };
  return row;
}

const TLICON = { action: 'diamond', event: 'activity', collect: 'refresh-cw' };
const TLCRIT = /admin|user_register|set_user_role|grant_super|deleted_user/i;
const EVLABEL = {
  upgrader_process_complete: 'Mise à jour terminée', wp_login: 'Connexion administrateur',
  user_register: 'Compte créé', set_user_role: 'Rôle modifié', deleted_user: 'Compte supprimé',
  activated_plugin: 'Extension activée', deactivated_plugin: 'Extension désactivée',
  switch_theme: 'Thème changé', grant_super_admin: 'Super administrateur accordé',
  wp_initialize_site: 'Sous-site créé',
};
/* Détail d'un événement rendu lisible : l'agent pousse du JSON brut. */
function tlDetail(e) {
  const raw = e.detail;
  if (raw == null || raw === '') return '';
  if (e.kind !== 'event') return stripPhpNoise(raw);
  let d;
  try { d = JSON.parse(raw); } catch (err) { return stripPhpNoise(raw).slice(0, 220); }
  if (!d || typeof d !== 'object') return String(raw).slice(0, 220);
  const slug = f => String(f).split('/')[0];
  const lab = String(e.label || '');
  if (lab === 'upgrader_process_complete') {
    const items = (d.items || []).map(slug).filter(Boolean);
    const quoi = { plugin: 'extension', theme: 'thème', core: 'cœur', translation: 'traduction' }[d.type] || d.type || 'élément';
    if (!items.length) return `${quoi} · ${d.action || 'mise à jour'}`;
    return `${quoi}${items.length > 1 ? 's' : ''} : ${items.join(', ')}`;
  }
  if (lab === 'wp_login') return `${d.login || '?'}${d.ip ? ' · depuis ' + d.ip : ''}`;
  if (lab === 'user_register' || lab === 'set_user_role' || lab === 'grant_super_admin') {
    return `${d.login || '?'}${d.email ? ' <' + d.email + '>' : ''}${(d.roles || []).length ? ' · ' + d.roles.join(', ') : ''}`;
  }
  if (lab === 'deleted_user') return `${d.login || d.id || '?'}`;
  if (lab === 'activated_plugin' || lab === 'deactivated_plugin') return slug(d.plugin || d.file || '?');
  if (lab === 'switch_theme') return d.name || d.stylesheet || '?';
  return Object.entries(d).filter(([, v]) => v !== null && v !== '' && v !== undefined)
    .map(([k, v]) => `${k} : ${Array.isArray(v) ? v.map(slug).join(', ') : v}`).join(' · ').slice(0, 220);
}

/* ---- chargements différés --------------------------------------------------- */
function chargerTout() {
  const s = CUR;
  if (!s) return;
  loadPolicy(s.srv, s.domain);
  loadRollbackPoints(s.srv, s.domain);
  loadSafeStatus(s.domain);
  loadVizUpStatus(s.srv, s.domain);
  chargerVulns(kName(s) || s.domain);
  chargerIncidents();
  ensureSettings().then(() => { if (CUR === s) { const b = document.getElementById('site-band'); if (b) b.replaceWith(bandeau(s)); renderVulnsSite(); } }).catch(() => {});
}

async function loadPolicy(srv, dom) {
  const seq = PAGESEQ;
  let f = [];
  try { const r = await api('/api/actions/policy?domain=' + encodeURIComponent(dom)); f = r.frozen || []; }
  catch (e) { f = []; }
  if (seq !== PAGESEQ) return;         // la page affiche un autre site : résultat périmé
  FROZEN = f;
  renderPolicy();
}

async function loadRollbackPoints(srv, dom) {
  const seq = PAGESEQ;
  let pts = [];
  try {
    const r = await api(`/api/actions/rollback_points?server=${encodeURIComponent(srv)}&domain=${encodeURIComponent(dom)}`);
    pts = r.points || [];
  } catch (e) { pts = []; }
  if (seq !== PAGESEQ) return;
  setRollbackPoints(pts, srv, dom);
  const sec = document.getElementById('site-rbsec'), list = document.getElementById('site-rblist');
  if (sec && list) {
    sec.hidden = !pts.length;
    if (pts.length) mount(list, pointsListeEl({ srv, dom }, () => loadFleet().then(refreshSite).catch(() => {})));
  }
}

/* Vulnérabilités du site : on ne demande QUE ce site (le parc entier pèse ~190 Ko). */
async function chargerVulns(cle) {
  const seq = PAGESEQ;
  try {
    const r = await api('/api/sec/vulns?domain=' + encodeURIComponent(cle));
    if (seq !== PAGESEQ) return;
    VULNS = (r.sites || [])[0] || { count: 0, worst: '', findings: [] };
  } catch (e) {
    if (seq !== PAGESEQ) return;
    VULNS = { count: 0, worst: '', findings: [], erreur: true };
  }
  renderVulnsSite();
  if (ONGLET === 'securite') renderVulnsListe();
  if (ONGLET === 'extensions') dessinerOnglet();
}

async function chargerIncidents() {
  const seq = PAGESEQ, s = CUR;
  const cle = kName(s) || s.domain;
  let j = null;
  try { j = await api('/api/incidents'); } catch (e) { j = null; }
  if (seq !== PAGESEQ) return;
  INCIDENTS = ((j && j.incidents) || []).filter(i => i.site === cle || i.site === s.domain);
  const box = document.getElementById('site-incidents');
  if (box && ONGLET === 'apercu') mount(box, h('h3', { text: 'À traiter sur ce site' }), incidentsEl());
}

/* ---- mise à jour sûre : archive → MAJ → contrôle → retour arrière si cassé --- */
function safeVerdictPill(v) {
  // « réussie avec anomalies visuelles » n'est PAS vert : la mise à jour tient,
  // mais le rendu a bougé et personne ne l'a encore regardé.
  const ok = v === 'réussi', neutre = (v === 'rien à faire');
  const cls = ok ? 'ok' : neutre ? 'mut' : (v || '').startsWith('ÉCHEC') ? 'err' : 'warn';
  return `<span class="pill ${cls}">${H(v || '…')}</span>`;
}
function renderSafe(stt, dom) {
  const box = consoleDe(dom);
  if (!box) return;
  box.hidden = false;
  const lignes = (stt.steps || []).map(x =>
    `<div class="logline"><span class="pill ${x.warn ? 'warn' : x.ok ? 'ok' : 'err'}">${x.warn ? 'attention' : x.ok ? 'ok' : 'échec'}</span>
      <b>${H(x.label)}</b> <span class="muted small">${H(x.ts)}</span>
      ${x.detail ? `<div class="muted small wrapline ml-8">${H(stripPhpNoise(x.detail))}</div>` : ''}</div>`).join('');
  box.innerHTML = `<div class="mb-6"><b>${icon('shield-check')} Mise à jour sûre</b> ${stt.running ? '<span class="pill mut">en cours…</span>' : safeVerdictPill(stt.verdict)}</div>${lignes}`;
  box.scrollTop = box.scrollHeight;
}
/* Suivi d'une MAJ sûre : le bouton et la console sont retrouvés à chaque tour
   (la page a pu être quittée puis rouverte), et le sondage s'arrête tout seul
   si le site affiché change ou si le backend ne répond plus. */
function suivreSafe(dom, lbl) {
  poll('safe', async () => {
    const stt = await api('/api/actions/safe_update_status');
    if (!CUR || CUR.domain !== dom) return { fini: true };   // le job continue côté serveur
    renderSafe(stt, dom);
    const bouton = () => (CUR && CUR.domain === dom) ? document.getElementById('safeup') : null;
    if (!stt.running) {
      const b = bouton();
      if (b) { b.disabled = false; if (lbl) b.innerHTML = lbl; }
      loadFleet().then(refreshSite).catch(() => {});
      return { fini: true };
    }
    const b = bouton();
    if (b) { b.disabled = true; b.textContent = 'en cours…'; }
    return { fini: false };
  }, { every: 3000, maxErrors: 5, until: r => !!(r && r.fini) });
}
/* Suivi pour la BARRE DE NOTIFICATIONS, indépendant de `suivreSafe` : celui-ci
   s'arrête dès que la page affiche un autre site. La barre, elle, doit tenir
   jusqu'au verdict. Nombre d'étapes d'une MAJ sûre nominale : contrôle avant,
   liste, à mettre à jour, sauvegarde, archivage fichiers, archivage base, mise
   à jour, page d'accueil, WordPress fonctionnel, contrôle visuel, terminé. */
const SAFE_ETAPES = 11;
function suivreSafeNotif(dom, nid) {
  let tours = 0;
  poll('safenotif', async () => {
    if (++tours > 400) return { fini: true };              // ≈ 20 min, garde-fou
    const stt = await api('/api/actions/safe_update_status');
    if (!stt || stt.domain !== dom) return { fini: false }; // le job n'a pas encore pris la main
    const n = (stt.steps || []).length, der = (stt.steps || [])[n - 1];
    if (stt.running) {
      NOTIF.update(nid, { progress: Math.min(.95, n / SAFE_ETAPES), detail: der ? der.label : 'préparation…' });
      return { fini: false };
    }
    const v = String(stt.verdict || '');
    NOTIF.update(nid, { progress: 1 });
    NOTIF.done(nid, { ok: v === 'réussi' || v === 'rien à faire', warn: /anomalie/i.test(v), message: v || 'terminée' });
    return { fini: true };
  }, {
    every: 3000, maxErrors: 5, until: r => !!(r && r.fini),
    onStop: () => NOTIF.done(nid, { ok: false, message: 'suivi interrompu — voir la page du site' }),
  });
}
/* À l'ouverture : si une MAJ sûre tourne encore sur CE site, on ré-affiche sa
   progression et on se raccroche au sondage. */
async function loadSafeStatus(dom) {
  const seq = PAGESEQ;
  let stt = null;
  try { stt = await api('/api/actions/safe_update_status'); } catch (e) { return; }
  if (seq !== PAGESEQ || !stt || !stt.domain || stt.domain !== dom) return;
  if (!(stt.steps || []).length && !stt.running) return;
  renderSafe(stt, dom);
  if (!stt.running) return;
  const b = document.getElementById('safeup');
  if (b) { b.dataset.label = b.dataset.label || b.innerHTML; b.disabled = true; b.textContent = 'en cours…'; }
  suivreSafe(dom, (b && b.dataset.label) || (icon('shield-check') + ' MAJ sûre'));
  // Rechargement de page ou MAJ lancée ailleurs : la barre reprend le suivi.
  const nid = 'safe:' + dom;
  if (!NOTIF.encours(nid)) {
    NOTIF.start({ id: nid, label: 'MAJ sûre · ' + dom, kind: 'safe', progress: 0, site: { srv: (CUR && CUR.srv) || '', domain: dom } });
    suivreSafeNotif(dom, nid);
  }
}

async function startSafeUpdate(srv, dom, btn) {
  const withCore = btn.dataset.core === '1';
  await ensureSettings();
  let msg = `Mise à jour sûre de <b>${H(dom)}</b> ?<br><br>Déroulé : sauvegarde UpdraftPlus → archivage de ce qui va changer → mise à jour → contrôle du site → retour arrière automatique si quelque chose casse.`;
  if (withCore) msg += `<br><br>${icon('triangle-alert')} Le cœur WordPress est inclus. Ses fichiers sont restaurables, mais les migrations de base de données ne sont PAS annulées par le retour arrière : la sauvegarde UpdraftPlus est le recours pour la base.`;
  msg += `<br><br>L'opération peut durer plusieurs minutes.`;
  // La case est pré-remplie avec le réglage, mais reste modifiable POUR CETTE
  // exécution : c'est au moment de lancer qu'on sait si le site supporte mal
  // une régression visuelle.
  const corps = `<label class="fld"><input type="checkbox" id="su-vizrb"${store.settings.viz_anomaly_rollback ? ' checked' : ''}>
      Annuler la mise à jour si VizProof détecte des anomalies visuelles</label>
    <p class="hint hint-loose">Pré-réglé d'après <b>Réglages</b>. Décoché : les anomalies sont signalées et la mise à jour est conservée.</p>`;
  const rep = await new Promise(res => {
    askOpen('Mise à jour sûre', msg, corps,
      () => res({ go: true, rb: document.getElementById('su-vizrb').checked }),
      () => res({ go: false }));
    const b = document.getElementById('ask-ok');
    b.textContent = 'Lancer';
  });
  if (!rep.go) return;
  const lbl = btn.innerHTML;
  btn.dataset.label = lbl;
  btn.disabled = true;
  btn.textContent = 'en cours…';
  let r;
  try { r = await api('/api/actions/safe_update', { server: srv, domain: dom, backup: true, viz: true, core: withCore, viz_rollback: rep.rb }); }
  catch (e) { r = { error: 'lancement impossible : ' + e }; }
  if (!r || r.error) {
    askInfo('Mise à jour sûre impossible', H((r && r.error) || 'réponse vide'));
    btn.disabled = false;
    btn.innerHTML = lbl;
    return;
  }
  suivreSafe(dom, lbl);
  const nid = 'safe:' + dom;
  NOTIF.start({ id: nid, label: 'MAJ sûre · ' + dom, kind: 'safe', progress: 0, detail: 'démarrage…', site: { srv, domain: dom } });
  suivreSafeNotif(dom, nid);
}

/* ---- job « baseline → mise à jour → verdict » (réponse {job:"viz_update"}) --- */
const VIZUP_PILL = {
  attente: ['mut', 'attente'], 'en cours': ['mut', 'en cours…'],
  ok: ['ok', 'ok'], warn: ['warn', 'attention'], erreur: ['err', 'échec'],
};
const VIZUP_DETAIL = { baseline: 'baseline VizProof…', update: 'mise à jour…', rescan: 'inventaire…' };
function vizupLigne(x) {
  const [c, l] = VIZUP_PILL[x.status] || ['mut', String(x.status || '')];
  return `<div class="logline"><span class="pill ${c}">${H(l)}</span> <b>${H(x.label)}</b>
    <span class="muted small">${H(x.ts || '')}</span>
    ${x.detail ? `<div class="muted small wrapline ml-8">${H(stripPhpNoise(x.detail))}</div>` : ''}</div>`;
}
function vizupCourante(job) {
  const s = (job && job.steps) || [];
  return s.filter(x => x.status === 'en cours').pop() || s.filter(x => x.status !== 'attente').pop() || s[0] || null;
}
function vizupFaites(job) { return ((job && job.steps) || []).filter(x => x.status !== 'attente').length; }
function vizupDetail(s) {
  if (!s) return 'préparation…';
  // Pour le contrôle visuel, le détail de l'étape EST la phase.
  if (s.key === 'viz') return VIZ_PHASES[s.detail] || 'contrôle visuel…';
  return VIZUP_DETAIL[s.key] || s.label || '';
}
/* '' | 'ok' | 'warn' | 'err' — une anomalie visuelle n'est pas un échec du job. */
function vizupFin(job) {
  const s = (job && job.steps) || [];
  if (s.some(x => x.status === 'erreur')) return 'err';
  if (s.some(x => x.status === 'warn')) return 'warn';
  return 'ok';
}
function vizupVerdict(job) {
  const f = vizupFin(job);
  return f === 'err' ? 'échec' : f === 'warn' ? 'terminée avec avertissement' : 'réussie';
}
function renderVizUp(job, dom) {
  const box = consoleDe(dom);
  if (!box) return;
  box.hidden = false;
  const v = (job.result && job.result.viz) || null;
  const tete = job.running ? '<span class="pill mut">en cours…</span>'
    : `<span class="pill ${vizupFin(job)}">${H(vizupVerdict(job))}</span>`;
  box.innerHTML = `<div class="mb-6"><b>${icon('scan-eye')} Mise à jour sous contrôle visuel</b> ${tete}</div>`
    + ((job.steps || []).map(vizupLigne).join(''))
    + (v ? vizConsoleLigne(v) : '');
  box.scrollTop = box.scrollHeight;
}
/* Pendant le job, les boutons de mise à jour du site sont hors service : deux
   mises à jour de front sur le même WordPress, c'est un site cassé sans
   coupable (le serveur refuse d'ailleurs en 409). */
function vizupBoutons(dom, off) {
  if (!CUR || CUR.domain !== dom) return;
  document.querySelectorAll('#page-site [data-act]').forEach(b => { if (MAJ_ACTS.has(b.dataset.act)) b.disabled = !!off; });
  document.querySelectorAll('#page-site .prb').forEach(b => { b.disabled = !!off; });
  const su = document.getElementById('safeup');
  if (su) su.disabled = !!off;
}
function suivreVizUp(srv, dom, nid) {
  let tours = 0;
  poll('vizup:' + dom, async () => {
    if (++tours > 600) return { fini: true };        // ≈ 30 min, garde-fou
    const job = await api('/api/actions/viz_update_status?domain=' + encodeURIComponent(dom));
    if (!job || !(job.steps || []).length) return { fini: false };
    if (CUR && CUR.domain === dom) { renderVizUp(job, dom); vizupBoutons(dom, job.running); }
    const n = (job.steps || []).length || 1;
    if (job.running) {
      NOTIF.update(nid, { progress: Math.min(.95, vizupFaites(job) / n), detail: vizupDetail(vizupCourante(job)) });
      return { fini: false };
    }
    const v = (job.result && job.result.viz) || null, f = vizupFin(job);
    NOTIF.update(nid, { progress: 1 });
    NOTIF.done(nid, { ok: f !== 'err', warn: f === 'warn', message: vizupVerdict(job) + (v ? ' · ' + vizPhrase(v) : '') });
    // L'inventaire a été re-scanné côté serveur : on recharge, puis on remet la
    // console du job (le rendu la réinitialise).
    loadFleet().then(() => { if (CUR && CUR.domain === dom) { refreshSite(); renderVizUp(job, dom); } }).catch(() => {});
    return { fini: true };
  }, {
    every: 3000, maxErrors: 5, until: r => !!(r && r.fini),
    onStop: () => { NOTIF.done(nid, { ok: false, message: 'suivi interrompu — voir l’historique du site' }); vizupBoutons(dom, false); },
  });
}
/* À l'ouverture : si un job tourne encore sur CE site, on le ré-affiche et on
   se raccroche — la page a pu être quittée entre-temps. */
async function loadVizUpStatus(srv, dom) {
  const seq = PAGESEQ;
  let job = null;
  try { job = await api('/api/actions/viz_update_status?domain=' + encodeURIComponent(dom)); }
  catch (e) { return; }
  if (seq !== PAGESEQ || !job || !(job.steps || []).length) return;
  renderVizUp(job, dom);
  if (!job.running) return;
  vizupBoutons(dom, true);
  const nid = 'vizup:' + dom;
  if (!NOTIF.encours(nid)) {
    NOTIF.start({ id: nid, label: 'MAJ contrôlée · ' + dom, kind: 'maj', progress: 0, detail: 'reprise du suivi…', site: { srv, domain: dom } });
  }
  suivreVizUp(srv, dom, nid);
}

/* ---- exécution d'une action unitaire --------------------------------------- */
/* Confirmation à deux clics pour ce qui MODIFIE le site ; le reste part
   directement — tout confirmer revient à ne plus rien signaler. */
export function confirmRun(btn, label) {
  if (!ACT_RISQUE.has(btn.dataset.act)) { runAction(btn); return; }
  if (btn.dataset.confirm) { runAction(btn); return; }
  if (!btn.isConnected) {                 // bouton fabriqué par le menu : modale
    askConfirm(`${H(label || actLib(btn.dataset.act, btn.dataset.arg))} sur <b>${H(CUR ? CUR.domain : '')}</b> ?`
      + '<br><br>Cette action <b>modifie le site</b>.',
      { titre: actLib(btn.dataset.act, btn.dataset.arg), ok: 'Lancer' })
      .then(ok => { if (ok) runAction(btn); });
    return;
  }
  btn.dataset.confirm = '1';
  btn.dataset.label = btn.innerHTML;
  btn.textContent = 'Confirmer ?';
  btn.classList.add('danger');
  setTimeout(() => {
    if (btn.dataset.confirm) {
      delete btn.dataset.confirm;
      btn.innerHTML = btn.dataset.label;
      btn.classList.remove('danger');
    }
  }, 4000);
}

async function runAction(btn) {
  const act = btn.dataset.act, arg = btn.dataset.arg || null, s = CUR;
  if (!s) return;
  delete btn.dataset.confirm;
  btn.classList.remove('danger');
  if (btn.isConnected) setBusy(btn);
  const head = `$ ${act}${arg ? ' ' + arg : ''} sur ${s.domain}\n`;
  const con = consoleVisible();
  if (con) con.textContent = head + '…';
  const nid = NOTIF.start({ label: notifLabel(act, arg, s), site: { srv: s.srv, domain: s.domain }, kind: ACT_KIND[act] || 'action' });
  try {
    const j = await api('/api/actions/run', { server: s.srv, domain: s.domain, action: act, arg }) || {};
    /* Site relié à VizProof : la route a démarré un job (baseline → MAJ →
       verdict) au lieu de faire la mise à jour dans sa réponse. */
    if (j.job === 'viz_update') {
      renderVizUp({ running: true, steps: j.steps || [], result: null }, s.domain);
      vizupBoutons(s.domain, true);
      NOTIF.update(nid, { progress: 0, detail: 'démarrage…' });
      suivreVizUp(s.srv, s.domain, nid);
      return;
    }
    /* rc 2 sur un scan visuel = anomalies détectées, pas un échec technique.
       rc 96 = extension gelée · 97 = site sans SSH · 99 = plugin trop ancien :
       ce sont des RÉPONSES, elles se disent en clair. */
    const anom = !j.ok && Number(j.rc) === 2 && /^viz_/.test(act);
    const refus = { 96: 'extension gelée pour ce site', 97: 'site géré sans SSH : action impossible', 99: 'extension du site trop ancienne' }[Number(j.rc)];
    const verdict = j.ok ? `<b class="ok">${icon('circle-check')} OK</b>`
      : anom ? `<b class="warn">${icon('triangle-alert')} anomalies visuelles détectées</b>`
        : refus ? `<b class="warn">${icon('triangle-alert')} ${H(refus)}</b>`
          : `<b class="err">${icon('circle-x')} rc ${H(j.rc ?? '?')}</b>`;
    const v = (j.viz && typeof j.viz === 'object') ? j.viz : null;
    const c1 = consoleDe(s.domain);
    if (c1) c1.innerHTML = H(head + (j.output || '') + '\n\n') + verdict + (v ? '\n' + vizConsoleLigne(v) : '');
    if (v && v.pending) NOTIF.update(nid, { detail: 'contrôle visuel : ' + vizPhrase(v), progress: null });
    else {
      NOTIF.done(nid, {
        ok: !!(j.ok || anom), warn: anom || !!refus || (v ? vizEtat(v) === 'warn' : false),
        message: anom ? 'anomalies visuelles détectées'
          : refus || (j.ok ? (v ? 'contrôle visuel : ' + vizPhrase(v) : '')
            : stripPhpNoise(String(j.output || j.error || '')).slice(-160) || ('rc ' + (j.rc ?? '?'))),
      });
    }
    if ((j.ok || anom) && act !== 'rescan' && act !== 'verify_checksums') {
      await api('/api/actions/run', { server: s.srv, domain: s.domain, action: 'rescan' });
    }
    const html = c1 ? c1.innerHTML : '';
    await loadFleet();
    refreshSite();
    const c2 = consoleDe(s.domain);
    if (c2 && html) { c2.hidden = false; c2.innerHTML = html; }
    if (v && v.pending) suivreVizLast(s.srv, s.domain, nid);
  } catch (e) {
    const c = consoleDe(s.domain);
    if (c) c.innerHTML += H('\n') + `<b class="err">${icon('circle-x')} ${H(String(e))}</b>`;
    if (btn.isConnected) setIdle(btn, btn.dataset.label || act);
    NOTIF.done(nid, { ok: false, message: String(e) });
  }
}

/* Quitter la page site : les jobs continuent côté serveur, pas les sondages
   liés à l'affichage. */
export function quitterSite() {
  stopPoll('safe');          // le job continue côté serveur, pas le sondage d'affichage
  fermerMenus();
}
