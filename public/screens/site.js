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
import { auBas, collerEnBas, esc as H, h, mount } from '../lib/dom.js';
import {
  absTime, detailEvenement, relTime, safeUrl, stripPhpNoise, tsMs,
  udIntervalFr, udHorizon, udRulesFr,
} from '../lib/format.js';
import { icon, iconEl } from '../lib/icons.js';
import { poll, stopPoll } from '../lib/poll.js';
import {
  store, allSites, etatSite, bkAge, kName, nomDeSite, clientDe, loadFleet, phpEol, seuilBackup,
} from '../lib/state.js';

import { setBusy, setIdle } from '../components/button.js';
import { chipEl, chipEtat } from '../components/chip.js';
import { erreurPhpEl, incidentEl } from '../components/incident.js';
import { askConfirm, askInfo, askOpen } from '../components/confirm.js';
import { menuActions, fermerMenus } from '../components/actions-menu.js';
import { askVersion, pointsListeEl, setRollbackPoints, rollbackPoints } from '../components/rollback.js';
import { NOTIF } from '../components/toast.js';
import {
  openVizConnect, openVizPages, vizBlocEl, vizConnected, vizConsoleLigne, vizDisconnect, vizEtat,
  vizEtatTexte, vizInstall, vizPhrase, vizPhraseLongue, vizState, setVizConsole, setVizRefresh,
  VIZ_PHASES, suivreVizLast, chargerVizRapport, vizReportHtml,
  vizAnom, vizGravite, vizBaselinePartielle} from '../components/viz.js';
import { wpCredentials } from '../components/wpauth.js';
import { loadWpCred } from './gestion.js';
import { ensureSettings } from './reglages.js';
import { sevPill, SEVLABEL, SEVRANK, grouperParExtension, kindChip } from './securite.js';

/* ---- état de la page ------------------------------------------------------ */
const ONGLETS = [
  ['apercu', 'Aperçu'],
  /* Le SLUG reste `extensions` : les liens déjà partagés (et ceux des
     incidents) ne doivent pas casser parce que l'onglet parle aussi des
     thèmes. Seul le libellé change. */
  ['extensions', 'Extensions et thèmes'],
  ['securite', 'Sécurité'],
  /* VizProof a sa place ici, et pas au fond de l'Aperçu : c'est le seul volet
     qui dit à quoi le site RESSEMBLE, et il porte trois actions (relier,
     choisir les pages, scanner) qu'on ne trouvait qu'en dépliant le menu. La
     pastille de l'onglet dit son état sans qu'on l'ouvre. */
  ['vizproof', 'VizProof', vizPastilleOnglet],
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
let FROZEN_TH = [];      // thèmes gelés
let INCIDENTS = null;    // incidents de CE site — null tant qu'ils ne sont pas chargés
let FOCUS_ONGLET = false;   // rendre le focus à l'onglet après une flèche

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
  theme_update: 'MAJ thème',
  updraft_backup: 'Sauvegarde UpdraftPlus', cache_flush: 'Vidage des caches',
  autoupdate_on: 'Activation des auto-MAJ', autoupdate_off: 'Désactivation des auto-MAJ',
  verify_checksums: 'Intégrité du cœur', vizproof_install: 'Installation VizProof',
  viz_baseline: 'Baseline visuelle', viz_scan: 'Scan visuel', viz_disconnect: 'Dissociation VizProof',
  rescan: 'Re-scan',
};
const ACT_KIND = {
  core_update: 'maj', plugins_update_all: 'maj', plugins_update_except: 'maj',
  plugin_update: 'maj', themes_update_all: 'maj', theme_update: 'maj',
  updraft_backup: 'backup', cache_flush: 'cache',
  verify_checksums: 'check', vizproof_install: 'install', viz_baseline: 'viz', viz_scan: 'viz',
  viz_disconnect: 'connect', rescan: 'rescan',
};
export function actLib(act, arg) { return (ACT_LIB[act] || act) + (arg ? ' ' + arg : ''); }
function notifLabel(act, arg, s) { return actLib(act, arg) + ' · ' + ((s && (kName(s) || s.domain)) || ''); }

/* Seules les actions qui MODIFIENT le site demandent confirmation : tout
   confirmer revient à ne plus rien signaler. */
const ACT_RISQUE = new Set(['core_update', 'plugins_update_all', 'plugin_update',
  'themes_update_all', 'theme_update', 'autoupdate_on', 'autoupdate_off', 'vizproof_install']);
const MAJ_ACTS = new Set(['core_update', 'plugins_update_all', 'plugins_update_except',
  'plugin_update', 'themes_update_all', 'theme_update']);

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
    /* `null` = pas encore chargé, `[]` = chargé et vide. Sans cette distinction,
       la page d'un site affichait « Rien à traiter » — ou pire, les incidents
       du site PRÉCÉDENT — pendant toute la durée de la requête. */
    INCIDENTS = null;
    VULNS = null;
    FROZEN = [];
    FROZEN_TH = [];
    setRollbackPoints([], s.srv, s.domain);
  }
  dessiner();
  if (change) chargerTout();
}

/* Rafraîchissement après une action : la flotte a changé, la console et
   l'onglet courant restent. */
function refreshSite() {
  if (!CUR) return;
  const s = siteParCle(CLE) || siteParCle(cleDeSite(CUR));
  if (!s) return;
  CUR = s;
  store.cur = s;
  /* La console est reconstruite par `dessiner()` : on garde son contenu ET sa
     position. Sans la position, un rafraîchissement de fond ramenait la vue en
     haut du journal — et le verdict qu'on attendait sortait de l'écran. */
  const box = document.getElementById('site-console');
  const garde = (box && !box.hidden) ? box.innerHTML : null;
  const gardeTop = box ? box.scrollTop : 0;
  // Une action a pu changer l'autorisation WordPress : on la relit plutôt que
  // de laisser le menu affirmer un état périmé.
  WPETAT.delete(s.domain);
  dessiner();
  chargerWpEtat(s).catch(() => {});
  if (garde !== null) {
    const b2 = document.getElementById('site-console');
    if (b2) { b2.hidden = false; b2.innerHTML = garde; b2.scrollTop = gardeTop; }
  }
  renderPolicy();
  renderVulnsSite();
}
setVizRefresh(refreshSite);

function dessiner() {
  const s = CUR;
  mount('page-site',
    entete(s),
    bandeau(s),
    ongletsNav(),
    h('div', {
      id: 'site-tab', class: 'sitetab', role: 'tabpanel',
      'aria-labelledby': 'sitetab-' + ONGLET, tabindex: '0',
    }),
    h('div', { class: 'console', id: 'site-console', hidden: true, dataset: { domain: s.domain } }));
  renderVulnsSite();
  dessinerOnglet();
  // Navigation aux flèches : le volet a été reconstruit, on rend le focus à
  // l'onglet qui vient d'être choisi.
  if (FOCUS_ONGLET) {
    FOCUS_ONGLET = false;
    const b = document.getElementById('sitetab-' + ONGLET);
    if (b) b.focus();
  }
}

/* Attente visible. Le « chargement… » gris se confondait avec les textes d'aide
   qui l'entourent, au point qu'on croyait la zone vide plutôt qu'en train de se
   remplir. Une roue qui tourne dit la différence sans un mot de plus, et le mot
   reste pour les lecteurs d'écran (`role=status`). */
function attente(texte) {
  return h('span', { class: 'chargement small', role: 'status' },
    iconEl('loader-circle', { size: 14, cls: 'ic-spin' }),
    h('span', { text: texte || 'chargement…' }));
}

/* ---- en-tête -------------------------------------------------------------- */
function entete(s) {
  const e = etatSite(s);
  const client = clientDe(s);
  const meta = h('div', { class: 'meta sitemeta' });
  const bout = (txt, cls) => h('span', { class: cls || '', text: txt });
  const sep = () => h('span', { class: 'sep', text: '·' });
  if (client) { meta.append(bout(client)); meta.append(sep()); }
  meta.append(bout(s.srv || '—'));
  if (s.path) { meta.append(sep()); meta.append(h('code', { class: 'small', text: s.path })); }
  meta.append(sep());
  meta.append(h('span', { title: absTime(s.collected_at || store.fleet?.generated_at), text: 'relevé ' + relTime(s.collected_at || store.fleet?.generated_at) }));
  if (s.via !== 'rest') {
    /* « Relevé il y a 42 min » appelle « et maintenant ? ». Le re-scan était
       au fond du menu Actions ; il est ici, contre la phrase qui le motive. */
    const rs = h('button', {
      type: 'button', class: 'btn xs', title: 'Relire l’inventaire de ce site maintenant',
      'aria-label': 'Re-scanner l’inventaire de ce site',
    }, iconEl('refresh-cw', { size: 13 }));
    rs.dataset.act = 'rescan';
    rs.onclick = () => confirmRun(rs, 'Re-scan de l’inventaire');
    meta.append(rs);
  }
  meta.append(sep());
  meta.append(h('span', {
    class: 'pill mut',
    title: s.via === 'rest' ? "inventaire poussé par l'agent, sans accès SSH" : 'inventaire relevé en SSH',
    text: s.via === 'rest' ? 'via REST' : 'via SSH',
  }));

  const nom = nomDeSite(s);
  const fil = h('nav', { class: 'fil', 'aria-label': "Fil d'Ariane" },
    h('a', { href: '#parc', text: 'Parc' }),
    h('span', { class: 'sep', text: '›' }),
    h('span', { 'aria-current': 'page', text: nom }));

  /* Le bloc de statut live suit la MÊME règle que la colonne État du Parc :
     Kuma s'il surveille ce site, sinon la sonde du dashboard, et l'infobulle
     dit laquelle des deux a parlé. */
  const titre = h('div', { class: 'sitetitle' },
    h('h1', { text: nom }),
    chipEtat(e),
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

/* Porteur d'action DÉTACHÉ. `confirmRun`, `vizInstall` et `vizDisconnect`
   travaillent sur un élément qui porte `data-act` / `data-arg` et sur lequel
   elles posent un état de chargement. Lancées depuis une entrée de menu, il
   n'y a aucun bouton à l'écran : on leur en fabrique un porteur, qui n'entre
   jamais dans le document.

   Un <span> plutôt qu'un <button> : un bouton hors du document n'a pas de nom
   accessible, et c'est exactement ce que refuse tools/check_a11y.py — à juste
   titre, on ne saurait pas quoi y écrire. */
function porteurAction(act, arg) {
  const el = h('span', { class: 'btn', hidden: true });
  if (act) el.dataset.act = act;
  if (arg) el.dataset.arg = arg;
  return el;
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
    onSelect: () => confirmRun(porteurAction(act, def.arg), def.label),
  };
}

function menuDuSite(s) {
  const rest = s.via === 'rest';
  const R = raisons(s);
  const vs = vizState(s);
  const nEx = s.plugins_updates || 0;
  const nTh = s.themes_updates || 0;
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
    /* Comme les autres entrées : le nombre est DANS le libellé quand il y a de
       quoi faire, et l'entrée reste grisée avec sa raison quand il n'y a rien. */
    itemAct(s, { action: 'themes_update_all', label: 'Tous les thèmes' + (nTh ? ' (' + nTh + ')' : ''), ic: 'arrow-up', raison: rest ? R.rest : (nTh ? '' : 'aucun thème à mettre à jour') }),
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

  return menuActions({
    label: 'Actions', ic: 'list', groups: [
      { titre: 'Mettre à jour', items: maj },
      { titre: 'Vérifier', items: verif },
      { titre: 'Sauvegarder', items: sauv },
      { titre: 'Connecter', items: groupeConnecter(s) },
    ],
  });
}

/* ---- groupe « Connecter » : l'état d'abord, puis ce qui a du sens ----------

   Il listait TOUT — installer, connecter, dissocier, agent, WordPress — et
   grisait ce qui ne s'appliquait pas. Devant « Installer VizProof » barré
   d'un « extension déjà présente », on ne savait toujours pas si le site
   était RELIÉ. Trois lignes d'état le disent maintenant en toutes lettres, et
   la liste ne garde que les entrées qui ont un sens dans cet état-là.

   Ce qui reste grisé plutôt que masqué : les cas REST, où l'action existe mais
   demande un accès SSH. La raison reste en infobulle — la masquer laisserait
   croire que le dashboard ne sait pas le faire. */
function groupeConnecter(s) {
  const rest = s.via === 'rest';
  const R = raisons(s);
  const t = vizEtatTexte(s), vs = t.etat;
  const items = [];

  /* --- VizProof --- */
  items.push({ etat: true, ic: 'scan-eye', label: 'VizProof :', detail: t.long });
  if (vs === 'absent' || vs === 'nodata') {
    items.push({
      action: 'vizproof_install',
      label: 'Installer VizProof', ic: 'plus', attention: true,
      disabled: rest,
      raison: rest ? 'site sans SSH : passez par « Autoriser WordPress » puis le bloc VizProof' : '',
      onSelect: () => vizInstall(porteurAction(), s.srv, s.domain),
    });
  } else if (vs === 'nonconnecte') {
    items.push({
      label: 'Connecter VizProof…', ic: 'link',
      disabled: rest, raison: rest ? R.rest : '',
      onSelect: () => openVizConnect([s]),
    });
  } else if (vs === 'connecte') {
    items.push({
      label: 'Pages surveillées…', ic: 'scan-eye',
      disabled: rest, raison: rest ? 'site sans SSH : à choisir dans wp-admin' : '',
      onSelect: () => openVizPages(s),
    }, {
      label: 'Reconnecter VizProof…', ic: 'link',
      disabled: rest, raison: rest ? R.rest : '',
      onSelect: () => openVizConnect([s]),
    }, {
      label: 'Dissocier VizProof', ic: 'x', attention: true,
      disabled: rest, raison: rest ? R.rest : '',
      onSelect: () => vizDisconnect(porteurAction(), s),
    });
  }
  // 'inactif' et 'nocli' : rien à proposer d'ici, la ligne d'état dit quoi faire
  // (activer l'extension, ou la mettre à jour depuis l'onglet Extensions).

  /* --- autorisation WordPress ---
     Elle n'existe que pour les sites sans SSH : en SSH le dashboard agit déjà
     directement. Lue AVANT le bloc agent : sans SSH, c'est elle qui décide si
     l'agent peut être posé d'ici. */
  const cred = rest ? WPETAT.get(s.domain) : undefined;
  // `su` : true autorisé · false non autorisé · null on ne sait pas encore.
  const su = (cred && typeof cred === 'object') ? !!cred.has_password : null;

  /* --- agent Dash ---
     La collecte ne relève pas sa présence : sur un site en SSH, l'état est
     honnêtement INCONNU, et les deux actions restent offertes par SSH. Sur un
     site REST, l'agent est là par construction — c'est lui qui pousse
     l'inventaire — et les deux gestes passent par l'API REST de WordPress. */
  items.push({
    etat: true, ic: 'link', label: 'Agent Dash :',
    detail: rest
      ? 'relié — c’est lui qui pousse l’inventaire de ce site'
      : 'état inconnu — la collecte ne relève pas sa présence',
  });
  if (rest) {
    const bloque = su === true ? '' : 'autorisez d’abord WordPress sur ce site';
    items.push({
      label: 'Réinstaller et relier l’agent Dash', ic: 'refresh-cw', attention: true,
      disabled: !!bloque, raison: bloque,
      onSelect: () => agentRest(s, true),
    }, {
      label: 'Retirer l’agent Dash', ic: 'x', attention: true,
      disabled: !!bloque, raison: bloque,
      onSelect: () => agentRest(s, false),
    });
  } else {
    items.push({
      label: 'Installer l’agent Dash (alertes temps réel)', ic: 'link', attention: true,
      onSelect: () => dashAgent(s, true),
    }, {
      label: 'Dissocier l’agent Dash', ic: 'x', attention: true,
      onSelect: () => dashAgent(s, false),
    });
  }

  items.push({
    etat: true, ic: 'link', label: 'WordPress :',
    detail: !rest ? 'sans objet — ce site est piloté en SSH'
      : cred === WPENCOURS ? 'état en cours de lecture…'
        : su === null ? 'état indisponible'
          : su ? 'autorisé' + (cred.user ? ' (' + cred.user + ')' : '') : 'non autorisé',
  });
  if (rest && su !== true) {
    items.push({
      label: 'Autoriser WordPress (mot de passe d’application)', ic: 'link', attention: true,
      onSelect: () => cliquerWpCred('[data-wpauth]', 'Autoriser'),
    });
  }
  if (rest && su !== false) {
    items.push({
      label: 'Révoquer l’autorisation WordPress', ic: 'trash-2', attention: true,
      disabled: su !== true, raison: su === true ? '' : 'aucune autorisation enregistrée pour ce site',
      onSelect: () => cliquerWpCred('[data-wprevoke]', 'Révoquer'),
    });
  }
  return items;
}

/* État des identifiants WordPress, lu une fois par site REST. Le menu est
   construit d'un bloc : sans ce cache il ne pourrait pas savoir s'il faut
   proposer « Autoriser » ou « Révoquer », et les montrerait tous les deux. */
const WPETAT = new Map();
const WPENCOURS = 'encours';

async function chargerWpEtat(s) {
  if (!s || s.via !== 'rest' || WPETAT.has(s.domain)) return;
  WPETAT.set(s.domain, WPENCOURS);            // en vol : pas de second appel
  const j = await wpCredentials(s.domain);
  WPETAT.set(s.domain, j || null);
  if (CUR && CUR.domain === s.domain) majBarreActions();
}

/** Redessine la seule barre d'actions de l'en-tête (pas toute la page). */
function majBarreActions() {
  const box = document.querySelector('#page-site .siteact');
  if (box && CUR) mount(box, actionPrincipale(CUR), menuDuSite(CUR));
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

/* ---- agent Dash sur un site SANS SSH --------------------------------------
   Tout passe par l'API REST de WordPress et le mot de passe d'application déjà
   autorisé : l'extension vient de wordpress.org, puis le dashboard appelle la
   route d'appairage de l'agent. Le repli « code » n'est PAS un échec — l'agent
   déjà en place est antérieur à 1.4.0 et ne sait pas se relier à distance : on
   rend alors le code à coller dans l'écran de réglages du site. */
const AGENT_REST_POSE = 'L’extension « sumotori-dash-agent » sera téléchargée depuis '
  + 'wordpress.org, installée et activée sur le site, puis reliée à ce dashboard. Aucune '
  + 'donnée du site n’est transmise avant que la liaison soit établie.';

async function agentRest(s, installer) {
  const quoi = installer ? 'Installer l’agent Dash' : 'Retirer l’agent Dash';
  const msg = installer
    ? `Installer l’agent Dash sur <b>${H(s.domain)}</b> ?<br><br>${H(AGENT_REST_POSE)}`
    : `Retirer l’agent Dash de <b>${H(s.domain)}</b> ?<br><br>Le site cesse d’envoyer son `
      + 'inventaire et ses évènements, l’extension est désactivée puis supprimée, et le secret '
      + 'local est effacé.';
  if (!await askConfirm(msg, { titre: quoi, ok: installer ? 'Installer' : 'Retirer', danger: !installer })) return;
  const nid = NOTIF.start({ kind: 'connect', label: quoi + ' · ' + (kName(s) || s.domain), site: { srv: s.srv, domain: s.domain } });
  let j;
  // Deux routes écrites en toutes lettres : une URL construite par concaténation
  // échappe au croisement front ↔ backend de tools/check_front.py.
  try {
    j = installer
      ? await api('/api/mgmt/rest_agent_install', { domain: s.domain }) || {}
      : await api('/api/mgmt/rest_agent_remove', { domain: s.domain }) || {};
  } catch (e) { j = { ok: false, message: String(e) }; }
  const out = String(j.message ?? j.error ?? '').slice(-300);
  const code = j.ok && j.mode === 'code';
  NOTIF.done(nid, { ok: !!j.ok, message: code ? 'code d’appairage à coller sur le site' : out });
  if (code) { askInfo('Code d’appairage', codeAgentHtml(j, out)); return; }
  if (!j.ok) { askInfo(quoi + ' — échec', H(out || 'échec')); return; }
  loadFleet();
}

function codeAgentHtml(j, out) {
  const u = safeUrl(j.admin_url);
  const min = Math.max(1, Math.round(Number(j.expires_in || 0) / 60));
  return `${H(out)}<br><br><code>${H(String(j.code || ''))}</code> — valable ${min} min.`
    + (u ? `<br><br><a href="${H(u)}" target="_blank" rel="noopener noreferrer">Ouvrir `
      + 'l’écran de réglages du site</a>' : '');
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

/* ---- onglets --------------------------------------------------------------
   Ce sont de VRAIS onglets — un seul volet à la fois sur un même objet — donc
   le motif ARIA complet : `role="tablist"`, un `tab` par bouton lié à son
   `tabpanel`, un seul atteignable par tabulation (tabindex mobile), les
   flèches pour circuler. Sans ce motif, un lecteur d'écran annonce cinq
   boutons sans dire qu'ils commandent une même zone.

   En étroit, la liste défile horizontalement : c'est `initDebordement()` qui
   pose l'ombre de débordement quand il y a de quoi défiler. */
/* Pastille de l'onglet VizProof : l'état tient en un mot, et c'est celui qui
   décide si on a besoin d'ouvrir. Un site sans inventaire n'en porte aucune —
   « inconnu » sur un onglet n'apprend rien et fait du bruit. */
function vizPastilleOnglet(s) {
  const t = vizEtatTexte(s);
  if (!t || t.etat === 'nodata') return null;
  if (t.etat === 'connecte') {
    const g = vizGravite(s);
    return g ? { texte: g === 'err' ? 'cassé' : 'à voir', ton: g } : null;
  }
  return { texte: t.etat === 'absent' ? 'absent' : 'à faire', ton: 'warn' };
}

function ongletsNav() {
  const nav = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Sections du site' });
  ONGLETS.forEach(([slug, label, pastille]) => {
    const actif = slug === ONGLET;
    const b = h('button', {
      type: 'button', class: 'tab' + (actif ? ' active' : ''),
      role: 'tab', id: 'sitetab-' + slug, 'aria-controls': 'site-tab',
      'aria-selected': actif ? 'true' : 'false', tabindex: actif ? '0' : '-1',
    }, h('span', { text: label }));
    const p = (pastille && CUR) ? pastille(CUR) : null;
    /* Une pastille qui dit « à voir » sans dire pourquoi oblige à ouvrir pour
       le savoir. L'état complet tient dans l'infobulle — et il vaut la peine
       d'être là même sans pastille : « reliée · 3 pages · dernier scan il y a
       2 h » répond à la question avant qu'on la pose. */
    if (CUR && slug === 'vizproof') b.title = vizEtatTexte(CUR).long;
    // La pastille est décorative : son sens est déjà dans le libellé du volet,
    // et un lecteur d'écran qui annoncerait « VizProof 3 » ne dirait pas quoi.
    if (p) b.append(h('span', { class: 'tab-p ' + p.ton, 'aria-hidden': 'true', text: p.texte }));
    b.onclick = () => allerOnglet(slug);
    b.onkeydown = e => {
      const pas = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (pas) {
        e.preventDefault();
        const i = ONGLET_SLUGS.indexOf(slug);
        FOCUS_ONGLET = true;
        allerOnglet(ONGLET_SLUGS[(i + pas + ONGLET_SLUGS.length) % ONGLET_SLUGS.length]);
      } else if (e.key === 'Home') { e.preventDefault(); FOCUS_ONGLET = true; allerOnglet(ONGLET_SLUGS[0]); }
      else if (e.key === 'End') { e.preventDefault(); FOCUS_ONGLET = true; allerOnglet(ONGLET_SLUGS[ONGLET_SLUGS.length - 1]); }
    };
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
  else if (ONGLET === 'vizproof') mount(cible, ongletVizproof(s));
  else if (ONGLET === 'sauvegardes') { mount(cible, ongletSauvegardes(s)); bloquerRetablissementSansSsh(s); }
  else if (ONGLET === 'historique') mount(cible, ongletHistorique(s));
  else mount(cible, ongletApercu(s));
  renderPolicy();
  if (ONGLET === 'securite') renderVulnsListe();
  if (ONGLET === 'apercu' && s.via === 'rest') loadWpCred(s.srv, s.domain);
  if (ONGLET === 'securite') { chargerAdmins(); chargerChecksums(); chargerPhpErrors(); }
  if (ONGLET === 'historique') loadTimeline(s.srv, s.domain);
  if (ONGLET === 'vizproof') brancherViz();
}

/* ---- onglet VizProof ------------------------------------------------------
   VizProof répond à une question qu'aucun autre volet ne pose : est-ce que le
   site RESSEMBLE toujours à ce qu'il était ? Une mise à jour peut réussir,
   n'écrire aucune erreur dans les journaux, et casser une page.

   Le bloc d'état vient de components/viz.js — c'est le même que celui de la
   modale de liaison, et il traite déjà les cinq états (absent, inactif, trop
   ancienne, non reliée, reliée). Ce que le volet ajoute, c'est ce qui manquait :
   les deux actions de contrôle visuel, jusque-là enterrées dans le menu
   Actions, et une phrase qui dit à quoi tout cela sert. */
function ongletVizproof(s) {
  const blocs = [];
  const viz = vizBlocEl(s, { titre: false, compact: true });

  /* Site géré par l'agent : VizProof continue de scanner et d'archiver tout
     seul — c'est la LECTURE du détail qui manque ici, parce qu'elle passe par
     `wp vizproof report`, une commande wp-cli. Sans cette phrase, l'absence de
     tableau se lit comme un scan qui n'aurait pas eu lieu. */
  /* Avant la 1.3.12, une baseline ne promouvait que la première page : les
     autres comparaient à leur propre dernière capture, donc ne signalaient
     jamais rien. Le dire ici, avec le geste exact — mettre à jour PUIS refaire
     la baseline, l'ordre compte. */
  const bp = vizBaselinePartielle(s);
  const notéBaseline = bp
    ? h('div', { class: 'warnbox small mt2' }, iconEl('triangle-alert'), ' ',
      h('b', { text: 'Baseline incomplète' }),
      ' — l’extension est en ', h('code', { text: 'v' + bp.version }),
      ', et avant la ', h('code', { text: '1.3.12' }), ' une baseline ne couvrait que la '
      + 'première page. Les ' + (bp.pages - 1) + ' autre'
      + (bp.pages > 2 ? 's' : '') + ' comparent à leur propre dernière capture : elles ne '
      + 'signaleront jamais rien. Mettez l’extension à jour, ',
      h('b', { text: 'puis refaites la baseline' }), ' — dans cet ordre.')
    : null;

  const notéSansSsh = s.via === 'rest'
    ? h('p', { class: 'hint hint-loose' },
      h('b', { text: 'Site géré sans SSH' }),
      ' : VizProof surveille ce site et enregistre ses scans normalement, mais le '
      + 'dashboard ne peut pas en lire le détail — il passe par une commande wp-cli. '
      + 'L’état et la date ci-dessus viennent de l’agent ; le tableau des écarts se '
      + 'consulte dans VizProof ou dans wp-admin.')
    : null;

  blocs.push(h('section', { class: 'sitesec', id: 'site-vizbloc' },
    h('h3', { text: 'Contrôle visuel' }),
    notéSansSsh,
    notéBaseline,
    viz || h('p', { class: 'hint hint-tight',
      text: 'État inconnu : aucun inventaire d’extensions pour ce site.' })));

  const t = vizEtatTexte(s);
  const relie = t && t.etat === 'connecte';
  const rest = s.via === 'rest';

  /* Une extension trop ancienne pour être pilotée, alors que la mise à jour
     est disponible et à un clic dans l'onglet d'à côté : le volet doit porter
     ce clic. Sans ça, la phrase « mettez-la à jour » envoie chercher ailleurs
     un bouton qui existe déjà. */
  const majViz = (s.plugins_updates_list || []).find(x => x && x.name === 'vizproof-timeline');
  if (t && (t.etat === 'nocli' || t.etat === 'nonconnecte') && majViz && !rest) {
    const b = h('button', { type: 'button', class: 'btn primary' },
      iconEl('arrow-up'), 'Mettre à jour vizproof-timeline vers ' + (majViz.to || '?'));
    b.dataset.act = 'plugin_update';
    b.dataset.arg = 'vizproof-timeline';
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', { text: 'Débloquer' }),
      h('p', { class: 'hint hint-tight' },
        'La version installée (', h('code', { text: majViz.from || t.etat }),
        ') n’expose pas la commande que le dashboard utilise. La mise à jour vers ',
        h('b', { text: majViz.to || '?' }), ' suffit à rendre la liaison possible.'),
      h('div', { class: 'actions mt2' }, b)));
  }

  if (relie && !rest) {
    const base = h('button', { type: 'button', class: 'btn' }, iconEl('scan-eye'), 'Capturer une baseline');
    base.dataset.act = 'viz_baseline';
    const scan = h('button', { type: 'button', class: 'btn primary' }, iconEl('scan-eye'), 'Lancer un scan visuel');
    scan.dataset.act = 'viz_scan';
    blocs.push(h('section', { class: 'sitesec', id: 'site-vizact' },
      h('h3', { text: 'Contrôler maintenant' }),
      h('p', { class: 'hint hint-tight' },
        'La ', h('b', { text: 'baseline' }), ' fige l’apparence de référence ; le ',
        h('b', { text: 'scan' }), ' compare le rendu actuel à cette référence et signale ce qui a bougé. '
        + 'C’est ce que fait la MAJ sûre avant et après une mise à jour.'),
      h('div', { class: 'actions mt2' }, base, scan)));
  }

  blocs.push(h('section', { class: 'sitesec' },
    h('h3', { text: 'À quoi ça sert' }),
    h('p', { class: 'hint hint-loose' },
      'Les autres volets disent ce que le site ', h('b', { text: 'contient' }),
      ' — versions, failles, sauvegardes, erreurs PHP. Aucun ne dit ce qu’un visiteur ',
      h('b', { text: 'voit' }), '. Une mise à jour peut réussir sans une ligne d’erreur et '
      + 'vider une page de son contenu : c’est exactement ce que le contrôle visuel rattrape.')));

  return blocs;
}

/* Branchements du volet VizProof : les boutons `data-act` passent par la
   confirmation commune, et le résumé du dernier rapport arrive après coup —
   une requête en tâche de fond dont l'échec ne se voit pas. */
function brancherViz() {
  const s = CUR;
  if (!s) return;
  document.querySelectorAll('#site-tab [data-act]').forEach(b => { b.onclick = () => confirmRun(b); });
  const slot = document.querySelector('#site-tab .vzr-slot');
  if (slot) {
    // La requête passe par SSH jusqu'au site : plusieurs secondes, parfois.
    // Toutes les autres zones asynchrones de cette page disent « chargement… ».
    slot.innerHTML = '<span class="chargement small" role="status">'
      + icon('loader-circle', { size: 14, cls: 'ic-spin' })
      + '<span>lecture du dernier rapport sur le site…</span></span>';
    chargerVizRapport(s, slot, { replie: false, site: s })
      .catch(() => {})
      .finally(() => { if (slot.querySelector('.ic-spin')) slot.innerHTML = ''; });
  }
}

/* ---- onglet Aperçu -------------------------------------------------------- */
function ongletApercu(s) {
  const blocs = [];

  blocs.push(h('section', { class: 'sitesec', id: 'site-incidents' },
    h('h3', { text: 'À traiter sur ce site' }),
    incidentsEl()));

  if (s.via === 'rest') {
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', { text: 'Identifiants WordPress' }),
      h('div', { id: 'wpcred' }, attente()),
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
      /* Serveur, chemin, client, disponibilité et date de collecte vivent déjà
         dans l'en-tête, à trois centimètres au-dessus. Les répéter ici donnait
         une fiche dont cinq lignes sur huit n'apprenaient rien. Ne restent que
         les trois qui ne sont nulle part ailleurs. */
      h('span', { class: 'k', text: 'Administrateurs' }), adm)));

  const errs = Object.keys(s.errors || {});
  if (errs.length) {
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', { text: 'Erreurs de collecte' }),
      h('div', { class: 'errbox', text: Object.entries(s.errors).map(([k, v]) => k + ': ' + v).join('\n\n') })));
  }
  return blocs;
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
      hF ? h('span', { class: 'muted small', text: ' ' + hF }) : null,
      rF ? h('div', { class: 'muted small', text: 'puis ' + rF }) : null),
    h('span', { class: 'k', text: 'Base de données' }),
    h('span', {}, udIntervalFr(ud.interval_db), ' · ', h('b', { text: (ud.retain_db || '?') + ' jeux' }),
      hD ? h('span', { class: 'muted small', text: ' ' + hD }) : null,
      rD ? h('div', { class: 'muted small', text: 'puis ' + rD }) : null),
    h('span', { class: 'k', text: 'Destination' }), h('span', { text: ud.service || '?' }),
    h('span', { class: 'k', text: 'Dernière' }),
    h('span', {}, age === null ? h('span', { class: 'pill warn', text: 'jamais' })
      : h('span', { class: 'pill ' + (age >= seuilBackup() ? 'warn' : 'ok'), text: relTime(ud.last_backup_ts) })));
}

/* ---- incidents de ce site -------------------------------------------------- */
/* Ce qui attend sur ce site sans être un incident : des mises à jour
   disponibles. Elles ne remontent pas dans la file du parc — cinquante sites
   qui ont des mises à jour ne font pas cinquante urgences — mais écrire « rien
   à traiter » juste au-dessus d'un bouton « MAJ sûre — 6 ext. » était faux. */
function resteAFaire(s) {
  const out = [];
  const p = Number(s.plugins_updates) || 0;
  const t = Number(s.themes_updates) || 0;
  if (s.core_update) out.push(['WordPress ' + s.core_update + ' disponible', 'extensions']);
  if (p) out.push([p + ' extension' + (p > 1 ? 's' : '') + ' à mettre à jour', 'extensions']);
  if (t) out.push([t + ' thème' + (t > 1 ? 's' : '') + ' à mettre à jour', 'extensions']);
  const nv = (VULNS && Array.isArray(VULNS.findings)) ? VULNS.findings.length : 0;
  if (nv) out.push([nv + ' vulnérabilité' + (nv > 1 ? 's' : '') + ' connue' + (nv > 1 ? 's' : ''), 'securite']);
  return out;
}

function incidentsEl() {
  if (INCIDENTS === null) {
    return h('p', { class: 'hint hint-tight' }, attente('recherche des alertes de ce site…'));
  }
  if (!INCIDENTS.length) {
    const reste = resteAFaire(CUR || {});
    if (!reste.length) {
      return h('p', { class: 'hint hint-tight', text: 'Rien à traiter sur ce site.' });
    }
    const p = h('p', { class: 'hint hint-tight' },
      'Aucune alerte en attente. Ce site porte par ailleurs : ');
    reste.forEach(([txt, onglet], i) => {
      if (i) p.append(', ');
      p.append(h('a', { href: '#site/' + encodeURIComponent(CLE) + '/' + onglet, text: txt }));
    });
    p.append('.');
    return p;
  }
  const box = h('div', { class: 'inclist' });
  INCIDENTS.forEach(i => box.append(incidentLigne(i, false, chargerIncidents)));
  return box;
}

/* Une ligne d'incident, partagée avec l'écran Parc : trait de gravité, site,
   titre, détail court, ancienneté, action en ligne — et le pli qui donne le
   message entier, la pile d'appels, le « que faire » et « Ne plus signaler… »
   (components/incident.js, le même objet que sur l'écran Incidents).

   `recharger` : ce que l'écran appelant relit après un acquittement. Sans lui,
   le bouton « Ne plus signaler… » ne s'affiche pas — une ligne qu'on acquitte
   sans pouvoir la voir disparaître ne rassure personne. */
export function incidentLigne(inc, avecSite, recharger) {
  return incidentEl(inc, {
    siteEl: avecSite && inc.site ? h('b', { class: 'inc-s', text: inc.site }) : null,
    actions: incidentAction(inc, avecSite),
    onAck: recharger || null,
  });
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

/* Bouton d'action groupée pour l'en-tête d'une section. Ces gestes n'existaient
   que dans le menu « Actions », replié : pour mettre à jour toutes les
   extensions, il fallait savoir que le menu contenait cette ligne. Ils restent
   dans le menu — qui garde son rôle de liste exhaustive — et apparaissent ici,
   là où on regarde quand on veut les faire. */
/* Aucune commande wp-cli sur un site géré par l'agent : les boutons d'action
   étaient tous actifs SOUS la phrase qui annonce l'inverse. On les désactive
   plutôt que de les cacher — une ligne amputée de ses boutons ne dit pas
   pourquoi, un bouton grisé qui porte sa raison le dit. */
const SANS_SSH = "site géré sans SSH : à faire depuis wp-admin";
function siSansSsh(s, ...boutons) {
  if (s.via !== 'rest') return;
  boutons.filter(Boolean).forEach(b => { b.disabled = true; b.title = SANS_SSH; });
}

function boutonLot(s, act, libelle, titre) {
  const b = h('button', { type: 'button', class: 'btn sm fr', title: titre || '' }, iconEl('arrow-up'), libelle);
  b.dataset.act = act;
  b.onclick = () => confirmRun(b, libelle);
  return b;
}

/* ---- onglet Extensions et thèmes -------------------------------------------- */
/* `kind` : une extension et un thème peuvent porter le MÊME slug (twentyseven,
   par exemple). Sans lui, la pastille de vulnérabilité d'un thème se serait
   affichée sur l'extension du même nom. Les relevés antérieurs ne portent pas
   `kind` : on les rattache alors au composant demandé, comme avant. */
function cveChip(nom, kind) {
  if (!VULNS) return null;
  const g = (VULNS.findings || []).filter(v => v.component === nom && (!v.kind || v.kind === kind));
  if (!g.length) return null;
  let worst = '';
  g.forEach(v => { if ((SEVRANK[v.severity] || 0) > (SEVRANK[worst] || 0)) worst = v.severity; });
  /* La pastille disait « élevée » et rien d'autre : ni de quoi il s'agit, ni où
     le lire. Elle devient un LIEN vers la section qui le dit — celle-là seule
     porte le titre de la faille, sa description et son lien CVE — et son
     infobulle donne le titre, pas seulement un identifiant CVE que personne ne
     reconnaît. */
  const titres = g.map(v => v.title || v.cve).filter(Boolean);
  const el = h('a', {
    class: 'sevlink',
    href: '#site/' + encodeURIComponent(CLE) + '/securite',
    title: g.length + (g.length > 1 ? ' vulnérabilités connues' : ' vulnérabilité connue') + ' : '
      + titres.slice(0, 3).join(' · ') + (titres.length > 3 ? ` (+${titres.length - 3})` : '')
      + ' — cliquer pour le détail',
  });
  el.innerHTML = sevPill(worst);
  el.onclick = e => e.stopPropagation();
  return el;
}

/* `data-l` porte le libellé de colonne : en étroit, le tableau devient une
   liste empilée et chaque valeur reprend son libellé (voir screens.css). Sans
   lui, « 4.2.3 → 4.2.4 » se retrouverait seul sous un nom d'extension. */
function ligneExtension(s, p, maj) {
  const tr = h('tr', { dataset: { plug: p.name } },
    h('td', { 'data-l': 'Extension' }, h('b', { text: p.name }), cveChip(p.name, 'plugin')),
    h('td', { 'data-l': 'Version' },
      maj ? h('span', {}, p.version || '?', ' → ', h('b', { text: p.to || '?' })) : (p.version || '?'),
      p.status !== 'active' ? h('span', { class: 'pill mut', text: 'inactive' }) : null),
    h('td', { class: 'pcell' }));
  const cell = tr.lastElementChild;
  if (maj) {
    const b = h('button', { type: 'button', class: 'btn sm', title: 'Mise à jour immédiate, sans sauvegarde ni archive', text: 'MAJ' });
    b.dataset.act = 'plugin_update';
    b.dataset.arg = p.name;
    b.onclick = () => confirmRun(b);
    /* Le même geste, avec le filet : sauvegarde, archive de cette seule
       extension, contrôle visuel, et un point de rétablissement à la clé. */
    const sb = h('button', { type: 'button', class: 'btn sm psafe',
      title: 'Sauvegarde, archive cette extension, met à jour, contrôle le rendu — et laisse un point de rétablissement' },
      iconEl('shield-check'), 'sûre');
    sb.onclick = () => startSafeUpdate(s.srv, s.domain, sb, { slug: p.name });
    siSansSsh(s, b, sb);
    cell.append(b, sb);
  }
  const gel = h('button', {
    type: 'button', class: 'btn sm pfreeze',
    title: 'Ne plus jamais mettre à jour cette extension sur ce site', text: 'Geler',
  });
  gel.dataset.slug = p.name;
  gel.dataset.gtype = 'plugin';
  const reb = h('button', { type: 'button', class: 'btn sm prb', title: 'Revenir à une version antérieure' }, iconEl('rotate-ccw'), 'Rétablir');
  reb.dataset.slug = p.name;
  reb.onclick = () => askVersion(p.name, reb, { srv: s.srv, dom: s.domain }, () => loadFleet().then(refreshSite).catch(() => {}), 'plugin');
  siSansSsh(s, gel, reb);
  cell.append(gel, reb);
  return tr;
}

/* ---- thèmes ----------------------------------------------------------------
   Même modèle que les extensions : « à mettre à jour » d'abord, puis la liste
   complète repliée. Deux différences propres aux thèmes : un seul est ACTIF
   (et c'est celui dont une régression se voit tout de suite), et un thème
   enfant dépend d'un parent qu'il ne faut pas retirer. Les deux se lisent sur
   la ligne. */

/** Un thème est-il à mettre à jour ?

    Mêmes valeurs que côté collecteur (`has_update()` de collect.py) : wp-cli
    dit `"available"`, l'agent envoie un booléen. Un relevé qui ne porte que
    `update_version` — sans champ `update` du tout — est compris aussi. */
export function estMajTheme(t) {
  if (!t) return false;
  if (t.update !== undefined && t.update !== null) {
    return t.update === 'available' || t.update === true || t.update === 'true' || t.update === 1;
  }
  return !!t.update_version;
}

/** Nom lisible d'un thème, le slug servant de repli. */
export function nomTheme(t) { return (t && (t.title || t.name)) || ''; }

function ligneTheme(s, t, maj) {
  const cible = t.update_version || t.to || '?';
  /* `h()` ignore les enfants nuls, `Element.append()` non — il y écrirait le
     mot « null ». D'où la construction en une seule liste d'enfants. */
  const nom = h('td', { 'data-l': 'Thème' },
    h('b', { text: nomTheme(t) }),
    h('code', { class: 'small', text: t.name }),
    t.status === 'active' ? chipEl('actif', 'ok') : null,
    t.status === 'parent' ? chipEl('thème parent', 'mut', { title: 'utilisé par le thème enfant actif' }) : null,
    (t.status !== 'active' && t.status !== 'parent') ? h('span', { class: 'pill mut', text: 'inactif' }) : null,
    t.parent ? h('span', { class: 'muted small', text: 'enfant de ' + t.parent }) : null,
    cveChip(t.name, 'theme'));

  const tr = h('tr', { dataset: { thm: t.name } }, nom,
    h('td', { 'data-l': 'Version' },
      maj ? h('span', {}, t.version || '?', ' → ', h('b', { text: cible })) : (t.version || '?')),
    h('td', { class: 'pcell' }));
  const cell = tr.lastElementChild;
  if (maj) {
    const b = h('button', { type: 'button', class: 'btn sm', title: 'Mise à jour immédiate, sans sauvegarde ni archive', text: 'MAJ' });
    b.dataset.act = 'theme_update';
    b.dataset.arg = t.name;
    b.onclick = () => confirmRun(b);
    const sb = h('button', { type: 'button', class: 'btn sm psafe',
      title: 'Sauvegarde, archive ce thème, met à jour, contrôle le rendu — et laisse un point de rétablissement' },
      iconEl('shield-check'), 'sûre');
    sb.onclick = () => startSafeUpdate(s.srv, s.domain, sb, { theme: t.name });
    siSansSsh(s, b, sb);
    cell.append(b, sb);
  }
  const gel = h('button', {
    type: 'button', class: 'btn sm pfreeze',
    title: 'Ne plus jamais mettre à jour ce thème sur ce site', text: 'Geler',
  });
  gel.dataset.slug = t.name;
  gel.dataset.gtype = 'theme';
  const reb = h('button', { type: 'button', class: 'btn sm prb', title: 'Revenir à une version antérieure' }, iconEl('rotate-ccw'), 'Rétablir');
  reb.dataset.slug = t.name;
  reb.onclick = () => askVersion(t.name, reb, { srv: s.srv, dom: s.domain }, () => loadFleet().then(refreshSite).catch(() => {}), 'theme');
  siSansSsh(s, gel, reb);
  cell.append(gel, reb);
  return tr;
}

/* Un site sans SSH ne pousse qu'un COMPTEUR de thèmes : on le dit, plutôt que
   d'afficher une liste vide qui se lirait « ce site n'a pas de thème ». */
function sectionThemes(s) {
  const liste = Array.isArray(s.themes_list) ? s.themes_list.filter(t => t && t.name) : null;
  const nMaj = s.themes_updates || 0;
  if (!liste) {
    return h('section', { class: 'sitesec' },
      h('h3', { text: 'Thèmes' }),
      h('p', { class: 'hint hint-tight' },
        nMaj
          ? 'Ce site remonte ' + nMaj + ' thème(s) à mettre à jour, sans le détail : '
          : 'Ce site ne remonte aucun thème à mettre à jour, mais pas le détail non plus : ',
        "l'inventaire est poussé par l'agent, qui n'envoie qu'un compteur. ",
        'La liste des thèmes installés est à consulter dans wp-admin.'));
  }
  const aMaj = liste.filter(estMajTheme);
  const blocs = [h('section', { class: 'sitesec' },
    h('h3', {}, 'Thèmes à mettre à jour (' + aMaj.length + ')',
      aMaj.length && s.via !== 'rest'
        ? boutonLot(s, 'themes_update_all', 'Tout mettre à jour',
          'Met à jour les ' + aMaj.length + ' thèmes d’un coup, sans sauvegarde ni archive')
        : null),
    aMaj.length
      ? h('table', { class: 'ptable' }, h('tbody', {}, aMaj.map(t => ligneTheme(s, t, true))))
      : h('p', { class: 'hint hint-tight', text: 'Tous les thèmes sont à jour.' }))];

  if (liste.length) {
    const tbl = h('table', { class: 'ptable', hidden: true }, h('tbody', {}, liste.map(t => ligneTheme(s, t, estMajTheme(t)))));
    const bt = h('button', { type: 'button', class: 'btn sm fr', text: 'Afficher (' + liste.length + ')' });
    bt.onclick = () => {
      tbl.hidden = !tbl.hidden;
      bt.textContent = tbl.hidden ? 'Afficher (' + liste.length + ')' : 'Masquer';
      renderPolicy();
    };
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', {}, 'Tous les thèmes', bt),
      h('p', { class: 'hint' }, 'Repliée par défaut. ',
        h('span', { class: 'info', 'data-tip': "Les themes installes, actifs ou non, avec le theme actif et les liens parent/enfant. Utile pour retablir une version anterieure, ou pour verifier qu'un theme parent est toujours la.", text: '?' })),
      tbl));
  }
  return blocs;
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

  if (s.core_update && s.via !== 'rest') {
    /* Une mise à jour du CŒUR ne se voyait que dans le menu replié, alors
       qu'elle est la plus lourde de conséquences. Elle a sa ligne, avec les
       deux mêmes gestes que les extensions — et le même avertissement sur ce
       que le retour arrière ne rattrape pas. */
    const maj = h('button', { type: 'button', class: 'btn sm', title: 'Mise à jour immédiate, sans sauvegarde ni archive', text: 'MAJ' });
    maj.dataset.act = 'core_update';
    maj.onclick = () => confirmRun(maj);
    const sure = h('button', { type: 'button', class: 'btn sm primary',
      title: 'Sauvegarde, archive, met à jour le cœur, contrôle le rendu' },
      iconEl('shield-check'), 'sûre');
    sure.dataset.core = '1';
    sure.onclick = () => startSafeUpdate(s.srv, s.domain, sure, { core: true });
    blocs.push(h('section', { class: 'sitesec' },
      h('h3', { text: 'Cœur WordPress' }),
      h('p', { class: 'hint hint-tight' },
        'Version ', h('b', { text: s.core_version || '?' }), ' — ',
        h('b', { text: s.core_update }), ' disponible. Le retour arrière rétablit les '
        + 'fichiers, pas les migrations de base de données : la sauvegarde UpdraftPlus '
        + 'est le seul recours pour elle.'),
      h('div', { class: 'actions mt2' }, maj, sure)));
  }

  blocs.push(h('section', { class: 'sitesec' },
    h('h3', {}, 'À mettre à jour (' + aMaj.length + ')',
      aMaj.length && s.via !== 'rest'
        ? boutonLot(s, 'plugins_update_all', 'Tout mettre à jour',
          'Met à jour les ' + aMaj.length + ' extensions d’un coup, sans sauvegarde ni archive')
        : null),
    /* Le bouton « MAJ » de ces lignes lance un `wp plugin update` et rien
       d'autre : ni sauvegarde UpdraftPlus, ni archive des fichiers, donc aucun
       point de rétablissement. La « MAJ sûre » du haut fait les deux. Les deux
       boutons se ressemblent trop pour que la différence aille sans dire. */
    aMaj.length && s.via !== 'rest'
      ? h('p', { class: 'hint hint-tight' },
        h('b', { text: 'MAJ' }), ' met à jour tout de suite, ',
        h('b', { text: 'sans sauvegarde' }), ' — rien à rétablir si le site casse. ',
        h('b', { text: 'sûre' }), ' sauvegarde, archive ce seul composant, contrôle le rendu '
        + 'et laisse un point de rétablissement ; comptez une à deux minutes.')
      : null,
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

  blocs.push(sectionThemes(s));

  blocs.push(h('section', { class: 'sitesec', id: 'site-frozen', hidden: true },
    h('h3', { text: 'Extensions et thèmes gelés' }),
    h('p', { class: 'hint' }, 'Jamais mis à jour par le dashboard. ',
      h('span', { class: 'info', 'data-tip': 'Ni par un bouton, ni par une action groupee, ni par la MAJ sure. Utile quand une version casse le site, ou quand un client doit valider avant.', text: '?' })),
    h('div', { id: 'site-frozenlist', class: 'small' })));
  return blocs;
}

/* ---- politique par extension et par thème (gel) ----------------------------
   UN SEUL endroit connaît la forme du corps et de la réponse de
   /api/actions/policy : `gelerCible()` pour l'écriture, `lireGels()` pour la
   lecture, `gelsDeReponse()` pour la relecture. Si le backend décrit les
   thèmes autrement, c'est ici — et nulle part ailleurs — que ça se corrige.

   Le contrat, tel que le backend le sert :
     * écriture  : {server, domain, slug, kind: 'plugin'|'theme', frozen: bool}
     * lecture   : {frozen: [slugs d'extensions], frozen_themes: [slugs]}
   Le mot du protocole est `kind`, comme sur `plugin_rollback`,
   `plugin_versions` et le `kind` des vulnérabilités — d'où la traduction ici,
   à la frontière, plutôt qu'un `kind` promené dans tout l'écran.
   Deux autres formes de réponse restent acceptées sans rien changer d'autre :
   `frozen` en objet {plugins, themes}, ou `themes` au lieu de `frozen_themes`.

   La réponse d'une ÉCRITURE n'est utilisée que si elle est non ambiguë : le
   backend renvoie la liste du seul type modifié, sous le nom `frozen` dans les
   deux cas — croire cette liste sur parole afficherait les thèmes gelés parmi
   les extensions. Sans les deux listes, on relit. */
function gelsDeReponse(r) {
  const tab = x => (Array.isArray(x) ? x.map(String) : []);
  const f = r && r.frozen;
  if (f && !Array.isArray(f) && typeof f === 'object') {
    return { plugins: tab(f.plugins), themes: tab(f.themes) };
  }
  return { plugins: tab(f), themes: tab(r && (r.frozen_themes || r.themes)) };
}

function reponseComplete(r) {
  if (!r || typeof r !== 'object') return false;
  const f = r.frozen;
  if (f && !Array.isArray(f) && typeof f === 'object') return true;
  return Array.isArray(r.frozen_themes) || Array.isArray(r.themes);
}

async function gelerCible(site, type, slug, gele) {
  const r = await api('/api/actions/policy', {
    server: site.srv, domain: site.domain, slug, kind: type, frozen: gele,
  });
  return reponseComplete(r) ? gelsDeReponse(r) : lireGels(site.domain);
}

async function lireGels(dom) {
  return gelsDeReponse(await api('/api/actions/policy?domain=' + encodeURIComponent(dom)));
}

function gelesDe(type) { return type === 'theme' ? FROZEN_TH : FROZEN; }

/* Une ligne (extension ou thème) reflète le gel : bouton inversé, mise à jour
   hors service, ligne estompée. */
function refletGel(tr, slug, type) {
  const gel = gelesDe(type).includes(slug);
  const b = tr.querySelector('.pfreeze');
  const maj = tr.querySelector(type === 'theme' ? '[data-act="theme_update"]' : '[data-act="plugin_update"]');
  if (b) { b.textContent = gel ? 'Dégeler' : 'Geler'; b.classList.toggle('primary', gel); }
  // Le gel n'est pas la seule raison de griser : un site sans SSH n'exécute
  // rien. Sans ce `||`, cette fonction rallumait le bouton après coup.
  const sansSsh = CUR ? CUR.via === 'rest' : false;
  if (maj) maj.disabled = gel || sansSsh;
  /* La MAJ sûre saute elle aussi une extension gelée — le serveur l'écarte et
     le journalise. Laisser le bouton actif lancerait tout le cycle (sauvegarde,
     archive, contrôle) pour ne rien mettre à jour. */
  const sure = tr.querySelector('.psafe');
  if (sure) {
    sure.disabled = gel || sansSsh;
    if (gel) sure.title = 'Extension gelée : la mise à jour sûre l’écarterait aussi';
  }
  tr.classList.toggle('row-frozen', gel);
}

function renderPolicy() {
  const sec = document.getElementById('site-frozen'), list = document.getElementById('site-frozenlist');
  if (sec && list) {
    const tout = FROZEN.map(sl => ['plugin', sl]).concat(FROZEN_TH.map(sl => ['theme', sl]));
    sec.hidden = !tout.length;
    mount(list, tout.map(([type, sl]) => {
      const b = h('button', { type: 'button', class: 'btn sm pthaw', text: 'Dégeler' });
      b.dataset.slug = sl;
      b.dataset.gtype = type;
      return h('div', { class: 'vulnrow' },
        h('span', { class: 'pill warn', text: type === 'theme' ? 'thème gelé' : 'extension gelée' }),
        h('b', { text: sl }), b);
    }));
  }
  document.querySelectorAll('#site-tab [data-plug]').forEach(tr => refletGel(tr, tr.dataset.plug, 'plugin'));
  document.querySelectorAll('#site-tab [data-thm]').forEach(tr => refletGel(tr, tr.dataset.thm, 'theme'));
  document.querySelectorAll('#site-tab .pfreeze,#site-tab .pthaw').forEach(b => {
    b.onclick = async () => {
      const type = b.dataset.gtype === 'theme' ? 'theme' : 'plugin';
      const sl = b.dataset.slug, gel = !gelesDe(type).includes(sl);
      b.disabled = true;
      try {
        const g = await gelerCible(CUR, type, sl, gel);
        FROZEN = g.plugins;
        FROZEN_TH = g.themes;
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
      h('div', { id: 'site-admins', class: 'small' }, attente())),
    h('section', { class: 'sitesec' },
      h('h3', { text: 'Intégrité du cœur (checksums)' }),
      h('p', { class: 'hint' }, 'Lance ', h('code', { text: 'wp core verify-checksums' }), ' et compare au cœur officiel.'),
      h('div', { id: 'site-checksums', class: 'small' }, attente())),
    h('section', { class: 'sitesec' },
      h('h3', { text: 'Erreurs PHP' }),
      h('p', { class: 'hint', text: 'Lecture des journaux que le serveur écrit déjà, regroupées par message et par fichier.' }),
      h('div', { id: 'site-phperr', class: 'small' }, attente())),
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
      h('b', { text: g.component }), kindChip(g.kind),
      h('span', { class: 'muted small', text: g.version || '' }),
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
  // Même ligne dépliable que la section Erreurs PHP de Sécurité : le message
  // entier, la pile d'appels et le « que faire » sont à un clic, pas coupés.
  mount(box, h('div', { class: 'inclist' }, rec.groups.slice(0, 30).map(g => {
    const fatale = /Fatal|Parse/.test(String(g.severity || ''));
    return erreurPhpEl(g, [chipEl(g.severity || '?', fatale ? 'err' : 'warn'),
      chipEl('×' + (g.count ?? 1), 'mut')]);
  })));
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

/* Les pastilles de rétablissement sont cliquables : sans SSH, elles promettent
   ce qu'elles ne peuvent pas tenir. Elles se désactivent après coup, la liste
   étant construite par un composant partagé avec la modale. */
function bloquerRetablissementSansSsh(s) {
  if (!s || s.via !== 'rest') return;
  document.querySelectorAll('#site-rblist button, #site-rblist [role="button"]').forEach(b => {
    b.disabled = true;
    b.title = SANS_SSH;
    b.setAttribute('aria-disabled', 'true');
  });
}

/* ---- onglet Historique ------------------------------------------------------ */
const TLKIND = { action: 'actions', collect: 'collectes', event: 'événements' };
let TLGROUPS = [], TLSHOWN = 0, TLFILTRE = '';
const TLPAGE = 20;
let TLSEQ = 0;

/* Ce n'est PAS un `tablist` : ce sont des bascules de filtre sur une seule
   liste. Elles portent donc `aria-pressed`, pas `aria-selected`. */
function ongletHistorique() {
  const barre = h('div', { class: 'tabs', role: 'group', 'aria-label': "Filtrer l'historique" });
  [['', 'Tout'], ...Object.entries(TLKIND)].forEach(([k, lbl]) => {
    const b = h('button', {
      type: 'button', class: 'tab' + (TLFILTRE === k ? ' active' : ''),
      'aria-pressed': TLFILTRE === k ? 'true' : 'false', text: lbl,
    });
    b.onclick = () => { TLFILTRE = k; TLSHOWN = TLPAGE; dessinerOnglet(); };
    barre.append(b);
  });
  return h('section', { class: 'sitesec' },
    h('h3', { text: 'Historique du site' }), barre,
    h('div', { id: 'site-timeline' }, attente()));
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
/* Détail d'une ligne d'historique. Un ÉVÈNEMENT d'agent est du JSON brut : sa
   mise en phrase vit dans lib/format.js (`detailEvenement`), partagée avec
   l'écran Changements — cet écran en portait une copie jusqu'à la phase 5, et
   les deux avaient commencé à diverger. Le reste (action, collecte) n'est que
   de la sortie wp-cli à débruiter. */
function tlDetail(e) {
  const brut = e.detail;
  if (brut === null || brut === undefined || brut === '') return '';
  return e.kind === 'event' ? detailEvenement(e.label, brut) : stripPhpNoise(brut);
}

/* ---- chargements différés --------------------------------------------------- */
function chargerTout() {
  const s = CUR;
  if (!s) return;
  loadPolicy(s.srv, s.domain);
  loadRollbackPoints(s.srv, s.domain);
  loadSafeStatus(s.domain);
  loadVizUpStatus(s.srv, s.domain);
  // Site sans SSH : l'état de l'autorisation WordPress alimente la ligne
  // « WordPress : … » du menu d'actions, et décide d'Autoriser OU Révoquer.
  chargerWpEtat(s).catch(() => {});
  chargerVulns(kName(s) || s.domain);
  chargerIncidents();
  ensureSettings().then(() => { if (CUR === s) { const b = document.getElementById('site-band'); if (b) b.replaceWith(bandeau(s)); renderVulnsSite(); } }).catch(() => {});
}

async function loadPolicy(srv, dom) {
  const seq = PAGESEQ;
  let g = { plugins: [], themes: [] };
  try { g = await lireGels(dom); }
  catch (e) { g = { plugins: [], themes: [] }; }
  if (seq !== PAGESEQ) return;         // la page affiche un autre site : résultat périmé
  FROZEN = g.plugins;
  FROZEN_TH = g.themes;
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
      ${x.detail ? `<div class="muted small wrapline ml-8">${H(stripPhpNoise(x.detail))}</div>` : ''}
      ${x.report ? `<div class="ml-8">${vizReportHtml(x.report, { replie: true })}</div>` : ''}</div>`).join('');
  const bas = auBas(box);          // mesuré AVANT l'écriture, cf. lib/dom.js
  box.innerHTML = `<div class="mb-6"><b>${icon('shield-check')} Mise à jour sûre</b> ${stt.running ? '<span class="pill mut">en cours…</span>' : safeVerdictPill(stt.verdict)}</div>${lignes}`;
  collerEnBas(box, bas);
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

/* `cible` : `{slug}` pour une seule extension, `{theme}` pour un seul thème,
   rien pour tout ce qui attend. Le backend sait viser depuis toujours — c'est
   l'interface qui ne demandait jamais, et laissait donc le choix entre « une
   extension sans filet » et « tout le site avec filet ». */
async function startSafeUpdate(srv, dom, btn, cible) {
  const withCore = btn.dataset.core === '1';
  const un = cible && (cible.slug || cible.theme || (cible.core ? 'le cœur WordPress' : ''));
  await ensureSettings();
  let msg = un
    ? `Mise à jour sûre de <b>${H(un)}</b> sur <b>${H(dom)}</b> ?<br><br>Déroulé : sauvegarde UpdraftPlus → archivage de ${cible.theme ? 'ce thème' : 'cette extension'} → mise à jour → contrôle du site → retour arrière automatique si quelque chose casse.<br><br>Rien d'autre ne sera mis à jour.`
    : `Mise à jour sûre de <b>${H(dom)}</b> ?<br><br>Déroulé : sauvegarde UpdraftPlus → archivage de ce qui va changer → mise à jour → contrôle du site → retour arrière automatique si quelque chose casse.`;
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
  const corpsReq = { server: srv, domain: dom, backup: true, viz: true, core: withCore, viz_rollback: rep.rb };
  if (cible && cible.slug) { corpsReq.slugs = [cible.slug]; corpsReq.with_themes = false; }
  // Un seul thème : `slugs: []` ne dirait pas « aucune extension » (une liste
  // vide est fausse, donc indistincte de « toutes ») — d'où `with_plugins`.
  if (cible && cible.theme) { corpsReq.themes = [cible.theme]; corpsReq.with_plugins = false; }
  if (cible && cible.core) { corpsReq.core = true; corpsReq.with_plugins = false; corpsReq.with_themes = false; }
  try { r = await api('/api/actions/safe_update', corpsReq); }
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
  /* Le défilement suit les étapes qui arrivent, mais ne le fait PAS si l'on a
     remonté soi-même : sur un job de plusieurs minutes, relire l'étape d'avant
     est exactement ce qu'on vient faire. */
  const bas = auBas(box);
  box.innerHTML = `<div class="mb-6"><b>${icon('scan-eye')} Mise à jour sous contrôle visuel</b> ${tete}</div>`
    + ((job.steps || []).map(vizupLigne).join(''))
    + (v ? vizConsoleLigne(v) : '');
  collerEnBas(box, bas);
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
    /* « Terminée avec avertissement · anomalies détectées » disait deux fois la
       même chose, et laissait croire que la mise à jour elle-même avait mal
       tourné. Quand l'avertissement vient du contrôle visuel, on sépare les
       deux faits : la mise à jour est passée, et il y a quelque chose à
       regarder. */
    const visuel = f === 'warn' && v && v.anomalies;
    const verdict = visuel ? 'mise à jour appliquée' : vizupVerdict(job);
    NOTIF.done(nid, { ok: f !== 'err', warn: f === 'warn',
                      // Le clic mène là où se lit le verdict, pas à l'Aperçu.
                      onglet: v ? 'vizproof' : '',
                      message: verdict + (v ? ' · ' + vizPhraseLongue(v) : '') });
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
    const refus = { 96: 'extension ou thème gelé pour ce site', 97: 'site géré sans SSH : action impossible', 99: 'extension du site trop ancienne' }[Number(j.rc)];
    const verdict = j.ok ? `<b class="ok">${icon('circle-check')} OK</b>`
      : anom ? `<b class="warn">${icon('triangle-alert')} anomalies visuelles détectées</b>`
        : refus ? `<b class="warn">${icon('triangle-alert')} ${H(refus)}</b>`
          : `<b class="err">${icon('circle-x')} rc ${H(j.rc ?? '?')}</b>`;
    const v = (j.viz && typeof j.viz === 'object') ? j.viz : null;
    const c1 = consoleDe(s.domain);
    if (c1) {
      const bas = auBas(c1);
      c1.innerHTML = H(head + (j.output || '') + '\n\n') + verdict + (v ? '\n' + vizConsoleLigne(v) : '');
      collerEnBas(c1, bas);
    }
    if (v && v.pending) NOTIF.update(nid, { detail: 'contrôle visuel : ' + vizPhrase(v), progress: null });
    else {
      NOTIF.done(nid, {
        ok: !!(j.ok || anom), warn: anom || !!refus || (v ? vizEtat(v) === 'warn' : false),
        // Dès qu'un verdict visuel accompagne l'action, le clic sur la ligne
        // mène au volet qui le détaille — c'est la seule page qui répond.
        onglet: (v || anom) ? 'vizproof' : '',
        message: anom ? 'anomalies visuelles détectées'
          : refus || (j.ok ? (v ? 'contrôle visuel : ' + vizPhraseLongue(v) : '')
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
