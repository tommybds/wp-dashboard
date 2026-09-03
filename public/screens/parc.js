/* Écran Parc — la file « à traiter », les compteurs, la liste des sites et la
   barre d'actions groupées.

   Ordre de lecture voulu : ce qui demande une action arrive en premier (la
   file), puis l'état du parc en un coup d'œil (les compteurs), puis la liste
   complète. Le tiroir a disparu : une ligne mène à la page du site.

   Tout le rendu passe par `h()` : plus une seule chaîne HTML construite à
   partir d'une donnée distante. */

import { api } from '../lib/api.js';
import { esc as H, h, mount, activeAuClavier, occupe } from '../lib/dom.js';
import { debounce } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import {
  store, allSites, st, bkAge, attn, key, kName, loadFleet, phpEol, seuilBackup,
} from '../lib/state.js';

import { chipEl, libelleKuma, niveauKuma } from '../components/chip.js';
import { askInfo, askText, askChoice, askOpen } from '../components/confirm.js';
import { demarrerJob } from '../components/job.js';
import { NOTIF } from '../components/toast.js';
import { bindSortable, setDensity, colonnesMasquees, enregistrerColonnes } from '../components/table.js';
import { setIncidentCount } from '../components/shell.js';
import { ouvrirFeuille, boutonFeuille } from '../components/sheet.js';
import { openVizConnect, vizCellEl, vizInfo, vizOf, vizVal } from '../components/viz.js';
import { incidentLigne, cleDeSite } from './site.js';

/* ---- colonnes -------------------------------------------------------------
   `fixe` : Site et État ne se masquent pas — sans eux la liste ne dit plus de
   quoi elle parle. La préférence retient les colonnes MASQUÉES, pour qu'une
   colonne ajoutée plus tard apparaisse chez tout le monde. */
const COLS = [
  { k: 'domain', lbl: 'Site', fixe: true },
  { k: 'status', lbl: 'État', fixe: true },
  { k: 'core', lbl: 'WordPress' },
  { k: 'plugins', lbl: 'Extensions' },
  { k: 'themes', lbl: 'Thèmes' },
  { k: 'viz', lbl: 'VizProof' },
  { k: 'php', lbl: 'PHP' },
  { k: 'backup', lbl: 'Sauvegarde' },
  { k: 'vuln', lbl: 'Vulnérabilités' },
  { k: 'server', lbl: 'Serveur' },
  { k: 'err', lbl: 'Erreurs' },
];
const COLS_CLE = 'dashCols';
const COLS_DEFAUT_OFF = ['server', 'err'];
let MASQUEES = colonnesMasquees(COLS_CLE, COLS_DEFAUT_OFF);
const visibles = () => COLS.filter(c => c.fixe || !MASQUEES.has(c.k));

/* ---- file « à traiter » ---------------------------------------------------- */
let INCIDENTS = [], INCERR = [], INCLU = false;
const TODO_CLE = 'dashTodoOpen';
function todoOuvert() { try { return localStorage.getItem(TODO_CLE) !== '0'; } catch (e) { return true; } }
function todoMemo(v) { try { localStorage.setItem(TODO_CLE, v ? '1' : '0'); } catch (e) { /* stockage refusé */ } }

/* ---- vulnérabilités du parc ------------------------------------------------
   Le croisement complet pèse ~190 Ko : il est demandé UNE fois, en arrière-plan,
   et seulement si la colonne est affichée. La cellule dit « … » en attendant. */
let VMAP = null, VLOAD = false;
function vulnDe(s) {
  if (!VMAP) return null;
  return VMAP[kName(s) || s.domain] || VMAP[s.domain] || { count: 0, worst: '', fixcrit: false };
}
async function chargerVulns() {
  if (VLOAD || VMAP) return;
  VLOAD = true;
  try {
    const r = await api('/api/sec/vulns');
    const m = {};
    (r.sites || []).forEach(x => {
      m[x.domain] = {
        count: x.count || (x.findings || []).length,
        worst: x.worst || '',
        fixcrit: (x.findings || []).some(v => String(v.severity) === 'critical' && String(v.update_to || '').trim()),
      };
    });
    VMAP = m;
  } catch (e) { VMAP = {}; }
  VLOAD = false;
  render();
}

/* ---- squelette de l'écran --------------------------------------------------- */
let MONTE = false;

function monterParc() {
  if (MONTE) return;
  MONTE = true;
  mount('page-dash',
    h('section', { class: 'todo', id: 'parc-todo' }),
    h('div', { class: 'counters', id: 'parc-counters' }),
    barreFiltres(),
    h('div', { class: 'wrap', id: 'parc-wrap' },
      h('table', { id: 'tbl' }, h('thead', { id: 'thd' }), h('tbody', { id: 'tb' }))),
    // La même liste, en cartes : le CSS n'en montre qu'une des deux selon la
    // largeur. Les deux sont alimentées par `objetLigne()`.
    h('ul', { class: 'scards', id: 'parc-cards', 'aria-label': 'Sites du parc' }),
    barreGroupee());
  setDensity(store.filt.compact);
  // Les vues vivent dans localStorage : elles sont remplies dès que le
  // `<select>` existe, pas au démarrage (l'écran n'était pas encore monté).
  loadViews();
  renderTodo();
}

/* ---- barre de filtres -------------------------------------------------------- */
function barreFiltres() {
  const q = h('input', { type: 'search', id: 'q', placeholder: 'Filtrer un site, une extension…', 'aria-label': 'Filtrer un site, une extension' });
  q.value = store.filt.q || '';
  q.oninput = debounce(e => { store.filt.q = e.target.value; render(); }, 200);

  const fsrv = h('select', { id: 'fsrv', 'aria-label': 'Serveur' }, h('option', { value: '', text: 'Tous les serveurs' }));
  const fgrp = h('select', { id: 'fgrp', 'aria-label': 'Client' }, h('option', { value: '', text: 'Tous les clients' }));
  const fst = h('select', { id: 'fst', 'aria-label': 'Statut' },
    h('option', { value: '', text: 'Tous statuts' }),
    h('option', { value: 'up', text: 'En ligne' }),
    h('option', { value: 'down', text: 'Down' }),
    h('option', { value: 'none', text: 'Sans monitoring' }));
  fsrv.onchange = e => { store.filt.srv = e.target.value; render(); };
  fgrp.onchange = e => { store.filt.grp = e.target.value; render(); };
  fst.onchange = e => { store.filt.st = e.target.value; render(); };

  const coche = (id, cle, lbl) => {
    const c = h('input', { type: 'checkbox', id });
    c.checked = !!store.filt[cle];
    c.onchange = e => {
      store.filt[cle] = e.target.checked;
      if (cle === 'compact') setDensity(e.target.checked);
      render();
    };
    return h('label', { class: 'small' }, c, ' ' + lbl);
  };

  const views = h('select', { id: 'views', title: 'Vues sauvegardées', 'aria-label': 'Vues sauvegardées' });
  views.onchange = choisirVue;
  const saveview = h('button', { type: 'button', class: 'btn sm', id: 'saveview' }, iconEl('plus'), 'Vue');
  saveview.onclick = enregistrerVue;
  const csvbtn = h('button', { type: 'button', class: 'btn sm', id: 'csvbtn' }, iconEl('download'), 'CSV');
  csvbtn.onclick = exportCsv;

  /* Mode sélection : il n'a de sens qu'en cartes, où la case à cocher ne peut
     pas rester affichée en permanence. Le CSS ne le montre que sous 720 px. */
  const selmode = h('button', {
    type: 'button', class: 'btn sm selmode-btn', id: 'selmode', 'aria-pressed': 'false',
    title: 'Cocher plusieurs sites pour une action groupée (ou appui long sur une carte)',
  }, iconEl('list'), 'Sélection');
  selmode.onclick = () => setSelMode(!SELMODE);

  return h('div', { class: 'filters', id: 'parc-filters' },
    q, fsrv, fgrp, fst,
    coche('ftodo', 'todo', 'à traiter'),
    coche('fgroupby', 'groupby', 'grouper par client'),
    coche('fcompact', 'compact', 'compact'),
    h('span', { class: 'spacer' }),
    selmode, menuColonnes(), views, saveview, csvbtn);
}

/* Menu « Colonnes » : un `<details>` natif, donc ouverture au clavier et
   fermeture par Échap sans une ligne de JavaScript. */
function menuColonnes() {
  const panneau = h('div', { class: 'menu-p start' });
  COLS.filter(c => !c.fixe).forEach(c => {
    const cb = h('input', { type: 'checkbox', 'aria-label': 'Afficher la colonne ' + c.lbl });
    cb.checked = !MASQUEES.has(c.k);
    cb.onchange = () => {
      if (cb.checked) MASQUEES.delete(c.k); else MASQUEES.add(c.k);
      enregistrerColonnes(COLS_CLE, MASQUEES);
      if (c.k === 'vuln' && cb.checked) chargerVulns();
      render();
    };
    panneau.append(h('label', { class: 'menu-i' }, cb, h('span', { class: 'menu-l', text: c.lbl })));
  });
  const d = h('details', { class: 'menu' },
    h('summary', { class: 'btn sm' }, 'Colonnes', h('span', { class: 'caret' }, iconEl('chevron-right', { size: 14 }))),
    panneau);
  document.addEventListener('click', e => { if (d.open && d.isConnected && !d.contains(e.target)) d.open = false; });
  return d;
}

/* ---- barre d'actions groupées ------------------------------------------------
   Elle colle en bas de la LISTE (et non de la fenêtre) : elle appartient au
   tableau qu'elle commande. Les garde-fous (sauvegarde avant, contrôle visuel,
   arrêt sur erreur) sont posés dans la confirmation, au moment où on décide. */
const BULK = [
  {
    action: 'plugins_update_all', label: 'MAJ sûre', safe: true, ic: 'shield-check',
    title: 'Sauvegarde UpdraftPlus avant, mise à jour des extensions, contrôle visuel après',
  },
  { action: 'plugins_update_all', label: 'MAJ extensions', ic: 'arrow-up' },
  { action: 'core_update', label: 'MAJ cœur', ic: 'arrow-up' },
  { action: 'themes_update_all', label: 'Thèmes', ic: 'arrow-up' },
  { action: 'updraft_backup', label: 'Sauvegarde', ic: 'download' },
  { action: 'autoupdate_on', label: 'Auto-MAJ on', ic: 'check' },
  { action: 'autoupdate_off', label: 'Auto-MAJ off', ic: 'x' },
  { action: 'verify_checksums', label: 'Checksums', ic: 'shield-check' },
  { action: 'rescan', label: 'Re-scan', ic: 'refresh-cw' },
  { action: 'vizproof_install', label: 'Installer VizProof', ic: 'plus' },
  { action: 'dash_connect', label: 'Agent Dash : installer', ic: 'link' },
  { action: 'dash_disconnect', label: 'Agent Dash : dissocier', ic: 'x' },
];

/* Les actions groupées, décrites une fois : la barre du bureau en fait une
   rangée de boutons, le mobile une feuille de boutons pleine largeur. */
function actionsGroupees() {
  const out = BULK.map(b => ({
    label: b.label, ic: b.ic, kind: b.safe ? 'primary' : '', title: b.title || '',
    onSelect: () => lancerGroupe(b),
  }));
  out.push({
    label: 'Connecter VizProof…', ic: 'link', kind: '',
    title: 'Relier les sites sélectionnés à VizProof : un identifiant par site, un seul jeton de compte',
    onSelect: () => openVizConnect(selection()),
  });
  return out;
}

function barreGroupee() {
  const bar = h('div', { class: 'bulkbar', id: 'bulkbar' },
    h('b', { id: 'bulk-n', text: '0 sélectionné' }));

  const desk = h('span', { class: 'bulkbar-desk actions' });
  actionsGroupees().forEach(a => {
    const el = h('button', {
      type: 'button', class: 'btn sm' + (a.kind ? ' ' + a.kind : ''), title: a.title,
    }, a.ic ? iconEl(a.ic) : null, a.label);
    el.onclick = () => a.onSelect();
    desk.append(el);
  });

  // Mobile : un seul bouton, qui ouvre la feuille. Douze boutons n'entrent pas
  // sur 360 px, et une barre qui déborde n'est pas une barre.
  const mob = h('button', {
    type: 'button', class: 'btn sm primary bulkbar-mob', id: 'bulk-actions',
  }, iconEl('list'), 'Actions…');
  mob.onclick = () => {
    const n = store.sel.size;
    ouvrirFeuille({
      titre: n + ' site' + (n > 1 ? 's' : '') + ' sélectionné' + (n > 1 ? 's' : ''),
      contenu: () => actionsGroupees().map(a => boutonFeuille(a)),
    });
  };

  const clr = h('button', { type: 'button', class: 'btn sm', id: 'bulk-clear', text: 'Tout désélectionner' });
  clr.onclick = () => { if (SELMODE) setSelMode(false); else { store.sel.clear(); render(); } };
  bar.append(desk, mob, clr);
  return bar;
}

function selection() { return allSites().filter(s => store.sel.has(key(s))); }

function bulkBar() {
  const n = store.sel.size;
  const lbl = document.getElementById('bulk-n');
  if (lbl) lbl.textContent = n + ' site' + (n > 1 ? 's' : '') + ' sélectionné' + (n > 1 ? 's' : '');
  const bar = document.getElementById('bulkbar');
  if (bar) bar.classList.toggle('open', n > 0);
}

async function lancerGroupe(def) {
  const sites = selection();
  if (!sites.length) { askInfo('Aucun site sélectionné', 'Cochez au moins un site dans la liste.'); return; }
  const rest = sites.filter(s => s.via === 'rest' && def.action !== 'rescan');
  const corps = `<label class="fld"><input type="checkbox" id="bk-backup" checked${def.safe ? ' disabled' : ''}>
      Sauvegarde UpdraftPlus avant chaque mise à jour</label>
    <label class="fld"><input type="checkbox" id="bk-viz"${def.safe ? ' checked disabled' : ''}>
      Contrôle visuel VizProof après l'action</label>
    <label class="fld"><input type="checkbox" id="bk-stop"> Arrêter la série à la première erreur</label>
    ${def.safe ? `<p class="hint hint-loose">La « MAJ sûre » groupée impose la sauvegarde et le contrôle visuel.
      Elle n'archive PAS les fichiers et n'annule PAS automatiquement : ce filet-là est propre à la MAJ sûre
      d'un seul site, depuis sa page.</p>` : ''}
    ${rest.length ? `<p class="hint hint-loose">${rest.length} site(s) de la sélection sont gérés <b>sans SSH</b> :
      l'action y sera refusée (rc 97), les autres se dérouleront normalement.</p>` : ''}`;
  const rep = await new Promise(res => {
    askOpen(def.label,
      `Exécuter <b>${H(def.label)}</b> sur <b>${sites.length}</b> site${sites.length > 1 ? 's' : ''} ?`,
      corps,
      () => res({
        go: true,
        backup: document.getElementById('bk-backup').checked,
        viz: document.getElementById('bk-viz').checked,
        stop: document.getElementById('bk-stop').checked,
      }),
      () => res({ go: false }));
    const b = document.getElementById('ask-ok');
    b.textContent = 'Exécuter';
  });
  if (!rep.go) return;
  const tasks = sites.map(s => ({ server: s.srv, domain: s.domain, action: def.action, arg: null }));
  let r;
  try {
    r = await api('/api/actions/bulk', {
      tasks, mode: rep.stop ? 'stop' : 'continue',
      backup_first: def.safe ? true : rep.backup,
      viz_verify: def.safe ? true : rep.viz,
    });
  } catch (e) { r = { error: String(e) }; }
  // Sans ce `else`, une réponse 400 du backend (action refusée, cible invalide)
  // ne produisait strictement rien à l'écran.
  if (r && r.job) demarrerJob(r.job, 'Exécution en masse', def.label + ' · ' + sites.length + ' site' + (sites.length > 1 ? 's' : ''));
  else askInfo('Action groupée impossible', (r && r.error) ? H(r.error) : "Le serveur n'a pas renvoyé de tâche.");
}

/* ---- file « à traiter » ------------------------------------------------------ */
export async function chargerIncidents() {
  occupe('todo-list', true);
  let j = null;
  try { j = await api('/api/incidents'); } catch (e) { j = null; }
  INCIDENTS = (j && Array.isArray(j.incidents)) ? j.incidents : [];
  INCERR = (j && Array.isArray(j.errors)) ? j.errors : (j ? [] : [{ source: 'réseau', error: 'file indisponible' }]);
  INCLU = true;
  // La pastille « Incidents » de la barre latérale dit exactement ce que
  // montre la file : une seule source, pas deux comptes qui divergent.
  const crit = INCIDENTS.filter(i => i.severity === 'critical').length;
  setIncidentCount(INCIDENTS.length, crit ? 'err' : 'warn');
  renderTodo();
  occupe('todo-list', false);
}

function renderTodo() {
  const box = document.getElementById('parc-todo');
  if (!box) return;
  const ouvert = todoOuvert();
  const n = INCIDENTS.length;
  const crit = INCIDENTS.filter(i => i.severity === 'critical').length;

  const bt = h('button', {
    type: 'button', class: 'todo-h', 'aria-expanded': ouvert ? 'true' : 'false', 'aria-controls': 'todo-list',
  },
    h('span', { class: 'todo-chev' + (ouvert ? ' open' : '') }, iconEl('chevron-right', { size: 14 })),
    h('span', { class: 'glbl', text: 'À traiter' }),
    n ? h('span', { class: 'chip ' + (crit ? 'err' : 'warn') }, h('span', { class: 'pt' }), String(n)) : null,
    crit ? h('span', { class: 'muted small', text: crit + ' critique' + (crit > 1 ? 's' : '') }) : null);

  const liste = h('div', { class: 'inclist', id: 'todo-list', hidden: !ouvert });
  if (!INCLU) liste.append(h('p', { class: 'hint hint-tight', text: 'analyse en cours…' }));
  else if (!n) liste.append(h('p', { class: 'hint hint-tight', text: 'Rien à traiter — le parc est en ordre.' }));
  else INCIDENTS.forEach(i => liste.append(incidentLigne(i, true)));
  INCERR.forEach(e => liste.append(h('p', { class: 'hint hint-tight' },
    h('span', { class: 'pill warn', text: 'source incomplète' }), ' ',
    h('span', { class: 'muted small', text: (e.source || '?') + ' : ' + (e.error || '') }))));

  bt.onclick = () => {
    const o = liste.hidden;
    liste.hidden = !o;
    bt.setAttribute('aria-expanded', o ? 'true' : 'false');
    bt.querySelector('.todo-chev').classList.toggle('open', o);
    todoMemo(o);
  };
  mount(box, bt, liste);
}

/* ---- compteurs cliquables ---------------------------------------------------- */
function compteurs() {
  const box = document.getElementById('parc-counters');
  if (!box) return;
  const S = allSites();
  let up = 0, down = 0;
  S.forEach(s => { const v = st(s); if (v === 1) up++; else if (v === 0) down++; });
  const seuil = seuilBackup();
  const core = S.filter(s => s.core_update).length;
  const plug = S.reduce((a, s) => a + (s.plugins_updates || 0), 0);
  const bk = S.filter(s => s.updraft && (bkAge(s) === null || bkAge(s) > seuil)).length;
  const err = S.filter(s => Object.keys(s.errors || {}).length).length;
  const defs = [
    ['', 'sites', S.length, ''],
    ['up', 'en ligne', up, 'ok'],
    ['down', 'down', down, down ? 'err' : 'ok'],
    ['core', 'MAJ cœur', core, core ? 'warn' : 'ok'],
    ['plug', 'MAJ extensions', plug, plug ? 'warn' : 'ok'],
    ['bk', 'sauvegarde > ' + seuil + ' h', bk, bk ? 'warn' : 'ok'],
    ['err', 'en erreur', err, err ? 'err' : 'ok'],
  ];
  mount(box, defs.map(([k, l, v, c]) => {
    const on = !!k && store.filt.card === k;
    const b = h('button', {
      type: 'button', class: 'cnt' + (c ? ' v-' + c : '') + (on ? ' sel' : ''),
      'aria-pressed': on ? 'true' : 'false',
      title: k ? 'Filtrer la liste sur « ' + l + ' »' : 'Tous les sites suivis',
    }, h('b', { text: String(v) }), h('small', { text: l }));
    b.dataset.card = k;
    b.onclick = () => { store.filt.card = (store.filt.card === k) ? '' : k; render(); };
    return b;
  }));
}

/* ---- filtrage et tri ---------------------------------------------------------- */
function rowVals(s) {
  const v = st(s), age = bkAge(s), vu = vulnDe(s);
  return {
    status: v === undefined ? 2.5 : v, domain: kName(s) || s.domain, server: s.srv || '',
    core: s.core_version || '', plugins: s.plugins_updates || 0, themes: s.themes_updates || 0,
    viz: vizVal(s), php: s.php_version || '',
    backup: age === null ? (s.updraft ? 9e9 : -1) : age,
    vuln: vu ? vu.count : -1,
    err: Object.keys(s.errors || {}).length,
  };
}

function filtered() {
  let S = allSites();
  const q = store.filt.q.toLowerCase();
  if (q) S = S.filter(s => (s._q || '').includes(q));
  if (store.filt.srv) S = S.filter(s => s.srv === store.filt.srv);
  if (store.filt.grp) S = S.filter(s => s.kuma_group === store.filt.grp);
  if (store.filt.st) {
    S = S.filter(s => { const v = st(s); return store.filt.st === 'up' ? v === 1 : store.filt.st === 'down' ? v === 0 : v === undefined; });
  }
  if (store.filt.todo) S = S.filter(attn);
  const seuil = seuilBackup();
  const cm = {
    core: s => s.core_update, plug: s => s.plugins_updates,
    bk: s => s.updraft && (bkAge(s) === null || bkAge(s) > seuil),
    err: s => Object.keys(s.errors || {}).length,
    down: s => st(s) === 0, up: s => st(s) === 1,
  };
  if (cm[store.filt.card]) S = S.filter(cm[store.filt.card]);
  S.sort((a, b) => {
    const va = rowVals(a)[store.sort.k], vb = rowVals(b)[store.sort.k];
    return (typeof va === 'string' ? va.localeCompare(vb) : va - vb) * store.sort.dir;
  });
  return S;
}

/* ---- l'objet de ligne -----------------------------------------------------------
   Le tableau du bureau et la carte du mobile lisent le MÊME objet : ils ne
   peuvent donc pas dire deux choses différentes du même site. Il ne porte que
   ce qui s'affiche — libellés et niveaux déjà décidés —, pas de logique. */
function objetLigne(s) {
  const cle = kName(s) || s.domain;
  const age = bkAge(s), seuil = seuilBackup();
  const v = st(s);
  const nMaj = (s.plugins_updates || 0) + (s.core_update ? 1 : 0) + (s.themes_updates || 0);
  const bk = !s.updraft ? ['aucune', 'warn']
    : age === null ? ['jamais', 'warn']
      : age >= seuil ? ['il y a ' + (age / 24).toFixed(1) + ' j', 'warn']
        : ['il y a ' + Math.round(age) + ' h', 'ok'];
  const sous = [
    s.kuma_group || '',
    cle !== s.domain ? s.domain : '',
    (s.blogname && s.blogname !== cle) ? s.blogname : '',
  ].filter(Boolean).join(' · ');
  return {
    site: s, cle, label: cle, sous,
    etat: { txt: libelleKuma(v), niv: niveauKuma(v) },
    stale: !!s._stale,
    maj: { n: nMaj, txt: nMaj ? String(nMaj) : 'à jour', niv: nMaj ? 'warn' : '' },
    backup: { txt: bk[0], niv: bk[1] === 'ok' ? '' : 'warn' },
    selKey: key(s),
    coche: store.sel.has(key(s)),
  };
}

/* ---- cellules ------------------------------------------------------------------ */
function celluleSite(s) {
  const label = kName(s) || s.domain;
  const td = h('td', { class: 'site' }, h('b', { text: label }));
  const rs = h('button', { type: 'button', class: 'rowscan', title: 'Re-scanner ce site maintenant', 'aria-label': 'Re-scanner ce site' },
    iconEl('refresh-cw', { size: 14 }));
  rs.dataset.rowscan = '1';
  rs.dataset.key = s.srv + '|' + s.domain;
  rs.onclick = e => { e.stopPropagation(); rowRescan(rs, s.srv, s.domain); };
  rs.onkeydown = e => e.stopPropagation();
  td.append(rs);
  const sub = h('div', { class: 'sub' });
  if (label !== s.domain) sub.append(h('span', { text: s.domain }));
  if (s.blogname && s.blogname !== label) {
    sub.append(h('span', { class: 'muted', text: (sub.children.length ? ' · ' : '') + s.blogname }));
  }
  if (sub.children.length) td.append(sub);
  return td;
}

function celluleEtat(s) {
  const v = st(s);
  const td = h('td', {}, chipEl(libelleKuma(v), niveauKuma(v)));
  if (s._stale) {
    td.append(' ', chipEl('ancien', 'warn', {
      tip: 'données du ' + (s._srvAt || 'dernière collecte réussie') + ', serveur ' + (s.srv || '')
        + ' injoignable' + (s._srvErr ? ' : ' + s._srvErr : ''),
    }));
  }
  return td;
}

function celluleCore(s) {
  if (!s.core_version) return h('td', {}, chipEl('—', 'mut'));
  const txt = s.core_update ? s.core_version + ' → ' + s.core_update : s.core_version;
  return h('td', {}, chipEl(txt, s.core_update ? 'warn' : 'ok'));
}

function cellulePlugins(s) {
  if (s.plugins_total == null) return h('td', {}, chipEl('—', 'mut'));
  const td = h('td', {}, h('span', { class: 'num', text: s.plugins_active + '/' + s.plugins_total }), ' ');
  td.append(s.plugins_updates ? chipEl(s.plugins_updates + ' MAJ', 'warn') : chipEl('ok', 'ok'));
  return td;
}

function celluleBackup(s) {
  const age = bkAge(s), seuil = seuilBackup();
  if (!s.updraft) return h('td', {}, chipEl('aucune', 'warn', { title: 'UpdraftPlus non détecté sur ce site' }));
  if (age === null) return h('td', {}, chipEl('jamais', 'warn'));
  const txt = age >= seuil ? 'il y a ' + (age / 24).toFixed(1) + ' j' : 'il y a ' + Math.round(age) + ' h';
  const ud = s.updraft;
  return h('td', {
    title: 'fichiers : ' + (ud.interval || '?') + ' × ' + (ud.retain || '?') + ' jeux · base : '
      + (ud.interval_db || '?') + ' × ' + (ud.retain_db || '?') + ' jeux',
  }, chipEl(txt, age >= seuil ? 'warn' : 'ok'));
}

function celluleVuln(s) {
  const v = vulnDe(s);
  if (!v) return h('td', {}, h('span', { class: 'muted small', text: '…' }));
  if (!v.count) return h('td', {}, chipEl('0', 'ok'));
  return h('td', {}, chipEl(String(v.count), v.fixcrit ? 'err' : 'warn', {
    title: v.fixcrit ? 'au moins une vulnérabilité critique corrigeable par une mise à jour'
      : 'vulnérabilités connues — gravité maximale : ' + (v.worst || '?'),
  }));
}

const CELLULE = {
  domain: celluleSite,
  status: celluleEtat,
  core: celluleCore,
  plugins: cellulePlugins,
  themes: s => h('td', {}, s.themes_updates ? chipEl(String(s.themes_updates), 'warn') : chipEl('—', 'mut')),
  viz: s => h('td', { class: 'vizcell' }, vizCellEl(s)),
  php: s => h('td', {}, phpEol(s.php_version)
    ? chipEl(s.php_version || '?', 'warn', { title: 'branche PHP hors support' })
    : h('span', { class: 'sub', text: s.php_version || '?' })),
  backup: celluleBackup,
  vuln: celluleVuln,
  server: s => h('td', {}, s.via === 'rest'
    ? h('span', { class: 'pill mut', title: "inventaire via l'agent, sans SSH" + (s.srv ? ' · ' + s.srv : ''), text: 'REST' })
    : h('span', { class: 'pill mut', text: s.srv || '—' })),
  err: s => {
    const n = Object.keys(s.errors || {}).length;
    return h('td', {}, n ? chipEl(String(n), 'err', { title: Object.keys(s.errors).join(', ') }) : null);
  },
};

/* ---- rendu du tableau ---------------------------------------------------------- */
function rowEl(s) {
  const label = kName(s) || s.domain;
  const tr = h('tr', { tabindex: '0', role: 'button', 'aria-label': 'Ouvrir la page de ' + label });
  tr.dataset.d = s.domain;
  tr.dataset.s = s.srv;
  const cb = h('input', { type: 'checkbox', class: 'rowchk', 'aria-label': 'Sélectionner ' + label });
  cb.checked = store.sel.has(key(s));
  cb.onclick = e => {
    e.stopPropagation();
    if (e.target.checked) store.sel.add(key(s)); else store.sel.delete(key(s));
    bulkBar();
  };
  tr.append(h('td', {}, cb));
  visibles().forEach(c => tr.append(CELLULE[c.k](s)));
  const ouvrir = () => { location.hash = '#site/' + encodeURIComponent(cleDeSite(s)); };
  tr.onclick = ouvrir;
  // La case à cocher garde sa touche Espace : on ne prend que la ligne elle-même.
  tr.onkeydown = e => { if (e.target !== tr) return; activeAuClavier(e, ouvrir); };
  return tr;
}

/* ---- carte (mobile) --------------------------------------------------------------
   Même objet de ligne que le tableau, réduit à ce qui tient sur 320 px : nom et
   client, chip d'état, deux chiffres clés, VizProof en chip.

   La case à cocher ne s'affiche qu'en MODE SÉLECTION — sinon elle vole la
   moitié des touches destinées à ouvrir le site. On y entre par le bouton
   « Sélection » de la barre de filtres, ou par un APPUI LONG sur une carte. */
const APPUI_LONG = 500;

function carteEl(o) {
  const li = h('li', { class: 'scard' + (o.coche ? ' sel' : '') });
  const cb = h('input', { type: 'checkbox', 'aria-label': 'Sélectionner ' + o.label });
  cb.checked = o.coche;
  cb.onclick = e => e.stopPropagation();
  cb.onchange = e => {
    if (e.target.checked) store.sel.add(o.selKey); else store.sel.delete(o.selKey);
    li.classList.toggle('sel', e.target.checked);
    bulkBar();
  };

  const chiffre = (lbl, val, niv) => h('span', {},
    h('span', { class: 'scard-kl', text: lbl }),
    h('span', { class: 'scard-kv' + (niv ? ' ' + niv : ''), text: val }));

  const main = h('button', { type: 'button', class: 'scard-main' },
    h('span', { class: 'scard-h' },
      h('span', { class: 'scard-n', text: o.label }),
      chipEl(o.etat.txt, o.etat.niv),
      o.stale ? chipEl('ancien', 'warn') : null),
    o.sous ? h('span', { class: 'scard-sub', text: o.sous }) : null,
    h('span', { class: 'scard-k' },
      chiffre('MAJ', o.maj.txt, o.maj.niv),
      chiffre('Sauvegarde', o.backup.txt, o.backup.niv)),
    h('span', { class: 'scard-viz' }, vizCellEl(o.site)));

  main.onclick = () => {
    if (SELMODE) { cb.checked = !cb.checked; cb.onchange({ target: cb }); return; }
    location.hash = '#site/' + encodeURIComponent(o.cle);
  };
  // Appui long : on entre en mode sélection et la carte touchée est cochée.
  let t = null;
  const armer = () => { t = setTimeout(() => { t = null; setSelMode(true, o.selKey); }, APPUI_LONG); };
  const desarmer = () => { if (t) { clearTimeout(t); t = null; } };
  main.addEventListener('touchstart', armer, { passive: true });
  ['touchend', 'touchmove', 'touchcancel'].forEach(x => main.addEventListener(x, desarmer, { passive: true }));

  li.append(h('span', { class: 'scard-chk' }, cb), main);
  return li;
}

/* Mode sélection : explicite (bouton) ou déclenché par un appui long. */
let SELMODE = false;

function setSelMode(on, cleAcocher) {
  SELMODE = !!on;
  if (!SELMODE) store.sel.clear();
  else if (cleAcocher) store.sel.add(cleAcocher);
  const b = document.getElementById('selmode');
  if (b) {
    b.setAttribute('aria-pressed', SELMODE ? 'true' : 'false');
    b.classList.toggle('primary', SELMODE);
  }
  const l = document.getElementById('parc-cards');
  if (l) l.classList.toggle('selmode', SELMODE);
  render();
}

function renderHead() {
  const cols = visibles();
  const selall = h('input', { type: 'checkbox', id: 'selall', title: 'tout sélectionner', 'aria-label': 'Tout sélectionner' });
  selall.onclick = e => {
    filtered().forEach(s => { if (e.target.checked) store.sel.add(key(s)); else store.sel.delete(key(s)); });
    render();
  };
  const tr = h('tr', {}, h('th', { class: 'col-chk' }, selall));
  cols.forEach(c => {
    const th = h('th', { text: c.lbl });
    th.dataset.k = c.k;
    tr.append(th);
  });
  mount('thd', tr);
  bindSortable('#tbl', { get: () => store.sort, set: v => { store.sort = v; }, onChange: render });
  return cols.length + 1;
}

function render() {
  if (!store.fleet) return;
  monterParc();
  compteurs();
  const nbCols = renderHead();
  const S = filtered();
  const corps = [];
  if (!S.length) {
    corps.push(h('tr', { class: 'grouprow' }, h('td', { colspan: String(nbCols) },
      h('span', { class: 'muted', text: allSites().length ? 'Aucun site ne correspond aux filtres.' : 'Aucun site dans le parc.' }))));
  } else if (store.filt.groupby) {
    const by = {};
    S.forEach(s => { const g = s.kuma_group || '— autres —'; (by[g] = by[g] || []).push(s); });
    Object.keys(by).sort().forEach(g => {
      corps.push(h('tr', { class: 'grouprow' }, h('td', { colspan: String(nbCols), text: g + ' · ' + by[g].length })));
      by[g].forEach(s => corps.push(rowEl(s)));
    });
  } else S.forEach(s => corps.push(rowEl(s)));
  mount('tb', corps);
  // La liste de cartes suit exactement le même filtrage et le même tri.
  const cartes = document.getElementById('parc-cards');
  if (cartes) {
    cartes.classList.toggle('selmode', SELMODE);
    mount(cartes, S.length
      ? S.map(s => carteEl(objetLigne(s)))
      : h('li', { class: 'scard-vide', text: allSites().length ? 'Aucun site ne correspond aux filtres.' : 'Aucun site dans le parc.' }));
  }
  bulkBar();
  if (!MASQUEES.has('vuln') && !VMAP) chargerVulns();
}

/* Après un re-rendu, le nœud d'origine n'existe plus : on retrouve le bouton de
   la même ligne par sa clé serveur|domaine. */
function rowscanFor(k) { return document.querySelector(`#tb [data-rowscan][data-key="${CSS.escape(k)}"]`); }

/* Re-scan d'un seul site depuis sa ligne, sans quitter la liste. `loadFleet()`
   redessine le tableau et DÉTRUIT le bouton : le verdict était posé sur un nœud
   déjà remplacé, donc invisible. On re-cible par data-key après le rendu, et on
   laisse l'état 2,5 s. */
async function rowRescan(btn, srv, dom) {
  if (btn.dataset.busy) return;
  const cle = srv + '|' + dom;
  btn.dataset.busy = '1';
  mount(btn, iconEl('loader-circle', { size: 14, spin: true, label: 're-scan en cours' }));
  const nid = NOTIF.start({ id: 'rescan:' + cle, label: 'Re-scan · ' + dom, kind: 'rescan', site: { srv, domain: dom } });
  let ok = false, titre = 'erreur réseau';
  try {
    const j = await api('/api/actions/run', { server: srv, domain: dom, action: 'rescan' });
    ok = !!(j && j.ok);
    titre = ok ? 'site re-scanné' : ('échec : ' + ((j && (j.output || j.error)) || '').slice(0, 120));
    if (ok) await loadFleet();
  } catch (e) { ok = false; titre = 'erreur réseau'; }
  NOTIF.done(nid, { ok, message: ok ? '' : titre });
  const b2 = rowscanFor(cle) || btn;
  b2.dataset.busy = '1';
  mount(b2, iconEl(ok ? 'check' : 'x', { size: 14, label: titre }));
  b2.title = titre;
  setTimeout(() => {
    const b3 = rowscanFor(cle) || b2;
    mount(b3, iconEl('refresh-cw', { size: 14, label: 'Re-scanner ce site' }));
    b3.title = 'Re-scanner ce site maintenant';
    delete b3.dataset.busy;
    delete b2.dataset.busy;
  }, 2500);
}

/* ---- export CSV ---------------------------------------------------------------- */
function exportCsv() {
  const S = filtered();
  const rows = [['site', 'serveur', 'client', 'wordpress', 'maj_core', 'plugins_actifs', 'plugins_total',
    'maj_plugins', 'maj_themes', 'vizproof', 'php', 'backup_h', 'statut', 'vulnerabilites', 'erreurs']];
  S.forEach(s => {
    const v = st(s), age = bkAge(s), vu = vulnDe(s);
    rows.push([kName(s) || s.domain, s.srv, s.kuma_group || '', s.core_version || '', s.core_update || '',
      s.plugins_active ?? '', s.plugins_total ?? '', s.plugins_updates ?? '', s.themes_updates ?? '',
      vizInfo(s)?.version || vizOf(s)?.version || '', s.php_version || '',
      age === null ? '' : Math.round(age), v === 1 ? 'up' : v === 0 ? 'down' : '?',
      vu ? vu.count : '', Object.keys(s.errors || {}).join(';')]);
  });
  const csv = rows.map(r => r.map(x => `"${String(x).replace(/"/g, '""')}"`).join(',')).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'parc-wordpress.csv';
  a.click();
}

/* ---- vues sauvegardées ---------------------------------------------------------
   Une vue mémorise les filtres, le tri ET les colonnes affichées : sans les
   colonnes, deux vues différentes retombaient sur la même mise en page. */
function vuesLues() {
  try { return JSON.parse(localStorage.dashViews || '{}'); } catch (e) { return {}; }
}
function vuesEcrites(v) {
  try { localStorage.dashViews = JSON.stringify(v); } catch (e) { /* stockage refusé */ }
}

export function loadViews() {
  const v = vuesLues();
  const sel = document.getElementById('views');
  if (!sel) return;
  const avant = sel.value;
  mount(sel,
    h('option', { value: '', text: 'Vues…' }),
    Object.keys(v).map(n => h('option', { value: n, text: n })),
    Object.keys(v).length ? h('option', { value: '__del', text: 'Supprimer une vue…' }) : null);
  if (avant && v[avant]) sel.value = avant;
}

async function enregistrerVue() {
  const n = await askText('Enregistrer la vue', 'Elle mémorise les filtres, le tri et les colonnes affichées.', '');
  if (!n) return;
  const v = vuesLues();
  v[n] = { FILT: { ...store.filt, card: '' }, SORT: store.sort, columns: [...MASQUEES] };
  vuesEcrites(v);
  loadViews();
  const sel = document.getElementById('views');
  if (sel) sel.value = n;
}

function choisirVue(e) {
  const nom = e.target.value;
  const v = vuesLues();
  if (nom === '__del') {
    (async () => {
      const noms = Object.keys(v);
      const n = await askChoice('Supprimer une vue', 'Choisissez la vue à supprimer.', noms.map(x => ({ value: x, label: x })));
      if (n && v[n]) { delete v[n]; vuesEcrites(v); }
      const sel = document.getElementById('views');
      if (sel) sel.value = '';
      loadViews();
    })();
    return;
  }
  const vue = v[nom];
  if (!vue) return;
  Object.assign(store.filt, vue.FILT);
  store.sort = vue.SORT || store.sort;
  if (Array.isArray(vue.columns)) {
    MASQUEES = new Set(vue.columns.map(String));
    enregistrerColonnes(COLS_CLE, MASQUEES);
  }
  setDensity(store.filt.compact);
  // La barre est reconstruite : cases des filtres ET du menu Colonnes à jour.
  const f = document.getElementById('parc-filters');
  if (f) f.replaceWith(barreFiltres());
  remplirSelects();
  loadViews();
  const sel = document.getElementById('views');
  if (sel) sel.value = nom;
  render();
}

function remplirSelects() {
  const sel = document.getElementById('fsrv');
  if (sel) {
    const avant = store.filt.srv;
    mount(sel, h('option', { value: '', text: 'Tous les serveurs' }),
      (store.fleet?.servers || []).map(s => h('option', { value: s.name, text: s.name })));
    sel.value = avant;
  }
  const g = document.getElementById('fgrp');
  if (g) {
    const avant = store.filt.grp;
    const grps = [...new Set(allSites().map(s => s.kuma_group).filter(Boolean))].sort();
    mount(g, h('option', { value: '', text: 'Tous les clients' }),
      grps.map(x => h('option', { value: x, text: x })));
    g.value = avant;
  }
}

/* ---- ponts avec la coque --------------------------------------------------------
   Le tableau se redessine quand la flotte ou le statut Kuma changent : c'est
   l'abonnement au store qui déclenche, plus un appel depuis le chargeur. */
export function onFleetChange() {
  if (!store.fleet) return;
  monterParc();
  remplirSelects();
  render();
}

/** Filtre la liste sur une extension (depuis la recherche globale). */
export function filtrerSurExtension(nom) {
  store.filt.q = String(nom || '');
  store.filt.card = '';
  const q = document.getElementById('q');
  if (q) q.value = store.filt.q;
  render();
}
