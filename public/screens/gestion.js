/* Écran Gestion — « comment le parc est-il branché ? »

   Phase 4 : les six sous-onglets ont disparu. La destination est UNE page,
   ouverte par un sommaire d'ancres chiffré, puis les sections dans l'ordre du
   branchement :

     1. Serveurs             (formulaires structurés, plus d'éditeur JSON)
     2. Installs découverts  (visibilité, alias, moniteur, agent, identifiants)
     3. Sites sans SSH       (assistant d'ajout par URL + liste des sites REST)
     4. Moniteurs Kuma       (pause, réactivation, suppression)
     5. Docroots             (chemins scannés en plus des motifs du serveur)
     6. Non gérés            (supervisés dans Kuma mais absents du parc)

   Les anciens fragments continuent de fonctionner : #gestion/serveurs,
   #mgmt/installs, #gestion/mode-rest… font défiler jusqu'à la section — la
   correspondance vit dans app.js.

   L'ÉDITEUR JSON des serveurs reste accessible en repli (« éditer le JSON ») :
   un serveur peut porter une clé que le formulaire ne connaît pas, et on ne
   veut pas d'un écran qui perde une donnée qu'il ne sait pas afficher. */

import { api } from '../lib/api.js';
import { esc as H, h, mount, occupe, zoneMessage } from '../lib/dom.js';
import { relTime, absTime, safeUrl, hostOf, debounce } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { store, kName, loadFleet, loadStatus, cacheFrais, cacheVider } from '../lib/state.js';
import { askConfirm, askInfo, askChoice, registerModalCloser } from '../components/confirm.js';
import { confirm2, setBusy, setIdle } from '../components/button.js';
import { chipEl } from '../components/chip.js';
import { vizOf, vizInfo } from '../components/viz.js';
import { WPAUTH_ENABLED, WPAUTH_HELP, wpAuthorize, wpCredentials } from '../components/wpauth.js';
import { openAdd, setAddHooks, restList, restDomain } from '../components/add-site.js';
import { confirmRun } from './site.js';

/* ---- état du module -------------------------------------------------------- */
let MONTE = false;
let KEYS = null;                 // /api/mgmt/sshkeys : choix de clé d'un serveur
let RESTSITES = [];              // dernière liste REST connue
let CANDIDATS = [];
const CRED = new Map();          // domaine → état des identifiants WordPress (cache d'écran)

const pluriel = (n, sing, plur) => n + ' ' + (n > 1 ? (plur || sing + 's') : sing);

/* ============================================================================
   Squelette : sommaire + six sections. Monté une seule fois ; ensuite seul le
   CONTENU de chaque section est redessiné.
   ========================================================================== */
const ANCRES = [
  ['mgmt-serveurs', 'serveurs', 'Serveurs'],
  ['mgmt-installs', 'installs', 'Installs découverts'],
  ['mgmt-rest', 'mode-rest', 'Sites sans SSH'],
  ['mgmt-moniteurs', 'moniteurs', 'Moniteurs Kuma'],
  ['mgmt-docroots', 'docroots', 'Docroots'],
  ['mgmt-nongeres', 'sites-non-geres', 'Non gérés'],
];

function sectionEl(id, titre, tete, ...corps) {
  return h('section', { class: 'section secsec', id },
    h('div', { class: 'sechead' }, h('h2', { text: titre }), tete),
    ...corps);
}

function monterMgmt() {
  if (MONTE) return;
  MONTE = true;
  mount('page-mgmt',
    h('nav', { class: 'anchors', id: 'mgmt-somm', 'aria-label': 'Sections de la page Gestion' }),
    sectionServeurs(),
    sectionInstalls(),
    sectionRest(),
    sectionMoniteurs(),
    sectionDocroots(),
    sectionCandidats());
  majSommaire();
}

function compteursSommaire() {
  const m = store.mgmt || {};
  const installs = toutesInstalls().length;
  const stale = (store.fleet?.servers || []).filter(x => x && x.stale).length;
  const sansMon = toutesInstalls().filter(s => !kName(s)).length;
  return {
    'mgmt-serveurs': [(m.servers || []).length, stale ? 'err' : 'mut'],
    'mgmt-installs': [installs, sansMon ? 'warn' : 'mut'],
    'mgmt-rest': [RESTSITES.length, 'mut'],
    'mgmt-moniteurs': [(m.kuma_monitors || []).filter(x => x && x.parent).length, 'mut'],
    'mgmt-docroots': [(m.extra_docroots || []).length, 'mut'],
    'mgmt-nongeres': [CANDIDATS.length, CANDIDATS.length ? 'warn' : 'ok'],
  };
}

function majSommaire() {
  const box = document.getElementById('mgmt-somm');
  if (!box) return;
  const c = compteursSommaire();
  mount(box, ANCRES.map(([id, slug, lbl]) => {
    const n = c[id];
    return h('a', { class: 'anchor', href: '#gestion/' + slug },
      h('span', { text: lbl }),
      n && n[0] ? chipEl(String(n[0]), n[1]) : null);
  }));
}

/** Toutes les installs découvertes, masquées comprises (ce n'est pas le parc). */
function toutesInstalls() {
  const out = [];
  (store.fleet?.servers || []).forEach(s => (s.sites || []).forEach(x => out.push({ srv: s.name, ...x })));
  return out;
}

/* ============================================================================
   1. Serveurs — formulaires structurés
   ========================================================================== */

/* Miroir EXACT de validate_server() côté serveur (actions_server.py). Le
   backend reste la seule autorité : ces règles ne servent qu'à dire l'erreur
   AVANT l'aller-retour, et à la placer sur le bon champ. Si l'une des deux
   change, c'est le message du backend qui s'affiche — cf. erreurBackend(). */
const RE_NOM = /^[a-z0-9][a-z0-9-]{0,39}$/;
const RE_HOTE = /^[A-Za-z0-9.:-]+$/;
const RE_USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const RE_CHEMIN = /^\/[A-Za-z0-9_./*@-]+$/;
const SSH_DIR = '/root/.ssh';

/** Champs du formulaire, dans l'ordre d'affichage. */
const CHAMPS = ['name', 'host', 'port', 'user', 'key', 'patterns', 'parallel', 'priority'];

function entier(v) {
  const s = String(v ?? '').trim();
  if (!/^-?\d+$/.test(s)) return null;
  return parseInt(s, 10);
}

/** validerServeur(obj) → { champ: message } (vide si tout passe). */
function validerServeur(o) {
  const e = {};
  if (!RE_NOM.test(String(o.name || ''))) {
    e.name = 'Nom obligatoire : minuscules, chiffres et tirets, 40 caractères au plus, '
      + 'commençant par une lettre ou un chiffre.';
  }
  const hote = String(o.host || '');
  if (!RE_HOTE.test(hote) || hote.startsWith('-') || hote.includes('..')) {
    e.host = 'Hôte obligatoire : nom de domaine, IPv4 ou IPv6 (lettres, chiffres, « . », « : » et « - »), '
      + 'sans « .. » ni tiret initial.';
  }
  const port = entier(o.port);
  if (port === null || port < 1 || port > 65535) e.port = 'Port attendu entre 1 et 65535.';
  if (o.user && !RE_USER.test(String(o.user))) {
    e.user = 'Utilisateur SSH invalide : minuscules, chiffres, « _ » et « - », 32 caractères au plus, '
      + 'ne commençant pas par un chiffre.';
  }
  if (o.key && !(String(o.key).startsWith(SSH_DIR + '/') && !String(o.key).includes('..'))) {
    e.key = 'Clé SSH invalide : un fichier existant sous ' + SSH_DIR + '.';
  }
  const pats = Array.isArray(o.patterns) ? o.patterns : [];
  if (!pats.length) e.patterns = 'Au moins un motif de docroot (un par ligne).';
  else {
    const mauvais = pats.find(p => !RE_CHEMIN.test(String(p)) || String(p).includes('..'));
    if (mauvais !== undefined) {
      e.patterns = 'Motif invalide : « ' + String(mauvais).slice(0, 60) + ' ». Chemin absolu, '
        + 'caractères A-Z a-z 0-9 _ . / * @ - , sans « .. ».';
    }
  }
  if (o.parallel !== null && o.parallel !== undefined && o.parallel !== '') {
    const n = entier(o.parallel);
    if (n === null || n < 1 || n > 16) e.parallel = 'Parallélisme attendu entre 1 et 16.';
  }
  if (o.priority !== null && o.priority !== undefined && o.priority !== '') {
    if (entier(o.priority) === null) e.priority = 'Priorité attendue : un entier (3 = production, 1 = ancien).';
  }
  return e;
}

/* Message d'erreur du backend → champ concerné. Les messages nomment le
   serveur (« utilisateur ssh invalide pour « x » ») : on ne pose l'erreur sur
   un champ que si c'est bien le serveur en cours d'édition. */
const MAP_ERR = [
  [/^nom de serveur invalide/i, 'name'],
  [/^h[oô]te invalide/i, 'host'],
  [/^utilisateur ssh invalide/i, 'user'],
  [/^port invalide/i, 'port'],
  [/^cl[ée] ssh invalide/i, 'key'],
  [/^patterns manquants/i, 'patterns'],
  [/^chemin invalide/i, 'patterns'],
  [/^parallel invalide/i, 'parallel'],
  [/^priority invalide/i, 'priority'],
];

/** erreurBackend(message, nomEdite) → {champ, message} ou {champ:null, message}. */
function erreurBackend(msg, nomEdite) {
  const m = String(msg || '');
  const hit = MAP_ERR.find(([rx]) => rx.test(m));
  if (!hit) return { champ: null, message: m };
  // « … pour « nom » » / « nom de serveur invalide : « nom » »
  const nom = (/«\s*([^»]*?)\s*»/.exec(m) || [])[1];
  if (hit[1] !== 'name' && nom && nomEdite && nom !== nomEdite) return { champ: null, message: m };
  return { champ: hit[1], message: m };
}

/* ---- fabrique de champ -----------------------------------------------------
   Un champ = un libellé, un contrôle, une aide, et une place pour son erreur.
   `.field.error` colore la bordure ET affiche le message : la couleur seule ne
   dirait rien à qui ne la voit pas. */
function champ({ id, label, aide, type = 'text', value = '', options = null, placeholder = '', rows = 0, attrs = {} }) {
  let ctrl;
  if (options) {
    ctrl = h('select', { id, 'aria-describedby': id + '-a', ...attrs },
      options.map(o => h('option', { value: o.value, text: o.label, selected: o.value === value })));
    ctrl.value = value;
  } else if (rows) {
    ctrl = h('textarea', { id, class: 'code short', rows: String(rows), placeholder, 'aria-describedby': id + '-a', ...attrs });
    ctrl.value = value;
  } else {
    ctrl = h('input', { id, class: 'inp w100', type, placeholder, 'aria-describedby': id + '-a', ...attrs });
    ctrl.value = value;
  }
  const err = h('div', { class: 'ferr', id: id + '-e', role: 'alert' });
  const wrap = h('div', { class: 'field' },
    h('label', { for: id, text: label }),
    ctrl,
    aide ? h('div', { class: 'aide', id: id + '-a', text: aide }) : null,
    err);
  return {
    wrap,
    ctrl,
    valeur: () => (rows ? ctrl.value : String(ctrl.value ?? '').trim()),
    erreur(msg) {
      wrap.classList.toggle('error', !!msg);
      err.textContent = msg || '';
    },
  };
}

/* ---- table des serveurs ----------------------------------------------------- */
function sectionServeurs() {
  const ajout = h('button', { type: 'button', class: 'btn sm primary', id: 'srv-add' },
    iconEl('plus'), ' Ajouter un serveur');
  ajout.onclick = () => ouvrirFormServeur(null);
  const json = h('button', {
    type: 'button', class: 'btn sm', id: 'srv-jsonbtn', text: 'éditer le JSON',
    title: 'Repli : le fichier servers.json tel quel, pour une clé que le formulaire ne connaît pas',
  });
  json.onclick = ouvrirJsonServeurs;
  return sectionEl('mgmt-serveurs', 'Serveurs',
    [h('span', { class: 'small', id: 'srv-sum' }), h('span', { class: 'spacer' }), json, ajout],
    h('p', { class: 'hint' },
      'Les serveurs SSH que le collecteur interroge. Les valeurs partent en arguments de ',
      h('code', { text: 'ssh' }), ' et, pour les motifs, dans un shell distant : elles sont validées '
      + 'à la saisie et de nouveau côté serveur. Un serveur ',
      h('b', { text: 'injoignable' }), ' garde les chiffres de la collecte précédente.'),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', { text: 'Serveur' }), h('th', { text: 'Hôte' }), h('th', { text: 'Port' }),
          h('th', { text: 'Utilisateur' }), h('th', { text: 'Clé' }),
          h('th', { text: 'Prio.' }), h('th', { text: 'Parall.' }),
          h('th', { text: 'Motifs de docroot' }), h('th', { text: 'Installs' }),
          h('th', { text: 'Dernier relevé' }),
          h('th', {}, h('span', { class: 'sr-only', text: 'Actions' })))),
        h('tbody', { id: 'srv-tb' }))));
}

/** Nom lisible d'une clé (le chemin complet mange la colonne). */
function nomCle(chemin) {
  if (!chemin) return '';
  const k = (KEYS && KEYS.keys || []).find(x => x.path === chemin);
  return k ? k.name : String(chemin).replace(/^.*\//, '');
}

function renderServeurs() {
  const tb = document.getElementById('srv-tb');
  if (!tb) return;
  if (!store.mgmt) {
    mount(tb, h('tr', {}, h('td', { colspan: '11' },
      chipEl('état indisponible', 'err'), ' ',
      h('span', { class: 'muted small', text: 'la liste des serveurs vient de /api/mgmt/state.' }))));
    mount('srv-sum');
    return;
  }
  const servers = store.mgmt.servers || [];
  const parNom = {};
  (store.fleet?.servers || []).forEach(s => { parNom[s.name] = s; });

  mount(tb, servers.length ? servers.map(s => {
    const f = parNom[s.name];
    const nSites = f ? (f.sites || []).length : null;
    const stale = !!(f && f.stale);
    const releve = stale
      ? chipEl('injoignable', 'err', { title: (f.error || '') + (f.last_attempt ? ' — essai du ' + f.last_attempt : '') })
      : f
        ? h('span', { class: 'muted small', title: absTime(store.fleet?.generated_at), text: relTime(store.fleet?.generated_at) })
        : chipEl('jamais relevé', 'mut', { title: 'aucun relevé dans fleet.json : lancez une collecte' });

    const mod = h('button', { type: 'button', class: 'btn sm', text: 'Modifier' });
    mod.onclick = () => ouvrirFormServeur(s);
    const sup = h('button', { type: 'button', class: 'btn sm danger', text: 'Retirer' });
    sup.onclick = () => supprimerServeur(s);

    return h('tr', {},
      h('td', {}, h('b', { text: s.name || '—' }),
        s.no_su ? h('div', { class: 'sub', text: 'sans su (mutualisé)' }) : null),
      h('td', { class: 'muted', text: s.host || '' }),
      h('td', { class: 'num', text: String(s.port ?? '') }),
      h('td', { class: 'muted', text: s.user || 'root' }),
      h('td', { class: 'muted', title: s.key || 'clé par défaut du dashboard', text: nomCle(s.key) || '(défaut)' }),
      h('td', { class: 'num', text: s.priority === undefined || s.priority === null ? '2' : String(s.priority) }),
      h('td', { class: 'num', text: s.parallel === undefined || s.parallel === null ? '4' : String(s.parallel) }),
      h('td', {}, h('div', { class: 'sub', title: (s.patterns || []).join('\n'), text: (s.patterns || []).join(' · ') })),
      h('td', { class: 'num', text: nSites === null ? '—' : String(nSites) }),
      h('td', {}, releve),
      h('td', {}, mod, ' ', sup));
  }) : h('tr', {}, h('td', { colspan: '11' },
    h('span', { class: 'muted small', text: 'aucun serveur déclaré — « Ajouter un serveur ».' }))));

  const stale = (store.fleet?.servers || []).filter(x => x && x.stale).length;
  mount('srv-sum', servers.length
    ? chipEl(pluriel(servers.length, 'serveur') + (stale ? ' · ' + pluriel(stale, 'injoignable') : ''),
      stale ? 'err' : 'ok')
    : chipEl('aucun serveur', 'mut'));
}

/* ---- modale-formulaire ------------------------------------------------------ */
let FORM = null;      // { champs: {…}, origine: serveur édité ou null }

function optionsCles(courante) {
  const opts = [{ value: '', label: '(clé par défaut du dashboard)' }];
  (KEYS && KEYS.keys || []).forEach(k => opts.push({ value: k.path, label: k.name + ' — ' + k.path }));
  if (courante && !opts.some(o => o.value === courante)) {
    opts.push({ value: courante, label: courante + ' (déclarée, absente de la liste)' });
  }
  return opts;
}

function ouvrirFormServeur(srv) {
  const neuf = !srv;
  const o = srv || {};
  const champs = {
    name: champ({
      id: 'srvf-name', label: 'Nom', value: o.name || '',
      aide: 'Identifiant court, unique. Minuscules, chiffres et tirets (40 max). Il sert de clé partout ailleurs.',
      attrs: neuf ? {} : { readonly: true },
    }),
    host: champ({
      id: 'srvf-host', label: 'Hôte', value: o.host || '', placeholder: '203.0.113.10',
      aide: 'Nom de domaine, IPv4 ou IPv6.',
    }),
    port: champ({
      id: 'srvf-port', label: 'Port SSH', type: 'number', value: String(o.port ?? 22),
      aide: 'Entre 1 et 65535. 22 en général, 10022 sur un Plesk.',
    }),
    user: champ({
      id: 'srvf-user', label: 'Utilisateur SSH', value: o.user || '', placeholder: 'root',
      aide: 'Vide = root. Sur un mutualisé, le login SSH de l’hébergeur.',
    }),
    key: champ({
      id: 'srvf-key', label: 'Clé SSH', value: o.key || '', options: optionsCles(o.key),
      aide: 'Clé propre à ce serveur. Vide = la clé générale du dashboard. Les clés se gèrent dans Réglages → Clés SSH.',
    }),
    patterns: champ({
      id: 'srvf-patterns', label: 'Motifs de docroot', rows: 4,
      value: (o.patterns || []).join('\n'), placeholder: '/var/www/vhosts/*/httpdocs',
      aide: 'Un motif par ligne. Chemin absolu, « * » autorisé. Le collecteur y cherche les wp-load.php.',
    }),
    parallel: champ({
      id: 'srvf-parallel', label: 'Parallélisme', type: 'number',
      value: o.parallel === undefined || o.parallel === null ? '' : String(o.parallel),
      aide: 'Sites collectés simultanément (1 à 16). Vide = 4.',
    }),
    priority: champ({
      id: 'srvf-priority', label: 'Priorité', type: 'number',
      value: o.priority === undefined || o.priority === null ? '' : String(o.priority),
      aide: 'Départage un domaine trouvé sur deux serveurs. Vide = 2 ; 3 sur la production, 1 sur l’ancien.',
    }),
  };
  const nosu = h('input', { type: 'checkbox', id: 'srvf-nosu' });
  nosu.checked = !!o.no_su;
  FORM = { champs, nosu, origine: srv };

  document.getElementById('srvm-title').textContent = neuf ? 'Ajouter un serveur' : 'Modifier « ' + o.name + ' »';
  mount('srvm-intro', neuf
    ? 'Le serveur est enregistré dans servers.json. La prochaine collecte l’interroge.'
    : 'Le nom ne se modifie pas ici : il sert de clé aux overrides, aux docroots et au journal.');
  mount('srvm-body',
    h('div', { class: 'fieldrow' }, champs.name.wrap, champs.host.wrap),
    h('div', { class: 'fieldrow' }, champs.port.wrap, champs.user.wrap),
    champs.key.wrap,
    champs.patterns.wrap,
    h('div', { class: 'fieldrow' }, champs.parallel.wrap, champs.priority.wrap),
    h('div', { class: 'field' },
      h('label', { class: 'fld' }, nosu, ' wp-cli sans « su » (hébergement mutualisé)'),
      h('div', { class: 'aide', text: 'À cocher quand l’utilisateur SSH est déjà le propriétaire des fichiers.' })));
  mount('srvm-err');

  const test = document.getElementById('srvm-test');
  test.disabled = neuf;
  test.title = neuf
    ? 'Enregistrez le serveur d’abord : le test se fait sur un serveur déclaré.'
    : 'Ouvre une session SSH avec la clé choisie et affiche la réponse.';
  document.getElementById('srvm-ok').textContent = neuf ? 'Ajouter' : 'Enregistrer';
  document.getElementById('srvmodal').classList.add('open');
  champs[neuf ? 'name' : 'host'].ctrl.focus();
}

function fermerFormServeur() {
  document.getElementById('srvmodal').classList.remove('open');
  FORM = null;
}

/** Objet serveur construit depuis le formulaire, clés inconnues préservées. */
function serveurDuForm() {
  const c = FORM.champs;
  const o = { ...(FORM.origine || {}) };
  o.name = c.name.valeur();
  o.host = c.host.valeur();
  o.port = entier(c.port.valeur());
  if (o.port === null) o.port = c.port.valeur();          // laisse la validation le dire
  const user = c.user.valeur();
  if (user) o.user = user; else delete o.user;
  const key = c.key.valeur();
  if (key) o.key = key; else delete o.key;
  o.patterns = c.patterns.valeur().split('\n').map(x => x.trim()).filter(Boolean);
  const par = c.parallel.valeur();
  if (par) o.parallel = entier(par) ?? par; else delete o.parallel;
  const pri = c.priority.valeur();
  if (pri) o.priority = entier(pri) ?? pri; else delete o.priority;
  if (FORM.nosu.checked) o.no_su = true; else delete o.no_su;
  return o;
}

function poserErreurs(erreurs) {
  CHAMPS.forEach(k => FORM.champs[k].erreur(erreurs[k] || ''));
  const premier = CHAMPS.find(k => erreurs[k]);
  if (premier) FORM.champs[premier].ctrl.focus();
}

async function enregistrerServeur() {
  if (!FORM) return;
  const bouton = document.getElementById('srvm-ok');
  const o = serveurDuForm();
  const erreurs = validerServeur(o);
  mount('srvm-err');
  if (Object.keys(erreurs).length) { poserErreurs(erreurs); return; }
  poserErreurs({});

  const liste = ((store.mgmt && store.mgmt.servers) || []).slice();
  const i = FORM.origine ? liste.findIndex(x => x.name === FORM.origine.name) : -1;
  if (i >= 0) liste[i] = o;
  else {
    if (liste.some(x => x.name === o.name)) {
      poserErreurs({ name: 'Un serveur porte déjà ce nom.' });
      return;
    }
    liste.push(o);
  }

  const lbl = bouton.innerHTML;
  setBusy(bouton, 'enregistrement…');
  let r;
  try { r = await api('/api/mgmt/servers', { servers: liste }) || {}; }
  catch (e) { r = { error: String(e) }; }
  setIdle(bouton, lbl);

  if (r.error || r.ok === false) {
    const { champ: cible, message } = erreurBackend(r.error || 'refus du serveur', o.name);
    if (cible) poserErreurs({ [cible]: message });
    else {
      mount('srvm-err', chipEl('refusé', 'err'), ' ', h('span', { class: 'muted small', text: message }));
    }
    return;
  }
  store.mgmt.servers = liste;
  fermerFormServeur();
  renderServeurs();
  majSommaire();
  remplirSelectDocroot();
  loadMgmt(true);
}

async function supprimerServeur(s) {
  const f = (store.fleet?.servers || []).find(x => x.name === s.name);
  const n = f ? (f.sites || []).length : 0;
  if (!await askConfirm(
    `Retirer le serveur <b>${H(s.name)}</b> de servers.json ?<br><br>`
    + (n ? `Ses <b>${n} install(s)</b> disparaîtront du parc à la prochaine collecte. ` : '')
    + 'Rien n’est touché sur la machine : ni les sites, ni la clé SSH, ni les moniteurs Kuma.',
    { titre: 'Retirer un serveur', ok: 'Retirer', danger: true })) return;
  const liste = ((store.mgmt && store.mgmt.servers) || []).filter(x => x.name !== s.name);
  let r;
  try { r = await api('/api/mgmt/servers', { servers: liste }) || {}; }
  catch (e) { r = { error: String(e) }; }
  if (r.error || r.ok === false) {
    askInfo('Suppression refusée', H(String(r.error || 'refus du serveur')));
    return;
  }
  store.mgmt.servers = liste;
  renderServeurs();
  majSommaire();
  remplirSelectDocroot();
}

async function testerServeur() {
  if (!FORM || !FORM.origine) return;
  const b = document.getElementById('srvm-test');
  const cle = FORM.champs.key.valeur();
  mount('srvm-err', h('span', { class: 'muted small', text: 'connexion…' }));
  setBusy(b, 'test…');
  let j;
  try { j = await api('/api/mgmt/sshkeys/test', { server: FORM.origine.name, key: cle || undefined }) || {}; }
  catch (e) { j = { ok: false, output: String(e) }; }
  setIdle(b, 'Tester la connexion');
  mount('srvm-err', chipEl(j.ok ? 'joignable' : 'échec', j.ok ? 'ok' : 'err'), ' ',
    h('span', { class: 'muted small', text: String(j.output || j.error || '').slice(-200) }));
}

/* ---- repli : l'éditeur JSON ------------------------------------------------- */
function ouvrirJsonServeurs() {
  document.getElementById('srv-json').value =
    JSON.stringify((store.mgmt && store.mgmt.servers) || [], null, 1);
  mount('srv-msg');
  document.getElementById('jsonmodal').classList.add('open');
  document.getElementById('srv-json').focus();
}

function fermerJsonServeurs() { document.getElementById('jsonmodal').classList.remove('open'); }

async function enregistrerJsonServeurs() {
  const msg = document.getElementById('srv-msg');
  let servers;
  try { servers = JSON.parse(document.getElementById('srv-json').value); }
  catch (e) { mount(msg, chipEl('JSON invalide', 'err'), ' ', h('span', { class: 'muted small', text: String(e.message || e) })); return; }
  if (!Array.isArray(servers)) { mount(msg, chipEl('JSON invalide', 'err'), ' ', h('span', { class: 'muted small', text: 'un tableau de serveurs est attendu.' })); return; }
  let r;
  try { r = await api('/api/mgmt/servers', { servers }) || {}; }
  catch (e) { r = { error: String(e) }; }
  if (r.error || r.ok === false) {
    mount(msg, chipEl('refusé', 'err'), ' ', h('span', { class: 'muted small', text: String(r.error || '') }));
    return;
  }
  store.mgmt.servers = servers;
  mount(msg, chipEl('enregistré', 'ok'));
  renderServeurs();
  majSommaire();
  remplirSelectDocroot();
}

/* ============================================================================
   2. Installs découverts
   ========================================================================== */
function sectionInstalls() {
  const srv = h('select', { id: 'inst-srv', 'aria-label': 'Serveur' });
  srv.onchange = renderInstalls;
  const vue = h('select', { id: 'inst-vue', 'aria-label': 'Filtre' },
    h('option', { value: '', text: 'Toutes les installs' }),
    h('option', { value: 'vis', text: 'Visibles dans le parc' }),
    h('option', { value: 'mask', text: 'Masquées' }),
    h('option', { value: 'nomon', text: 'Sans moniteur Kuma' }));
  vue.onchange = renderInstalls;
  const q = h('input', {
    type: 'search', id: 'inst-q', class: 'w-md',
    placeholder: 'Filtrer un vhost, un alias…', 'aria-label': 'Filtrer les installs',
  });
  q.oninput = debounce(renderInstalls, 200);

  return sectionEl('mgmt-installs', 'Installs découverts',
    [h('span', { class: 'small', id: 'mgmt-count' })],
    h('p', { class: 'hint' },
      'Tous les WordPress trouvés en SSH. « Visibilité » prime sur le filtre Kuma du tableau de bord ; '
      + 'l’alias force le rattachement à un moniteur nommé différemment du domaine. '
      + 'Connecter un site installe la liaison temps réel : il pousse ses évènements (nouvel administrateur, '
      + 'activation d’extension) sans attendre la collecte. Le dashboard ne garde PAS de témoin de cette '
      + 'liaison pour un site en SSH : la colonne « Dashboard » montre le résultat de la dernière action '
      + 'lancée d’ici, pas un état relu.'),
    h('div', { class: 'filters' }, q, srv, vue,
      h('span', { class: 'spacer' }), h('span', { class: 'muted small', id: 'inst-count' })),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', { text: 'Install (vhost)' }), h('th', { text: 'Serveur' }),
          h('th', { text: 'Moniteur Kuma' }), h('th', { text: 'Visibilité' }),
          h('th', { text: 'Alias' }), h('th', { text: 'Dashboard' }),
          h('th', { text: 'WordPress' }),
          h('th', {}, h('span', { class: 'sr-only', text: 'Enregistrer' })))),
        h('tbody', { id: 'mgmt-tb' }))));
}

function remplirSelectServeurs() {
  const sel = document.getElementById('inst-srv');
  if (!sel) return;
  const avant = sel.value;
  const noms = [...new Set(toutesInstalls().map(s => s.srv))].sort();
  mount(sel, h('option', { value: '', text: 'Tous les serveurs' }),
    noms.map(n => h('option', { value: n, text: n })));
  sel.value = noms.includes(avant) ? avant : '';
}

/** Cellule « Dashboard » : état de l'agent + connexion / dissociation. */
function celluleAgent(s) {
  if (s.via === 'rest') {
    return h('span', {}, chipEl('agent (REST)', 'ok',
      { title: "c'est l'agent qui pousse l'inventaire : la liaison est par définition en place" }));
  }
  const res = h('span', { class: 'small' });
  const co = h('button', { type: 'button', class: 'btn sm', text: 'Connecter' });
  co.onclick = () => confirm2(co, async () => {
    setBusy(co);
    mount(res);
    try {
      const j = await api('/api/mgmt/dash_connect', { server: s.srv, domain: s.domain }) || {};
      const out = String(j.output ?? j.error ?? '').slice(-400);
      mount(res, chipEl(j.ok ? 'connecté' : 'échec', j.ok ? 'ok' : 'err', { title: out }));
    } catch (e) { mount(res, chipEl('échec', 'err', { title: String(e) })); }
    setIdle(co, 'Connecter');
  });
  const dis = h('button', { type: 'button', class: 'btn sm', text: 'Dissocier' });
  dis.onclick = () => confirm2(dis, async () => {
    setBusy(dis);
    mount(res);
    try {
      const j = await api('/api/mgmt/dash_disconnect', { server: s.srv, domain: s.domain }) || {};
      const out = String(j.output ?? j.error ?? '').slice(-400);
      mount(res, chipEl(j.ok ? 'dissocié' : 'échec', j.ok ? 'ok' : 'err', { title: out }));
    } catch (e) { mount(res, chipEl('échec', 'err', { title: String(e) })); }
    setIdle(dis, 'Dissocier');
  });
  return h('span', {}, co, ' ', dis, ' ', res);
}

/* ---- identifiants WordPress d'une ligne ------------------------------------
   Une requête par ligne : sur 40 installs, les lancer toutes d'un coup ouvre
   40 connexions pour des réponses de 80 octets. Quatre à la fois suffisent, et
   le résultat est mémorisé pour la durée de l'écran (un filtre qui redessine le
   tableau ne redemande rien). */
const FILE_CRED = [];
let ENCOURS = 0;

function fileCred(fn) {
  FILE_CRED.push(fn);
  depiler();
}

function depiler() {
  while (ENCOURS < 4 && FILE_CRED.length) {
    const fn = FILE_CRED.shift();
    ENCOURS++;
    Promise.resolve().then(fn).finally(() => { ENCOURS--; depiler(); });
  }
}

/** Cellule « WordPress » : identifiants d'application, remplie en différé. */
function celluleWp(dom, srv) {
  const cell = h('span', { class: 'small' }, h('span', { class: 'muted', text: '…' }));
  if (CRED.has(dom)) remplirWp(cell, dom, srv);
  else fileCred(() => remplirWp(cell, dom, srv));
  return cell;
}

async function remplirWp(cell, dom, srv) {
  if (!dom) { mount(cell, h('span', { class: 'muted', text: '—' })); return; }
  let j = CRED.get(dom);
  if (j === undefined) {
    j = await wpCredentials(dom);
    CRED.set(dom, j);
  }
  if (!j) { mount(cell, h('span', { class: 'muted', text: '—' })); return; }
  if (j.has_password) {
    const rev = h('button', { type: 'button', class: 'btn sm', text: 'Révoquer' });
    const msg = h('span', { class: 'small' });
    rev.onclick = () => confirm2(rev, async () => {
      setBusy(rev);
      try {
        const r = await api('/api/mgmt/wp_credentials/delete', { domain: dom }) || {};
        if (r.ok === false) {
          mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: r.error || '' }));
          setIdle(rev, 'Révoquer');
          return;
        }
        CRED.delete(dom);
        remplirWp(cell, dom, srv);
      } catch (e) {
        mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) }));
        setIdle(rev, 'Révoquer');
      }
    });
    mount(cell, chipEl('autorisé' + (j.user ? ' · ' + j.user : ''), 'ok'), ' ',
      j.verified === false ? [chipEl('à vérifier', 'warn', { title: 'dernier contrôle non concluant' }), ' '] : null,
      rev, ' ', msg);
    return;
  }
  if (!WPAUTH_ENABLED) { mount(cell, chipEl('sans SSH', 'mut')); return; }
  const msg = h('span', { class: 'small' });
  const bt = h('button', { type: 'button', class: 'btn sm primary', title: WPAUTH_HELP },
    iconEl('link'), ' Autoriser');
  bt.onclick = () => wpAuthorize(bt, srv, dom, (ok, err) => {
    if (!ok) { mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: err })); return; }
    mount(msg, chipEl("en attente d'approbation…", 'warn'));
    mount(bt, iconEl('refresh-cw'), ' Vérifier');
    bt.classList.remove('primary');
    bt.onclick = () => { CRED.delete(dom); remplirWp(cell, dom, srv); };
  });
  mount(cell, chipEl('non autorisé', 'warn'), ' ', bt, ' ', msg);
}

function renderInstalls() {
  const tb = document.getElementById('mgmt-tb');
  if (!tb) return;
  const m = store.mgmt;
  if (!m) {
    mount(tb, h('tr', {}, h('td', { colspan: '8' },
      chipEl('état indisponible', 'err'), ' ',
      h('span', { class: 'muted small', id: 'mgmt-err', text: '' }))));
    return;
  }
  const srvF = (document.getElementById('inst-srv') || {}).value || '';
  const vueF = (document.getElementById('inst-vue') || {}).value || '';
  const q = ((document.getElementById('inst-q') || {}).value || '').toLowerCase().trim();

  /* Même règle que allSites() dans lib/state.js : la visibilité forcée prime,
     sinon un site sans moniteur Kuma reste masqué (sauf s'il est en mode REST,
     géré explicitement). Deux règles qui divergent, c'est un site qu'on croit
     suivi et qui ne l'est pas. */
  const visible = s => {
    const ov = m.overrides[s.domain] || {};
    if (ov.visible === true) return true;
    if (ov.visible === false) return false;
    return s.via === 'rest' || !!kName(s);
  };

  let list = toutesInstalls();
  mount('mgmt-count', chipEl(pluriel(list.length, 'install'), 'mut'));
  if (srvF) list = list.filter(s => s.srv === srvF);
  if (vueF === 'vis') list = list.filter(visible);
  if (vueF === 'mask') list = list.filter(s => !visible(s));
  if (vueF === 'nomon') list = list.filter(s => !kName(s));
  if (q) list = list.filter(s => (s.domain + ' ' + (s.blogname || '') + ' ' + s.srv + ' ' + ((m.overrides[s.domain] || {}).alias || '')).toLowerCase().includes(q));

  const cnt = document.getElementById('inst-count');
  if (cnt) cnt.textContent = list.length === toutesInstalls().length ? '' : pluriel(list.length, 'ligne affichée', 'lignes affichées');

  mount(tb, list.length ? list.map(s => {
    const ov = m.overrides[s.domain] || {};
    const mon = kName(s);
    let monCell;
    if (mon) monCell = chipEl(mon, 'ok');
    else {
      const b = h('button', { type: 'button', class: 'btn sm' }, iconEl('plus'), ' créer moniteur');
      b.onclick = () => creerMoniteur(b, s.domain);
      monCell = b;
    }

    const vis = h('select', { 'aria-label': 'Visibilité de ' + s.domain },
      h('option', { value: 'auto', text: 'auto (Kuma)' }),
      h('option', { value: 'show', text: 'toujours afficher' }),
      h('option', { value: 'hide', text: 'masquer' }));
    vis.value = ov.visible === true ? 'show' : ov.visible === false ? 'hide' : 'auto';
    const alias = h('input', {
      class: 'inp w-xs', placeholder: 'nom du moniteur', 'aria-label': 'Alias de ' + s.domain,
    });
    alias.value = ov.alias || '';

    const save = h('button', {
      type: 'button', class: 'btn sm', title: 'Enregistrer la visibilité et l’alias',
    }, iconEl('check', { label: 'Enregistrer' }));
    save.onclick = async () => {
      setBusy(save);
      const v = vis.value;
      try {
        const r = await api('/api/mgmt/override', {
          domain: s.domain,
          visible: v === 'show' ? true : v === 'hide' ? false : null,
          alias: alias.value,
        }) || {};
        if (r.overrides) store.mgmt.overrides = r.overrides;
      } catch (e) { /* le rechargement de la flotte dira l'état réel */ }
      setIdle(save, null);
      mount(save, iconEl('check', { label: 'Enregistré' }));
      await loadFleet();
    };

    return h('tr', {},
      h('td', {}, h('b', { text: s.domain }),
        s.blogname ? h('div', { class: 'sub', text: s.blogname }) : null),
      h('td', { class: 'muted', text: s.srv }),
      h('td', {}, monCell),
      h('td', {}, vis),
      h('td', {}, alias),
      h('td', {}, celluleAgent(s)),
      h('td', {}, celluleWp(s.domain, s.srv)),
      h('td', {}, save));
  }) : h('tr', {}, h('td', { colspan: '8' },
    h('span', { class: 'muted small', text: 'aucune install ne correspond au filtre.' }))));
}

async function creerMoniteur(b, domaine) {
  const groupes = (store.mgmt && store.mgmt.kuma_groups) || [];
  if (!groupes.length) {
    askInfo('Aucun groupe Kuma', "Uptime Kuma ne déclare aucun groupe : créez-en un dans Kuma, "
      + 'puis revenez ici. Le moniteur doit être rangé dans un client.');
    return;
  }
  const gid = await askChoice('Créer le moniteur', 'Dans quel client ce moniteur doit-il être rangé ?',
    groupes.map(g => ({ value: g.id, label: g.name })), groupes[0].id);
  if (!gid) return;
  const type = await askChoice('Type de surveillance',
    'Le contrôle par mot-clé détecte aussi un site en ligne mais cassé ; le contrôle HTTP se contente '
    + 'du code de réponse.',
    [{ value: 'keyword', label: 'Mot-clé sur /wp-login.php (recommandé pour WordPress)' },
      { value: 'http', label: "Contrôle HTTP simple de la page d'accueil" }], 'keyword');
  if (!type) return;
  setBusy(b, 'redémarrage Kuma…');
  let r;
  try { r = await api('/api/mgmt/kuma/create', { domain: domaine, group_id: gid, type }) || {}; }
  catch (e) { r = { error: String(e) }; }
  askInfo(r.ok ? 'Moniteur créé' : 'Échec de la création',
    r.ok ? 'Kuma redémarre — le statut apparaîtra dans une quinzaine de secondes.'
      : H(String(r.output || r.error || '')));
  setTimeout(() => { loadStatus(); loadMgmt(true); }, 16000);
}

/* ============================================================================
   3. Sites sans SSH (agent) — assistant d'ajout + liste des sites REST
   ========================================================================== */
function sectionRest() {
  const ajout = h('button', { type: 'button', class: 'btn sm primary', id: 'addsite' },
    iconEl('plus'), ' Ajouter un site par URL');
  ajout.onclick = () => openAdd('', false);

  const url = h('input', { class: 'inp w-md', id: 'rest-url', placeholder: 'https://exemple.fr', 'aria-label': 'URL du site' });
  const nom = h('input', { class: 'inp w-sm', id: 'rest-name', placeholder: 'nom du site (facultatif)', 'aria-label': 'Nom du site' });
  const add = h('button', { type: 'button', class: 'btn sm', id: 'rest-add' }, iconEl('plus'), ' Ajouter manuellement');
  add.onclick = () => ajouterRestManuel(url, nom);

  return sectionEl('mgmt-rest', 'Sites sans SSH (agent)',
    [h('span', { class: 'small', id: 'rest-count' }), h('span', { class: 'spacer' }), ajout],
    h('p', { class: 'hint' },
      'Sites gérés par l’agent Dash à travers l’API REST : l’inventaire remonte sans accès SSH au serveur. '
      + 'L’assistant « Ajouter un site par URL » analyse l’adresse, choisit la méthode (SSH ou appairage) et '
      + 'guide l’installation de l’agent — c’est le chemin normal.'),
    h('div', { class: 'small', id: 'rest-body' }, h('span', { class: 'muted', text: 'chargement…' })),
    h('h3', { text: 'Ajout manuel' }),
    h('p', { class: 'hint', text: 'Ne sert que si l’agent est déjà installé et appairé sur le site.' }),
    h('div', { class: 'filters' }, url, nom, add, zoneMessage('rest-msg')));
}

async function ajouterRestManuel(url, nom) {
  const msg = document.getElementById('rest-msg');
  const u = url.value.trim();
  if (!u) { mount(msg, h('span', { class: 'muted', text: 'indiquez une URL' })); return; }
  mount(msg, h('span', { class: 'muted', text: '…' }));
  try {
    const j = await api('/api/mgmt/rest_sites', { url: u, name: nom.value.trim() }) || {};
    if (j.ok === false || j.error) {
      mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: j.error || '' }));
      return;
    }
    mount(msg, chipEl('ajouté', 'ok'));
    url.value = ''; nom.value = '';
    loadRestSites();
    loadFleet();
  } catch (e) {
    mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) }));
  }
}

async function loadRestSites() {
  const bd = document.getElementById('rest-body');
  if (!bd) return;
  mount(bd, h('span', { class: 'muted', text: 'chargement…' }));
  let j;
  try { j = await api('/api/mgmt/rest_sites'); }
  catch (e) { mount(bd, h('span', { class: 'muted small', text: 'liste indisponible : ' + e })); return; }
  RESTSITES = restList(j).filter(x => x && typeof x === 'object');
  mount('rest-count', RESTSITES.length ? chipEl(pluriel(RESTSITES.length, 'site'), 'mut') : null);
  majSommaire();
  if (!RESTSITES.length) {
    mount(bd, h('span', { class: 'muted', text: 'aucun site en mode REST pour le moment.' }));
    return;
  }
  mount(bd, h('div', { class: 'wrap' },
    h('table', {},
      h('thead', {}, h('tr', {},
        h('th', { text: 'Domaine' }), h('th', { text: 'Nom' }), h('th', { text: 'Ajouté le' }),
        h('th', { text: 'Multisite' }), h('th', { text: 'WordPress' }),
        h('th', {}, h('span', { class: 'sr-only', text: 'Actions' })))),
      h('tbody', {}, RESTSITES.map(ligneRest)))));
}

function ligneRest(x) {
  const d = restDomain(x), u = safeUrl(x.url);
  const res = h('span', { class: 'small' });
  const del = h('button', { type: 'button', class: 'btn sm danger', text: 'Retirer' });
  del.onclick = () => confirm2(del, () => retirerRest(d, del, res));
  return h('tr', {},
    h('td', {}, h('b', {}, u
      ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: d })
      : h('span', { text: d || '—' }))),
    h('td', { text: x.name || '—' }),
    h('td', { class: 'muted', title: absTime(x.added_at), text: x.added_at ? relTime(x.added_at) : '—' }),
    h('td', {}, x.multisite ? chipEl('oui', 'warn') : chipEl('non', 'mut')),
    h('td', {}, celluleWp(d, x.server || x.srv || '')),
    h('td', {}, del, ' ', res));
}

async function retirerRest(d, bouton, res) {
  // `keep_account` : par défaut le désenrôlement retire aussi le compte dédié
  // du site distant, sinon il y resterait un administrateur orphelin.
  const garder = await askChoice('Retirer un site sans SSH',
    `Le site <b>${H(d)}</b> sort du parc. Que faire du compte dédié que le dashboard s'est créé sur le site ?`,
    [{ value: '0', label: 'Supprimer le compte du site (recommandé)' },
      { value: '1', label: 'Le laisser en place (site déjà injoignable, nettoyage manuel)' }], '0');
  if (garder === null) { setIdle(bouton, 'Retirer'); return; }
  setBusy(bouton);
  try {
    const r = await api('/api/mgmt/rest_sites/delete', { domain: d, keep_account: garder === '1' }) || {};
    if (r.ok === false) {
      mount(res, chipEl('échec', 'err', { title: r.error || '' }));
      setIdle(bouton, 'Retirer');
      return;
    }
    CRED.delete(d);
    loadRestSites();
    loadFleet();
  } catch (e) {
    mount(res, chipEl('échec', 'err', { title: String(e) }));
    setIdle(bouton, 'Retirer');
  }
}

/* ============================================================================
   4. Moniteurs Uptime Kuma
   ========================================================================== */
function sectionMoniteurs() {
  return sectionEl('mgmt-moniteurs', 'Moniteurs Uptime Kuma',
    [h('span', { class: 'small', id: 'mon-sum' })],
    h('p', { class: 'hint', text: 'Mettre en pause, réactiver ou supprimer un moniteur. Toute modification '
      + 'redémarre Kuma : environ 15 s d’interruption du monitoring.' }),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', { text: 'Moniteur' }), h('th', { text: 'Client' }), h('th', { text: 'État' }),
          h('th', { text: 'Dernier battement' }),
          h('th', {}, h('span', { class: 'sr-only', text: 'Actions' })))),
        h('tbody', { id: 'mon-tb' }))));
}

function renderMoniteurs() {
  const tb = document.getElementById('mon-tb');
  if (!tb) return;
  const m = store.mgmt;
  if (!m) {
    mount(tb, h('tr', {}, h('td', { colspan: '5' }, h('span', { class: 'muted small', text: 'moniteurs indisponibles' }))));
    return;
  }
  const parId = {};
  (m.kuma_monitors || []).forEach(x => { parId[x.id] = x; });
  const list = (m.kuma_monitors || []).filter(x => x && x.parent);
  mount('mon-sum', list.length ? chipEl(pluriel(list.length, 'moniteur'), 'mut') : null);

  mount(tb, list.length ? list.map(mon => {
    const grp = parId[mon.parent] ? parId[mon.parent].name : '';
    // `store.status` est indexé par NOM de moniteur (status page publique).
    const etatKuma = store.status[mon.name];
    const pause = h('button', { type: 'button', class: 'btn sm', text: mon.active ? 'Pause' : 'Réactiver' });
    pause.onclick = async () => {
      setBusy(pause, 'redémarrage Kuma…');
      await api('/api/mgmt/kuma/pause', { monitor_id: +mon.id, active: mon.active ? 0 : 1 }).catch(() => {});
      setTimeout(() => { loadStatus(); loadMgmt(true); }, 16000);
    };
    const del = h('button', { type: 'button', class: 'btn sm danger', text: 'Retirer' });
    del.onclick = async () => {
      if (!await askConfirm(
        `Retirer le moniteur <b>${H(mon.name)}</b> ?<br><br>Kuma redémarre : ~15 s d'interruption du monitoring.`,
        { titre: 'Retirer un moniteur', ok: 'Retirer', danger: true })) return;
      setBusy(del, 'redémarrage Kuma…');
      await api('/api/mgmt/kuma/delete', { monitor_id: +mon.id }).catch(() => {});
      setTimeout(() => { loadStatus(); loadMgmt(true); }, 16000);
    };
    return h('tr', {},
      h('td', {}, h('b', { text: mon.name })),
      h('td', { class: 'muted', text: grp }),
      h('td', {}, mon.active ? chipEl('actif', 'ok') : chipEl('en pause', 'mut')),
      h('td', {}, etatKuma === undefined
        ? h('span', { class: 'muted small', text: '—' })
        : chipEl(etatKuma === 1 ? 'en ligne' : etatKuma === 0 ? 'down' : 'en attente',
          etatKuma === 1 ? 'ok' : etatKuma === 0 ? 'err' : 'warn')),
      h('td', {}, pause, ' ', del));
  }) : h('tr', {}, h('td', { colspan: '5' }, h('span', { class: 'muted small', text: 'aucun moniteur' }))));
}

/* ============================================================================
   5. Docroots supplémentaires
   ========================================================================== */
function sectionDocroots() {
  const srv = h('select', { id: 'doc-srv', 'aria-label': 'Serveur' });
  const path = h('input', {
    class: 'inp w-lg', id: 'doc-path', placeholder: '/var/www/vhosts/exemple.fr/dev',
    'aria-label': 'Chemin du docroot',
  });
  const add = h('button', { type: 'button', class: 'btn sm', id: 'doc-add' }, iconEl('plus'), ' Ajouter');
  add.onclick = () => ajouterDocroot(srv, path);
  path.onkeydown = e => { if (e.key === 'Enter') ajouterDocroot(srv, path); };
  return sectionEl('mgmt-docroots', 'Docroots supplémentaires',
    [h('span', { class: 'small', id: 'doc-sum' })],
    h('p', { class: 'hint' },
      'Chemins à scanner en plus des motifs du serveur (installs de développement, sous-installs). '
      + 'Le prochain scan les prend en compte. Même règle que les motifs : chemin absolu, caractères ',
      h('code', { text: 'A-Z a-z 0-9 _ . / * @ -' }), ', sans ', h('code', { text: '..' }), '.'),
    h('div', { id: 'doc-list' }),
    h('div', { class: 'filters mt2' }, srv, path, add, zoneMessage('doc-msg')));
}

function remplirSelectDocroot() {
  const sel = document.getElementById('doc-srv');
  if (!sel) return;
  const avant = sel.value;
  const noms = ((store.mgmt && store.mgmt.servers) || []).map(s => s.name);
  mount(sel, noms.length
    ? noms.map(n => h('option', { value: n, text: n }))
    : h('option', { value: '', text: '(aucun serveur)' }));
  if (noms.includes(avant)) sel.value = avant;
}

function renderDocroots() {
  const box = document.getElementById('doc-list');
  if (!box) return;
  const docs = (store.mgmt && store.mgmt.extra_docroots) || [];
  mount('doc-sum', docs.length ? chipEl(pluriel(docs.length, 'chemin'), 'mut') : null);
  mount(box, docs.length ? docs.map((d, i) => {
    const b = h('button', { type: 'button', class: 'btn sm danger fr', text: 'Retirer' });
    b.onclick = async () => {
      setBusy(b);
      const reste = docs.slice();
      reste.splice(i, 1);
      const r = await api('/api/mgmt/docroots', { docroots: reste }).catch(e => ({ error: String(e) })) || {};
      if (r.error) { mount('doc-msg', chipEl('refusé', 'err'), ' ', h('span', { class: 'muted small', text: r.error })); setIdle(b, 'Retirer'); return; }
      loadMgmt(true);
    };
    return h('div', { class: 'logline' },
      h('b', { text: d.server || '?' }), ' · ', h('code', { text: d.path || '' }), b);
  }) : h('span', { class: 'muted small', text: 'aucun' }));
}

async function ajouterDocroot(srv, path) {
  const msg = document.getElementById('doc-msg');
  const server = srv.value, p = path.value.trim();
  mount(msg);
  if (!server) { mount(msg, chipEl('aucun serveur', 'err'), ' ', h('span', { class: 'muted small', text: 'déclarez d’abord un serveur.' })); return; }
  if (!p) { mount(msg, h('span', { class: 'muted', text: 'indiquez un chemin' })); return; }
  if (!RE_CHEMIN.test(p) || p.includes('..')) {
    mount(msg, chipEl('chemin invalide', 'err'), ' ',
      h('span', { class: 'muted small', text: 'chemin absolu, caractères A-Z a-z 0-9 _ . / * @ - , sans « .. ».' }));
    return;
  }
  const docs = ((store.mgmt && store.mgmt.extra_docroots) || []).slice();
  docs.push({ server, path: p });
  const r = await api('/api/mgmt/docroots', { docroots: docs }).catch(e => ({ error: String(e) })) || {};
  if (r.error) { mount(msg, chipEl('refusé', 'err'), ' ', h('span', { class: 'muted small', text: r.error })); return; }
  path.value = '';
  mount(msg, chipEl('ajouté', 'ok'));
  loadMgmt(true);
}

/* ============================================================================
   6. Sites supervisés non gérés
   ========================================================================== */
function sectionCandidats() {
  return sectionEl('mgmt-nongeres', 'Sites supervisés non gérés',
    [h('span', { class: 'small', id: 'cand-count' })],
    h('p', { class: 'hint', text: 'Sites vus par le monitoring mais absents du parc géré : ajoutez-les en un '
      + 'clic, l’URL est reprise automatiquement dans l’assistant.' }),
    h('div', { class: 'small', id: 'cand-body' }, h('span', { class: 'muted', text: 'chargement…' })));
}

async function loadCandidates() {
  const bd = document.getElementById('cand-body');
  if (!bd) return;
  mount(bd, h('span', { class: 'muted', text: 'chargement…' }));
  let j;
  try { j = await api('/api/mgmt/candidates'); }
  catch (e) { mount(bd, h('span', { class: 'muted small', text: 'liste indisponible : ' + e })); return; }
  CANDIDATS = (j && Array.isArray(j.candidates)) ? j.candidates.filter(x => x && typeof x === 'object') : [];
  mount('cand-count', CANDIDATS.length ? chipEl(pluriel(CANDIDATS.length, 'site'), 'warn') : null);
  majSommaire();
  if (!CANDIDATS.length) {
    mount(bd, chipEl('tous les sites supervisés sont gérés', 'ok'));
    return;
  }
  mount(bd, h('div', { class: 'wrap' },
    h('table', {},
      h('thead', {}, h('tr', {},
        h('th', { text: 'Site' }), h('th', { text: 'URL' }), h('th', { text: 'Pourquoi' }),
        h('th', {}, h('span', { class: 'sr-only', text: 'Actions' })))),
      h('tbody', {}, CANDIDATS.map(c => {
        const brut = String(c.url ?? ''), u = safeUrl(brut);
        const b = h('button', { type: 'button', class: 'btn sm primary', text: 'Ajouter par URL' });
        b.onclick = () => openAdd(brut, true);
        return h('tr', {},
          h('td', {}, h('b', { text: c.name || hostOf(brut) || '—' }),
            c.source ? h('div', { class: 'sub', text: c.source }) : null),
          h('td', { class: 'muted' }, u
            ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: brut })
            : h('span', { text: brut || '—' })),
          h('td', {}, chipEl(c.reason || 'non géré', 'mut')),
          h('td', {}, b));
      })))));
}

/* ============================================================================
   Identifiants WordPress dans la PAGE SITE (importé par screens/site.js)
   ========================================================================== */
let WPCSEQ = 0;

async function loadWpCred(srv, dom) {
  const seq = ++WPCSEQ;
  const cell = document.getElementById('wpcred');
  if (!cell) return;
  if (!WPAUTH_ENABLED) {
    mount(cell, chipEl('aucun', 'mut'), ' ',
      h('span', { class: 'muted small', text: 'inventaire en lecture seule, aucune action distante possible.' }));
    wpCredActions(false);
    return;
  }
  const j = await wpCredentials(dom);
  if (seq !== WPCSEQ) return;
  const c = document.getElementById('wpcred');
  if (!c) return;
  if (!j) {
    mount(c, h('span', { class: 'muted small', text: 'état des identifiants indisponible' }));
    wpCredActions(false);
    return;
  }
  wpCredRender(c, srv, dom, j);
}

function wpCredRender(c, srv, dom, j) {
  const has = !!j.has_password;
  const msg = h('span', { class: 'small' });
  if (has) {
    const rb = h('button', { type: 'button', class: 'btn sm', text: 'Révoquer' });
    rb.onclick = () => confirm2(rb, async () => {
      setBusy(rb);
      try {
        const r = await api('/api/mgmt/wp_credentials/delete', { domain: dom }) || {};
        if (r.ok === false) {
          mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: r.error || '' }));
          setIdle(rb, 'Révoquer');
          return;
        }
        CRED.delete(dom);
        loadWpCred(srv, dom);
      } catch (e) {
        mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) }));
        setIdle(rb, 'Révoquer');
      }
    });
    mount(c, chipEl('autorisé' + (j.user ? ' · ' + j.user : ''), 'ok'), ' ',
      j.verified === false ? [chipEl('à vérifier', 'warn', { title: 'dernier contrôle non concluant' }), ' '] : null,
      j.checked_ts ? [h('span', { class: 'muted small', title: absTime(j.checked_ts), text: 'contrôlé ' + relTime(j.checked_ts) }), ' '] : null,
      rb, ' ', msg);
  } else if (!WPAUTH_ENABLED) {
    mount(c, chipEl('aucun', 'mut'), ' ',
      h('span', { class: 'muted small', text: "le dashboard n'a pas d'identifiant WordPress sur ce site (inventaire en lecture seule)." }));
  } else {
    const ab = h('button', { type: 'button', class: 'btn sm primary' }, iconEl('link'), ' Autoriser en un clic');
    ab.onclick = () => wpAuthorize(ab, srv, dom, (ok, err) => {
      if (!ok) { mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: err })); return; }
      mount(msg, chipEl("en attente d'approbation…", 'warn'));
      mount(ab, iconEl('refresh-cw'), ' Vérifier');
      ab.classList.remove('primary');
      ab.onclick = () => { mount(msg, h('span', { class: 'muted', text: '…' })); CRED.delete(dom); loadWpCred(srv, dom); };
    });
    mount(c, chipEl('non autorisé', 'warn'), ' ', ab, ' ', msg,
      h('div', { class: 'muted small mt1', text: WPAUTH_HELP }));
  }
  wpCredActions(has);
}

/* Avec des identifiants, l'installation d'extensions publiques redevient
   possible sans SSH : la page site rouvre le bouton et change sa note. */
function wpCredActions(has) {
  const slot = document.getElementById('rest-vizslot'), note = document.getElementById('rest-note');
  if (slot) {
    const can = has && store.cur && !(vizOf(store.cur) || vizInfo(store.cur));
    if (!can) mount(slot);
    else {
      const b = h('button', { type: 'button', class: 'btn sm', text: 'Installer vizproof' });
      b.dataset.act = 'vizproof_install';
      b.onclick = () => confirmRun(b);
      mount(slot, b, ' ');
    }
  }
  if (note) {
    mount(note, has
      ? h('span', {}, 'Site géré ', h('b', { text: 'sans SSH' }),
        " : seules les installations d'extensions publiques sont possibles via l'autorisation WordPress.")
      : h('span', {}, 'Site géré ', h('b', { text: 'sans SSH' }),
        " : l'agent est en lecture seule, les actions distantes (mises à jour, backup, checksums, caches) "
        + 'ne sont pas disponibles ici. À faire depuis wp-admin, ou en rattachant le serveur en SSH depuis '
        + 'Gestion → Serveurs.'));
  }
}

/* ============================================================================
   Chargement de l'écran
   ========================================================================== */
async function loadMgmt(force) {
  monterMgmt();
  if (cacheFrais('mgmt', force)) return;
  // `aria-busy` le temps du relevé : la page n'est pas vide, elle se remplit.
  occupe('page-mgmt', true);

  // Indépendants de /api/mgmt/state : leur échec ne doit pas laisser la page muette.
  loadCandidates();
  loadRestSites();
  chargerCles();

  let etat = null;
  try { etat = await api('/api/mgmt/state'); }
  catch (e) {
    cacheVider('mgmt');
    store.mgmt = null;
    renderInstalls();
    renderMoniteurs();
    const err = document.getElementById('mgmt-err');
    if (err) err.textContent = String(e);
    occupe('page-mgmt', false);
    return;
  }
  if (!etat || typeof etat !== 'object' || etat.error) {
    cacheVider('mgmt');
    store.mgmt = null;
    renderInstalls();
    renderMoniteurs();
    const err = document.getElementById('mgmt-err');
    if (err) err.textContent = (etat && etat.error) || 'réponse vide';
    occupe('page-mgmt', false);
    return;
  }
  etat.kuma_monitors = etat.kuma_monitors || [];
  etat.kuma_groups = etat.kuma_groups || [];
  etat.overrides = etat.overrides || {};
  etat.servers = etat.servers || [];
  etat.extra_docroots = etat.extra_docroots || [];
  store.mgmt = etat;

  renderServeurs();
  remplirSelectServeurs();
  renderInstalls();
  renderMoniteurs();
  remplirSelectDocroot();
  renderDocroots();
  majSommaire();
  occupe('page-mgmt', false);
}

/** Les clés SSH ne servent ici qu'à nommer et à choisir la clé d'un serveur. */
async function chargerCles() {
  try { KEYS = await api('/api/mgmt/sshkeys'); }
  catch (e) { KEYS = null; }
  if (store.mgmt) renderServeurs();
}

/* ---- crochets de l'assistant d'ajout ---------------------------------------- */
setAddHooks({
  apresAppairage: () => { loadRestSites(); },
  allerInstalls: dom => {
    const cible = String(dom || '');
    const lignes = [...document.querySelectorAll('#mgmt-tb tr')];
    const tr = lignes.find(x => {
      const b = x.querySelector('td b');
      return b && (b.textContent === cible || hostOf(b.textContent) === hostOf(cible));
    });
    if (!tr) return false;
    tr.scrollIntoView({ block: 'center' });
    tr.classList.add('flash');
    setTimeout(() => { tr.classList.remove('flash'); }, 4000);
    return true;
  },
});

/* ---- branchements des deux modales de la section Serveurs -------------------- */
document.getElementById('srvm-cancel').onclick = fermerFormServeur;
document.getElementById('srvm-ok').onclick = enregistrerServeur;
document.getElementById('srvm-test').onclick = testerServeur;
document.getElementById('srvmodal').onclick = e => { if (e.target.id === 'srvmodal') fermerFormServeur(); };
registerModalCloser('srvmodal', fermerFormServeur);

document.getElementById('jsonm-cancel').onclick = fermerJsonServeurs;
document.getElementById('srv-save').onclick = enregistrerJsonServeurs;
document.getElementById('jsonmodal').onclick = e => { if (e.target.id === 'jsonmodal') fermerJsonServeurs(); };
registerModalCloser('jsonmodal', fermerJsonServeurs);

export { loadMgmt, loadWpCred, openAdd };
