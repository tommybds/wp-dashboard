/* Assistant « Ajouter un WordPress » : URL → méthode → appairage.

   Trois étapes, une modale, rendues avec h() :

     1. URL         `POST /api/mgmt/discover` — WordPress ? API REST ouverte ?
                    multisite ? agent déjà là ? déjà connu du parc ?
     2. Méthode     SSH (le serveur est déjà branché : rien à installer à la
                    main) ou appairage (aucun SSH : ZIP + code).
     3a. SSH        renvoie à la ligne de l'install, dans « Installs découverts ».
     3b. Appairage  ZIP de l'agent, code à usage unique avec son compte à
                    rebours, marche à suivre dans wp-admin, puis attente : on
                    interroge `rest_sites` toutes les 5 s pendant 6 min.

   Le composant ne connaît pas l'écran Gestion : celui-ci lui donne deux
   crochets (`setAddHooks`) — rafraîchir ses listes après un appairage, et
   emmener l'utilisateur jusqu'à la bonne ligne d'install. */

import { api } from '../lib/api.js';
import { h, mount, zoneMessage } from '../lib/dom.js';
import { safeUrl, hostOf } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { loadFleet } from '../lib/state.js';
import { chipEl } from './chip.js';
import { registerModalCloser } from './confirm.js';
import { WPAUTH_ENABLED, WPAUTH_HELP, wpAuthorize } from './wpauth.js';

/* ---- forme des réponses de /api/mgmt/rest_sites ---------------------------
   La route a porté plusieurs clés au fil du temps ; on accepte les trois
   formes plutôt que de dépendre de la dernière. */
export function restList(j) {
  if (Array.isArray(j)) return j;
  if (!j || typeof j !== 'object') return [];
  for (const k of ['rest_sites', 'sites']) if (Array.isArray(j[k])) return j[k];
  return [];
}

export function restDomain(x) {
  return String((x && (x.domain || hostOf(x.url))) || '');
}

/* ---- crochets posés par l'écran Gestion ----------------------------------- */
const HOOKS = {
  apresAppairage: () => {},          // rafraîchir la liste des sites REST
  allerInstalls: () => false,        // → true si la ligne d'install a été trouvée
};

export function setAddHooks(x) { Object.assign(HOOKS, x || {}); }

/* ---- état de l'assistant --------------------------------------------------- */
const ADD0 = {
  open: false, step: 1, url: '', info: null, method: null,
  domain: '', expires: 0, timer: null, poll: null, pollUntil: 0,
};
let ADD = { ...ADD0 };

function addStop() {
  if (ADD.timer) { clearInterval(ADD.timer); ADD.timer = null; }
  if (ADD.poll) { clearTimeout(ADD.poll); ADD.poll = null; }
}

function closeAdd() {
  addStop();
  ADD.open = false;
  document.getElementById('addmodal').classList.remove('open');
}

/** openAdd(url, auto) — `auto` lance l'analyse tout de suite (candidat connu). */
export function openAdd(url, auto) {
  addStop();
  ADD = { ...ADD0, open: true, url: String(url || '').trim() };
  document.getElementById('addmodal').classList.add('open');
  addRender();
  if (auto && ADD.url) addDiscover();
}

/* ---- rendu ----------------------------------------------------------------- */
function addRender() {
  const etapes = [[1, 'URL'], [2, 'Méthode'], [3, ADD.method === 'ssh' ? 'Connexion SSH' : 'Appairage']];
  const fil = [];
  etapes.forEach(([n, t], i) => {
    if (i) fil.push(h('span', { class: 'muted' }, iconEl('chevron-right', { size: 14 })));
    fil.push(chipEl(n + '. ' + t, n === ADD.step ? 'ok' : 'mut'));
  });
  mount('add-steps', fil);
  mount('add-body', ADD.step === 1 ? addStep1() : ADD.step === 2 ? addStep2() : addStep3());
  const inp = document.getElementById('add-url');
  if (inp) {
    inp.oninput = e => { ADD.url = e.target.value; };
    inp.onkeydown = e => { if (e.key === 'Enter') addDiscover(); };
    inp.focus();
  }
}

function retour() {
  const b = h('button', { type: 'button', class: 'btn sm', id: 'add-back', text: '← Retour' });
  b.onclick = () => { addStop(); ADD.step = ADD.step === 3 ? 2 : 1; addRender(); };
  return b;
}

function addStep1() {
  const url = h('input', {
    class: 'inp w-lg', id: 'add-url', placeholder: 'https://exemple.fr', value: ADD.url,
    'aria-label': 'URL du site à ajouter',
  });
  const scan = h('button', { type: 'button', class: 'btn primary sm', id: 'add-scan', text: 'Analyser' });
  scan.onclick = addDiscover;
  return [
    h('p', { class: 'hint', text: "Saisissez l'URL du site à ajouter : l'analyse détecte WordPress, "
      + "l'état de l'API REST, le multisite et un agent déjà installé." }),
    h('div', { class: 'filters' }, url, scan, zoneMessage('add-msg')),
    h('div', { id: 'add-res' }, ADD.info ? addInfo(ADD.info) : null),
  ];
}

function kv(cle, ...valeur) {
  return [h('span', { class: 'k', text: cle }), h('span', {}, ...valeur)];
}

function addInfo(i) {
  const shown = i.url_effective || i.home || ADD.url || '';
  const u = safeUrl(shown);
  const ns = Array.isArray(i.namespaces) ? i.namespaces.join(' · ') : '';
  const suivant = h('button', {
    type: 'button', class: 'btn primary sm', id: 'add-next',
    text: i.is_wordpress ? 'Continuer' : 'Continuer quand même',
  });
  suivant.onclick = () => { ADD.step = 2; addRender(); };
  return [
    h('div', { class: 'kv mt4' },
      kv('Site', h('b', { text: i.name || '—' })),
      kv('URL', u
        ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: shown })
        : h('span', { text: shown || '—' })),
      kv('WordPress', chipEl(i.is_wordpress ? 'détecté' : 'non détecté', i.is_wordpress ? 'ok' : 'err')),
      kv('API REST', chipEl(i.rest_open ? 'ouverte' : 'fermée ou filtrée', i.rest_open ? 'ok' : 'warn',
        ns ? { title: ns } : {})),
      kv('Agent Dash',
        chipEl(i.has_agent ? 'déjà installé' : 'absent', i.has_agent ? 'ok' : 'mut'),
        i.has_vizproof ? [' ', chipEl('VizProof présent', 'ok')] : null),
      kv('Multisite', i.multisite
        ? chipEl('oui — réglages dans Réseau → Dash Agent', 'warn')
        : chipEl('non', 'mut')),
      kv('Dans le parc', i.already_known
        ? chipEl('déjà connu du dashboard', 'warn')
        : chipEl('nouveau', 'ok'))),
    i.is_wordpress ? null : h('p', { class: 'hint mt3',
      text: "WordPress n'a pas été reconnu à cette adresse : vérifiez l'URL (redirection, "
        + 'sous-dossier, site en maintenance) avant de continuer.' }),
    h('div', { class: 'actions mt4' }, suivant),
  ];
}

async function addDiscover() {
  const msg = document.getElementById('add-msg'), res = document.getElementById('add-res');
  const inp = document.getElementById('add-url');
  if (inp) ADD.url = inp.value.trim();
  if (!ADD.url) {
    if (msg) mount(msg, h('span', { class: 'muted', text: 'indiquez une URL' }));
    return;
  }
  if (msg) mount(msg, h('span', { class: 'muted', text: 'analyse…' }));
  if (res) mount(res);
  let j;
  try { j = await api('/api/mgmt/discover', { url: ADD.url }) || {}; }
  catch (e) {
    if (msg) mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) }));
    return;
  }
  if (!ADD.open) return;
  if (j.ok === false || !j || typeof j !== 'object') {
    if (msg) {
      mount(msg, chipEl('analyse impossible', 'err'), ' ',
        h('span', { class: 'muted small', text: (j && j.error) || 'réponse vide' }));
    }
    ADD.info = null; ADD.step = 1;
    return;
  }
  ADD.info = j;
  ADD.domain = hostOf(j.url_effective || j.home || ADD.url);
  if (msg) mount(msg);
  if (res) mount(res, addInfo(j));
}

function addStep2() {
  const i = ADD.info || {}, ssh = i.suggestion === 'ssh';
  const carte = (m, titre, reco, txt) => {
    const c = h('div', { class: 'card choice' + (ADD.method === m ? ' sel' : ''), tabindex: '0', role: 'button' },
      h('b', {}, titre, reco ? [' ', chipEl('recommandé', 'ok')] : null),
      h('small', { text: txt }));
    const choisir = () => { ADD.method = m; ADD.step = 3; addRender(); };
    c.onclick = choisir;
    c.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choisir(); } };
    return c;
  };
  return [
    h('p', { class: 'hint', text: ssh
      ? 'Ce site est hébergé sur un serveur déjà connecté au dashboard : la voie SSH est la plus rapide.'
      : "Aucun serveur SSH connu n'héberge ce site : l'appairage est la voie adaptée." }),
    h('div', { class: 'cards' },
      carte('ssh', 'Via SSH', ssh,
        "Le serveur est déjà connecté : l'agent s'installe en une commande depuis « Installs découverts », "
        + 'sans rien toucher dans wp-admin.'),
      carte('pair', 'Sans SSH (appairage)', !ssh,
        "L'API REST de WordPress n'installe que des extensions publiées sur wordpress.org, or notre agent "
        + "est privé : on télécharge son ZIP, on l'installe depuis wp-admin, puis on colle un code d'appairage.")),
    h('div', { class: 'actions mt4' }, retour()),
  ];
}

function addStep3() {
  const i = ADD.info || {}, dom = ADD.domain || hostOf(ADD.url);
  if (ADD.method === 'ssh') {
    const aller = h('button', {
      type: 'button', class: 'btn primary sm', id: 'add-goinstalls',
      text: 'Aller à la ligne « ' + (dom || '?') + ' »',
    });
    aller.onclick = () => addGoInstalls(dom);
    return [
      h('p', { class: 'hint', text: 'Rien à installer à la main : la liaison se pose en SSH depuis la liste des installs.' }),
      h('div', { class: 'steps' }, h('ol', { class: 'small' },
        h('li', {}, 'Dans « Installs découverts », repérez la ligne ', h('b', { text: dom || 'du site' }), '.'),
        h('li', {}, 'Colonne « Dashboard » : cliquez sur ', h('b', { text: 'Connecter' }), ', puis confirmez le second clic.'),
        h('li', {}, 'La pastille passe à ', chipEl('connecté', 'ok'),
          ' — le site pousse alors ses évènements en temps réel.'))),
      h('div', { class: 'actions mt4' }, retour(), aller, h('span', { class: 'small', id: 'add-msg3' })),
    ];
  }
  const gen = h('button', { type: 'button', class: 'btn primary sm', id: 'add-gen', text: 'Générer un code' });
  gen.onclick = addGen;
  return [
    h('p', { class: 'hint', text: "Environ deux minutes dans l'admin du site. L'agent est une extension "
      + "privée : elle ne peut pas être installée à distance par l'API REST, d'où le ZIP + le code d'appairage." }),
    h('div', { class: 'actions' },
      h('a', { class: 'btn sm', id: 'add-zip', href: '/api/mgmt/agent.zip', download: true },
        iconEl('download'), " Télécharger l'agent (.zip)"),
      gen,
      zoneMessage('add-genmsg')),
    h('div', { id: 'add-code' }),
    h('div', { class: 'steps' }, h('ol', { class: 'small' },
      h('li', {}, 'Dans wp-admin : ', h('b', { text: 'Extensions → Ajouter → Téléverser une extension' }),
        ', puis choisissez le ZIP téléchargé.'),
      h('li', {}, h('b', { text: 'Activer' }), " l'extension."),
      h('li', {}, 'Ouvrez ', h('b', { text: i.multisite ? 'Réseau → Dash Agent' : 'Réglages → Dash Agent' }),
        h('span', { class: 'muted', text: i.multisite
          ? ' (site multisite : le réglage est au niveau du réseau)'
          : ' — en multisite, passez par Réseau → Dash Agent' }), '.'),
      h('li', {}, 'Collez le code ci-dessus, puis validez.'))),
    h('div', { class: 'small muted mt3', id: 'add-wait', text: 'Générez un code pour démarrer l’appairage.' }),
    h('div', { class: 'actions mt4' }, retour()),
  ];
}

function addWait(...contenu) {
  const el = document.getElementById('add-wait');
  if (el) mount(el, contenu);
}

function addTick() {
  const el = document.getElementById('add-exp');
  if (!el || !ADD.open) {
    if (ADD.timer) { clearInterval(ADD.timer); ADD.timer = null; }
    return;
  }
  const s = Math.max(0, Math.ceil((ADD.expires - Date.now()) / 1000));
  if (s <= 0) {
    mount(el, chipEl('code expiré — générez-en un nouveau', 'err'));
    clearInterval(ADD.timer); ADD.timer = null;
    return;
  }
  el.textContent = 'expire dans ' + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}

async function addGen() {
  const msg = document.getElementById('add-genmsg');
  addStop();
  if (msg) mount(msg, h('span', { class: 'muted', text: '…' }));
  let j;
  try { j = await api('/api/mgmt/pair_code', { url: ADD.url }) || {}; }
  catch (e) {
    if (msg) mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) }));
    return;
  }
  if (!ADD.open) return;
  const code = String((j && j.code) || '');
  if (!code) {
    if (msg) {
      mount(msg, chipEl('échec', 'err'), ' ',
        h('span', { class: 'muted small', text: (j && j.error) || 'aucun code renvoyé' }));
    }
    return;
  }
  if (msg) mount(msg);
  ADD.expires = Date.now() + (Number(j.expires_in) || 0) * 1000;
  const box = document.getElementById('add-code');
  if (box) {
    mount(box,
      h('div', { class: 'codebox' },
        h('span', { class: 'codebig', id: 'add-codeval', text: code }),
        h('span', { class: 'muted small ml-8', id: 'add-exp' })),
      h('div', { class: 'muted small', text: 'Code à usage unique : cliquez dessus pour le sélectionner.' }),
      h('div', { class: 'muted small mt1' },
        'À coller dans ', h('b', { text: 'Réglages → Dash Agent' }), ' du site, avec l’adresse du dashboard : ',
        h('code', { text: location.origin })));
  }
  addTick();
  ADD.timer = setInterval(addTick, 1000);
  ADD.pollUntil = Date.now() + 360000;
  addWait(chipEl("en attente d'appairage…", 'warn'), ' ',
    h('span', { class: 'muted small', text: 'vérification toutes les 5 s' }));
  ADD.poll = setTimeout(addPoll, 5000);
}

async function addPoll() {
  ADD.poll = null;
  if (!ADD.open) return;
  if (Date.now() > ADD.pollUntil) {
    addWait(chipEl('appairage non détecté', 'mut'), ' ',
      h('span', { class: 'muted small', text: 'générez un nouveau code et réessayez.' }));
    return;
  }
  let j = null;
  try { j = await api('/api/mgmt/rest_sites'); } catch (e) { /* réessai au tour suivant */ }
  if (!ADD.open) return;
  const want = ADD.domain || hostOf(ADD.url);
  const hit = restList(j).some(x => x && hostOf(restDomain(x) || x.url) === want);
  if (!hit) { ADD.poll = setTimeout(addPoll, 5000); return; }

  addStop();
  const bloc = [
    chipEl('site appairé', 'ok'), ' ',
    h('span', { class: 'muted small', text: 'il apparaît maintenant dans le parc.' }),
  ];
  if (WPAUTH_ENABLED) {
    const bt = h('button', { type: 'button', class: 'btn primary sm', id: 'add-wpauth' },
      iconEl('link'), " Autoriser l'installation d'extensions (1 clic)");
    bt.onclick = () => wpAuthorize(bt, '', want, (ok, err) => {
      const m = document.getElementById('add-wpmsg');
      if (!m) return;
      if (ok) mount(m, chipEl("approuvez dans l'onglet ouvert…", 'warn'));
      else mount(m, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: err }));
    });
    bloc.push(h('div', { class: 'mt3' }, bt, ' ', zoneMessage('add-wpmsg'),
      h('div', { class: 'muted small mt1' }, h('b', { text: 'Étape facultative.' }), ' ' + WPAUTH_HELP
        + ' Le dashboard pourra alors installer les extensions publiques (VizProof…) sans SSH.')));
  }
  addWait(bloc);
  HOOKS.apresAppairage();
  loadFleet();
}

function addGoInstalls(dom) {
  const msg = document.getElementById('add-msg3');
  if (HOOKS.allerInstalls(dom)) { closeAdd(); return; }
  if (msg) {
    mount(msg, chipEl('ligne introuvable', 'warn'), ' ',
      h('span', { class: 'muted small', text: 'lancez une collecte pour que le site apparaisse.' }));
  }
}

/* ---- branchements de la modale --------------------------------------------- */
document.getElementById('add-close').onclick = closeAdd;
document.getElementById('addmodal').onclick = e => { if (e.target.id === 'addmodal') closeAdd(); };
registerModalCloser('addmodal', closeAdd);
