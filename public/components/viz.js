/* VizProof : lecture de l'état d'un site, cellule du tableau, bloc de la page
   site, et les trois opérations (installer, connecter, dissocier).

   Tout est réuni ici parce que l'écran Parc et la page site déduisaient
   séparément le même état et finissaient par se contredire : un seul
   `vizState()` fait foi, la colonne et le bloc en découlent. */

import { api } from '../lib/api.js';
import { esc as H, h } from '../lib/dom.js';
import { absTime, relTime, safeUrl, stripPhpNoise } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { poll } from '../lib/poll.js';
import { kName, loadFleet } from '../lib/state.js';
import { setBusy, setIdle } from './button.js';
import { askConfirm, askInfo, registerModalCloser } from './confirm.js';
import { NOTIF } from './toast.js';

/* Réglages VizProof (jeton enregistré) : fournis par l'écran Réglages, qui les
   lit paresseusement. Enregistrés plutôt qu'importés — ce composant ne doit
   dépendre d'aucun écran. */
let SETTINGS = async () => ({});
export function setVizSettings(fn) { SETTINGS = fn; }

/* Rafraîchissement de la page site après une opération (le store a changé mais
   la console et l'onglet courant doivent être conservés). */
let REFRESH = () => {};
export function setVizRefresh(fn) { REFRESH = fn; }

/* Console d'exécution de la page site : `(domaine) → élément | null`. */
let CONSOLE_DE = () => null;
export function setVizConsole(fn) { CONSOLE_DE = fn; }

export const VIZ = 'vizproof-timeline';

export function vizOf(s) { return (s.plugins_list || []).find(p => p.name === VIZ) || null; }
export function vizInfo(s) { const v = s && s.vizproof; return (v && typeof v === 'object') ? v : null; }
export function vizConnected(s) { const v = vizInfo(s); return !!(v && v.connected); }
export function vizRun(s) { const v = vizInfo(s); const r = v && v.last_run; return (r && typeof r === 'object') ? r : null; }
export function vizAnom(s) {
  const r = vizRun(s);
  if (!r) return false;
  return (Number(r.anomalies) > 0) || /anomal/i.test(String(r.status ?? ''));
}
/* `configured` est arrivé avec la 1.3.6 côté plugin ; sur un inventaire plus
   ancien, la connexion établie est la seule preuve disponible. */
function vizConfigured(s) { const v = vizInfo(s); if (!v) return false; return v.configured === undefined ? !!v.connected : !!v.configured; }
/* La CLI `wp vizproof` n'existe qu'à partir de la 1.3 : en dessous, le plugin
   est bien là mais le dashboard ne peut rien en faire tant qu'il n'est pas à jour. */
function vizVerOld(ver) {
  const m = /^(\d+)\.(\d+)/.exec(String(ver || ''));
  if (!m) return true;
  const M = +m[1], n = +m[2];
  return M < 1 || (M === 1 && n < 3);
}
/* 'nodata' inventaire absent · 'absent' pas installé · 'inactif' désactivé
   · 'nocli' trop ancien pour la CLI · 'nonconnecte' · 'connecte'. */
export function vizState(s) {
  const list = s.plugins_list || [], p = vizOf(s), v = vizInfo(s);
  if (!p && !v) return list.length ? 'absent' : 'nodata';
  if (p && p.status && p.status !== 'active') return 'inactif';
  const ver = (v && v.version) || (p && p.version) || '';
  if (!v || v.has_cli === false || (ver && vizVerOld(ver))) return 'nocli';
  return (vizConfigured(s) && v.connected) ? 'connecte' : 'nonconnecte';
}
export function vizVersion(s) { const v = vizInfo(s), p = vizOf(s); return (v && v.version) || (p && p.version) || '?'; }
/** Connectable d'ici ? Il faut du SSH : l'agent REST est en lecture seule. */
export function vizConnectable(s) { return s.via !== 'rest' && ['nonconnecte', 'connecte'].includes(vizState(s)); }
export function vizAdminUrl(s) {
  return safeUrl((s.siteurl || ('https://' + s.domain)).replace(/\/+$/, '')
    + '/wp-admin/admin.php?page=vizproof-timeline');
}
/* tri : anomalies(-1) < absent(0) < inactif(.5) < sans CLI(.8) < non connecté(1)
   < connecté sans run(2) < connecté OK(3) < sans données(4) */
export function vizVal(s) {
  const e = vizState(s);
  if (e === 'nodata') return 4;
  if (e === 'absent') return 0;
  if (e === 'inactif') return .5;
  if (e === 'nocli') return .8;
  if (e === 'nonconnecte') return 1;
  if (vizAnom(s)) return -1;
  return vizRun(s) ? 3 : 2;
}

/* Un lien ouvert dans un onglet ne doit pas aussi ouvrir la page du site :
   la ligne du tableau est cliquable, le lien capte donc son propre clic. */
function lienEl(url, texte, cls) {
  const u = safeUrl(url);
  if (!u) return null;
  const a = h('a', { class: cls || 'small', href: u, target: '_blank', rel: 'noopener noreferrer' }, texte);
  a.onclick = e => e.stopPropagation();
  return a;
}

/** Pastille du dernier scan, commune à la colonne et à la page site. */
export function vizRunBadgeEl(s) {
  const r = vizRun(s);
  if (!r) return null;
  const bad = vizAnom(s), an = Number(r.anomalies) || 0;
  const ttl = 'dernier scan : ' + (r.at ? absTime(r.at) : '?') + ' · '
    + (bad ? ((an || '?') + ' anomalie(s) visuelle(s)') : 'aucune anomalie');
  const corps = bad
    ? h('span', { class: 'pill err' }, iconEl('triangle-alert'), String(an || 'anomalies'))
    : h('span', { class: 'dot up' });
  const u = safeUrl(r.url);
  if (!u) return h('span', { class: 'vizrun', title: ttl }, corps);
  const a = h('a', { class: 'vizrun', href: u, target: '_blank', rel: 'noopener noreferrer', title: ttl }, corps);
  a.onclick = e => e.stopPropagation();
  return a;
}

/* ---- cellule de la colonne VizProof du tableau --------------------------- */
export function vizCellEl(s) {
  const e = vizState(s), ver = vizVersion(s);
  if (e === 'nodata') return document.createTextNode('—');
  if (e === 'absent') {
    if (s.via === 'rest') return h('span', { class: 'pill mut', title: 'site sans SSH : installation depuis la page du site', text: 'absent' });
    const b = h('button', { type: 'button', class: 'btn sm' }, iconEl('plus'), 'installer');
    b.onclick = ev => { ev.stopPropagation(); vizInstall(b, s.srv, s.domain); };
    return b;
  }
  if (e === 'inactif') return h('span', { class: 'pill mut', title: 'extension présente mais désactivée', text: 'v' + ver + ' · inactif' });
  if (e === 'nocli') {
    return h('span', {
      class: 'pill warn',
      title: "cette version n'expose pas la commande wp vizproof — mettez l'extension à jour",
      text: 'v' + ver + ' · à mettre à jour',
    });
  }
  if (e === 'nonconnecte') {
    const frag = h('span', { class: 'vizwrap' },
      h('span', { class: 'pill warn', title: 'extension installée mais pas encore reliée à VizProof', text: 'v' + ver + ' · non connecté' }));
    if (s.via !== 'rest') {
      const b = h('button', { type: 'button', class: 'btn sm', text: 'Connecter' });
      b.onclick = ev => { ev.stopPropagation(); openVizConnect([s]); };
      frag.append(b);
    }
    const a = lienEl(vizAdminUrl(s), 'wp-admin');
    if (a) frag.append(a);
    return frag;
  }
  const n = Number((vizInfo(s) || {}).pages) || 0;
  return h('span', { class: 'vizwrap' },
    h('span', { class: 'pill ok', text: 'v' + ver + ' · ' + n + ' page' + (n > 1 ? 's' : '') }),
    vizRunBadgeEl(s));
}

/* ---- bloc VizProof de la page site --------------------------------------- */
function vizLastRunEl(s) {
  const r = vizRun(s);
  if (!r) return h('p', { class: 'hint hint-tight', text: 'Aucun scan visuel enregistré pour l’instant.' });
  const bad = vizAnom(s), an = Number(r.anomalies) || 0;
  const stt = String(r.status || '').toLowerCase();
  const casse = /err|échec|echec|fail/.test(stt);
  const cls = bad ? 'warn' : (casse ? 'err' : 'ok');
  const quoi = bad ? ((an || '?') + ' anomalie' + (an > 1 ? 's' : ''))
    : (casse ? (r.status || 'échec') : 'aucune anomalie');
  return h('p', { class: 'hint hint-tight' }, 'Dernier scan ',
    h('span', { title: absTime(r.at), text: relTime(r.at) }), ' ',
    h('span', { class: 'pill ' + cls, text: quoi }), ' ',
    lienEl(r.url, 'voir le rapport'));
}

export function vizBlocEl(s) {
  const e = vizState(s);
  if (e === 'nodata') return null;
  const ver = vizVersion(s), rest = s.via === 'rest';
  const n = Number((vizInfo(s) || {}).pages) || 0;
  const sid = (vizInfo(s) || {}).site_id;
  const txt = h('p', { class: 'hint hint-tight' });
  const btns = h('div', { class: 'actions' });

  if (e === 'absent') {
    txt.append('Extension non installée sur ce site.');
    // Sans SSH, l'installation passe par l'autorisation WordPress : le bouton
    // est posé par gestion.js une fois les identifiants connus, pas ici.
    if (!rest) {
      const b = h('button', { type: 'button', class: 'btn sm', text: 'Installer vizproof' });
      b.dataset.act = 'vizproof_install';
      btns.append(b);
    }
  } else if (e === 'inactif') {
    txt.append('Extension présente en v' + ver + ' mais ', h('b', { text: 'désactivée' }), ' — à activer depuis wp-admin.');
  } else if (e === 'nocli') {
    txt.append('Extension en v' + ver + ' : cette version n’expose pas la commande ',
      h('code', { text: 'wp vizproof' }),
      '. Mettez-la à jour (bouton de MAJ de l’extension) pour pouvoir la connecter d’ici.');
  } else if (e === 'nonconnecte') {
    txt.append('Extension en v' + ver + ' installée, mais ', h('b', { text: 'pas encore reliée' }), ' à VizProof.');
    if (rest) txt.append(' Ce site est géré sans SSH : la connexion se fait depuis wp-admin.');
    else {
      const b = h('button', { type: 'button', class: 'btn primary sm', text: 'Connecter VizProof' });
      b.onclick = () => openVizConnect([s]);
      btns.append(b);
    }
  } else {
    txt.append('Reliée à VizProof · ', h('b', { text: n + ' page' + (n > 1 ? 's' : '') }), ' suivie' + (n > 1 ? 's' : ''));
    if (sid) txt.append(' · identifiant ', h('code', { text: String(sid) }));
    txt.append('.');
    if (!rest) {
      const b = h('button', { type: 'button', class: 'btn sm', text: 'Dissocier' });
      b.onclick = () => vizDisconnect(b, s);
      btns.append(b);
    }
  }
  const a = lienEl(vizAdminUrl(s), 'ouvrir dans wp-admin');
  if (a) txt.append(' ', a);
  if (e === 'connecte') { const p = vizRunBadgeEl(s); if (p) txt.append(' ', p); }

  return h('div', { class: 'agroup' },
    h('span', { class: 'glbl', text: 'VizProof' }),
    txt,
    e === 'connecte' ? vizLastRunEl(s) : null,
    btns.children.length ? btns : null);
}

/* ---- contrôle visuel automatique après une MAJ unitaire (réponse `viz`) ----
   Le scan est le plus souvent lancé par le PLUGIN lui-même : le dashboard
   attend ce verdict-là et ne scanne qu'en repli. D'où `phase` pendant
   l'attente et `source` dans le verdict. */
export const VIZ_PHASES = {
  'attente du scan du plugin': 'le plugin VizProof scanne…',
  'scan en cours': 'scan du plugin en cours…',
  'scan dashboard': 'scan lancé par le dashboard…',
};
function vizSource(v) {
  return v && v.source === 'plugin' ? ' (scan du plugin)'
    : v && v.source === 'dashboard' ? ' (scan dashboard)' : '';
}
export function vizPhrase(v) {
  if (!v || typeof v !== 'object') return '';
  if (v.pending) return VIZ_PHASES[v.phase] || 'contrôle en cours…';
  if (!v.ran) return 'non lancé (' + (v.reason || v.message || '?') + ')';
  const n = Number(v.anomalies_count) || 0;
  if (v.anomalies) return 'anomalies détectées' + (n ? ' (' + n + ')' : '') + vizSource(v);
  if (Number(v.rc) === 0) return 'aucune anomalie' + vizSource(v);
  /* rc absent : le scan du plugin n'était pas terminé dans le délai d'attente —
     ni « ok » ni « échec », un verdict qui n'est pas venu. */
  if (v.rc == null) return (v.message || 'verdict non parvenu') + vizSource(v);
  return 'échec (' + (v.message || ('rc ' + (v.rc ?? '?'))) + ')' + vizSource(v);
}
/* « Non lancé » est NEUTRE : la grande majorité des sites n'est pas reliée à
   VizProof, tout mettre en orange reviendrait à ne plus rien signaler. */
export function vizEtat(v) {
  if (!v) return '';
  if (v.pending) return 'warn';
  if (!v.ran) return '';
  if (v.anomalies || v.rc == null) return 'warn';
  return Number(v.rc) === 0 ? 'ok' : 'err';
}
export function vizConsoleLigne(v) {
  if (!v) return '';
  const u = safeUrl(v.report_url);
  // Marqueur : le verdict REMPLACE le « scan en cours… » au lieu de s'empiler.
  return `<span data-vizline><b class="${vizEtat(v)}">Contrôle visuel VizProof : ${H(vizPhrase(v))}</b>`
    + (u ? ` <a href="${H(u)}" target="_blank" rel="noopener noreferrer">rapport</a>` : '') + '</span>';
}
export function vizConsoleMaj(dom, v) {
  const c = CONSOLE_DE(dom);
  if (!c) return;
  const l = c.querySelector('[data-vizline]');
  if (l) l.outerHTML = vizConsoleLigne(v);
  else c.innerHTML += '\n' + vizConsoleLigne(v);
}
/* Le contrôle se joue côté serveur APRÈS la réponse : on interroge
   /api/actions/viz_last jusqu'au verdict, borné dans le temps. */
export function suivreVizLast(srv, dom, nid) {
  let tours = 0, vue = null;
  poll('vizlast:' + dom, async () => {
    if (++tours > 150) return { fini: true, perdu: true };        // ≈ 10 min
    const j = await api('/api/actions/viz_last?domain=' + encodeURIComponent(dom));
    const v = (j && j.viz) || null;
    if (!v || v.pending) {
      if (v && v.phase && v.phase !== vue) {
        vue = v.phase;
        NOTIF.update(nid, { detail: 'contrôle visuel : ' + vizPhrase(v), progress: null });
        vizConsoleMaj(dom, v);
      }
      return { fini: false };
    }
    NOTIF.done(nid, { ok: vizEtat(v) !== 'err', warn: vizEtat(v) === 'warn', message: 'contrôle visuel : ' + vizPhrase(v) });
    vizConsoleMaj(dom, v);
    loadFleet().catch(() => {});
    return { fini: true };
  }, {
    every: 4000, maxErrors: 5, until: r => !!(r && r.fini),
    onStop: () => NOTIF.done(nid, { ok: false, message: 'contrôle visuel : suivi interrompu, voir l’historique du site' }),
  });
}

/* ---- installation --------------------------------------------------------- */
export async function vizInstall(btn, srv, dom) {
  if (!await askConfirm(`Installer et activer <b>${H(VIZ)}</b> sur <b>${H(dom)}</b> ?`,
    { titre: 'Installer VizProof', ok: 'Installer' })) return;
  const cle = srv + '|' + dom;
  setBusy(btn, 'installation…');
  const nid = NOTIF.start({ id: 'vizinstall:' + cle, label: 'Installation VizProof · ' + dom, kind: 'install', site: { srv, domain: dom } });
  try {
    const j = await api('/api/actions/run', { server: srv, domain: dom, action: 'vizproof_install', arg: null });
    if (!j.ok) {
      const t = String(j.output || ('rc ' + j.rc)).slice(-300);
      NOTIF.done(nid, { ok: false, message: t });
      setIdle(btn);
      askInfo('Installation impossible', H(t));
      return;
    }
    await api('/api/actions/run', { server: srv, domain: dom, action: 'rescan', arg: null });
    NOTIF.done(nid, { ok: true, message: 'extension installée et activée' });
    await loadFleet();
    REFRESH();
  } catch (e) {
    NOTIF.done(nid, { ok: false, message: String(e) });
    setIdle(btn);
  }
}

/* ---- connexion d'un site (ou d'un lot) à VizProof ----
   Depuis que le jeton de compte s'enregistre dans les Réglages, le cas courant
   est le clic unique : ni jeton à saisir, ni identifiant à trouver. Les champs
   restent là pour les cas particuliers. */
let VZSITES = [], VZTOK = false;
function vizSlug(d) {
  return String(d || '').toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
}
const VZ_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;

export function closeViz() { document.getElementById('vizmodal').classList.remove('open'); }

function brancherModale() {
  document.getElementById('vz-cancel').onclick = closeViz;
  document.getElementById('vizmodal').onclick = e => { if (e.target.id === 'vizmodal') closeViz(); };
  document.getElementById('vz-adv').onclick = () => {
    const b = document.getElementById('vz-advbox');
    b.hidden = !b.hidden;
    document.getElementById('vz-adv').textContent = b.hidden ? 'Options avancées' : 'Masquer les options';
  };
  document.getElementById('vz-mode').onchange = e => {
    const tok = e.target.value === 'token';
    document.getElementById('vz-tokwrap').hidden = !tok;
    document.getElementById('vz-codewrap').hidden = tok;
  };
  /* Le bloc « jeton / code » se replie derrière un lien dès qu'un jeton est
     enregistré : on ne montre un champ secret que si on en a besoin. */
  document.getElementById('vz-othertok').onclick = () => {
    document.getElementById('vz-credbox').hidden = false;
    document.getElementById('vz-othertok').hidden = true;
    const f = document.getElementById('vz-token');
    if (f) f.focus();
  };
  document.getElementById('vz-setlink').onclick = () => { closeViz(); document.getElementById('setbtn').click(); };
  registerModalCloser('vizmodal', closeViz);
}
brancherModale();

function vzOtherTok() { return !document.getElementById('vz-credbox').hidden; }

export async function openVizConnect(sites) {
  // Éligibles : accès SSH et une CLI vizproof réellement disponible.
  VZSITES = (sites || []).filter(s => s && vizConnectable(s));
  if (!VZSITES.length) {
    askInfo('Connecter VizProof',
      "Aucun site éligible dans la sélection. Il faut un accès <b>SSH</b> et une extension VizProof assez récente "
      + "pour exposer <code>wp vizproof</code> (pastille « à mettre à jour » sinon).");
    return;
  }
  const cfg = await SETTINGS();
  VZTOK = !!cfg.vizproof_token_set;
  document.getElementById('vz-intro').innerHTML = VZSITES.length > 1
    ? `<b>${VZSITES.length}</b> site(s) à relier.` + (VZTOK
      ? ' Le jeton enregistré vaut pour tous ; laissez l’identifiant vide pour que chaque site soit retrouvé ou créé d’après son URL.'
      : " L'identifiant est propre à chaque site ; le jeton, lui, est celui de votre compte et vaut pour tous.")
    : `Relier <b>${H(kName(VZSITES[0]) || VZSITES[0].domain)}</b> à VizProof.`;
  document.getElementById('vz-rows').innerHTML = VZSITES.map((s, i) => {
    // Avec un jeton enregistré, le champ reste VIDE : « par URL » est le défaut.
    const cur = VZTOK ? '' : ((vizInfo(s) || {}).site_id || vizSlug(s.domain));
    return `<div class="logline"><b>${H(kName(s) || s.domain)}</b>
      <span class="muted small">${H(s.srv)}</span>
      <input class="inp w-sm" data-vzid="${i}" aria-label="${H('identifiant VizProof de ' + s.domain)}"
             autocomplete="off" spellcheck="false" value="${H(cur)}"
             placeholder="${VZTOK ? 'par URL' : ''}">
      <span class="small" data-vzres="${i}"></span></div>`;
  }).join('');
  document.getElementById('vz-idhint').hidden = !VZTOK;
  document.getElementById('vz-tokstored').hidden = !VZTOK;
  document.getElementById('vz-toktail').textContent = '…' + (cfg.vizproof_token_tail || '');
  document.getElementById('vz-othertok').hidden = false;
  document.getElementById('vz-credbox').hidden = VZTOK;   // replié tant qu'un jeton suffit
  document.getElementById('vz-goset').hidden = VZTOK;
  document.getElementById('vz-out').innerHTML = '';
  document.getElementById('vz-apercu').innerHTML = '';
  document.getElementById('vz-token').value = '';
  document.getElementById('vz-code').value = '';
  const go = document.getElementById('vz-go');
  go.disabled = false;
  go.textContent = (VZTOK && VZSITES.length > 1) ? `Connecter ${VZSITES.length} sites` : 'Connecter';
  go.onclick = runVizConnect;
  const ap = document.getElementById('vz-preview');
  ap.hidden = !VZTOK; ap.disabled = false; ap.textContent = 'Aperçu';
  ap.onclick = () => runVizPreview();
  const an = document.getElementById('vz-cancel');
  an.textContent = 'Annuler'; an.className = 'btn';
  document.getElementById('vizmodal').classList.add('open');
  const f = document.querySelector('#vz-rows input');
  if (f) f.focus();
  // Aperçu automatique sur un site unique : on affiche AVANT de connecter quel
  // site VizProof recevra ce WordPress.
  if (VZTOK && VZSITES.length === 1) runVizPreview().catch(() => {});
}

/* Aperçu : `viz_resolve` ne crée rien. Il dit quel site existant sera relié. */
function vizApercuTexte(j) {
  if (!j || j.ok === false) return `<span class="pill err">aperçu impossible</span> <span class="muted">${H(String((j && j.error) || 'échec'))}</span>`;
  const nom = H(j.name || j.host || '?');
  if (j.created) return `<span class="pill ok">Site VizProof : <b>${nom}</b></span> <span class="muted">créé pour <code>${H(j.host || '')}</code></span>`;
  if (j.would_create) return `<span class="pill warn">Aucun site VizProof pour <code>${H(j.host || '')}</code></span> <span class="muted">il sera créé à la connexion</span>`;
  return `<span class="pill ok">Site VizProof : <b>${nom}</b></span> <span class="muted">existant, domaine <code>${H(j.matched_domain || j.host || '')}</code></span>`
    + (j.ambiguous ? ' <span class="pill warn" title="plusieurs sites VizProof portent cet hôte : le premier est retenu">ambigu</span>' : '');
}
async function vizResolveOne(s) {
  const corps = { server: s.srv, domain: s.domain };
  const api_base = document.getElementById('vz-api').value.trim();
  if (api_base) corps.api_base = api_base;
  try { return await api('/api/actions/viz_resolve', corps) || {}; }
  catch (e) { return { ok: false, error: String(e) }; }
}
async function runVizPreview() {
  const zone = document.getElementById('vz-apercu'), ap = document.getElementById('vz-preview');
  ap.disabled = true; ap.textContent = '…';
  if (VZSITES.length === 1) {
    zone.innerHTML = '<span class="muted">aperçu…</span>';
    zone.innerHTML = vizApercuTexte(await vizResolveOne(VZSITES[0]));
  } else {
    zone.innerHTML = '<span class="muted">aperçu des ' + VZSITES.length + ' sites…</span>';
    for (let i = 0; i < VZSITES.length; i++) {
      const res = document.querySelector(`#vz-rows [data-vzres="${i}"]`);
      if (res) res.innerHTML = '<span class="pill mut">…</span>';
      const j = await vizResolveOne(VZSITES[i]);
      if (res) {
        res.innerHTML = (j && j.ok)
          ? `<span class="pill ${j.created ? 'warn' : 'ok'}" title="${H(j.site_id || '')}">${H(j.name || j.host || '?')} · ${j.created ? 'créé' : 'existant'}</span>`
          : `<span class="pill err" title="${H(String((j && j.error) || ''))}">aperçu échoué</span>`;
      }
    }
    zone.innerHTML = '<span class="muted">aperçu terminé — rien n’a été connecté.</span>';
  }
  ap.disabled = false; ap.textContent = 'Aperçu';
}

async function runVizConnect() {
  const autre = vzOtherTok();
  const mode = document.getElementById('vz-mode').value;
  const token = autre ? document.getElementById('vz-token').value.trim() : '';
  const code = autre ? document.getElementById('vz-code').value.trim() : '';
  const api_base = document.getElementById('vz-api').value.trim();
  const scope = document.getElementById('vz-scope').value;
  const out = document.getElementById('vz-out');
  const ids = VZSITES.map((s, i) => document.querySelector(`#vz-rows [data-vzid="${i}"]`).value.trim());
  // Vide = résolution par URL côté serveur ; sinon le jeu de caractères est fermé.
  const mauvais = ids.findIndex(v => v !== '' ? !VZ_ID_RE.test(v) : !VZTOK);
  if (mauvais >= 0) {
    out.innerHTML = ids[mauvais] === ''
      ? '<span class="pill err">identifiant requis</span> <span class="muted">enregistrez un jeton VizProof dans les Réglages pour le déduire de l’URL.</span>'
      : '<span class="pill err">identifiant invalide</span> <span class="muted">lettres, chiffres, « _ » et « - », 80 caractères au plus.</span>';
    document.querySelector(`#vz-rows [data-vzid="${mauvais}"]`).focus();
    return;
  }
  if (autre && mode === 'token' && !token) { out.innerHTML = '<span class="pill err">jeton manquant</span>'; return; }
  if (autre && mode === 'code' && !code) { out.innerHTML = '<span class="pill err">code manquant</span>'; return; }
  const go = document.getElementById('vz-go');
  const lbl = go.textContent;
  go.disabled = true; go.textContent = 'en cours…';
  out.innerHTML = '';
  const seul = VZSITES.length === 1;
  const nid = NOTIF.start({
    id: 'vizconnect', kind: 'connect',
    label: 'Connexion VizProof' + (seul ? ' · ' + (kName(VZSITES[0]) || VZSITES[0].domain) : ' · ' + VZSITES.length + ' sites'),
    progress: seul ? null : 0,
    site: seul ? { srv: VZSITES[0].srv, domain: VZSITES[0].domain } : null,
  });
  let nok = 0;
  for (let i = 0; i < VZSITES.length; i++) {
    const s = VZSITES[i], res = document.querySelector(`#vz-rows [data-vzres="${i}"]`);
    if (!seul) NOTIF.update(nid, { progress: i / VZSITES.length, detail: s.domain });
    if (res) res.innerHTML = '<span class="pill mut">…</span>';
    const corps = { server: s.srv, domain: s.domain };
    if (ids[i]) corps.site_id = ids[i];
    if (autre) { if (mode === 'token') corps.token = token; else corps.code = code; }
    if (api_base) corps.api_base = api_base;
    if (scope) corps.scope = scope;
    let j;
    try { j = await api('/api/actions/viz_connect', corps) || {}; }
    catch (e) { j = { ok: false, rc: '—', error: String(e) }; }
    if (j.ok) nok++;
    const det = stripPhpNoise(String(j.output || j.error || '')).slice(-200);
    const sid = j.site_id ? ` <span class="muted">${H(j.site_name || j.site_id)}${j.site_created ? ' · créé' : ' · existant'}</span>` : '';
    if (res) {
      res.innerHTML = (j.ok ? '<span class="pill ok">connecté</span>'
        : `<span class="pill err" title="${H(det)}">rc ${H(j.rc ?? '?')}</span>`) + sid;
    }
    if (!j.ok) out.innerHTML += `<div class="logline"><b>${H(s.domain)}</b> <code>${H(det || 'échec')}</code></div>`;
  }
  // Le champ jeton n'est jamais réinjecté : il est vidé dès l'envoi.
  document.getElementById('vz-token').value = '';
  document.getElementById('vz-code').value = '';
  NOTIF.done(nid, {
    ok: nok === VZSITES.length, warn: !!nok && nok < VZSITES.length,
    message: nok + '/' + VZSITES.length + ' connecté' + (nok > 1 ? 's' : ''),
  });
  out.innerHTML = `<div class="mt2"><span class="pill ${nok === VZSITES.length ? 'ok' : nok ? 'warn' : 'err'}">${nok}/${VZSITES.length} connecté(s)</span></div>` + out.innerHTML;
  go.textContent = lbl; go.disabled = false;
  const an = document.getElementById('vz-cancel');
  an.textContent = 'Fermer'; an.className = 'btn primary';
  if (nok) loadFleet().then(() => REFRESH()).catch(() => {});
}

export async function vizDisconnect(btn, s) {
  if (!await askConfirm(`Dissocier <b>${H(s.domain)}</b> de VizProof ?<br><br>Le suivi visuel s'arrête ; l'extension reste installée.`,
    { titre: 'Dissocier VizProof', ok: 'Dissocier', danger: true })) return;
  setBusy(btn, 'en cours…');
  const nid = NOTIF.start({
    kind: 'connect', label: 'Dissociation VizProof · ' + (kName(s) || s.domain),
    site: { srv: s.srv, domain: s.domain },
  });
  let j;
  try { j = await api('/api/actions/viz_disconnect', { server: s.srv, domain: s.domain }) || {}; }
  catch (e) { j = { ok: false, error: String(e) }; }
  setIdle(btn);
  NOTIF.done(nid, { ok: !!j.ok, message: j.ok ? '' : stripPhpNoise(String(j.output || j.error || '')).slice(-160) });
  if (!j.ok) {
    askInfo('Dissociation impossible', H(stripPhpNoise(String(j.output || j.error || '')).slice(-300) || 'échec'));
    return;
  }
  await loadFleet();
  REFRESH();
}
