/* VizProof : lecture de l'état d'un site, cellule du tableau, bloc de la page
   site, et les trois opérations (installer, connecter, dissocier).

   Tout est réuni ici parce que l'écran Parc et la page site déduisaient
   séparément le même état et finissaient par se contredire : un seul
   `vizState()` fait foi, la colonne et le bloc en découlent. */

import { api } from '../lib/api.js';
import { auBas, collerEnBas, esc as H, h, mount } from '../lib/dom.js';
import { absTime, debounce, relTime, safeUrl, stripPhpNoise } from '../lib/format.js';
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

const VIZ = 'vizproof-timeline';

export function vizOf(s) { return (s.plugins_list || []).find(p => p.name === VIZ) || null; }
export function vizInfo(s) { const v = s && s.vizproof; return (v && typeof v === 'object') ? v : null; }
export function vizConnected(s) { const v = vizInfo(s); return !!(v && v.connected); }
function vizRun(s) { const v = vizInfo(s); const r = v && v.last_run; return (r && typeof r === 'object') ? r : null; }
function vizAnom(s) {
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
function vizVersion(s) { const v = vizInfo(s), p = vizOf(s); return (v && v.version) || (p && p.version) || '?'; }
/** Connectable d'ici ? Il faut du SSH : l'agent REST est en lecture seule. */
function vizConnectable(s) { return s.via !== 'rest' && ['nonconnecte', 'connecte'].includes(vizState(s)); }
function vizAdminUrl(s) {
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

/* ---- vocabulaire d'état ----------------------------------------------------
   UN seul jeu de mots pour les trois endroits qui parlent de VizProof : la
   colonne du Parc, le bloc de l'onglet Aperçu et le menu d'actions de la page
   site. Ils disaient la même chose de trois façons — « non connecté », « pas
   encore reliée », « extension déjà présente » — et on ne savait plus, devant
   le menu, si le plugin était installé, relié, ou ni l'un ni l'autre.

   `court` tient dans une chip de tableau ; `long` est la ligne d'état d'un
   menu ou d'une fiche ; `niveau` est l'un des quatre du langage d'état. */
export function vizEtatTexte(s) {
  const e = vizState(s), v = 'v' + vizVersion(s);
  const n = Number((vizInfo(s) || {}).pages) || 0;
  const pages = n + ' page' + (n > 1 ? 's' : '');
  if (e === 'nodata') {
    return { etat: e, niveau: 'mut', court: 'inconnu',
      long: 'état inconnu — aucun inventaire d’extensions pour ce site' };
  }
  if (e === 'absent') return { etat: e, niveau: 'mut', court: 'absent', long: 'extension absente' };
  if (e === 'inactif') {
    return { etat: e, niveau: 'mut', court: v + ' · inactif',
      long: 'installée en ' + v + ', mais désactivée' };
  }
  if (e === 'nocli') {
    return { etat: e, niveau: 'warn', court: v + ' · à mettre à jour',
      long: v + ' — trop ancienne pour être pilotée d’ici (wp vizproof absent)' };
  }
  if (e === 'nonconnecte') {
    return { etat: e, niveau: 'warn', court: v + ' · non connecté',
      long: 'installée en ' + v + ', pas encore reliée' };
  }
  const r = vizRun(s);
  return { etat: e, niveau: vizAnom(s) ? 'warn' : 'ok', court: v + ' · ' + pages,
    long: 'reliée · ' + pages + ' surveillée' + (n > 1 ? 's' : '') + ' · '
      + (r && r.at ? 'dernier scan ' + relTime(r.at) : 'aucun scan enregistré') };
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
function vizRunBadgeEl(s) {
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
  const t = vizEtatTexte(s), e = t.etat;
  if (e === 'nodata') return document.createTextNode('—');
  if (e === 'absent') {
    if (s.via === 'rest') return h('span', { class: 'pill mut', title: 'site sans SSH : installation depuis la page du site', text: t.court });
    const b = h('button', { type: 'button', class: 'btn sm' }, iconEl('plus'), 'installer');
    b.onclick = ev => { ev.stopPropagation(); vizInstall(b, s.srv, s.domain); };
    return b;
  }
  if (e === 'inactif' || e === 'nocli') {
    return h('span', { class: 'pill ' + t.niveau, title: t.long, text: t.court });
  }
  if (e === 'nonconnecte') {
    const frag = h('span', { class: 'vizwrap' },
      h('span', { class: 'pill ' + t.niveau, title: t.long, text: t.court }));
    if (s.via !== 'rest') {
      const b = h('button', { type: 'button', class: 'btn sm', text: 'Connecter' });
      b.onclick = ev => { ev.stopPropagation(); openVizConnect([s]); };
      frag.append(b);
    }
    const a = lienEl(vizAdminUrl(s), 'wp-admin');
    if (a) frag.append(a);
    return frag;
  }
  return h('span', { class: 'vizwrap' },
    h('span', { class: 'pill ok', title: t.long, text: t.court }),
    vizRunBadgeEl(s));
}

/* ---- détail des anomalies (bloc `report` du verdict, plugin ≥ 1.3.9) -------
   Le dashboard n'affichait qu'un compte : « anomalies détectées (2) ». Le
   plugin, lui, sait DE QUOI il parle — pages scannées, pages qui ont bougé, et
   pour chacune l'écran, l'écart et son libellé. Un seul rendu (chaîne HTML)
   sert les quatre endroits qui montraient ce compte : la console d'exécution
   (fond sombre, écrite en innerHTML), le bloc de l'onglet Aperçu, la modale et
   — en texte seul — la barre de notifications. */
const VZ_ST = { fail: ['err', 'échec'], warn: ['warn', 'à vérifier'], ok: ['ok', 'inchangée'] };
const VZ_ORDRE = { fail: 0, warn: 1, other: 2, ok: 3 };
const VZ_REPLI = 6;            // au-delà, le tableau s'ouvre sur demande

function vzNb(n) { return Number(n) || 0; }

/** Le verdict porte-t-il un détail exploitable ? */
function vizReport(v) {
  const r = v && typeof v === 'object' ? v.report : null;
  return (r && typeof r === 'object') ? r : null;
}

/* « 2 pages scannées · 1 avec différence · 0 échec, 2 à vérifier ». Un run
   BASELINE n'a rien à comparer : le dire, plutôt qu'aligner des zéros qui se
   lisent comme « tout va bien ». */
function vizReportResume(rep) {
  if (!rep) return '';
  if (rep.is_baseline) return 'baseline de référence — rien à comparer';
  const s = rep.summary || {}, t = rep.totals || {};
  const n = vzNb(s.pages_scanned), c = vzNb(s.pages_changed);
  return [n + ' page' + (n > 1 ? 's' : '') + ' scannée' + (n > 1 ? 's' : ''),
    c + ' avec différence',
    vzNb(t.fail) + ' échec' + (vzNb(t.fail) > 1 ? 's' : '') + ', ' + vzNb(t.warn) + ' à vérifier',
  ].join(' · ');
}

/* Écart en pour cent. Quatre décimales sous le centième : c'est là que se
   jouent les écarts que VizProof appelle « mineurs », et « 0,00 % » les
   effacerait tous. */
function vzPct(v) {
  const n = Number(v);
  if (!isFinite(n)) return '—';
  return n.toFixed(n && Math.abs(n) < 0.01 ? 4 : 2).replace('.', ',') + ' %';
}

/* Trié par GRAVITÉ d'abord (échec, à vérifier, reste, inchangée), puis par
   écart décroissant : la première ligne est celle qu'il faut regarder. */
function vizReportLignes(rep) {
  const it = (Array.isArray(rep && rep.items) ? rep.items : []).filter(x => x && typeof x === 'object');
  return it.slice().sort((a, b) =>
    ((VZ_ORDRE[a.status] ?? 9) - (VZ_ORDRE[b.status] ?? 9))
    || (Number(b.diff_percent) || 0) - (Number(a.diff_percent) || 0));
}

function vzLigneHtml(x) {
  const [c, l] = VZ_ST[x.status] || ['mut', String(x.status || '?')];
  const u = safeUrl(x.url), nom = String(x.page || '') || u || '—';
  const page = u ? `<a href="${H(u)}" target="_blank" rel="noopener noreferrer">${H(nom)}</a>` : H(nom);
  const lib = String(x.label || '');
  return `<tr><td>${page}</td><td>${H(x.viewport || '—')}</td>`
    + `<td class="num">${H(vzPct(x.diff_percent))}</td>`
    + `<td><span class="pill ${c}">${H(l)}</span>`
    + (lib && lib.toLowerCase() !== l ? ` <span class="muted">${H(lib)}</span>` : '') + '</td></tr>';
}

/** Détail d'un rapport, en HTML. `opts.replie` force le repli (onglet Aperçu). */
export function vizReportHtml(rep, opts) {
  if (!rep) return '';
  const o = opts || {};
  const u = safeUrl(rep.report_url);
  const lien = u ? ` <a href="${H(u)}" target="_blank" rel="noopener noreferrer">voir le rapport</a>` : '';
  const resume = `<div class="vzr-s">${H(vizReportResume(rep))}${lien}</div>`;
  const lignes = vizReportLignes(rep);
  // Une baseline n'a aucune ligne à comparer : le tableau n'aurait rien à dire.
  if (rep.is_baseline || !lignes.length) return `<div class="vzr">${resume}</div>`;
  const top = String((rep.summary || {}).top_page || '');
  const tab = '<div class="vzr-w"><table class="vzr-t">'
    + '<thead><tr><th>Page</th><th>Écran</th><th>Écart</th><th>Statut</th></tr></thead>'
    + '<tbody>' + lignes.map(vzLigneHtml).join('') + '</tbody></table></div>'
    + (rep.has_more ? `<div class="vzr-s muted">liste tronquée — ${H(String(vzNb(rep.total_items)))} lignes au total, voir le rapport.</div>` : '')
    + (top ? `<div class="vzr-s muted">Page la plus impactée : <b>${H(top)}</b></div>` : '');
  if (!o.replie && lignes.length <= VZ_REPLI) return `<div class="vzr">${resume}${tab}</div>`;
  // Repli natif : ouverture au clavier, aucun état à tenir dans le module.
  return `<div class="vzr">${resume}<details class="vzr-d"><summary>Voir le détail`
    + ` (${H(String(lignes.length))} ligne${lignes.length > 1 ? 's' : ''})</summary>${tab}</details></div>`;
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
  const t = vizEtatTexte(s), e = t.etat;
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
    txt.append('Reliée à VizProof · ', h('b', { text: n + ' page' + (n > 1 ? 's' : '') }), ' surveillée' + (n > 1 ? 's' : ''));
    if (sid) txt.append(' · identifiant ', h('code', { text: String(sid) }));
    txt.append('.');
    if (!rest) {
      /* Le choix des pages est la suite naturelle de la connexion : c'est ici
         qu'on y revient, sans repasser par la modale de liaison. */
      const bp = h('button', { type: 'button', class: 'btn sm' }, iconEl('scan-eye'), 'Pages surveillées…');
      bp.onclick = () => openVizPages(s);
      const b = h('button', { type: 'button', class: 'btn sm', text: 'Dissocier' });
      b.onclick = () => vizDisconnect(b, s);
      btns.append(bp, b);
    } else {
      txt.append(' Ce site est géré sans SSH : le choix des pages se fait dans wp-admin.');
    }
  }
  const a = lienEl(vizAdminUrl(s), 'ouvrir dans wp-admin');
  if (a) txt.append(' ', a);
  if (e === 'connecte') { const p = vizRunBadgeEl(s); if (p) txt.append(' ', p); }

  return h('div', { class: 'agroup' },
    h('span', { class: 'glbl', text: 'VizProof' }),
    txt,
    e === 'connecte' ? vizLastRunEl(s) : null,
    // Réceptacle du résumé du dernier rapport : rempli APRÈS coup par
    // `chargerVizRapport`, pour que le bloc s'affiche sans attendre le réseau.
    e === 'connecte' ? h('div', { class: 'vzr-slot' }) : null,
    btns.children.length ? btns : null);
}

/* Résumé du dernier rapport, sous « Dernier scan il y a X ». Chargé à
   l'ouverture de l'onglet, EN TÂCHE DE FOND et en une seule requête : le bloc
   est déjà à l'écran quand la réponse arrive. Un échec ne dit rien — le compte
   d'anomalies et le lien restent la vérité affichée. */
export async function chargerVizRapport(s, slot) {
  if (!slot || !s || s.via === 'rest' || vizState(s) !== 'connecte') return;
  // Le réceptacle de la modale, lui, SURVIT à sa fermeture : sans ce marquage,
  // la réponse d'un site rouvert sur un autre s'y afficherait quand même.
  slot.dataset.domain = s.domain;
  let j = null;
  try {
    j = await api('/api/actions/viz_report?server=' + encodeURIComponent(s.srv)
      + '&domain=' + encodeURIComponent(s.domain));
  } catch (e) { return; }                 // site injoignable : on n'affiche rien de plus
  if (!slot.isConnected || slot.dataset.domain !== s.domain || !j || !j.report) return;
  slot.innerHTML = vizReportHtml(j.report, { replie: true });
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
/* Verdict + résumé du rapport, en TEXTE : la barre de notifications n'affiche
   que du texte (`textContent`, coupé à 180 caractères), un tableau n'y a pas sa
   place mais « 2 pages scannées · 1 avec différence » y tient. */
export function vizPhraseLongue(v) {
  const p = vizPhrase(v), r = vizReport(v);
  if (!r) return p;
  const top = String((r.summary || {}).top_page || '');
  return p + ' · ' + vizReportResume(r)
    + (top && !r.is_baseline ? ' · page la plus impactée : ' + top : '');
}
export function vizConsoleLigne(v) {
  if (!v) return '';
  const u = safeUrl(v.report_url), rep = vizReport(v);
  // Marqueur : le verdict REMPLACE le « scan en cours… » au lieu de s'empiler.
  return `<span data-vizline><b class="${vizEtat(v)}">Contrôle visuel VizProof : ${H(vizPhrase(v))}</b>`
    + (u && !(rep && rep.report_url) ? ` <a href="${H(u)}" target="_blank" rel="noopener noreferrer">rapport</a>` : '')
    + vizReportHtml(rep) + '</span>';
}
function vizConsoleMaj(dom, v) {
  const c = CONSOLE_DE(dom);
  if (!c) return;
  const bas = auBas(c);            // mesuré AVANT l'écriture, cf. lib/dom.js
  const l = c.querySelector('[data-vizline]');
  if (l) l.outerHTML = vizConsoleLigne(v);
  else c.innerHTML += '\n' + vizConsoleLigne(v);
  collerEnBas(c, bas);
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
    NOTIF.done(nid, { ok: vizEtat(v) !== 'err', warn: vizEtat(v) === 'warn', message: 'contrôle visuel : ' + vizPhraseLongue(v) });
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

function closeViz() { document.getElementById('vizmodal').classList.remove('open'); }

/* La modale a DEUX étapes dans une seule couche : relier, puis choisir les
   pages. Les boutons de pied changent avec l'étape — un seul jeu de boutons
   pour deux écrans donnait un « Connecter » inerte devant la liste des pages. */
function montrerEtape(quoi) {
  const pages = quoi === 'pages';
  document.getElementById('vz-connect').hidden = pages;
  document.getElementById('vz-pages').hidden = !pages;
  document.getElementById('vz-go').hidden = pages;
  document.getElementById('vz-pg-save').hidden = !pages;
  document.getElementById('vz-pg-base').hidden = !pages;
  if (pages) document.getElementById('vz-preview').hidden = true;
}

/* Les identifiants de site VizProof ne sont montrés d'emblée que là où ils
   servent : un lot à relier. Sur un site déjà relié, ils passent derrière
   « Options avancées » — le champ « par URL » en évidence donnait à croire
   qu'il fallait le remplir avant de pouvoir faire quoi que ce soit. */
let VZROWSADV = false;
function majLignesAvancees(ouvert) {
  document.getElementById('vz-rows').hidden = VZROWSADV && !ouvert;
  document.getElementById('vz-idhint').hidden = !VZTOK || (VZROWSADV && !ouvert);
}

function brancherModale() {
  document.getElementById('vz-cancel').onclick = closeViz;
  document.getElementById('vizmodal').onclick = e => { if (e.target.id === 'vizmodal') closeViz(); };
  document.getElementById('vz-adv').onclick = () => {
    const b = document.getElementById('vz-advbox');
    b.hidden = !b.hidden;
    document.getElementById('vz-adv').textContent = b.hidden ? 'Options avancées' : 'Masquer les options';
    majLignesAvancees(!b.hidden);
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
  // Depuis la phase 4, Réglages est une page à ancres : on vise directement
  // sa section VizProof plutôt que d'ouvrir la page en haut.
  document.getElementById('vz-setlink').onclick = () => { closeViz(); location.hash = '#reglages/vizproof'; };
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
  const seul = VZSITES.length === 1;
  const relie = seul && vizState(VZSITES[0]) === 'connecte';
  montrerEtape('connect');
  /* Le titre nomme le site : ouverte sur un site déjà relié, la modale ne
     « connecte » plus rien, elle montre l'état et propose de refaire la
     liaison. « Connecter VizProof » y était un contresens. */
  document.getElementById('vz-title').textContent = seul
    ? 'VizProof · ' + (kName(VZSITES[0]) || VZSITES[0].domain)
    : 'Connecter VizProof';
  if (relie) {
    const info = vizInfo(VZSITES[0]) || {};
    const n = Number(info.pages) || 0;
    document.getElementById('vz-intro').innerHTML =
      `Relié à <b>${H(VZSITES[0].blogname || VZSITES[0].domain)}</b> · `
      + `<b>${n} page${n > 1 ? 's' : ''}</b> surveillée${n > 1 ? 's' : ''}`
      + (info.site_id ? ` · identifiant <code>${H(info.site_id)}</code>` : '')
      + '. <b>Reconnecter</b> refait la liaison avec le jeton enregistré — utile après un '
      + 'changement d’URL, un jeton révoqué, ou un site VizProof recréé. Rien d’autre à saisir.';
  } else {
    document.getElementById('vz-intro').innerHTML = VZSITES.length > 1
      ? `<b>${VZSITES.length}</b> site(s) à relier.` + (VZTOK
        ? ' Le jeton enregistré vaut pour tous ; laissez l’identifiant vide pour que chaque site soit retrouvé ou créé d’après son URL.'
        : " L'identifiant est propre à chaque site ; le jeton, lui, est celui de votre compte et vaut pour tous.")
      : `Relier <b>${H(kName(VZSITES[0]) || VZSITES[0].domain)}</b> à VizProof.`;
  }
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
  // Site déjà relié : les identifiants passent derrière « Options avancées ».
  VZROWSADV = relie;
  const adv = document.getElementById('vz-advbox');
  adv.hidden = true;
  document.getElementById('vz-adv').textContent = 'Options avancées';
  majLignesAvancees(false);
  document.getElementById('vz-tokstored').hidden = !VZTOK;
  document.getElementById('vz-toktail').textContent = '…' + (cfg.vizproof_token_tail || '');
  document.getElementById('vz-othertok').hidden = false;
  document.getElementById('vz-credbox').hidden = VZTOK;   // replié tant qu'un jeton suffit
  document.getElementById('vz-goset').hidden = VZTOK;
  document.getElementById('vz-out').innerHTML = '';
  document.getElementById('vz-apercu').innerHTML = '';
  /* Site déjà relié : le détail du dernier rapport se charge en tâche de fond.
     Ailleurs il n'y a pas encore de run à montrer, et la zone reste vide. */
  const rep = document.getElementById('vz-report');
  rep.innerHTML = '';
  if (relie) chargerVizRapport(VZSITES[0], rep).catch(() => {});
  document.getElementById('vz-token').value = '';
  document.getElementById('vz-code').value = '';
  const go = document.getElementById('vz-go');
  go.disabled = false;
  go.textContent = relie ? 'Reconnecter'
    : (VZTOK && VZSITES.length > 1) ? `Connecter ${VZSITES.length} sites` : 'Connecter';
  go.onclick = runVizConnect;
  const ap = document.getElementById('vz-preview');
  ap.hidden = !VZTOK || relie; ap.disabled = false; ap.textContent = 'Aperçu';
  ap.onclick = () => runVizPreview();
  const an = document.getElementById('vz-cancel');
  an.textContent = relie ? 'Fermer' : 'Annuler'; an.className = 'btn';
  document.getElementById('vizmodal').classList.add('open');
  const f = relie ? go : document.querySelector('#vz-rows input');
  if (f) f.focus();
  /* Aperçu automatique sur un site unique PAS ENCORE RELIÉ : on montre avant de
     connecter quel site VizProof recevra ce WordPress. Sur un site relié il n'y
     a rien à résoudre — l'aperçu ne faisait qu'un appel réseau pour rien et
     brouillait la seule question posée : reconnecter, ou fermer. */
  if (VZTOK && seul && !relie) runVizPreview().catch(() => {});
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
  /* « 1/1 connecté(s) » devant un seul site est un compte rendu de lot pour un
     lot qui n'existe pas : sur un site unique, on dit simplement ce qui s'est
     passé. La pastille de décompte reste au GROUPÉ, où elle informe. */
  out.innerHTML = (seul
    ? (nok ? '<div class="mt2"><span class="pill ok">site relié</span></div>'
      : '<div class="mt2"><span class="pill err">connexion impossible</span></div>')
    : `<div class="mt2"><span class="pill ${nok === VZSITES.length ? 'ok' : nok ? 'warn' : 'err'}">${nok}/${VZSITES.length} connecté(s)</span></div>`)
    + out.innerHTML;
  go.textContent = lbl; go.disabled = false;
  const an = document.getElementById('vz-cancel');
  an.textContent = 'Fermer'; an.className = 'btn primary';
  if (nok) loadFleet().then(() => REFRESH()).catch(() => {});
  // La connexion faite, la question suivante est « quelles pages surveiller ? ».
  // On y enchaîne dans la même couche plutôt que de renvoyer l'utilisateur
  // chercher un bouton : c'est exactement là qu'il ne savait plus quoi cliquer.
  if (seul && nok) { setTimeout(() => openVizPages(VZSITES[0]), 400); }
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

/* ---- étape « Pages surveillées » -------------------------------------------

   Ce que le plugin scanne : tout le site, ou une liste de pages. Jusqu'ici
   c'était invisible depuis le dashboard — on reliait un site, et le choix des
   pages restait dans wp-admin, sans que rien ne le dise.

   Deux routes, un seul contrat :
     GET  /api/actions/viz_pages?server=&domain=
     POST /api/actions/viz_pages {server, domain, ids, scope}
   → {scope, selected, critical, pages:[{id,title,url,type,selected,critical}],
      limit, source, message}

   `type` vaut `page`, `front` (l'accueil est une page statique) ou `home`
   (l'accueil est le flux d'articles). Ce dernier n'a pas d'identifiant de page
   à capturer : il ne se surveille qu'avec la portée « tout le site », et sa
   case reste donc désactivée.

   `source` dit par quel chemin le serveur a répondu : `plugin` (1.3.8, qui
   valide) ou `repli-1.3.7` (lecture/écriture directes des options, sans
   validation). L'interface le REDIT à l'utilisateur : ce n'est pas la même
   garantie. */
const PG = { site: null, pages: [], sel: new Set(), scope: 'selected_pages', limit: 20, source: '', enr: false };

function pgEl(id) { return document.getElementById(id); }
function pgDire(niveau, texte) {
  mount(pgEl('vz-pg-msg'), h('span', { class: 'pill ' + niveau, text: texte }));
}

/** Ouvre la modale VizProof directement sur le choix des pages. */
export async function openVizPages(s) {
  if (!s) return;
  PG.site = s;
  PG.pages = []; PG.sel = new Set(); PG.scope = 'selected_pages';
  PG.limit = 20; PG.source = ''; PG.enr = false;
  pgEl('vz-title').textContent = 'Pages surveillées · ' + (kName(s) || s.domain);
  montrerEtape('pages');
  pgEl('vz-pg-intro').textContent = 'Chargement des pages publiées du site…';
  mount(pgEl('vz-pg-list'), h('span', { class: 'muted small', text: 'chargement…' }));
  mount(pgEl('vz-pg-msg'));
  pgEl('vz-pg-q').value = '';
  pgEl('vz-pg-note').textContent = '';
  const an = pgEl('vz-cancel');
  an.textContent = 'Fermer'; an.className = 'btn';
  pgEl('vz-pg-base').hidden = true;              // la baseline vient APRÈS l'enregistrement
  pgEl('vizmodal').classList.add('open');
  brancherPages();
  await chargerPages();
}

let PGBRANCHE = false;
function brancherPages() {
  if (PGBRANCHE) return;
  PGBRANCHE = true;
  pgEl('vz-pg-q').oninput = debounce(rendrePages, 150);
  pgEl('vz-pg-scope').onchange = e => { PG.scope = e.target.value; rendrePages(); };
  pgEl('vz-pg-all').onclick = () => { pagesVisibles().forEach(p => cocher(p, true)); rendrePages(); };
  pgEl('vz-pg-none').onclick = () => { pagesVisibles().forEach(p => cocher(p, false)); rendrePages(); };
  pgEl('vz-pg-save').onclick = enregistrerPages;
  pgEl('vz-pg-base').onclick = capturerBaseline;
}

/** L'accueil « flux d'articles » n'a pas de page à capturer : jamais cochable. */
function cochable(p) { return p.type !== 'home'; }
function cocher(p, on) {
  if (!cochable(p)) return;
  if (on) PG.sel.add(p.id); else PG.sel.delete(p.id);
}

function pagesVisibles() {
  const q = String(pgEl('vz-pg-q').value || '').trim().toLowerCase();
  if (!q) return PG.pages;
  return PG.pages.filter(p => (p.title + ' ' + p.url).toLowerCase().includes(q));
}

async function chargerPages() {
  const s = PG.site;
  let j;
  try {
    j = await api('/api/actions/viz_pages?server=' + encodeURIComponent(s.srv)
      + '&domain=' + encodeURIComponent(s.domain)) || {};
  } catch (e) { j = { ok: false, error: String(e) }; }
  if (!PG.site || PG.site.domain !== s.domain) return;      // modale rouverte ailleurs
  if (!j.ok) return pagesIndisponibles(j);
  PG.pages = Array.isArray(j.pages) ? j.pages : [];
  PG.limit = Number(j.limit) || 20;
  PG.source = String(j.source || '');
  PG.scope = j.scope === 'site' ? 'site' : 'selected_pages';
  PG.sel = new Set((j.selected || []).filter(x => Number.isInteger(x) && x > 0));
  // Sélection vide sur un site qui vient d'être relié : l'accueil est le
  // premier témoin utile, et c'est la page qui casse le plus visiblement.
  if (!PG.sel.size) {
    const acc = PG.pages.find(p => p.type === 'front');
    if (acc) PG.sel.add(acc.id);
  }
  pgEl('vz-pg-scope').value = PG.scope;
  pgEl('vz-pg-intro').textContent = 'Choisissez les pages que VizProof photographie à chaque scan. '
    + 'L’accueil en tête : c’est le témoin le plus parlant quand une mise à jour casse le rendu.';
  rendrePages();
}

function pagesIndisponibles(j) {
  const s = PG.site, rest = Number(j.rc) === 97 || s.via === 'rest';
  pgEl('vz-pg-intro').textContent = '';
  pgEl('vz-pg-save').hidden = true;
  pgEl('vz-pg-base').hidden = true;
  const lien = vizAdminUrl(s);
  mount(pgEl('vz-pg-list'),
    h('p', { class: 'hint hint-tight' },
      rest
        ? 'Ce site est géré sans SSH : choisissez les pages à surveiller dans wp-admin.'
        : 'La liste des pages n’a pas pu être lue depuis ce site.'),
    rest && lien
      ? h('p', { class: 'hint hint-tight' },
        h('a', { href: lien, target: '_blank', rel: 'noopener noreferrer',
          text: 'Ouvrir VizProof dans wp-admin' }))
      : h('p', { class: 'hint hint-tight' }, h('code', { text: String(j.error || 'échec').slice(-300) })));
}

function ligneEl(p) {
  const ok = cochable(p);
  const c = h('input', { type: 'checkbox', 'aria-label': 'Surveiller ' + (p.title || p.url || ('page ' + p.id)) });
  c.checked = ok && PG.sel.has(p.id);
  c.disabled = !ok;
  c.onchange = () => { cocher(p, c.checked); majCompte(); };
  const roles = [];
  if (p.type === 'front') roles.push('accueil');
  if (p.type === 'home') roles.push('accueil — flux d’articles');
  if (p.critical) roles.push('critique');
  return h('label', { class: 'vzpage' + (ok ? '' : ' off') },
    c,
    h('span', { class: 'vzp-b' },
      h('span', { class: 'vzp-t' }, p.title || '(sans titre)',
        roles.length ? [' ', h('span', { class: 'pill mut', text: roles.join(' · ') })] : null),
      h('span', { class: 'vzp-u', text: p.url || ('#' + p.id) })));
}

function rendrePages() {
  const liste = pagesVisibles();
  mount(pgEl('vz-pg-list'), liste.length
    ? liste.map(ligneEl)
    : h('span', { class: 'muted small', text: 'aucune page ne correspond' }));
  const tout = PG.scope === 'site';
  pgEl('vz-pg-scope').value = PG.scope;
  pgEl('vz-pg-save').hidden = false;
  pgEl('vz-pg-save').textContent = 'Enregistrer';
  pgEl('vz-pg-note').textContent = (tout
    ? 'Portée « tout le site » : le plugin parcourt le site entier, la sélection ci-dessous est '
      + 'conservée pour un retour à « pages sélectionnées ». '
    : '')
    + 'Le plugin ne scanne pas plus de ' + PG.limit + ' pages : au-delà, les suivantes sont ignorées. '
    + (PG.source === 'repli-1.3.7'
      ? 'Extension en 1.3.7 : l’enregistrement écrit directement les options du site, sans validation par l’extension. '
      : '');
  majCompte();
}

function majCompte() {
  const n = PG.sel.size;
  const trop = n > PG.limit;
  mount(pgEl('vz-pg-count'),
    h('span', { class: 'pill ' + (trop ? 'err' : n ? 'ok' : 'mut') },
      n + ' / ' + PG.limit + ' page' + (n > 1 ? 's' : '') + ' sélectionnée' + (n > 1 ? 's' : '')));
}

async function enregistrerPages() {
  const s = PG.site, b = pgEl('vz-pg-save');
  const ids = [...PG.sel];
  if (ids.length > PG.limit) { pgDire('err', PG.limit + ' pages au maximum'); return; }
  if (PG.scope === 'selected_pages' && !ids.length) {
    pgDire('err', 'choisissez au moins une page, ou passez à « tout le site »');
    return;
  }
  setBusy(b, 'enregistrement…');
  mount(pgEl('vz-pg-msg'));
  let j;
  try { j = await api('/api/actions/viz_pages', { server: s.srv, domain: s.domain, ids, scope: PG.scope }) || {}; }
  catch (e) { j = { ok: false, error: String(e) }; }
  setIdle(b, 'Enregistrer');
  if (!j.ok) { pgDire('err', String(j.error || 'échec').slice(-200)); return; }
  PG.enr = true;
  if (Array.isArray(j.pages) && j.pages.length) PG.pages = j.pages;
  PG.sel = new Set((j.selected || []).filter(x => Number.isInteger(x) && x > 0));
  PG.scope = j.scope === 'site' ? 'site' : 'selected_pages';
  rendrePages();
  pgDire('ok', 'sélection enregistrée');
  pgEl('vz-pg-base').hidden = false;
  pgEl('vz-pg-note').textContent += ' Étape suivante : capturer une baseline — '
    + 'le témoin « avant » auquel les prochains scans seront comparés. Sans elle, '
    + 'le premier contrôle n’a rien à quoi se comparer.';
  /* Le re-scan rafraîchit `pages` dans l'inventaire : sans lui, la colonne du
     Parc et le bloc de l'Aperçu afficheraient encore l'ancien décompte. */
  try {
    await api('/api/actions/run', { server: s.srv, domain: s.domain, action: 'rescan', arg: null });
    await loadFleet();
    REFRESH();
  } catch (e) { /* l'enregistrement, lui, a bien eu lieu */ }
}

async function capturerBaseline() {
  const s = PG.site, b = pgEl('vz-pg-base');
  setBusy(b, 'capture…');
  const nid = NOTIF.start({
    kind: 'viz', label: 'Baseline VizProof · ' + (kName(s) || s.domain),
    site: { srv: s.srv, domain: s.domain },
  });
  let j;
  try { j = await api('/api/actions/run', { server: s.srv, domain: s.domain, action: 'viz_baseline', arg: null }) || {}; }
  catch (e) { j = { ok: false, error: String(e) }; }
  setIdle(b, 'Capturer une baseline');
  const det = stripPhpNoise(String(j.output || j.error || '')).slice(-200);
  NOTIF.done(nid, { ok: !!j.ok, message: j.ok ? 'baseline capturée' : det });
  pgDire(j.ok ? 'ok' : 'err', j.ok ? 'baseline capturée' : (det || 'échec'));
  if (j.ok) loadFleet().then(() => REFRESH()).catch(() => {});
}
