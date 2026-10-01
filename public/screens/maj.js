/* Écran Mises à jour — « qui se met à jour seul, et qu'est-ce qui s'est passé
   cette nuit ? ».

   Le mode automatique était un réglage parmi d'autres, au fond de l'onglet
   Réglages de chaque site : on ne voyait ni QUELS sites étaient en
   automatique, ni ce que la nuit avait donné. Cette page le met au premier
   plan :

     1. les trois façons de mettre à jour, en une phrase chacune — les boutons
        « Contrôlée » et « Directe » de la page site renvoient à ce vocabulaire ;
     2. le bilan de la nuit : les mises à jour faites par le dashboard
        (data/maj_nuit.json, 4 h) et celles faites par un tiers — hébergeur,
        WordPress — que viz_nuit.py a contrôlées après coup (6 h 45) ;
     3. le mode automatique site par site (data/auto_mode.json), avec le
        RETOUR ARRIÈRE AUTOMATIQUE.

   Depuis le 01/10, « automatique » veut dire : LE DASHBOARD met à jour le site
   chaque nuit, en mise à jour Contrôlée. Activer le mode coupe donc les MAJ
   automatiques natives du site (extensions et thèmes) : WordPress et WP
   Toolkit, qui les lit, n'y touchent plus. Un site dont les MAJ natives sont
   actives sans être en automatique est affiché « hébergeur » : il se met à jour
   seul, sans référence d'avant ni retour arrière depuis une archive. */

import { api } from '../lib/api.js';
import { esc as H, h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { allSites, nomDeSite, store } from '../lib/state.js';
import { chipEl, estPreprod } from '../components/chip.js';
import { askInfo, askOpen } from '../components/confirm.js';
import { demarrerJob } from '../components/job.js';
import { vizConnected } from '../components/viz.js';
import { cleDeSite, extensionsMajables } from './site.js';

let ETAT = { modes: {}, nuit: {}, maj: {} };
let MONTE = false;
const FILT = { q: '', mode: '' };

/* ---- état d'un site --------------------------------------------------------- */
function etatAuto(s) {
  const ext = extensionsMajables(s).n || 0;
  const nExt = s.plugins_auto_update == null ? null : Math.min(s.plugins_auto_update, ext);
  const th = Array.isArray(s.themes_list) ? s.themes_list.length : null;
  const nTh = s.themes_auto_update == null || th == null ? null : Math.min(s.themes_auto_update, th);
  const natives = (nExt || 0) + (nTh || 0);
  const reglage = ETAT.modes[s.domain];
  let mode = 'manuel';
  if (reglage) mode = 'auto';
  else if (ext > 0 && nExt >= ext && (th == null || nTh == null || nTh >= th)) mode = 'hebergeur';
  else if (natives > 0) mode = 'partiel';
  const attente = (s.plugins_updates || 0) + (s.themes_updates || 0);
  return { ext, nExt, th, nTh, natives, mode, attente, rollback: !!(reglage || {}).rollback };
}

const MODE_CHIP = {
  auto: ['automatique', 'ok', 'le dashboard met le site à jour chaque nuit, en mise à jour Contrôlée'],
  hebergeur: ['hébergeur', 'warn', 'WordPress / WP Toolkit mettent le site à jour seuls, sans référence d’avant ni retour arrière'],
  partiel: ['partiel', 'warn', 'une partie des extensions ou des thèmes se met à jour seule, sans contrôle'],
  manuel: ['manuel', 'mut', 'aucune mise à jour automatique'],
};
const ORDRE = { auto: 0, hebergeur: 1, partiel: 2, manuel: 3 };

/* ---- squelette -------------------------------------------------------------- */
function monter() {
  if (MONTE) return;
  MONTE = true;
  const q = h('input', {
    type: 'search', id: 'maj-q', class: 'w-md', placeholder: 'Filtrer un site…',
    'aria-label': 'Filtrer les sites',
  });
  q.oninput = () => { FILT.q = q.value.trim().toLowerCase(); rendreSites(); };
  const sel = h('select', { id: 'maj-mode', 'aria-label': 'Filtrer par mode' },
    h('option', { value: '', text: 'Tous les modes' }),
    h('option', { value: 'auto', text: 'Automatique' }),
    h('option', { value: 'hebergeur', text: 'Hébergeur (sans contrôle)' }),
    h('option', { value: 'partiel', text: 'Partiel' }),
    h('option', { value: 'manuel', text: 'Manuel' }));
  sel.onchange = () => { FILT.mode = sel.value; rendreSites(); };

  mount('page-maj',
    h('section', { class: 'section secsec', id: 'maj-modes' },
      h('div', { class: 'sechead' }, h('h2', { text: 'Trois façons de mettre à jour' })),
      h('dl', { class: 'majmodes' },
        h('dt', {}, iconEl('shield-check'), ' Contrôlée'),
        h('dd', { text: 'Depuis la page d’un site. Sauvegarde, archive, mise à jour, contrôle visuel '
          + 'VizProof, et retour arrière tout seul si une page casse. Le geste recommandé à la main.' }),
        h('dt', {}, iconEl('arrow-up'), ' Directe'),
        h('dd', { text: 'Immédiate, sans sauvegarde ni retour possible. Pour une extension sans enjeu.' }),
        h('dt', {}, iconEl('zap'), ' Automatique'),
        h('dd', { text: 'La nuit, sans vous : à 4 h, le dashboard fait une mise à jour Contrôlée de '
          + 'chaque site en automatique qui en a besoin — et la défait si une page casse, quand le '
          + 'retour arrière automatique est coché. Une version annulée n’est pas retentée ; un site '
          + 'dont VizProof montre un écart non réglé attend. WordPress et l’hébergeur ne mettent plus '
          + 'ces sites à jour, sauf les correctifs mineurs du cœur.' }))),
    h('section', { class: 'section secsec', id: 'maj-nuit' },
      h('div', { class: 'sechead' }, h('h2', { text: 'Cette nuit' }),
        h('span', { class: 'muted small', id: 'maj-nuit-quand' })),
      h('div', { id: 'maj-nuit-body' })),
    h('section', { class: 'section secsec', id: 'maj-sites' },
      h('div', { class: 'sechead' }, h('h2', { text: 'Mode automatique, site par site' })),
      h('p', { class: 'hint', text: 'Le retour arrière automatique demande VizProof : sans contrôle '
        + 'visuel, seul un site tombé ferait annuler la mise à jour. « Auto-MAJ natives » : ce que '
        + 'WordPress et l’hébergeur mettent à jour seuls — à zéro pour un site en automatique.' }),
      h('div', { class: 'filters' }, q, sel, h('span', { class: 'muted small', id: 'maj-count' })),
      h('div', { class: 'wrap' }, h('table', { id: 'maj-tbl' },
        h('thead', {}, h('tr', {},
          ['Site', 'Mode', 'En attente', 'Auto-MAJ natives', 'Contrôle visuel', 'Retour arrière auto', '']
            .map(t => h('th', { text: t })))),
        h('tbody', { id: 'maj-tb' })))));
}

/* ---- bilan de la nuit ------------------------------------------------------- */
function rendreNuit() {
  const box = document.getElementById('maj-nuit-body');
  if (!box) return;
  const n = ETAT.nuit || {}, m = ETAT.maj || {};
  const quand = document.getElementById('maj-nuit-quand');
  if (quand) {
    quand.textContent = [m.generated_at ? 'mises à jour du ' + m.generated_at : '',
      n.generated_at ? 'contrôle du ' + n.generated_at : ''].filter(Boolean).join(' · ');
  }
  const parDash = Object.values(m.sites || {}).filter(r => r && typeof r === 'object');
  const parTiers = Object.values(n.sites || {}).filter(r => r && typeof r === 'object');
  if (!parDash.length && !parTiers.length) {
    mount(box, h('p', { class: 'hint hint-tight', text: 'Aucune mise à jour cette nuit.' }));
    return;
  }
  const tri = (a, b) => String(a.domain || a.site).localeCompare(String(b.domain || b.site));
  mount(box, h('div', { class: 'wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Site', 'Mis à jour', 'Par', 'Résultat'].map(t => h('th', { text: t })))),
    h('tbody', {}, parDash.sort(tri).map(ligneMaj), parTiers.sort(tri).map(ligneNuit)))));
}

function lienSite(dom, cle) {
  const s = allSites().find(x => x.domain === dom);
  return h('a', { class: 'seclien', href: '#site/' + encodeURIComponent(s ? cleDeSite(s) : cle || dom),
    text: s ? nomDeSite(s) : (cle || dom) });
}

function lienRapport(url) {
  return url ? [' ', h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: 'rapport' })] : null;
}

/* Verdict de la chaîne Contrôlée (safe_update_run) → pastille. */
function resultatMaj(r) {
  const v = String(r.verdict || '');
  if (v === 'réussi') return chipEl('aucun écart', 'ok');
  if (v === 'réussie avec anomalies visuelles') return chipEl('écart, MAJ conservée', 'warn');
  if (v.startsWith('annulé (retour')) {
    return chipEl('annulée, site rétabli', 'warn',
      { title: r.ecarts_apres === 0 ? 'scan de contrôle propre après le retour arrière' : '' });
  }
  if (v.startsWith('ÉCHEC')) return chipEl('échec — intervention requise', 'err');
  if (v === 'bloqué') return chipEl('en attente : écart non réglé', 'mut');
  if (v === 'rien à faire') return chipEl('versions refusées, rien d’autre', 'mut');
  return chipEl('non faite', 'warn');
}

function ligneMaj(r) {
  const cause = r.cause ? h('div', { class: 'sub', text: r.cause }) : null;
  const ec = (r.ecartees || []).length
    ? h('div', { class: 'sub', text: 'non retentées (annulées une nuit précédente) : ' + r.ecartees.join(', ') }) : null;
  return h('tr', {},
    h('td', {}, lienSite(r.domain)),
    h('td', { class: 'wrapcell' }, (r.items || []).join(', ') || '—', ec),
    h('td', {}, chipEl('dashboard', 'ok', { title: 'mise à jour Contrôlée lancée à 4 h' })),
    h('td', { class: 'wrapcell' }, resultatMaj(r), lienRapport(r.report_url), cause));
}

function ligneNuit(r) {
  const items = (r.items || []).join(', ') || '—';
  const nc = r.non_couvertes || [];
  const controle = !nc.length ? chipEl('hébergeur · VizProof', 'warn', { title: 'mise à jour faite par l’hébergeur ou WordPress, scannée par le plugin' })
    : (r.rattrapage === 0 || r.rattrapage === 2)
      ? chipEl('hébergeur · rattrapé', 'warn', { title: 'le plugin n’a pas scanné : le dashboard l’a fait à 6 h 45' })
      : chipEl('hébergeur · non contrôlé', 'err', { title: 'ni le plugin ni le dashboard n’ont pu photographier le site' });
  const t = r.retour;
  let res;
  if (t && (t.retablis || []).length) {
    res = chipEl('annulée : ' + t.retablis.map(x => x.slug + ' → ' + x.version).join(', '),
      t.ecarts_apres === 0 ? 'warn' : 'err');
  } else if ((r.ecarts || []).length) {
    res = chipEl(r.ecarts.length + ' page' + (r.ecarts.length > 1 ? 's' : '') + ' en échec', 'err',
      { title: r.ecarts.map(e => e.page).join(', ') });
  } else {
    res = chipEl('aucun écart', 'ok');
  }
  const sans = (r.sans_effet || []).length
    ? h('div', { class: 'sub', text: 'sans effet : ' + r.sans_effet.join(', ') }) : null;
  return h('tr', {},
    h('td', {}, lienSite(r.domain, r.site),
      r.confirme ? h('div', { class: 'sub', text: 'écart de la nuit du ' + String(r.at).slice(0, 10) }) : null),
    h('td', { class: 'wrapcell' }, items, sans),
    h('td', {}, controle),
    h('td', {}, res, lienRapport(r.report_url)));
}

/* ---- sites ------------------------------------------------------------------ */
function rendreSites() {
  const tb = document.getElementById('maj-tb');
  if (!tb) return;
  let S = allSites().filter(s => s.via !== 'rest' || s.plugins_auto_update != null);
  if (FILT.q) S = S.filter(s => (nomDeSite(s) + ' ' + s.domain).toLowerCase().includes(FILT.q));
  const lignes = S.map(s => ({ s, e: etatAuto(s) }))
    .filter(x => !FILT.mode || x.e.mode === FILT.mode)
    .sort((a, b) => (ORDRE[a.e.mode] - ORDRE[b.e.mode])
      || nomDeSite(a.s).localeCompare(nomDeSite(b.s)));
  const cnt = document.getElementById('maj-count');
  if (cnt) {
    const nAuto = allSites().filter(s => ETAT.modes[s.domain]).length;
    cnt.textContent = nAuto + ' site' + (nAuto > 1 ? 's' : '') + ' en automatique';
  }
  mount(tb, lignes.length ? lignes.map(({ s, e }) => ligneSite(s, e))
    : h('tr', { class: 'grouprow' }, h('td', { colspan: '7' },
      h('span', { class: 'muted', text: 'Aucun site ne correspond au filtre.' }))));
}

function fraction(n, total) {
  if (total == null) return h('span', { class: 'muted', text: '?' });
  if (n == null) return h('span', { class: 'muted', text: '? / ' + total });
  return h('span', { class: 'num', text: n + ' / ' + total });
}

function ligneSite(s, e) {
  const rest = s.via === 'rest';
  const viz = vizConnected(s);
  const [txt, niv, aide] = MODE_CHIP[e.mode];
  const nom = h('td', { class: 'site' },
    h('a', { class: 'seclien', href: '#site/' + encodeURIComponent(cleDeSite(s)) + '/reglages', text: nomDeSite(s) }),
    estPreprod(s) ? ' ' : null, estPreprod(s) ? chipEl('préprod', 'mut', { point: false }) : null);

  const rb = h('input', { type: 'checkbox', 'aria-label': 'Retour arrière automatique sur ' + nomDeSite(s) });
  rb.checked = e.rollback;
  if (e.mode !== 'auto') { rb.disabled = true; rb.title = 'Le retour arrière accompagne le mode automatique'; }
  else if (!viz) { rb.disabled = true; rb.title = 'VizProof n’est pas relié : rien ne détecterait la casse'; }
  rb.onchange = async () => {
    rb.disabled = true;
    const ok = await poserMode(s, { rollback: rb.checked });
    rb.disabled = false;
    if (!ok) rb.checked = !rb.checked;
  };

  /* Auto-MAJ natives : pour un site en automatique, tout ce qui n'est pas zéro
     est une mise à jour qui passera SANS contrôle, à côté du dashboard. */
  const natives = e.nExt == null && e.nTh == null ? h('span', { class: 'muted', text: '?' })
    : h('span', {},
      fraction(e.nExt, e.ext), h('span', { class: 'muted', text: ' ext · ' }),
      fraction(e.nTh, e.th), h('span', { class: 'muted', text: ' th' }),
      e.mode === 'auto' && e.natives > 0
        ? [' ', chipEl('à couper', 'warn', { title: 'WordPress / WP Toolkit mettraient encore à jour sans contrôle — « Activer » de nouveau les coupe' })]
        : null);

  let action;
  if (e.mode === 'auto') {
    action = h('button', { type: 'button', class: 'btn sm', text: 'Désactiver' });
    action.onclick = () => desactiver(s);
  } else if (rest) {
    action = h('span', { class: 'muted small', text: 'sans SSH' });
  } else {
    action = h('button', { type: 'button', class: 'btn sm primary' }, iconEl('zap'), 'Activer');
    action.onclick = () => activer(s, e);
  }
  return h('tr', {},
    nom,
    h('td', {}, chipEl(txt, niv, { title: aide })),
    h('td', {}, e.attente ? h('span', { class: 'num', text: String(e.attente) }) : h('span', { class: 'muted', text: '—' })),
    h('td', {}, natives),
    h('td', {}, viz ? chipEl('VizProof', 'ok') : chipEl('non relié', 'mut')),
    h('td', {}, h('label', { class: 'small inlinechk' }, rb, e.rollback ? ' activé' : ' non')),
    h('td', {}, action));
}

/* ---- gestes ----------------------------------------------------------------- */
async function poserMode(s, corps) {
  let r = null;
  try { r = await api('/api/mgmt/auto_mode', { server: s.srv, domain: s.domain, ...corps }); }
  catch (err) { r = { error: String(err) }; }
  if (!r || !r.ok) {
    askInfo('Réglage impossible', H((r && r.error) || 'le serveur n’a pas répondu'));
    return false;
  }
  ETAT.modes = r.modes || {};
  rendreSites();
  return true;
}

async function lancer(s, actions, titre) {
  const tasks = actions.map(action => ({ server: s.srv, domain: s.domain, action, arg: null }));
  let r;
  try {
    r = await api('/api/actions/bulk', { tasks, mode: 'continue', backup_first: false, viz_verify: false });
  } catch (err) { r = { error: String(err) }; }
  if (r && r.job) { demarrerJob(r.job, titre, nomDeSite(s)); return true; }
  askInfo(titre + ' impossible', (r && r.error) ? H(r.error) : 'Le serveur n’a pas renvoyé de tâche.');
  return false;
}

function activer(s, e) {
  const viz = vizConnected(s);
  const corps = `<label class="fld"><input type="checkbox" id="auto-rb"${viz ? ' checked' : ' disabled'}>
      Retour arrière automatique si VizProof voit une page en échec</label>
    <p class="hint hint-loose">${viz
      ? 'Chaque nuit à 4 h, mise à jour Contrôlée : référence VizProof, sauvegarde, archive, mise à jour, scan. Si une page casse, le site est remis depuis l’archive — extensions premium comprises — et une alerte Telegram le dit. Un site tombé est remis dans tous les cas.'
      : '<b>VizProof n’est pas relié à ce site</b> : seul un site tombé ferait annuler la mise à jour. Reliez-le depuis l’onglet VizProof du site.'}</p>
    <p class="hint hint-loose">Les mises à jour automatiques de WordPress et de l’hébergeur (WP Toolkit) sont <b>coupées</b> sur ce site${e.natives ? ` (${e.natives} élément(s) aujourd’hui)` : ''} : c’est le dashboard qui s’en charge.</p>`;
  askOpen('Activer le mode automatique',
    `Confier les mises à jour de <b>${H(nomDeSite(s))}</b> au dashboard (toutes les extensions et tous les thèmes) ?`,
    corps,
    () => {
      const rb = document.getElementById('auto-rb');
      poserMode(s, { auto: true, rollback: !!(rb && rb.checked) })
        .then(ok => { if (ok) lancer(s, ['autoupdate_off', 'themes_autoupdate_off'], 'Mode automatique'); });
    });
  document.getElementById('ask-ok').textContent = 'Activer';
}

function desactiver(s) {
  askOpen('Désactiver le mode automatique',
    `Le dashboard ne mettra plus à jour <b>${H(nomDeSite(s))}</b> la nuit. Les mises à jour automatiques de WordPress et de l’hébergeur restent coupées : le site passe en manuel.`,
    '',
    () => { poserMode(s, { auto: false }); });
  document.getElementById('ask-ok').textContent = 'Désactiver';
}

/* ---- chargement --------------------------------------------------------------- */
async function charger() {
  try {
    const r = await api('/api/mgmt/auto_state');
    ETAT = { modes: (r && r.modes) || {}, nuit: (r && r.nuit) || {}, maj: (r && r.maj) || {} };
  } catch (err) { /* réseau : on garde l'état précédent */ }
  rendreNuit();
  rendreSites();
}

export function loadMaj() {
  monter();
  rendreNuit();
  rendreSites();
  charger();
}

/** Appelé quand la flotte change (re-scan après activation) : compteurs à jour. */
export function onFleetMaj() {
  if (MONTE && store.fleet) rendreSites();
}
