/* Écran Mises à jour — « qui se met à jour seul, et qu'est-ce qui s'est passé
   cette nuit ? ».

   Le mode automatique était un réglage parmi d'autres, au fond de l'onglet
   Réglages de chaque site : on ne voyait ni QUELS sites étaient en
   automatique, ni ce que la nuit avait donné. Cette page le met au premier
   plan :

     1. les trois façons de mettre à jour, en une phrase chacune — les boutons
        « Contrôlée » et « Directe » de la page site renvoient à ce vocabulaire ;
     2. le bilan de la nuit (data/viz_nuit.json, script de 6 h 45) : ce qui a
        été mis à jour, qui l'a contrôlé, ce que VizProof a vu, ce qui a été
        annulé ;
     3. le mode automatique site par site, avec le RETOUR ARRIÈRE AUTOMATIQUE,
        réglage propre au dashboard (data/auto_mode.json).

   Activer le mode automatique = deux actions sur le site (MAJ auto des
   extensions, puis des thèmes), lancées comme une action groupée, plus le
   réglage du retour arrière côté dashboard. Les compteurs viennent de la
   collecte : ils se mettent à jour au re-scan qui suit l'action. */

import { api } from '../lib/api.js';
import { esc as H, h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { allSites, nomDeSite, store } from '../lib/state.js';
import { chipEl, estPreprod } from '../components/chip.js';
import { askInfo, askOpen } from '../components/confirm.js';
import { demarrerJob } from '../components/job.js';
import { vizConnected } from '../components/viz.js';
import { cleDeSite, extensionsMajables } from './site.js';

let ETAT = { modes: {}, nuit: {} };
let MONTE = false;
const FILT = { q: '', mode: '' };

/* ---- état d'un site --------------------------------------------------------- */
function etatAuto(s) {
  const ext = extensionsMajables(s).n || 0;
  const nExt = s.plugins_auto_update == null ? null : Math.min(s.plugins_auto_update, ext);
  const th = Array.isArray(s.themes_list) ? s.themes_list.length : null;
  const nTh = s.themes_auto_update == null || th == null ? null : Math.min(s.themes_auto_update, th);
  let mode = 'manuel';
  if ((nExt || 0) > 0 || (nTh || 0) > 0) mode = 'partiel';
  if (ext > 0 && nExt >= ext && (th == null || nTh == null || nTh >= th)) mode = 'auto';
  return { ext, nExt, th, nTh, mode, rollback: !!(ETAT.modes[s.domain] || {}).rollback };
}

const MODE_CHIP = {
  auto: ['automatique', 'ok'],
  partiel: ['partiel', 'warn'],
  manuel: ['manuel', 'mut'],
};

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
        h('dd', { text: 'La nuit, sans vous : l’hébergeur applique les nouvelles versions vers 5 h, '
          + 'le dashboard vérifie à 6 h 45 que VizProof a tout contrôlé — et annule la mise à jour '
          + 'si une page casse, quand le retour arrière automatique est activé.' }))),
    h('section', { class: 'section secsec', id: 'maj-nuit' },
      h('div', { class: 'sechead' }, h('h2', { text: 'Cette nuit' }),
        h('span', { class: 'muted small', id: 'maj-nuit-quand' })),
      h('div', { id: 'maj-nuit-body' })),
    h('section', { class: 'section secsec', id: 'maj-sites' },
      h('div', { class: 'sechead' }, h('h2', { text: 'Mode automatique, site par site' })),
      h('p', { class: 'hint', text: 'Le retour arrière automatique demande VizProof : sans contrôle '
        + 'visuel, rien ne dit qu’une mise à jour a cassé quoi que ce soit.' }),
      h('div', { class: 'filters' }, q, sel, h('span', { class: 'muted small', id: 'maj-count' })),
      h('div', { class: 'wrap' }, h('table', { id: 'maj-tbl' },
        h('thead', {}, h('tr', {},
          ['Site', 'Mode', 'Extensions', 'Thèmes', 'Contrôle visuel', 'Retour arrière auto', '']
            .map(t => h('th', { text: t })))),
        h('tbody', { id: 'maj-tb' })))));
}

/* ---- bilan de la nuit ------------------------------------------------------- */
function rendreNuit() {
  const box = document.getElementById('maj-nuit-body');
  if (!box) return;
  const n = ETAT.nuit || {};
  const quand = document.getElementById('maj-nuit-quand');
  if (quand) quand.textContent = n.generated_at ? 'contrôle du ' + n.generated_at : '';
  const sites = Object.values(n.sites || {}).filter(r => r && typeof r === 'object');
  if (!sites.length) {
    mount(box, h('p', { class: 'hint hint-tight', text: 'Aucune mise à jour automatique relevée cette nuit.' }));
    return;
  }
  sites.sort((a, b) => String(a.site).localeCompare(String(b.site)));
  mount(box, h('div', { class: 'wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Site', 'Mis à jour', 'Contrôle', 'Résultat'].map(t => h('th', { text: t })))),
    h('tbody', {}, sites.map(ligneNuit)))));
}

function ligneNuit(r) {
  const s = allSites().find(x => x.domain === r.domain);
  const lien = h('a', { class: 'seclien', href: '#site/' + encodeURIComponent(s ? cleDeSite(s) : r.site), text: r.site });
  const items = (r.items || []).join(', ') || '—';
  const nc = r.non_couvertes || [];
  const controle = !nc.length ? chipEl('VizProof', 'ok', { title: 'scan lancé par le plugin après la mise à jour' })
    : (r.rattrapage === 0 || r.rattrapage === 2)
      ? chipEl('rattrapé par le dashboard', 'ok', { title: 'le plugin n’a pas scanné : le dashboard l’a fait à 6 h 45' })
      : chipEl('non contrôlé', 'warn', { title: 'ni le plugin ni le dashboard n’ont pu photographier le site' });
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
  const rap = r.report_url ? h('a', { href: r.report_url, target: '_blank', rel: 'noopener noreferrer', text: 'rapport' }) : null;
  return h('tr', {},
    h('td', {}, lien, r.confirme ? h('div', { class: 'sub', text: 'écart de la nuit du ' + String(r.at).slice(0, 10) }) : null),
    h('td', { class: 'wrapcell' }, items, sans),
    h('td', {}, controle),
    h('td', {}, res, rap ? ' ' : null, rap));
}

/* ---- sites ------------------------------------------------------------------ */
function rendreSites() {
  const tb = document.getElementById('maj-tb');
  if (!tb) return;
  let S = allSites().filter(s => s.via !== 'rest' || s.plugins_auto_update != null);
  if (FILT.q) S = S.filter(s => (nomDeSite(s) + ' ' + s.domain).toLowerCase().includes(FILT.q));
  const lignes = S.map(s => ({ s, e: etatAuto(s) }))
    .filter(x => !FILT.mode || x.e.mode === FILT.mode)
    .sort((a, b) => ({ auto: 0, partiel: 1, manuel: 2 }[a.e.mode] - { auto: 0, partiel: 1, manuel: 2 }[b.e.mode])
      || nomDeSite(a.s).localeCompare(nomDeSite(b.s)));
  const cnt = document.getElementById('maj-count');
  if (cnt) {
    const nAuto = allSites().filter(s => etatAuto(s).mode === 'auto').length;
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
  const [txt, niv] = MODE_CHIP[e.mode];
  const nom = h('td', { class: 'site' },
    h('a', { class: 'seclien', href: '#site/' + encodeURIComponent(cleDeSite(s)) + '/reglages', text: nomDeSite(s) }),
    estPreprod(s) ? ' ' : null, estPreprod(s) ? chipEl('préprod', 'mut', { point: false }) : null);

  const rb = h('input', { type: 'checkbox', 'aria-label': 'Retour arrière automatique sur ' + nomDeSite(s) });
  rb.checked = e.rollback;
  if (rest) { rb.disabled = true; rb.title = 'Site géré sans SSH : le retour arrière est impossible d’ici'; }
  else if (!viz) { rb.disabled = true; rb.title = 'VizProof n’est pas relié : rien ne détecterait la casse'; }
  rb.onchange = async () => {
    rb.disabled = true;
    const ok = await poserRollback(s, rb.checked);
    rb.disabled = false;
    if (!ok) rb.checked = !rb.checked;
  };

  let action;
  if (rest) {
    action = h('span', { class: 'muted small', text: 'sans SSH' });
  } else if (e.mode === 'auto') {
    action = h('button', { type: 'button', class: 'btn sm', text: 'Désactiver' });
    action.onclick = () => desactiver(s);
  } else {
    action = h('button', { type: 'button', class: 'btn sm primary' }, iconEl('zap'), 'Activer');
    action.onclick = () => activer(s);
  }
  return h('tr', {},
    nom,
    h('td', {}, chipEl(txt, niv)),
    h('td', {}, fraction(e.nExt, e.ext)),
    h('td', {}, fraction(e.nTh, e.th)),
    h('td', {}, viz ? chipEl('VizProof', 'ok') : chipEl('non relié', 'mut')),
    h('td', {}, h('label', { class: 'small inlinechk' }, rb, e.rollback ? ' activé' : ' non')),
    h('td', {}, action));
}

/* ---- gestes ----------------------------------------------------------------- */
async function poserRollback(s, actif) {
  let r = null;
  try { r = await api('/api/mgmt/auto_mode', { server: s.srv, domain: s.domain, rollback: actif }); }
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

function activer(s) {
  const viz = vizConnected(s);
  const corps = `<label class="fld"><input type="checkbox" id="auto-rb"${viz ? ' checked' : ' disabled'}>
      Retour arrière automatique si VizProof voit une page en échec</label>
    <p class="hint hint-loose">${viz
      ? 'La mise à jour fautive est remise à sa version d’avant, sortie des mises à jour automatiques, et une alerte Telegram le dit. Les extensions premium absentes de wordpress.org ne peuvent pas être rétablies ainsi.'
      : '<b>VizProof n’est pas relié à ce site</b> : les mises à jour de nuit ne seront pas contrôlées. Reliez-le depuis l’onglet VizProof du site.'}</p>`;
  askOpen('Activer le mode automatique',
    `Mettre <b>${H(nomDeSite(s))}</b> en mise à jour automatique (toutes les extensions et tous les thèmes) ?`,
    corps,
    () => {
      const rb = document.getElementById('auto-rb');
      const avecRetour = !!(rb && rb.checked);
      lancer(s, ['autoupdate_on', 'themes_autoupdate_on'], 'Mode automatique')
        .then(ok => { if (ok && avecRetour) poserRollback(s, true); });
    });
  document.getElementById('ask-ok').textContent = 'Activer';
}

function desactiver(s) {
  askOpen('Désactiver le mode automatique',
    `Plus aucune mise à jour automatique sur <b>${H(nomDeSite(s))}</b> (extensions et thèmes), et plus de retour arrière automatique ?`,
    '',
    () => {
      lancer(s, ['autoupdate_off', 'themes_autoupdate_off'], 'Mode manuel')
        .then(ok => { if (ok && etatAuto(s).rollback) poserRollback(s, false); });
    });
  document.getElementById('ask-ok').textContent = 'Désactiver';
}

/* ---- chargement --------------------------------------------------------------- */
async function charger() {
  try {
    const r = await api('/api/mgmt/auto_state');
    ETAT = { modes: (r && r.modes) || {}, nuit: (r && r.nuit) || {} };
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
