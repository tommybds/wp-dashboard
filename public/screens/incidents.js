/* Écran Incidents — « qu'est-ce qui est cassé ou périmé maintenant ? »

   La page s'ouvre sur la file complète de `GET /api/incidents`, déjà triée par
   le serveur (critique d'abord, puis le plus ancien). Elle n'invente aucun
   classement : elle groupe par gravité, traduit le `kind` en libellé humain, et
   propose SUR LA LIGNE ce qui répond à l'incident — une action (même mécanisme
   de confirmation que la page site) ou un lien vers la section concernée.

   TROIS blocs, et c'est le point de la refonte : « À traiter » (ce qui se règle
   maintenant, groupé par gravité), « À planifier » (les chantiers et les
   situations connues et assumées — ton neutre, sans trait rouge, hors pastille)
   et « Acquittés », replié, qui n'est chargé (`?include=acked`) qu'à
   l'ouverture. Une file dont rien ne peut disparaître n'est plus lue : c'est
   cette séparation, avec le bouton « Ne plus signaler… » du pli, qui la rend
   videable.

   Une source en échec (`errors`) ne se cache pas : elle s'affiche en
   avertissement discret, parce qu'une file « vide » n'a pas le même sens si
   l'une de ses sources n'a pas répondu.

   La pastille de la barre latérale est posée ici avec la MÊME règle que dans le
   Parc (les incidents « à traiter », rouge s'il y a du critique) : les deux
   écrans lisent la même route, ils ne peuvent pas diverger. */

import { api } from '../lib/api.js';
import { h, mount, occupe } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { debounce } from '../lib/format.js';
import { estNow, incidentLigneTableau, kindLabel, sourceIncompleteEl } from '../components/incident.js';
import { setIncidentCount } from '../components/shell.js';
import { siteParCle, cleDeSite, lancerSur } from './site.js';

/* Le libellé des types, la ligne dépliable et son panneau vivent dans
   components/incident.js : la page site montre exactement le même objet. */


let INCIDENTS = [], ACQUITTES = [], ACQ_CHARGES = false, ERREURS = [], CHARGE = false, AT = 0;
let NB_ACQUITTES = 0;
let MONTE = false;
const FILT = { sev: '', kind: '', q: '' };

/* Trois VUES d'une même liste, choisies par un sélecteur segmenté : ce qui se
   règle maintenant, ce qui se décide (chantiers, situations connues), et ce
   qu'on a écarté. Elles s'empilaient en trois blocs imbriqués, chacun avec ses
   sous-groupes de gravité : on ne savait plus où regarder. */
const VUES = [
  ['now', 'À traiter'],
  ['plan', 'À planifier'],
  ['acked', 'Acquittés'],
];
const VUE_CLE = 'dashIncVue';
let VUE = 'now';
try { VUE = VUES.some(([k]) => k === localStorage.getItem(VUE_CLE)) ? localStorage.getItem(VUE_CLE) : 'now'; }
catch (e) { VUE = 'now'; }
function vueMemo(v) { try { localStorage.setItem(VUE_CLE, v); } catch (e) { /* stockage refusé */ } }

const VUE_AIDE = {
  now: 'Ce qui se règle maintenant : c’est ce que compte la pastille de la barre latérale.',
  plan: 'Chantiers et situations connues : à décider, hors pastille.',
  acked: 'Mises en veille et alertes écartées : elles reviennent seules si la situation change.',
};

/* ---- squelette -------------------------------------------------------------- */
function monter() {
  if (MONTE) return;
  MONTE = true;
  const q = h('input', {
    type: 'search', id: 'inc-q', class: 'w-md',
    placeholder: 'Filtrer un site, un serveur…', 'aria-label': 'Filtrer les incidents',
  });
  q.value = FILT.q;
  q.oninput = debounce(e => { FILT.q = e.target.value; render(); }, 200);

  const sev = h('select', { id: 'inc-sev', 'aria-label': 'Gravité' },
    h('option', { value: '', text: 'Toutes gravités' }),
    h('option', { value: 'critical', text: 'Critique' }),
    h('option', { value: 'warning', text: 'Avertissement' }));
  sev.onchange = e => { FILT.sev = e.target.value; render(); };

  const kind = h('select', { id: 'inc-kind', 'aria-label': 'Type' });
  kind.onchange = e => { FILT.kind = e.target.value; render(); };

  const actualiser = h('button', { type: 'button', class: 'btn sm', id: 'inc-refresh' },
    iconEl('refresh-cw'), 'Actualiser');
  actualiser.onclick = () => charger(true);

  const vues = h('div', { class: 'tabs incvues', role: 'group', 'aria-label': 'Vue', id: 'inc-vues' },
    VUES.map(([k, lbl]) => {
      const bv = h('button', { type: 'button', class: 'tab', dataset: { vue: k } },
        h('span', { text: lbl }), h('span', { class: 'tab-n', dataset: { n: k } }));
      bv.onclick = () => {
        VUE = k;
        vueMemo(k);
        if (k === 'acked' && !ACQ_CHARGES) chargerAcquittes();
        render();
      };
      return bv;
    }));

  mount('page-incidents',
    h('div', { class: 'inc-tete' },
      vues,
      h('span', { class: 'muted small', id: 'inc-aide' })),
    h('div', { class: 'filters', id: 'inc-filters' },
      q, sev, kind,
      h('span', { class: 'spacer' }),
      h('span', { class: 'muted small', id: 'inc-count' }),
      actualiser),
    h('div', { id: 'inc-errors' }),
    h('div', { id: 'inc-body' }, h('p', { class: 'hint hint-tight', text: 'chargement…' })));
}

/* Un lien de section : `link` vient du backend, on ne garde que des fragments
   internes de forme connue. */
function lienSection(link) {
  const tab = String((link && link.tab) || '').replace(/[^a-z-]/g, '');
  const sub = String((link && link.sub) || '').replace(/[^a-z0-9-]/g, '');
  if (!tab) return null;
  return h('a', { class: 'btn sm', href: '#' + tab + (sub ? '/' + sub : ''), text: 'Voir' });
}

function ligne(inc, acquitte) {
  const s = inc.site ? siteParCle(inc.site) : null;
  const boutons = h('span', { class: 'inc-b' });

  if (inc.action && inc.action.act && s) {
    // « MAJ modern-events-calendar → 7.36.4 » : l'extension est déjà nommée
    // dans la colonne Problème ; le bouton garde le geste et la version.
    const lib = inc.action.label || 'Corriger';
    const court = lib.replace(/^MAJ \S+ → /, 'MAJ → ');
    const b = h('button', { type: 'button', class: 'btn sm', text: court, title: court !== lib ? lib : null });
    b.dataset.act = inc.action.act;
    if (inc.action.arg) b.dataset.arg = inc.action.arg;
    b.onclick = async () => {
      await lancerSur(s, b, inc.action.label);
      charger(true);
    };
    boutons.append(b);
  }
  if (s) {
    boutons.append(h('a', {
      class: 'btn sm', href: '#site/' + encodeURIComponent(cleDeSite(s)), text: 'Ouvrir',
    }));
  } else {
    const l = lienSection(inc.link);
    if (l) boutons.append(l);
  }

  const siteEl = inc.site
    ? h('a', {
      class: 'inc-s', href: '#site/' + encodeURIComponent(s ? cleDeSite(s) : inc.site), text: inc.site,
    })
    : (inc.server ? h('b', { class: 'inc-s', text: inc.server }) : null);
  return incidentLigneTableau(inc, {
    siteEl, actions: boutons, acquitte: !!acquitte, nbCols: COLS.length,
    onAck: () => charger(true),
  });
}

const COLS = ['', 'Gravité', 'Type', 'Site', 'Problème', 'Depuis', ''];

/* ---- rendu ------------------------------------------------------------------ */
function majTypes() {
  const sel = document.getElementById('inc-kind');
  if (!sel) return;
  const avant = FILT.kind;
  const kinds = [...new Set(INCIDENTS.map(i => i.kind).filter(Boolean))]
    .sort((a, b) => kindLabel(a).localeCompare(kindLabel(b)));
  mount(sel, h('option', { value: '', text: 'Tous les types' }),
    kinds.map(k => h('option', { value: k, text: kindLabel(k) })));
  sel.value = kinds.includes(avant) ? avant : '';
  FILT.kind = sel.value;
}

function filtres(lot) {
  const q = FILT.q.toLowerCase().trim();
  return (lot || INCIDENTS).filter(i =>
    (!FILT.sev || i.severity === FILT.sev)
    && (!FILT.kind || i.kind === FILT.kind)
    && (!q || ((i.site || '') + ' ' + (i.server || '') + ' ' + (i.title || '') + ' ' + (i.detail || ''))
      .toLowerCase().includes(q)));
}

function tableau(lot, acquitte) {
  return h('div', { class: 'wrap' }, h('table', { class: 'inctbl' },
    h('thead', {}, h('tr', {}, COLS.map(t => h('th', { text: t })))),
    h('tbody', {}, lot.flatMap(i => ligne(i, acquitte)))));
}

function render() {
  const body = document.getElementById('inc-body'), cnt = document.getElementById('inc-count');
  if (!body) return;

  // Sources en échec : dites AVANT la liste — une file vide n'a pas le même
  // sens si l'une de ses sources n'a pas répondu.
  mount('inc-errors', ERREURS.map(sourceIncompleteEl));

  const vus = filtres();
  const maintenant = vus.filter(estNow), plan = vus.filter(i => !estNow(i));
  const acq = ACQ_CHARGES ? filtres(ACQUITTES) : [];
  const nb = { now: maintenant.length, plan: plan.length, acked: ACQ_CHARGES ? acq.length : NB_ACQUITTES };
  document.querySelectorAll('#inc-vues .tab').forEach(b => {
    const on = b.dataset.vue === VUE;
    b.classList.toggle('active', on);
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
    const n = b.querySelector('.tab-n');
    if (n) n.textContent = CHARGE ? String(nb[b.dataset.vue]) : '';
  });
  const aide = document.getElementById('inc-aide');
  if (aide) aide.textContent = VUE_AIDE[VUE];

  if (!CHARGE) { mount(body, h('p', { class: 'hint hint-tight', text: 'chargement…' })); return; }
  const filtre = vus.length !== INCIDENTS.length;
  cnt.textContent = filtre ? 'filtre : ' + vus.length + ' / ' + INCIDENTS.length : '';

  let lot;
  if (VUE === 'acked') {
    if (!ACQ_CHARGES) { mount(body, h('p', { class: 'hint hint-tight', text: 'chargement…' })); return; }
    lot = acq;
  } else {
    lot = VUE === 'plan' ? plan : maintenant;
  }
  if (!lot.length) {
    if (VUE === 'now' && !maintenant.length && !filtre) {
      mount(body, h('div', { class: 'empty' },
        iconEl('circle-check', { size: 20 }),
        h('h2', { text: 'Rien à traiter' }),
        h('p', { text: 'Aucun site injoignable, aucune vulnérabilité critique corrigeable, '
          + 'aucun administrateur inconnu, aucune sauvegarde en retard'
          + (plan.length ? ' — ' + plan.length + ' point' + (plan.length > 1 ? 's' : '') + ' à planifier.' : '.') })));
    } else {
      mount(body, h('p', { class: 'hint hint-tight', text: filtre
        ? 'Aucun incident de cette vue ne correspond au filtre.'
        : VUE === 'plan' ? 'Rien à planifier.' : 'Aucune alerte acquittée.' }));
    }
    return;
  }
  // Critique d'abord, puis le plus ancien : l'ordre du serveur, qu'on garde.
  mount(body, tableau(lot, VUE === 'acked'));
}

/* ---- chargement -------------------------------------------------------------- */
async function charger(force) {
  if (!force && CHARGE && Date.now() - AT < 30000) { render(); return; }
  AT = Date.now();
  const bt = document.getElementById('inc-refresh');
  if (bt) bt.disabled = true;
  occupe('inc-body', true);
  let j = null;
  try { j = await api('/api/incidents'); } catch (e) { j = null; }
  INCIDENTS = (j && Array.isArray(j.incidents)) ? j.incidents : [];
  ERREURS = (j && Array.isArray(j.errors)) ? j.errors
    : (j ? [] : [{ source: 'réseau', error: 'file indisponible' }]);
  NB_ACQUITTES = Number((j && j.counts && j.counts.acked) || 0);
  ACQUITTES = [];
  CHARGE = true;
  if (bt) bt.disabled = false;
  occupe('inc-body', false);
  // Même règle que la file « à traiter » du Parc : une seule source, un seul
  // chiffre — et il ne compte QUE le bloc « à traiter ».
  const maintenant = INCIDENTS.filter(estNow);
  const crit = maintenant.filter(i => i.severity === 'critical').length;
  setIncidentCount(maintenant.length, crit ? 'err' : 'warn');
  majTypes();
  render();
  if (VUE === 'acked') chargerAcquittes();
}

/* La liste des acquittés est une requête À PART : la file par défaut n'a pas à
   la porter, et le bloc reste replié la plupart du temps. */
async function chargerAcquittes() {
  let j = null;
  try { j = await api('/api/incidents?include=acked'); } catch (e) { j = null; }
  ACQUITTES = (j && Array.isArray(j.acked)) ? j.acked : [];
  NB_ACQUITTES = ACQUITTES.length;
  ACQ_CHARGES = true;
  render();
}

export function renderIncidents() {
  monter();
  render();
  charger();
}
