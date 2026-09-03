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
import { chipEl } from '../components/chip.js';
import { estNow, incidentEl, kindLabel } from '../components/incident.js';
import { setIncidentCount } from '../components/shell.js';
import { siteParCle, cleDeSite, lancerSur } from './site.js';

/* Le libellé des types, la ligne dépliable et son panneau vivent dans
   components/incident.js : la page site montre exactement le même objet. */

const GRAVITES = [
  ['critical', 'Critique', 'err'],
  ['warning', 'Avertissement', 'warn'],
];

let INCIDENTS = [], ACQUITTES = [], ERREURS = [], CHARGE = false, AT = 0;
let NB_ACQUITTES = 0, ACK_OUVERT = false;
let MONTE = false;
const FILT = { sev: '', kind: '', q: '' };
const ACK_CLE = 'dashIncAcksOpen';

/* L'ouverture du bloc « Acquittés » est mémorisée : qui travaille sur ses
   décisions passées ne veut pas le rouvrir à chaque visite. Le stockage peut
   être refusé (navigation privée) — le bloc reste alors simplement replié. */
function ackMemo(v) { try { localStorage.setItem(ACK_CLE, v ? '1' : '0'); } catch (e) { /* refusé */ } }
try { ACK_OUVERT = localStorage.getItem(ACK_CLE) === '1'; } catch (e) { ACK_OUVERT = false; }

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

  mount('page-incidents',
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
    const b = h('button', { type: 'button', class: 'btn sm', text: inc.action.label || 'Corriger' });
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
  return incidentEl(inc, {
    siteEl, chipKind: true, actions: boutons, acquitte: !!acquitte,
    onAck: () => charger(true),
  });
}

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

/* Un groupe : un intitulé, un compteur, ses lignes. */
function groupe(titre, niveau, lot, acquitte) {
  return h('section', { class: 'incgrp' },
    h('div', { class: 'incgrp-h' },
      h('span', { class: 'glbl', text: titre }), chipEl(String(lot.length), niveau)),
    h('div', { class: 'inclist' }, lot.map(i => ligne(i, acquitte))));
}

/* Bloc « À planifier » : mêmes lignes, mais un intitulé qui dit ce qu'on en
   attend. Sans cette phrase, la section se lit comme une seconde file d'attente
   — c'est exactement ce dont on sortait. */
function blocPlan(lot) {
  if (!lot.length) return null;
  return h('section', { class: 'incgrp incplan' },
    h('div', { class: 'incgrp-h' },
      h('span', { class: 'glbl', text: 'À planifier' }), chipEl(String(lot.length), 'mut'),
      h('span', { class: 'muted small', text: 'chantiers et situations connues — hors pastille' })),
    h('div', { class: 'inclist' }, lot.map(i => ligne(i, false))));
}

/* Bloc « Acquittés », replié : il n'est chargé qu'à l'ouverture (une requête
   de plus, `?include=acked`), et son compteur vient de `counts.acked` — il est
   donc juste avant même d'avoir lu la liste. */
function blocAcquittes() {
  if (!NB_ACQUITTES && !ACQUITTES.length) return null;
  const liste = h('div', { class: 'inclist', id: 'inc-acked-list', hidden: !ACK_OUVERT });
  if (ACK_OUVERT) {
    const vus = filtres(ACQUITTES);
    if (!ACQUITTES.length) liste.append(h('p', { class: 'hint hint-tight', text: 'chargement…' }));
    else if (!vus.length) liste.append(h('p', { class: 'hint hint-tight', text: 'aucun acquitté ne correspond au filtre.' }));
    else vus.forEach(i => liste.append(ligne(i, true)));
  }
  const bt = h('button', {
    type: 'button', class: 'todo-h', 'aria-expanded': ACK_OUVERT ? 'true' : 'false',
    'aria-controls': 'inc-acked-list',
  },
    h('span', { class: 'todo-chev' + (ACK_OUVERT ? ' open' : '') }, iconEl('chevron-right', { size: 14 })),
    h('span', { class: 'glbl', text: 'Acquittés (' + (NB_ACQUITTES || ACQUITTES.length) + ')' }),
    h('span', { class: 'muted small', text: 'mises en veille et alertes écartées' }));
  bt.onclick = () => {
    ACK_OUVERT = !ACK_OUVERT;
    ackMemo(ACK_OUVERT);
    if (ACK_OUVERT && !ACQUITTES.length) chargerAcquittes();
    render();
  };
  return h('section', { class: 'incgrp incack' }, bt, liste);
}

function render() {
  const body = document.getElementById('inc-body'), cnt = document.getElementById('inc-count');
  if (!body) return;

  // Sources en échec : dites AVANT la liste — une file vide n'a pas le même
  // sens si l'une de ses sources n'a pas répondu.
  mount('inc-errors', ERREURS.map(e => h('p', { class: 'hint hint-tight' },
    chipEl('source incomplète', 'warn'), ' ',
    h('span', { class: 'muted small', text: (e.source || '?') + ' : ' + (e.error || '') }))));

  if (!CHARGE) { mount(body, h('p', { class: 'hint hint-tight', text: 'chargement…' })); return; }
  const ack = blocAcquittes();
  if (!INCIDENTS.length) {
    cnt.textContent = '';
    mount(body, h('div', { class: 'empty' },
      iconEl('circle-check', { size: 20 }),
      h('h2', { text: 'Rien à traiter' }),
      h('p', { text: 'Aucun site injoignable, aucune vulnérabilité critique corrigeable, '
        + 'aucun administrateur inconnu, aucune sauvegarde en retard : le parc est en ordre.' })),
      ack);
    return;
  }
  const vus = filtres();
  cnt.textContent = vus.length === INCIDENTS.length
    ? vus.length + ' incident' + (vus.length > 1 ? 's' : '')
    : vus.length + ' / ' + INCIDENTS.length;
  if (!vus.length) {
    mount(body, h('p', { class: 'hint hint-tight', text: 'aucun incident ne correspond au filtre.' }), ack);
    return;
  }
  // Deux natures, deux blocs : ce qui se règle maintenant, et ce qui se décide.
  const maintenant = vus.filter(estNow), plan = vus.filter(i => !estNow(i));
  const blocs = [];
  GRAVITES.forEach(([cle, titre, niveau]) => {
    const lot = maintenant.filter(i => i.severity === cle);
    if (lot.length) blocs.push(groupe(titre, niveau, lot, false));
  });
  // Gravité inconnue (backend plus récent que le front) : elle reste visible.
  const autres = maintenant.filter(i => !GRAVITES.some(g => g[0] === i.severity));
  if (autres.length) blocs.push(groupe('Autres', 'mut', autres, false));
  if (blocs.length) {
    blocs.unshift(h('h2', { class: 'incsec', text: 'À traiter' }));
  } else if (plan.length) {
    blocs.push(h('p', { class: 'hint hint-tight todo-ok' },
      iconEl('circle-check', { size: 16 }),
      h('span', { text: 'Rien à traiter — ' + plan.length + ' à planifier.' })));
  }
  blocs.push(blocPlan(plan), ack);
  mount(body, blocs);
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
  if (ACK_OUVERT && NB_ACQUITTES) chargerAcquittes();
}

/* La liste des acquittés est une requête À PART : la file par défaut n'a pas à
   la porter, et le bloc reste replié la plupart du temps. */
async function chargerAcquittes() {
  let j = null;
  try { j = await api('/api/incidents?include=acked'); } catch (e) { j = null; }
  ACQUITTES = (j && Array.isArray(j.acked)) ? j.acked : [];
  NB_ACQUITTES = ACQUITTES.length;
  render();
}

export function renderIncidents() {
  monter();
  render();
  charger();
}
