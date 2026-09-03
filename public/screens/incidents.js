/* Écran Incidents — « qu'est-ce qui est cassé ou périmé maintenant ? »

   La page s'ouvre sur la file complète de `GET /api/incidents`, déjà triée par
   le serveur (critique d'abord, puis le plus ancien). Elle n'invente aucun
   classement : elle groupe par gravité, traduit le `kind` en libellé humain, et
   propose SUR LA LIGNE ce qui répond à l'incident — une action (même mécanisme
   de confirmation que la page site) ou un lien vers la section concernée.

   Une source en échec (`errors`) ne se cache pas : elle s'affiche en
   avertissement discret, parce qu'une file « vide » n'a pas le même sens si
   l'une de ses sources n'a pas répondu.

   La pastille de la barre latérale est posée ici avec la MÊME règle que dans le
   Parc (nombre d'incidents, rouge s'il y a du critique) : les deux écrans lisent
   la même route, ils ne peuvent pas diverger. */

import { api } from '../lib/api.js';
import { h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { relTime, absTime, debounce } from '../lib/format.js';
import { chipEl } from '../components/chip.js';
import { setIncidentCount } from '../components/shell.js';
import { siteParCle, cleDeSite, lancerSur } from './site.js';

/* `kind` → ce que la ligne dit à un humain. Un type inconnu garde sa clé :
   mieux vaut un mot technique qu'une ligne muette. */
const KINDS = {
  down: 'site injoignable',
  php_fatal: 'erreur PHP fatale',
  vuln_critical_fixable: 'vulnérabilité critique corrigeable',
  checksums_modified: 'checksums modifiés',
  admin_unknown: 'administrateur inconnu',
  server_stale: 'serveur injoignable',
  backup_late: 'sauvegarde en retard',
  cert_expiring: 'certificat',
  php_eol: 'PHP en fin de support',
};
const kindLabel = k => KINDS[k] || String(k || 'incident');

const GRAVITES = [
  ['critical', 'Critique', 'err'],
  ['warning', 'Avertissement', 'warn'],
];

let INCIDENTS = [], ERREURS = [], CHARGE = false, AT = 0;
let MONTE = false;
const FILT = { sev: '', kind: '', q: '' };

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

/* ---- une ligne ------------------------------------------------------------- */
function anciennete(inc) {
  if (inc.since) return relTime(inc.since).replace(/^il y a /, 'depuis ');
  const age = Number(inc.age_h) || 0;
  if (!age) return '';
  return age < 48 ? 'depuis ' + Math.round(age) + ' h' : 'depuis ' + Math.round(age / 24) + ' j';
}

/* Un lien de section : `link` vient du backend, on ne garde que des fragments
   internes de forme connue. */
function lienSection(link) {
  const tab = String((link && link.tab) || '').replace(/[^a-z-]/g, '');
  const sub = String((link && link.sub) || '').replace(/[^a-z0-9-]/g, '');
  if (!tab) return null;
  return h('a', { class: 'btn sm', href: '#' + tab + (sub ? '/' + sub : ''), text: 'Voir' });
}

function ligne(inc) {
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

  const quand = anciennete(inc);
  return h('div', { class: 'inc ' + (inc.severity === 'critical' ? 'err' : 'warn') },
    h('div', { class: 'inc-m' },
      h('div', { class: 'inc-t' },
        chipEl(kindLabel(inc.kind), 'mut'),
        inc.site
          ? h('a', {
            class: 'inc-s', href: '#site/' + encodeURIComponent(s ? cleDeSite(s) : inc.site), text: inc.site,
          })
          : (inc.server ? h('b', { class: 'inc-s', text: inc.server }) : null),
        h('span', { class: 'inc-h', text: inc.title || '' })),
      inc.detail ? h('div', { class: 'muted small inc-d', text: inc.detail }) : null),
    quand ? h('span', {
      class: 'muted small inc-a', title: inc.since ? absTime(inc.since) : '', text: quand,
    }) : null,
    boutons);
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

function filtres() {
  const q = FILT.q.toLowerCase().trim();
  return INCIDENTS.filter(i =>
    (!FILT.sev || i.severity === FILT.sev)
    && (!FILT.kind || i.kind === FILT.kind)
    && (!q || ((i.site || '') + ' ' + (i.server || '') + ' ' + (i.title || '') + ' ' + (i.detail || ''))
      .toLowerCase().includes(q)));
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
  if (!INCIDENTS.length) {
    cnt.textContent = '';
    mount(body, h('div', { class: 'empty' },
      iconEl('circle-check', { size: 20 }),
      h('h2', { text: 'Rien à traiter' }),
      h('p', { text: 'Aucun site injoignable, aucune vulnérabilité critique corrigeable, '
        + 'aucun administrateur inconnu, aucune sauvegarde en retard : le parc est en ordre.' })));
    return;
  }
  const vus = filtres();
  cnt.textContent = vus.length === INCIDENTS.length
    ? vus.length + ' incident' + (vus.length > 1 ? 's' : '')
    : vus.length + ' / ' + INCIDENTS.length;
  if (!vus.length) {
    mount(body, h('p', { class: 'hint hint-tight', text: 'aucun incident ne correspond au filtre.' }));
    return;
  }
  const blocs = [];
  GRAVITES.forEach(([cle, titre, niveau]) => {
    const lot = vus.filter(i => i.severity === cle);
    if (!lot.length) return;
    blocs.push(h('section', { class: 'incgrp' },
      h('div', { class: 'incgrp-h' },
        h('span', { class: 'glbl', text: titre }), chipEl(String(lot.length), niveau)),
      h('div', { class: 'inclist' }, lot.map(ligne))));
  });
  // Gravité inconnue (backend plus récent que le front) : elle reste visible.
  const autres = vus.filter(i => !GRAVITES.some(g => g[0] === i.severity));
  if (autres.length) {
    blocs.push(h('section', { class: 'incgrp' },
      h('div', { class: 'incgrp-h' }, h('span', { class: 'glbl', text: 'Autres' }),
        chipEl(String(autres.length), 'mut')),
      h('div', { class: 'inclist' }, autres.map(ligne))));
  }
  mount(body, blocs);
}

/* ---- chargement -------------------------------------------------------------- */
async function charger(force) {
  if (!force && CHARGE && Date.now() - AT < 30000) { render(); return; }
  AT = Date.now();
  const bt = document.getElementById('inc-refresh');
  if (bt) bt.disabled = true;
  let j = null;
  try { j = await api('/api/incidents'); } catch (e) { j = null; }
  INCIDENTS = (j && Array.isArray(j.incidents)) ? j.incidents : [];
  ERREURS = (j && Array.isArray(j.errors)) ? j.errors
    : (j ? [] : [{ source: 'réseau', error: 'file indisponible' }]);
  CHARGE = true;
  if (bt) bt.disabled = false;
  // Même règle que la file « à traiter » du Parc : une seule source, un seul
  // chiffre. Sans cela, deux pastilles finiraient par se contredire.
  const crit = INCIDENTS.filter(i => i.severity === 'critical').length;
  setIncidentCount(INCIDENTS.length, crit ? 'err' : 'warn');
  majTypes();
  render();
}

export function renderIncidents() {
  monter();
  render();
  charger();
}
