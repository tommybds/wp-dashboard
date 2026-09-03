/* Écran Changements — « qu'est-ce qui a bougé, et qui l'a fait ? »

   Phase 3 : les deux sous-onglets ont disparu. La page est une CHRONOLOGIE
   unique, groupée par jour, qui fusionne :

     * les changements d'état réels détectés par la collecte
       (`/api/mgmt/changes` — version installée qui bouge, admin ou extension
       ajouté/retiré) ;
     * les actions lancées depuis le dashboard (`/api/actions/log`) ;
     * depuis la phase 4, les ÉVÈNEMENTS poussés par les agents
       (`/api/mgmt/events` — connexion, nouvel administrateur, extension
       activée, mise à jour faite depuis wp-admin). Ils arrivent en temps réel,
       sans attendre la collecte : c'est souvent la ligne la plus ancienne d'une
       compromission.

   La tendance du parc (les quatre courbes) ferme la page : elle répond à la
   même question sur un autre pas de temps.

   Ancres : #changements/changements et #changements/tendance continuent de
   fonctionner (la correspondance vit dans app.js). */

import { api } from '../lib/api.js';
import { h, mount } from '../lib/dom.js';
import { relTime, absTime, debounce, stripPhpNoise, tsMs, detailEvenement, evenementAlerte } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { cacheFrais, cacheVider } from '../lib/state.js';
import { chipEl } from '../components/chip.js';
import { actLib } from './site.js';

/* ---- état du module -------------------------------------------------------- */
let MONTE = false;
let ENTREES = [];        // chronologie fusionnée, du plus récent au plus ancien
let RESUME = null;       // résumé 24 h renvoyé par /api/mgmt/changes
let CHGERR = '', LOGERR = '', EVTERR = '';

const TYPES = {
  change: { lbl: 'changement', ic: 'refresh-cw' },
  action: { lbl: 'action', ic: 'diamond' },
  // L'éclair : ce qui arrive tout seul, poussé par le site, sans qu'on ait rien
  // demandé — c'est ce qui distingue un évènement d'une action.
  event: { lbl: 'évènement', ic: 'zap' },
};

/* ============================================================================
   Squelette
   ========================================================================== */
function monterHist() {
  if (MONTE) return;
  MONTE = true;
  mount('page-hist',
    h('nav', { class: 'anchors', 'aria-label': 'Sections de la page Changements' },
      h('a', { class: 'anchor', href: '#changements/changements' }, h('span', { text: 'Chronologie' })),
      h('a', { class: 'anchor', href: '#changements/tendance' }, h('span', { text: 'Tendance' }))),
    sectionChrono(),
    sectionTendance());
}

function sectionChrono() {
  const q = h('input', {
    type: 'search', id: 'chg-q', class: 'w-md',
    placeholder: 'Filtrer un site, un changement…', 'aria-label': 'Filtrer la chronologie',
  });
  q.oninput = debounce(renderChrono, 200);
  const site = h('select', { id: 'chg-site', 'aria-label': 'Site' });
  site.onchange = renderChrono;
  const type = h('select', { id: 'chg-type', 'aria-label': 'Type' },
    h('option', { value: '', text: 'Tous les types' }),
    h('option', { value: 'change', text: 'Changements' }),
    h('option', { value: 'action', text: 'Actions' }),
    h('option', { value: 'event', text: 'Évènements' }));
  type.onchange = renderChrono;
  const warn = h('input', { type: 'checkbox', id: 'chg-warn' });
  warn.onchange = renderChrono;

  return h('section', { class: 'section secsec', id: 'hist-chrono' },
    h('div', { class: 'sechead' },
      h('h2', { text: 'Chronologie' }),
      h('span', { class: 'small', id: 'chg-sum' })),
    h('p', { class: 'hint' },
      'Trois sources dans le même fil : ce que la collecte a détecté (version installée qui bouge, ',
      h('span', { class: 'new-admin', text: 'admin ou extension ajouté' }),
      ' — le signal n°1 d’une compromission), ce que le dashboard a lancé, et les ',
      h('b', { text: 'évènements' }), ' que les sites équipés de l’agent poussent en temps réel.'),
    h('div', { class: 'filters' },
      q, site, type,
      h('label', { class: 'small' }, warn, ' à surveiller seulement'),
      h('span', { class: 'spacer' }),
      h('span', { class: 'muted small', id: 'chg-count' })),
    h('p', { class: 'hint hint-tight', id: 'chg-note' }),
    h('div', { class: 'small mt2', id: 'chg-body' },
      h('span', { class: 'muted', text: 'chargement…' })));
}

function sectionTendance() {
  return h('section', { class: 'section secsec', id: 'hist-tendance' },
    h('div', { class: 'sechead' },
      h('h2', { text: 'Tendance du parc' }),
      h('span', { class: 'small', id: 'hist-sum' })),
    h('p', { class: 'hint' }, 'Relevé à chaque collecte. Montre si la dette de mises à jour se résorbe ou s’accumule. ',
      h('span', {
        class: 'info', text: '?', tabindex: '0', role: 'button',
        'data-tip': "Ces chiffres portent sur toutes les installations detectees, y compris celles qui ne sont pas suivies dans Kuma et n'apparaissent donc pas dans la liste du parc.",
      })),
    h('div', { class: 'dstats', id: 'hist-tiles' }),
    h('div', { id: 'hist-charts' }));
}

/* ============================================================================
   Chronologie
   ========================================================================== */
/* Une action du journal devient une entrée lisible : le verbe métier plutôt
   que le nom de commande, le verdict plutôt que le code de retour. */
function entreeAction(e) {
  const rc = Number(e.rc);
  const viz = /^viz_/.test(String(e.action || ''));
  const anom = rc === 2 && viz;                    // rc 2 sur un scan visuel = anomalies
  const etat = rc === 0 ? 'ok' : anom ? 'anomalies' : 'échec';
  const sortie = stripPhpNoise(String(e.output_tail || '')).slice(-200);
  return {
    ts: e.ts, ms: tsMs(e.ts) ?? 0, type: 'action',
    site: e.domain || '', label: actLib(e.action, e.arg),
    etat,
    niveau: rc === 0 ? 'ok' : anom ? 'warn' : 'err',
    warn: rc !== 0,
    detail: sortie,
    meta: [e.source || '', e.duration_s !== undefined && e.duration_s !== null ? e.duration_s + ' s' : '']
      .filter(Boolean).join(' · '),
  };
}

/* Évènement poussé par un agent : `{ts, domain, event, detail}`. Le détail est
   du JSON brut, rendu lisible par detailEvenement(). */
function entreeEvenement(e) {
  const label = String(e.event || e.type || e.label || 'évènement');
  const alerte = evenementAlerte(label, e.detail);
  return {
    ts: e.ts, ms: tsMs(e.ts) ?? 0, type: 'event',
    site: e.domain || '', label,
    etat: alerte ? 'à surveiller' : '',
    niveau: alerte ? 'err' : 'mut',
    warn: alerte,
    detail: detailEvenement(label, e.detail), meta: '',
  };
}

function entreeChange(c) {
  return {
    ts: c.ts, ms: tsMs(c.ts) ?? 0, type: 'change',
    site: c.domain || '', label: c.label || 'changement',
    etat: c.severity === 'warn' ? 'à surveiller' : '',
    niveau: c.severity === 'warn' ? 'err' : 'mut',
    warn: c.severity === 'warn',
    detail: c.detail || '', meta: '',
  };
}

function optionsSite() {
  const sel = document.getElementById('chg-site');
  if (!sel) return;
  const avant = sel.value;
  const sites = [...new Set(ENTREES.map(e => e.site).filter(Boolean))].sort();
  mount(sel, h('option', { value: '', text: 'Tous les sites' }),
    sites.map(s => h('option', { value: s, text: s })));
  sel.value = sites.includes(avant) ? avant : '';
}

/** Titre de journée : « aujourd'hui », « hier », sinon la date en toutes lettres. */
function jourLabel(ms) {
  const d = new Date(ms);
  const jour = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const auj = new Date();
  const j0 = new Date(auj.getFullYear(), auj.getMonth(), auj.getDate()).getTime();
  if (jour === j0) return "aujourd'hui";
  if (jour === j0 - 86400000) return 'hier';
  return d.toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
}

function ligneChrono(e) {
  const t = TYPES[e.type] || TYPES.change;
  const ic = h('span', { class: 'tlic ' + (e.niveau === 'ok' ? 'ok' : e.niveau === 'err' ? 'err' : e.niveau === 'warn' ? 'warn' : '') },
    iconEl(t.ic, { size: 14 }));
  return h('div', { class: 'tlrow' }, ic,
    h('div', { class: 'tlmain' },
      h('div', { class: 'tltop' },
        e.site
          ? h('a', {
            class: 'seclien', href: '#site/' + encodeURIComponent(e.site),
            text: e.site,
          })
          : h('span', { class: 'muted', text: '—' }),
        h('b', { text: e.label }),
        e.etat ? chipEl(e.etat, e.niveau) : null,
        h('span', { class: 'muted small tlwhen', title: absTime(e.ts), text: relTime(e.ts) })),
      e.detail ? h('div', { class: 'muted small tlsub', text: e.detail }) : null,
      e.meta ? h('div', { class: 'muted small', text: e.meta }) : null));
}

function renderChrono() {
  const body = document.getElementById('chg-body'), cnt = document.getElementById('chg-count');
  if (!body) return;
  const q = (document.getElementById('chg-q').value || '').toLowerCase().trim();
  const site = document.getElementById('chg-site').value;
  const type = document.getElementById('chg-type').value;
  const warnOnly = document.getElementById('chg-warn').checked;

  let rows = ENTREES;
  if (site) rows = rows.filter(e => e.site === site);
  if (type) rows = rows.filter(e => e.type === type);
  if (warnOnly) rows = rows.filter(e => e.warn);
  if (q) rows = rows.filter(e => (e.site + ' ' + e.label + ' ' + e.detail).toLowerCase().includes(q));

  cnt.textContent = rows.length ? rows.length + ' affiché' + (rows.length > 1 ? 's' : '') : '';
  if (!ENTREES.length) {
    mount(body, chipEl('rien enregistré', 'ok'), ' ',
      h('span', { class: 'muted', text: "la chronologie se remplit à chaque collecte et à chaque action (2 collectes minimum pour comparer)." }));
    return;
  }
  if (!rows.length) {
    mount(body, h('span', { class: 'muted', text: 'aucune entrée ne correspond au filtre.' }));
    return;
  }
  // Groupement par jour : la date complète ne se répète pas ligne à ligne.
  const blocs = [];
  let jour = null, bloc = null;
  rows.forEach(e => {
    const j = jourLabel(e.ms);
    if (j !== jour) {
      jour = j;
      bloc = h('div', { class: 'chrono-j' }, h('div', { class: 'chrono-jt', text: j }));
      blocs.push(bloc);
    }
    bloc.append(ligneChrono(e));
  });
  mount(body, blocs);
}

/* ============================================================================
   Tendance (courbes) — composant conservé de la phase 1
   ========================================================================== */
/* Courbe SVG : pas de bibliothèque, 60 points suffisent.
   Deux contraintes liées à `preserveAspectRatio="none"` (étirement en largeur) :
   - le trait s'écraserait sans `vector-effect="non-scaling-stroke"` ;
   - toute FORME ou TEXTE placé dans le SVG serait déformé. Le point final est
     donc un segment à bout rond, et les ordonnées sont en HTML à côté. */
function sparkline(points, couleur, hauteur = 90) {
  if (points.length < 2) return h('div', { class: 'muted small', text: 'pas assez de relevés' });
  const w = 400, pad = 6;
  const mn = Math.min(...points), mx = Math.max(...points), amp = (mx - mn) || 1;
  const x = i => pad + i * (w - 2 * pad) / (points.length - 1);
  const y = v => hauteur - pad - ((v - mn) / amp) * (hauteur - 2 * pad);
  const d = points.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
  const aire = `${d}L${x(points.length - 1).toFixed(1)},${hauteur - pad}L${x(0).toFixed(1)},${hauteur - pad}Z`;
  const der = points[points.length - 1], mid = (mn + mx) / 2;
  const ligne = (v, tirets) => `<line x1="0" y1="${y(v).toFixed(1)}" x2="${w}" y2="${y(v).toFixed(1)}"
      stroke="var(--line)" stroke-width="1" ${tirets ? 'stroke-dasharray="3 4"' : ''}
      vector-effect="non-scaling-stroke"/>`;
  const svg = `<svg viewBox="0 0 ${w} ${hauteur}" preserveAspectRatio="none" class="spark" role="img"
      aria-label="évolution de ${mn} à ${mx}">
    ${ligne(mn, false)}${ligne(mid, true)}${ligne(mx, true)}
    <path d="${aire}" fill="${couleur}" opacity=".13"/>
    <path d="${d}" fill="none" stroke="${couleur}" stroke-width="2" stroke-linejoin="round"
      stroke-linecap="round" vector-effect="non-scaling-stroke"/>
    <path d="M${x(points.length - 1).toFixed(1)},${y(der).toFixed(1)}L${x(points.length - 1).toFixed(1)},${y(der).toFixed(1)}"
      stroke="${couleur}" stroke-width="7" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
  </svg>`;
  // Graduations en HTML : alignées sur les lignes de référence grâce au même
  // rembourrage vertical que le SVG. Ce sont des décomptes : une graduation à
  // « 182,5 extensions » n'a pas de sens.
  const entiers = Number.isInteger(mn) && Number.isInteger(mx);
  const fmt = v => entiers ? Math.round(v) : (Number.isInteger(v) ? v : v.toFixed(1));
  // Le SVG est construit ICI, à partir de NOMBRES : rien de distant n'y entre.
  // Il est inséré en nœud (et non dans un conteneur) pour rester l'enfant
  // direct du flex `.chartbody`, dont il prend toute la largeur.
  const tpl = document.createElement('template');
  tpl.innerHTML = svg;
  return h('div', { class: 'chartbody' },
    h('div', { class: 'yaxis' },
      h('span', { text: String(fmt(mx)) }), h('span', { text: String(fmt(mid)) }), h('span', { text: String(fmt(mn)) })),
    tpl.content.firstElementChild);
}

function deltaPill(cur, ref, inverse) {
  if (ref === null || ref === undefined) return null;
  const d = cur - ref;
  if (!d) return chipEl('stable', 'mut');
  // `inverse` : pour une dette, une baisse est une bonne nouvelle.
  const bon = inverse ? d < 0 : d > 0;
  return chipEl((d > 0 ? '+' : '') + d, bon ? 'ok' : 'warn');
}

const MESURES = [
  { k: 'plugin_updates', lbl: 'MAJ extensions', c: 'var(--warn)', inv: true },
  { k: 'core_updates', lbl: 'MAJ cœur', c: 'var(--accent)', inv: true },
  { k: 'errors', lbl: 'Sites en erreur', c: 'var(--err)', inv: true },
  { k: 'sites', lbl: 'Installations', c: 'var(--ok)', inv: false },
];

function renderTendance(hist) {
  const charts = document.getElementById('hist-charts');
  if (!charts) return;
  if (!hist.length) {
    mount(charts, h('span', { class: 'muted', text: 'aucun relevé.' }));
    return;
  }
  const der = hist[hist.length - 1];
  // référence ≈ 24 h plus tôt : la collecte tourne toutes les 30 min
  const ref = hist[Math.max(0, hist.length - 49)];
  mount('hist-sum', chipEl(hist.length + ' relevés · depuis le ' + String(hist[0].ts || '').slice(0, 10), 'mut'));
  mount('hist-tiles', MESURES.map(m => h('div', { class: 'dstat' },
    h('div', { class: 'lbl', text: m.lbl }),
    h('div', { class: 'val', text: String(der[m.k] ?? '?') }),
    h('div', { class: 'sub' }, deltaPill(der[m.k] ?? 0, ref[m.k], m.inv), ' sur 24 h'))));
  // Deux colonnes fixes : quatre courbes pleine largeur donnent des rapports
  // hauteur/largeur absurdes sur un grand écran.
  mount(charts, h('div', { class: 'histgrid' }, MESURES.map(m => {
    const pts = hist.map(x => x[m.k] ?? 0);
    return h('div', { class: 'chart' },
      h('div', { class: 'charttop' },
        h('b', { text: m.lbl }),
        h('span', { class: 'muted small' }, 'actuel : ', h('b', { text: String(pts[pts.length - 1]) }))),
      sparkline(pts, m.c),
      h('div', { class: 'chartaxis' },
        h('span', { text: String(hist[0].ts || '').slice(5, 16) }),
        h('span', { text: String(der.ts || '').slice(5, 16) })));
  })));
}

/* ============================================================================
   Chargement
   ========================================================================== */
async function loadHist(force) {
  monterHist();
  if (cacheFrais('hist', force)) return;
  CHGERR = LOGERR = EVTERR = '';

  // 1. changements d'état détectés par la collecte
  let changes = [];
  try {
    const ch = await api('/api/mgmt/changes?limit=800');
    changes = Array.isArray(ch.changes) ? ch.changes : [];
    RESUME = ch.summary || null;
  } catch (e) { CHGERR = String(e); RESUME = null; cacheVider('hist'); }

  // 2. actions lancées depuis le dashboard
  let log = [];
  try {
    const j = await api('/api/actions/log');
    log = Array.isArray(j.log) ? j.log : [];
  } catch (e) { LOGERR = String(e); cacheVider('hist'); }

  // 3. évènements poussés par les agents, à l'échelle du parc
  let events = [];
  try {
    const j = await api('/api/mgmt/events?limit=400');
    events = Array.isArray(j.events) ? j.events : [];
  } catch (e) { EVTERR = String(e); cacheVider('hist'); }

  ENTREES = [...changes.map(entreeChange), ...log.map(entreeAction), ...events.map(entreeEvenement)]
    .filter(e => e.ms)
    .sort((a, b) => b.ms - a.ms);

  const sum = document.getElementById('chg-sum');
  if (RESUME && RESUME.day_total) {
    mount(sum, chipEl(
      `${RESUME.day_total} sur 24 h · ${RESUME.day_sites} site${RESUME.day_sites > 1 ? 's' : ''}`
      + (RESUME.day_warn ? ` · ${RESUME.day_warn} à surveiller` : ''),
      RESUME.day_warn ? 'err' : 'mut'));
  } else if (RESUME) mount(sum, chipEl('rien sur 24 h', 'ok'));
  else mount(sum, chipEl('résumé indisponible', 'warn'));

  // Une source en échec se DIT : « rien à afficher » ne doit pas se confondre
  // avec « on n'a pas pu regarder ». Les trois sources sont indépendantes.
  const note = document.getElementById('chg-note');
  const bouts = [];
  if (CHGERR) bouts.push('changements de collecte indisponibles : ' + CHGERR);
  if (LOGERR) bouts.push('journal des actions indisponible : ' + LOGERR);
  if (EVTERR) bouts.push('évènements des agents indisponibles : ' + EVTERR);
  if (bouts.length) {
    mount(note, chipEl('source incomplète', 'warn'), ' ',
      h('span', { class: 'muted small', text: bouts.join(' — ') }));
  } else mount(note);

  optionsSite();
  renderChrono();

  // 4. tendance
  try {
    const j = await api('/api/actions/collect_history');
    renderTendance((j.history || []).filter(x => x && typeof x === 'object'));
  } catch (e) {
    cacheVider('hist');
    const charts = document.getElementById('hist-charts');
    if (charts) mount(charts, h('span', { class: 'muted', text: 'historique indisponible : ' + e }));
  }
}

export { loadHist, renderChrono };
