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

   La tendance du parc (les quatre courbes) ouvre la page : elle répond à la
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
      h('a', { class: 'anchor', href: '#changements/tendance' }, h('span', { text: 'Tendance' })),
      h('a', { class: 'anchor', href: '#changements/changements' }, h('span', { text: 'Chronologie' }))),
    sectionTendance(),
    sectionChrono());
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
      h('span', { class: 'small', id: 'hist-sum' }),
      barrePeriode()),
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
/* Courbes SVG sans bibliothèque. `preserveAspectRatio="none"` étire le SVG en
   largeur : les traits sont donc en `non-scaling-stroke`, et tout ce qui serait
   déformé (points, bulle, graduations) vit en HTML par-dessus, en pourcentages. */
const PERIODES = [['semaine', 'Semaine'], ['mois', 'Mois'], ['annee', 'Année']];
const W = 400, HT = 90, PAD = 6, ECH = 240;
const SVGNS = 'http://www.w3.org/2000/svg';
let PERIODE = (() => { try { return localStorage.getItem('hist-periode') || 'semaine'; } catch { return 'semaine'; } })();
if (!PERIODES.some(([k]) => k === PERIODE)) PERIODE = 'semaine';
let HIST = [];
const COURBES = {};

function barrePeriode() {
  const barre = h('div', { class: 'tabs periodes', role: 'group', 'aria-label': 'Période affichée' });
  PERIODES.forEach(([k, lbl]) => {
    const b = h('button', { type: 'button', class: 'tab', dataset: { p: k }, text: lbl });
    b.onclick = () => {
      if (PERIODE === k) return;
      PERIODE = k;
      try { localStorage.setItem('hist-periode', k); } catch { /* stockage indisponible */ }
      marquerPeriode();
      chargerTendance();
    };
    barre.append(b);
  });
  queueMicrotask(marquerPeriode);
  return barre;
}

function marquerPeriode() {
  document.querySelectorAll('.periodes .tab').forEach(b => {
    const on = b.dataset.p === PERIODE;
    b.classList.toggle('active', on);
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

/* Abscisse = TEMPS, pas rang du point : le serveur garde les extrêmes de chaque
   tranche (nombre de points variable), et la collecte a pu s'interrompre.
   Pendant l'animation seulement, les courbes sont rééchantillonnées sur une
   grille commune de ECH colonnes ; la dernière image trace les vrais points. */
let T0 = 0, T1 = 1;
const fx = t => (t - T0) / ((T1 - T0) || 1);
const vx = t => PAD + fx(t) * (W - 2 * PAD);
const pctX = f => (PAD + f * (W - 2 * PAD)) / W * 100;
const py = (v, mn, mx) => HT - PAD - ((v - mn) / ((mx - mn) || 1)) * (HT - 2 * PAD);

// Valeur tenue à l'instant t (dernier relevé ≤ t) sur chaque colonne de la grille.
function grille(ts, vals) {
  const out = new Array(ECH);
  let i = 0;
  for (let j = 0; j < ECH; j++) {
    const t = T0 + j * (T1 - T0) / (ECH - 1);
    while (i + 1 < ts.length && ts[i + 1] <= t) i++;
    out[j] = vals[i] ?? 0;
  }
  return out;
}

function svgEl(tag, attrs) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function creerCourbe(m) {
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${HT}`, preserveAspectRatio: 'none', class: 'spark', 'aria-hidden': 'true' });
  const ref = y => svgEl('line', { x1: 0, x2: W, y1: y, y2: y, stroke: 'var(--line)', 'stroke-width': 1,
    'vector-effect': 'non-scaling-stroke', ...(y === HT - PAD ? {} : { 'stroke-dasharray': '3 4' }) });
  const aire = svgEl('path', { fill: m.c, opacity: '.13' });
  const trait = svgEl('path', { fill: 'none', stroke: m.c, 'stroke-width': 2, 'stroke-linejoin': 'round',
    'stroke-linecap': 'round', 'vector-effect': 'non-scaling-stroke' });
  svg.append(ref(PAD), ref(HT / 2), ref(HT - PAD), aire, trait);
  const ys = [0, 1, 2].map(() => h('span'));
  const fin = h('div', { class: 'spk-dot spk-end', style: { background: m.c } });
  const curseur = h('div', { class: 'spk-cursor', hidden: true });
  const point = h('div', { class: 'spk-dot', hidden: true, style: { background: m.c } });
  const plot = h('div', { class: 'spk-plot' }, svg, curseur, point, fin);
  const valeur = h('b');
  const legende = h('span', { class: 'muted small' }, h('span', { text: 'actuel : ' }), valeur);
  const axe = [0, 1, 2].map(() => h('span'));
  const noeud = h('div', { class: 'chart' },
    h('div', { class: 'charttop' }, h('b', { text: m.lbl }), legende),
    h('div', { class: 'chartbody' }, h('div', { class: 'yaxis' }, ys), plot),
    h('div', { class: 'chartaxis' }, axe));
  plot.onpointermove = e => {
    const r = plot.getBoundingClientRect();
    survoler(((e.clientX - r.left) / r.width * W - PAD) / (W - 2 * PAD));
  };
  plot.onpointerdown = plot.onpointermove;
  plot.onpointerleave = () => survoler(null);
  return { m, noeud, aire, trait, ys, fin, curseur, point, legende, valeur, axe,
    ech: null, mn: 0, mx: 1, anim: 0 };
}

function tracer(c, d, xFin, xDeb, vFin, mn, mx) {
  c.trait.setAttribute('d', d);
  c.aire.setAttribute('d', `${d}L${xFin.toFixed(1)},${HT - PAD}L${xDeb.toFixed(1)},${HT - PAD}Z`);
  const entiers = Number.isInteger(c.cibleMn) && Number.isInteger(c.cibleMx);
  const fmt = v => String(entiers ? Math.round(v) : Math.round(v * 10) / 10);
  [mx, (mn + mx) / 2, mn].forEach((v, i) => { c.ys[i].textContent = fmt(v); });
  c.fin.style.left = (xFin / W * 100) + '%';
  c.fin.style.top = (py(vFin, mn, mx) / HT * 100) + '%';
}

function tracerGrille(c, ech, mn, mx) {
  const x = j => PAD + j * (W - 2 * PAD) / (ECH - 1);
  const d = ech.map((v, j) => `${j ? 'L' : 'M'}${x(j).toFixed(1)},${py(v, mn, mx).toFixed(1)}`).join('');
  tracer(c, d, x(ECH - 1), x(0), ech[ECH - 1], mn, mx);
}

function tracerExact(c) {
  const { ts, vals, cibleMn: mn, cibleMx: mx } = c;
  const d = vals.map((v, i) => `${i ? 'L' : 'M'}${vx(ts[i]).toFixed(1)},${py(v, mn, mx).toFixed(1)}`).join('');
  tracer(c, d, vx(ts[ts.length - 1]), vx(ts[0]), vals[vals.length - 1], mn, mx);
}

const lisse = t => t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
const sansAnim = () => { try { return matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { return false; } };

// Morphing : on part de la courbe affichée (ou d'une ligne plate au premier
// rendu) et l'échelle glisse en même temps que les valeurs.
function animer(c, ts, vals) {
  const cible = grille(ts, vals);
  const mn = Math.min(...vals), mx = Math.max(...vals);
  c.ts = ts; c.vals = vals; c.cibleMn = mn; c.cibleMx = mx;
  const depart = c.ech || new Array(ECH).fill(mn);
  const mn0 = c.ech ? c.mn : mn, mx0 = c.ech ? c.mx : mx;
  cancelAnimationFrame(c.anim);
  const duree = sansAnim() ? 0 : 650, t0 = performance.now();
  const pas = now => {
    const t = duree ? Math.min(1, (now - t0) / duree) : 1, k = lisse(t);
    c.ech = depart.map((v, j) => v + (cible[j] - v) * k);
    c.mn = mn0 + (mn - mn0) * k; c.mx = mx0 + (mx - mx0) * k;
    if (t < 1) { tracerGrille(c, c.ech, c.mn, c.mx); c.anim = requestAnimationFrame(pas); }
    else tracerExact(c);
  };
  c.anim = requestAnimationFrame(pas);
}

function fmtMs(ms, court) {
  const d = new Date(ms), z = n => String(n).padStart(2, '0');
  const jm = `${z(d.getDate())}/${z(d.getMonth() + 1)}`;
  if (PERIODE === 'annee') return `${jm}/${String(d.getFullYear()).slice(2)}`;
  if (PERIODE === 'mois' && court) return jm;
  return `${jm} ${z(d.getHours())}h${z(d.getMinutes())}`;
}

// Curseur partagé : les quatre courbes montrent le même instant.
function survoler(frac) {
  const n = HIST.length;
  let i = -1;
  if (frac !== null && n >= 2) {
    const t = T0 + Math.max(0, Math.min(1, frac)) * (T1 - T0);
    let lo = 0, hi = n - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (HIST_MS[mid] <= t) lo = mid; else hi = mid - 1; }
    i = lo + 1 < n && HIST_MS[lo + 1] - t < t - HIST_MS[lo] ? lo + 1 : lo;
  }
  Object.values(COURBES).forEach(c => {
    if (i < 0 || !c.ech) {
      c.curseur.hidden = true; c.point.hidden = true;
      c.legende.firstChild.textContent = 'actuel : ';
      c.valeur.textContent = String(n ? (HIST[n - 1][c.m.k] ?? '?') : '?');
      return;
    }
    const v = HIST[i][c.m.k] ?? 0;
    const x = pctX(fx(HIST_MS[i]));
    c.curseur.hidden = false; c.point.hidden = false;
    c.curseur.style.left = x + '%';
    c.point.style.left = x + '%';
    c.point.style.top = (py(v, c.cibleMn, c.cibleMx) / HT * 100) + '%';
    c.legende.firstChild.textContent = fmtMs(HIST_MS[i]) + ' : ';
    c.valeur.textContent = String(v);
  });
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

let HIST_MS = [];

function renderTendance(hist) {
  const charts = document.getElementById('hist-charts');
  if (!charts) return;
  hist = hist.filter(x => tsMs(x.ts));
  HIST = hist;
  HIST_MS = hist.map(x => tsMs(x.ts));
  if (!hist.length) {
    Object.keys(COURBES).forEach(k => delete COURBES[k]);
    mount(charts, h('span', { class: 'muted', text: 'aucun relevé.' }));
    return;
  }
  const der = hist[hist.length - 1], prem = hist[0];
  const jours = { semaine: 7, mois: 30, annee: 365 }[PERIODE];
  T1 = HIST_MS[HIST_MS.length - 1];
  T0 = Math.max(HIST_MS[0], T1 - jours * 86400000);
  if (T1 <= T0) T0 = T1 - 1;
  // Moins d'historique que la période demandée : on le dit, sinon on croirait à un trou.
  const court = (T1 - HIST_MS[0]) < (jours - 1) * 86400000;
  const depuis = 'depuis le ' + fmtMs(HIST_MS[0], true);
  mount('hist-sum', chipEl((court ? 'historique ' : '') + depuis, 'mut'));
  // Les tuiles comparent au début de la période affichée, comme les courbes.
  const sur = court ? depuis : { semaine: 'sur 7 jours', mois: 'sur 30 jours', annee: 'sur 1 an' }[PERIODE];
  mount('hist-tiles', MESURES.map(m => h('div', { class: 'dstat' },
    h('div', { class: 'lbl', text: m.lbl }),
    h('div', { class: 'val', text: String(der[m.k] ?? '?') }),
    h('div', { class: 'sub' }, deltaPill(der[m.k] ?? 0, prem[m.k], m.inv), ' ' + sur))));
  // Deux colonnes fixes : quatre courbes pleine largeur donnent des rapports
  // hauteur/largeur absurdes sur un grand écran.
  if (!charts.querySelector('.histgrid')) {
    MESURES.forEach(m => { COURBES[m.k] = creerCourbe(m); });
    mount(charts, h('div', { class: 'histgrid' }, MESURES.map(m => COURBES[m.k].noeud)));
  }
  MESURES.forEach(m => {
    const c = COURBES[m.k];
    animer(c, HIST_MS, hist.map(x => x[m.k] ?? 0));
    [T0, (T0 + T1) / 2, T1].forEach((t, i) => { c.axe[i].textContent = fmtMs(t, true); });
  });
  survoler(null);
}

let SEQ_TENDANCE = 0;
async function chargerTendance() {
  const seq = ++SEQ_TENDANCE;
  try {
    const j = await api('/api/actions/collect_history?periode=' + PERIODE);
    if (seq !== SEQ_TENDANCE) return;
    renderTendance((j.history || []).filter(x => x && typeof x === 'object'));
  } catch (e) {
    if (seq !== SEQ_TENDANCE) return;
    cacheVider('hist');
    Object.keys(COURBES).forEach(k => delete COURBES[k]);
    const charts = document.getElementById('hist-charts');
    if (charts) mount(charts, h('span', { class: 'muted', text: 'historique indisponible : ' + e }));
  }
}

/* ============================================================================
   Chargement
   ========================================================================== */
async function loadHist(force) {
  monterHist();
  if (cacheFrais('hist', force)) return;
  CHGERR = LOGERR = EVTERR = '';
  // La tendance est en haut de page : elle part tout de suite, en parallèle.
  const tendance = chargerTendance();

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

  await tendance;
}

export { loadHist };
