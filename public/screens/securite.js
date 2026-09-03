/* Écran Sécurité — « qu'est-ce qui est exposé ? »

   Phase 3 : les huit sous-onglets ont disparu. La destination est UNE page,
   ouverte par un sommaire d'ancres chiffré, puis les sections dans l'ordre du
   risque :

     1. Vulnérabilités connues (+ versions de PHP vulnérables)
     2. Comptes administrateurs et référence
     3. Erreurs PHP
     4. Extensions à risque
     5. PHP obsolète (regroupé par version)
     6. Certificats SSL
     7. Intégrité du cœur (checksums)
     8. Recherche transversale d'extension

   Les anciens fragments continuent de fonctionner : #securite/vulnerabilites
   (ou #sec/vulnerabilites, ou le #securite/vulns des liens d'incidents) fait
   défiler jusqu'à la section — la correspondance vit dans app.js.

   Tout le rendu passe par h() : plus une seule chaîne HTML construite à partir
   d'une donnée distante. `sevPill()` reste une chaîne parce que la page site
   l'insère encore dans un gabarit. */

import { api } from '../lib/api.js';
import { esc as H, h, mount, activeAuClavier, occupe, zoneMessage } from '../lib/dom.js';
import { relTime, absTime, safeUrl, debounce } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { poll } from '../lib/poll.js';
import { store, allSites, siteByName, kName, cacheFrais, cacheVider } from '../lib/state.js';
import { askConfirm, askInfo } from '../components/confirm.js';
import { setBusy, setIdle } from '../components/button.js';
import { demarrerJob } from '../components/job.js';
import { majCompteursServeur } from '../components/shell.js';
import { chip, chipEl } from '../components/chip.js';

/* Extensions régulièrement exploitées en incident. */
const RISKY = ['wp-file-manager', 'file-manager-advanced', 'filester', 'duplicator',
  'all-in-one-wp-migration', 'backup-migration', 'adminer', 'wp-phpmyadmin-extension',
  'insert-php', 'php-everywhere', 'wp-file-upload'];

const SEVRANK = { critical: 4, high: 3, medium: 2, low: 1, '': 0 };
const SEVLABEL = { critical: 'critique', high: 'élevée', medium: 'moyenne', low: 'faible', '': 'non cotée' };

/* Gravité → un des quatre niveaux du langage d'état : mêmes mots et même forme
   que partout ailleurs. */
function sevNiveau(s) { return (s === 'critical' || s === 'high') ? 'err' : s === 'medium' ? 'warn' : 'mut'; }
/** Chaîne HTML — la page site l'insère dans un gabarit. */
function sevPill(s) { return chip(SEVLABEL[s] || s || '?', sevNiveau(s)); }
function sevChip(s) { return chipEl(SEVLABEL[s] || s || '?', sevNiveau(s)); }

/** « 1 site » / « 3 sites » — le pluriel irrégulier se donne en 3e argument. */
const pluriel = (n, sing, plur) => n + ' ' + (n > 1 ? (plur || sing + 's') : sing);

/* ---- état du module -------------------------------------------------------- */
let VULNS = { sites: [] };
let PHERR = { sites: [] };
let CERTS = null, CERTMSG = '';
let CKS = {};
let BLERR = '';
let MONTE = false;
let VLNOPEN = new Set(), VEXTOPEN = new Set();

/* ---- liens vers la page d'un site ------------------------------------------
   Les rapports nomment les sites par leur clé Kuma (souvent un alias) : on
   repasse par le parc pour retomber sur la clé d'URL de la page site. */
function cleUrl(nom) {
  const s = siteByName(nom);
  return s ? (kName(s) || s.domain) : String(nom || '');
}
function lienSite(nom, libelle) {
  return h('a', {
    class: 'seclien', href: '#site/' + encodeURIComponent(cleUrl(nom)) + '/securite',
    text: libelle || String(nom || ''),
  });
}

/* ============================================================================
   Squelette de la page : sommaire + huit sections. Monté une seule fois ;
   ensuite seul le CONTENU de chaque section est redessiné.
   ========================================================================== */
function sectionEl(id, titre, tete, ...corps) {
  return h('section', { class: 'section secsec', id },
    h('div', { class: 'sechead' }, h('h2', { text: titre }), tete),
    ...corps);
}

function monterSec() {
  if (MONTE) return;
  MONTE = true;
  mount('page-sec',
    h('nav', { class: 'anchors', id: 'sec-somm', 'aria-label': 'Sections de la page Sécurité' }),
    sectionVulns(),
    sectionAdmins(),
    sectionPhe(),
    sectionRisky(),
    sectionPhp(),
    sectionCerts(),
    sectionChecksums(),
    sectionRecherche());
  majSommaire();
}

/* ---- sommaire d'ancres -----------------------------------------------------
   Un lien par section, avec son chiffre et son niveau. Il est collant sous
   l'en-tête d'écran : la page est longue, on doit pouvoir sauter à tout moment. */
const ANCRES = [
  ['sec-vulns', 'vulnerabilites', 'Vulnérabilités'],
  ['sec-admins', 'administrateurs', 'Administrateurs'],
  ['sec-phperr', 'erreurs-php', 'Erreurs PHP'],
  ['sec-risky', 'plugins-a-risque', 'Extensions à risque'],
  ['sec-php', 'php-obsolete', 'PHP obsolète'],
  ['sec-certs', 'certificats', 'Certificats'],
  ['sec-checksums', 'integrite-core', 'Checksums'],
  ['sec-recherche', 'recherche-plugin', 'Recherche d’extension'],
];

/* Chiffres du sommaire : chacun dit ce qui reste à traiter dans sa section. */
function compteursSommaire() {
  const S = allSites();
  const nVuln = (VULNS.sites || []).reduce((a, s) => a + (s.findings || []).length, 0);
  const t = VULNS.totals || {};
  const nAdm = adminsInconnus().length;
  const nPhe = (PHERR.sites || []).reduce((a, s) => a + (s.groups || []).length, 0);
  const nRisky = risques().length;
  const nPhp = phpObsoletes(S).reduce((a, g) => a + g.sites.length, 0);
  const certs = (CERTS || []).filter(c => c.days !== null && c.days !== undefined && Number(c.days) < 21);
  const nCk = Object.values(CKS).filter(x => x && typeof x === 'object' && !x.ok).length;
  const nCkVus = Object.keys(CKS).length;
  return {
    'sec-vulns': [nVuln, t.critical ? 'err' : nVuln ? 'warn' : 'ok'],
    'sec-admins': [nAdm, nAdm ? 'err' : 'ok'],
    'sec-phperr': [nPhe, PHERR.fatals ? 'err' : nPhe ? 'warn' : 'ok'],
    'sec-risky': [nRisky, nRisky ? 'warn' : 'ok'],
    'sec-php': [nPhp, nPhp ? 'warn' : 'ok'],
    'sec-certs': [certs.length, certs.some(c => Number(c.days) < 7) ? 'err' : certs.length ? 'warn' : 'ok'],
    'sec-checksums': [nCk, nCk ? 'err' : nCkVus ? 'ok' : 'mut'],
  };
}

function majSommaire() {
  const box = document.getElementById('sec-somm');
  if (!box) return;
  const c = compteursSommaire();
  mount(box, ANCRES.map(([id, slug, lbl]) => {
    const n = c[id];
    const a = h('a', { class: 'anchor', href: '#securite/' + slug },
      h('span', { text: lbl }),
      n ? chipEl(String(n[0]), n[1]) : null);
    // Le clic pose le fragment ; le routeur fait défiler (et l'URL reste
    // partageable, comme du temps des sous-onglets).
    return a;
  }));
}

/* ============================================================================
   1. Vulnérabilités connues
   ========================================================================== */
function sectionVulns() {
  const run = h('button', { type: 'button', class: 'btn sm', id: 'vln-run' },
    iconEl('refresh-cw'), "Relancer l'analyse");
  run.onclick = () => lancerVulns(run);

  const q = h('input', {
    type: 'search', id: 'vln-q', class: 'w-md',
    placeholder: 'Filtrer un site, une extension, un CVE…', 'aria-label': 'Filtrer les vulnérabilités',
  });
  q.oninput = debounce(renderVulns, 200);
  const sev = h('select', { id: 'vln-sev', 'aria-label': 'Gravité minimale' },
    h('option', { value: '', text: 'Toutes gravités' }),
    h('option', { value: 'critical', text: 'Critique' }),
    h('option', { value: 'high', text: 'Élevée et +' }),
    h('option', { value: 'medium', text: 'Moyenne et +' }));
  sev.onchange = renderVulns;
  const fix = h('input', { type: 'checkbox', id: 'vln-fix' });
  fix.onchange = renderVulns;
  const vue = h('select', {
    id: 'vln-vue', 'aria-label': 'Vue',
    title: 'Par site : que corriger sur ce site ? — Par extension : une extension vulnérable sur plusieurs sites se traite en une fois.',
  },
    h('option', { value: 'site', text: 'Vue par site' }),
    h('option', { value: 'ext', text: 'Vue par extension (tout le parc)' }));
  vue.onchange = renderVulns;

  return sectionEl('sec-vulns', 'Vulnérabilités connues',
    [h('span', { class: 'small', id: 'vln-sum' }), h('span', { class: 'spacer' }), run],
    h('p', { class: 'hint' },
      "Croisement de l'inventaire (cœur, PHP, extensions et leurs versions exactes) avec la base ouverte ",
      h('a', { href: 'https://www.wpvulnerability.net/', target: '_blank', rel: 'noopener', text: 'WPVulnerability' }),
      ', qui agrège CVE.org, Patchstack, Wordfence et WPScan. Le croisement est local : on demande '
      + '« quelles failles pour l’extension X ? », jamais « voici mes sites ».'),
    h('div', { class: 'filters' },
      q, sev,
      h('label', { class: 'small' }, fix, ' corrigeable par une MAJ'),
      vue,
      h('span', { class: 'spacer' }),
      h('span', { class: 'muted small', id: 'vln-count' })),
    h('div', { class: 'small mt2 scroll-lg', id: 'vln-body' },
      h('span', { class: 'muted', text: 'chargement…' })),
    h('h3', { class: 'mt4', text: 'Versions de PHP' }),
    h('p', { class: 'hint' }, 'Regroupé par version : une faille PHP se corrige chez l’hébergeur, pas site par site. ',
      h('span', {
        class: 'info', text: '?', tabindex: '0', role: 'button',
        'data-tip': 'A lire avec prudence : Debian et Plesk retroportent les correctifs sans changer le numero de version, donc une version signalee ici peut deja etre corrigee. Le signal fiable est une branche en fin de support (7.x, 8.0).',
      })),
    h('div', { class: 'small', id: 'vln-php' }));
}

/* Regroupement par extension : 222 CVE brutes deviennent ~54 lignes lisibles.
   Une même extension cumule souvent 20 CVE — les lister une par une noie le
   signal, alors que la décision se prend au niveau de l'extension. */
function grouperParExtension(findings) {
  const g = new Map();
  for (const v of findings) {
    const cle = v.component + '@' + v.version;
    let e = g.get(cle);
    if (!e) {
      e = { component: v.component, version: v.version, kind: v.kind, update_to: v.update_to || '', unfixed: false, worst: '', cves: [], n: 0 };
      g.set(cle, e);
    }
    e.n++; e.cves.push(v);
    if (v.update_to) e.update_to = v.update_to;
    if (v.unfixed) e.unfixed = true;
    if ((SEVRANK[v.severity] || 0) > (SEVRANK[e.worst] || 0)) e.worst = v.severity;
  }
  return [...g.values()].sort((a, b) => (SEVRANK[b.worst] || 0) - (SEVRANK[a.worst] || 0) || b.n - a.n);
}

/* Vue inverse : une extension, tous les sites où elle est vulnérable.
   `wordpress-seo` vulnérable sur 5 sites se traite en une seule action. */
function grouperParParc(sites) {
  const g = new Map();
  for (const s of sites) {
    for (const v of s.findings) {
      let e = g.get(v.component);
      if (!e) { e = { component: v.component, kind: v.kind, sites: new Map(), worst: '', n: 0 }; g.set(v.component, e); }
      e.n++;
      if ((SEVRANK[v.severity] || 0) > (SEVRANK[e.worst] || 0)) e.worst = v.severity;
      let d = e.sites.get(s.domain);
      if (!d) {
        d = { domain: s.domain, server: s.server, via: s.via, version: v.version, update_to: v.update_to || '', n: 0, worst: '' };
        e.sites.set(s.domain, d);
      }
      d.n++;
      if (v.update_to) d.update_to = v.update_to;
      if ((SEVRANK[v.severity] || 0) > (SEVRANK[d.worst] || 0)) d.worst = v.severity;
    }
  }
  return [...g.values()].map(e => ({ ...e, sites: [...e.sites.values()] }))
    .sort((a, b) => b.sites.length - a.sites.length
      || (SEVRANK[b.worst] || 0) - (SEVRANK[a.worst] || 0) || b.n - a.n);
}

/* En-tête repliable partagé par les deux vues. */
function entetePliable(ouvert, bascule, ...contenu) {
  const t = h('div', {
    class: 'vsite' + (ouvert ? ' open' : ''), tabindex: '0', role: 'button',
    'aria-expanded': ouvert ? 'true' : 'false',
  },
    h('span', { class: 'tlchev' }, iconEl('chevron-right', { size: 14 })), ...contenu);
  t.onclick = ev => { if (ev.target.closest('.vbulk')) return; bascule(t); };
  t.onkeydown = ev => { if (ev.target !== t) return; activeAuClavier(ev, () => bascule(t)); };
  return t;
}

function vulnsFiltres() {
  const q = (document.getElementById('vln-q').value || '').toLowerCase().trim();
  const minSev = SEVRANK[document.getElementById('vln-sev').value] || 0;
  const fixOnly = document.getElementById('vln-fix').checked;
  return (VULNS.sites || []).map(s => {
    let f = (s.findings || []).filter(v => (SEVRANK[v.severity] || 0) >= minSev);
    if (fixOnly) f = f.filter(v => v.update_to);
    if (q) f = f.filter(v => (s.domain + ' ' + v.component + ' ' + (v.cve || '') + ' ' + v.title).toLowerCase().includes(q));
    return { ...s, findings: f };
  }).filter(s => s.findings.length);
}

function renderVulns() {
  const body = document.getElementById('vln-body'), cnt = document.getElementById('vln-count');
  if (!body) return;
  if (VULNS.running) {
    mount(body, chipEl('analyse en cours…', 'mut'), ' ',
      h('span', { class: 'muted small', text: VULNS.run_message || '' }));
    cnt.textContent = '';
    return;
  }
  if (!(VULNS.sites || []).length) {
    mount(body, VULNS.sites_scanned
      ? chipEl('aucune vulnérabilité connue sur le parc', 'ok')
      : h('span', { class: 'muted', text: 'Analyse jamais lancée — cliquez sur « Relancer l’analyse ».' }));
    cnt.textContent = '';
    renderVulnsPhp();
    return;
  }
  const filtres = vulnsFiltres();
  if (document.getElementById('vln-vue').value === 'ext') renderVulnsParExtension(filtres);
  else renderVulnsParSite(filtres);
  renderVulnsPhp();
}

function renderVulnsParSite(filtres) {
  const body = document.getElementById('vln-body'), cnt = document.getElementById('vln-count');
  const q = (document.getElementById('vln-q').value || '').trim();
  if (!filtres.length) {
    mount(body, h('span', { class: 'muted', text: 'aucune vulnérabilité ne correspond au filtre.' }));
    cnt.textContent = '';
    return;
  }
  let nGrp = 0;
  const noeuds = [];
  filtres.forEach(s => {
    const grp = grouperParExtension(s.findings);
    nGrp += grp.length;
    const corrigeables = grp.filter(e => e.update_to).length;
    const ouvert = VLNOPEN.has(s.domain) || !!q;
    const liste = h('div', { class: 'vlist', hidden: !ouvert });
    grp.forEach(e => {
      const refs = e.cves.filter(c => c.cve);
      const cves = h('div', { class: 'muted small vcves' });
      // Cinq références suffisent à enquêter ; au-delà la liste noie la ligne.
      refs.slice(0, 5).forEach(c => {
        const u = safeUrl(c.link);
        cves.append(u
          ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: c.cve })
          : h('span', { class: 'muted', text: c.cve + ' ' }));
      });
      if (refs.length > 5) cves.append(h('span', { class: 'muted', text: '+' + (refs.length - 5) }));
      liste.append(h('div', { class: 'vrow' },
        sevChip(e.worst),
        h('b', { text: e.component }), h('span', { class: 'muted', text: e.version || '' }),
        chipEl(pluriel(e.n, 'faille'), 'mut'),
        e.update_to ? chipEl('MAJ ' + e.update_to, 'ok') : chipEl('aucun correctif', 'err'),
        refs.length ? cves : null));
    });
    const tete = entetePliable(ouvert, el => {
      const o = liste.hidden;
      if (o) VLNOPEN.add(s.domain); else VLNOPEN.delete(s.domain);
      liste.hidden = !o;
      el.classList.toggle('open', o);
      el.setAttribute('aria-expanded', o ? 'true' : 'false');
    },
      lienSite(s.domain),
      sevChip(s.worst),
      h('span', { class: 'muted small', text: pluriel(grp.length, 'extension') + ' · ' + pluriel(s.findings.length, 'faille') }),
      corrigeables ? chipEl(pluriel(corrigeables, 'corrigeable'), 'ok') : chipEl('aucun correctif', 'mut'));
    noeuds.push(tete, liste);
  });
  cnt.textContent = nGrp ? pluriel(filtres.length, 'site') + ' · ' + pluriel(nGrp, 'extension') : '';
  mount(body, noeuds);
}

function renderVulnsParExtension(filtres) {
  const body = document.getElementById('vln-body'), cnt = document.getElementById('vln-count');
  const grp = grouperParParc(filtres);
  if (!grp.length) {
    mount(body, h('span', { class: 'muted', text: 'aucune vulnérabilité ne correspond au filtre.' }));
    cnt.textContent = '';
    return;
  }
  const multi = grp.filter(e => e.sites.length > 1).length;
  cnt.textContent = pluriel(grp.length, 'extension') + (multi ? ` · ${multi} sur plusieurs sites` : '');
  const noeuds = [];
  grp.forEach(e => {
    const ouvert = VEXTOPEN.has(e.component);
    const majables = e.sites.filter(d => d.update_to && d.via !== 'rest');
    const liste = h('div', { class: 'vlist', hidden: !ouvert });
    e.sites.slice().sort((a, b) => (SEVRANK[b.worst] || 0) - (SEVRANK[a.worst] || 0)).forEach(d => {
      liste.append(h('div', { class: 'vrow' },
        sevChip(d.worst), lienSite(d.domain),
        h('span', { class: 'muted', text: d.version || '' }),
        chipEl(pluriel(d.n, 'faille'), 'mut'),
        d.update_to ? chipEl('MAJ ' + d.update_to, 'ok') : chipEl('aucun correctif', 'err'),
        d.via === 'rest'
          ? chipEl('REST', 'mut', { title: 'site géré sans SSH : action distante indisponible' })
          : null));
    });
    let bouton;
    if (majables.length) {
      bouton = h('button', {
        type: 'button', class: 'btn sm primary vbulk',
        title: `Lance « MAJ ${e.component} » sur les ${majables.length} site(s) où une mise à jour existe`,
        text: 'MAJ sur ' + pluriel(majables.length, 'site'),
      });
      bouton.onclick = ev => { ev.stopPropagation(); majGroupee(e); };
    } else {
      bouton = chipEl('aucun correctif', 'mut');
    }
    const tete = entetePliable(ouvert, el => {
      const o = liste.hidden;
      if (o) VEXTOPEN.add(e.component); else VEXTOPEN.delete(e.component);
      liste.hidden = !o;
      el.classList.toggle('open', o);
      el.setAttribute('aria-expanded', o ? 'true' : 'false');
    },
      h('b', { text: e.component }), sevChip(e.worst),
      h('span', { class: 'muted small', text: pluriel(e.sites.length, 'site') + ' · ' + pluriel(e.n, 'faille') }),
      bouton);
    noeuds.push(tete, liste);
  });
  mount(body, noeuds);
}

/* Mise à jour d'une extension sur tous les sites où un correctif existe.
   Les sites gérés sans SSH sont exclus : l'action y serait refusée (rc 97). */
async function majGroupee(e) {
  const cibles = e.sites.filter(d => d.update_to && d.via !== 'rest');
  // Le rapport nomme les sites par leur clé Kuma (souvent un ALIAS) ;
  // `find_site()` côté serveur ne connaît que le vhost réel.
  const resolus = cibles.map(d => {
    const s = siteByName(d.domain, d.server);
    return {
      ...d,
      cible: { server: (s && s.srv) || d.server, domain: (s && s.domain) || d.domain },
      alias: !!(s && s.domain !== d.domain),
    };
  });
  const ok = await askConfirm(
    `Sur <b>${resolus.length} site(s)</b> où une mise à jour existe :<br>`
    + resolus.map(d => `${H(d.domain)}${d.alias ? ` <span class="muted small">(vhost ${H(d.cible.domain)})</span>` : ''} <span class="muted">${H(d.version)} → ${H(d.update_to)}</span>`).join('<br>')
    + '<br><br>Les extensions <b>gelées</b> sur un site seront ignorées automatiquement.',
    { titre: `Mettre à jour « ${e.component} »`, ok: 'Mettre à jour' });
  if (!ok) return;
  // Le cœur ne se met pas à jour avec `plugin_update` : action distincte, sans argument.
  const tasks = resolus.map(d => e.kind === 'core'
    ? { server: d.cible.server, domain: d.cible.domain, action: 'core_update', arg: null }
    : { server: d.cible.server, domain: d.cible.domain, action: 'plugin_update', arg: e.component });
  let r;
  try { r = await api('/api/actions/bulk', { tasks, mode: 'continue', backup_first: true, viz_verify: false }); }
  catch (err) { r = { error: String(err) }; }
  if (r && r.job) demarrerJob(r.job, 'Mise à jour de ' + e.component, pluriel(resolus.length, 'site'));
  else askInfo('Mise à jour groupée impossible', (r && r.error) ? H(r.error) : "Le serveur n'a pas renvoyé de tâche.");
}

function renderVulnsPhp() {
  const php = document.getElementById('vln-php');
  if (!php) return;
  const lignes = VULNS.php || [];
  if (!lignes.length) {
    mount(php, h('span', { class: 'muted', text: 'aucune version PHP avec faille connue.' }));
    return;
  }
  mount(php, lignes.map(e => {
    const eol = /^([0-7]\.|8\.0)/.test(String(e.version || ''));
    return h('div', { class: 'vulnrow' },
      sevChip(e.worst), h('b', { text: 'PHP ' + (e.version || '?') }),
      eol ? chipEl('fin de support', 'err') : null,
      h('span', { class: 'muted', text: pluriel(Number(e.count) || 0, 'faille connue', 'failles connues') }),
      h('span', {
        class: 'muted small',
        text: '— ' + pluriel((e.sites || []).length, 'site') + ' : '
          + (e.sites || []).slice(0, 4).join(', ') + ((e.sites || []).length > 4 ? '…' : ''),
      }));
  }));
}

async function loadVulns(force) {
  if (cacheFrais('vulns', force)) return;
  try {
    VULNS = await api('/api/sec/vulns');
    // Le chiffre utile n'est pas « 222 failles » mais la répartition entre ce
    // qui se corrige d'un clic et ce qui demande une décision.
    let corrigeables = 0, sansFix = 0;
    (VULNS.sites || []).forEach(x => (x.findings || []).forEach(v => v.update_to ? corrigeables++ : sansFix++));
    VULNS._fix = corrigeables; VULNS._nofix = sansFix;
    const t = VULNS.totals || {}, sum = document.getElementById('vln-sum');
    if (VULNS.sites_affected) {
      const bits = [];
      if (t.critical) bits.push(t.critical + ' critiques');
      if (t.high) bits.push(t.high + ' élevées');
      if (t.medium) bits.push(t.medium + ' moyennes');
      mount(sum,
        chipEl(`${VULNS.sites_affected}/${VULNS.sites_scanned} sites — ${bits.join(', ') || '—'}`,
          t.critical ? 'err' : t.high ? 'warn' : 'mut'), ' ',
        chipEl(corrigeables + ' corrigeables par une MAJ', 'ok'), ' ',
        chipEl(sansFix + ' sans correctif', 'mut'));
    } else mount(sum, VULNS.sites_scanned ? chipEl('parc sain', 'ok') : null);
    renderVulns();
    majSommaire();
    majCompteurSec();
  } catch (e) {
    cacheVider('vulns');
    const body = document.getElementById('vln-body');
    if (body) mount(body, h('span', { class: 'muted', text: 'erreur de chargement : ' + e }));
  }
}

async function lancerVulns(b) {
  setBusy(b, 'analyse…');
  mount('vln-body', chipEl('analyse en cours…', 'mut'), ' ',
    h('span', { class: 'muted', text: '~2 min (≈320 extensions à vérifier)' }));
  const fini = () => setIdle(b, null);
  let lancement;
  try { lancement = await api('/api/sec/vulns/run', { refresh: true }); }
  catch (err) { lancement = { error: String(err) }; }
  if (lancement && lancement.error && !lancement.running) {
    askInfo('Analyse impossible', H(lancement.error));
    fini();
    loadVulns(true);
    return;
  }
  poll('vulns', async () => {
    const r = await api('/api/sec/vulns');
    // `true` : forcer, sinon l'étranglement de 20 s avalerait la seule mise à
    // jour qui compte — celle qui suit l'analyse.
    if (r && !r.running) { loadVulns(true); majCompteurSec(true); return { fini: true }; }
    return { fini: false };
  }, { every: 5000, maxErrors: 5, until: r => !!(r && r.fini), onStop: fini });
}

/* ============================================================================
   2. Comptes administrateurs et référence
   ========================================================================== */
function sectionAdmins() {
  const tout = h('button', { type: 'button', class: 'btn sm', id: 'baseline-all', text: 'Tout marquer comme vu' });
  tout.onclick = async () => {
    if (!await askConfirm(
      'Figer la liste actuelle des administrateurs de <b>tous les sites</b> comme référence ?'
      + '<br><br>Tout compte ajouté ensuite sera signalé en rouge.',
      { titre: 'Tout marquer comme vu', ok: 'Marquer comme vu' })) return;
    setBusy(tout, '…');
    await api('/api/sec/baseline', {}).catch(() => {});
    setIdle(tout, null);
    loadSec(true);
  };
  return sectionEl('sec-admins', 'Comptes administrateurs',
    [h('span', { class: 'small', id: 'adm-sum' }), h('span', { class: 'spacer' }), tout],
    h('p', { class: 'hint' }, 'Un administrateur absent de la référence est signalé ',
      h('span', { class: 'new-admin', text: 'en rouge' }),
      ' — le signal n°1 d’une compromission. « Marquer comme vu » fige la liste actuelle comme référence.'),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', { text: 'Site' }), h('th', { text: 'Administrateurs' }),
          h('th', {}, h('span', { class: 'sr-only', text: 'Actions' })))),
        h('tbody', { id: 'admin-tb' }))));
}

/** Référence enregistrée pour un site (clé Kuma d'abord, comme le backend). */
function refAdmins(s) {
  const b = store.baseline || {};
  const r = b[kName(s)] || b[s.domain];
  return (r && Array.isArray(r.logins)) ? r.logins : null;
}

/** Comptes présents sur un site mais absents de sa référence. */
function adminsInconnus() {
  const out = [];
  allSites().forEach(s => {
    const base = refAdmins(s);
    if (!base) return;
    (s.admins || []).forEach(a => { if (a && a.login && !base.includes(a.login)) out.push({ s, a }); });
  });
  return out;
}

function renderAdmins() {
  const tb = document.getElementById('admin-tb');
  if (!tb) return;
  const S = allSites().filter(s => s.admins !== null && s.admins !== undefined);
  const lignes = [];
  if (BLERR) {
    lignes.push(h('tr', {}, h('td', { colspan: '3' },
      chipEl('référence indisponible', 'err'), ' ',
      h('span', { class: 'muted small', text: BLERR }))));
  }
  S.forEach(s => {
    const base = refAdmins(s);
    const cellules = h('td', {});
    (s.admins || []).forEach(a => {
      const isNew = base && !base.includes(a.login);
      cellules.append(h('span', {
        class: 'tag' + (isNew ? ' new-admin' : ''),
        title: (a.email || '') + ' · inscrit ' + (a.registered || '?'),
      }, isNew ? iconEl('triangle-alert', { size: 14 }) : null, ' ' + a.login), ' ');
    });
    if (!(s.admins || []).length) cellules.append(h('span', { class: 'muted', text: '—' }));
    if (!base) cellules.append(h('span', { class: 'muted small', text: ' (pas de référence)' }));
    const bt = h('button', { type: 'button', class: 'btn sm', text: 'Marquer comme vu' });
    bt.onclick = async () => {
      setBusy(bt, '…');
      await api('/api/sec/baseline', { domain: s.domain }).catch(() => {});
      setIdle(bt, null);
      loadSec(true);
    };
    lignes.push(h('tr', {},
      h('td', {}, lienSite(kName(s) || s.domain)),
      cellules,
      h('td', {}, bt)));
  });
  mount(tb, lignes);
  const n = adminsInconnus().length;
  mount('adm-sum', n
    ? chipEl(pluriel(n, 'compte inconnu', 'comptes inconnus'), 'err')
    : chipEl('conformes à la référence', 'ok'));
}

/* ============================================================================
   3. Erreurs PHP
   ========================================================================== */
const PHRANK = { 'Fatal error': 4, 'Parse error': 4, Warning: 3, Deprecated: 2, Notice: 1, 'Strict Standards': 1 };

function sectionPhe() {
  const run = h('button', { type: 'button', class: 'btn sm', id: 'phe-run' },
    iconEl('refresh-cw'), "Relancer l'analyse");
  run.onclick = () => lancerPhe(run);
  const q = h('input', {
    type: 'search', id: 'phe-q', class: 'w-md',
    placeholder: 'Filtrer un site, un message, un fichier…', 'aria-label': 'Filtrer les erreurs PHP',
  });
  q.oninput = debounce(renderPhe, 200);
  const sev = h('select', { id: 'phe-sev', 'aria-label': 'Gravité minimale' },
    h('option', { value: '', text: 'Toutes gravités' }),
    h('option', { value: '4', text: 'Fatales seulement' }),
    h('option', { value: '3', text: 'Warnings et +' }));
  sev.onchange = renderPhe;
  const fen = h('select', { id: 'phe-h', 'aria-label': "Fenêtre d'analyse" },
    h('option', { value: '24', text: '24 h' }),
    h('option', { value: '72', text: '3 jours' }),
    h('option', { value: '168', text: '7 jours' }));
  return sectionEl('sec-phperr', 'Erreurs PHP',
    [h('span', { class: 'small', id: 'phe-sum' }), h('span', { class: 'spacer' }), run],
    h('p', { class: 'hint' }, 'Lecture des journaux que vos serveurs écrivent ', h('b', { text: 'déjà' }),
      ' — aucune modification des sites, aucun mode debug à activer. Les occurrences sont regroupées par message, fichier et ligne.'),
    h('div', { class: 'filters' }, q, sev, fen,
      h('span', { class: 'spacer' }), h('span', { class: 'muted small', id: 'phe-count' })),
    h('div', { class: 'small mt2 scroll-lg', id: 'phe-body' },
      h('span', { class: 'muted', text: 'chargement…' })));
}

/* « Aucune erreur » n'a pas le même sens si un journal a été tronqué ou si un
   serveur n'a pas répondu : l'absence de résultat doit alors se dire.
   `truncated` = {serveur: [{file, reason}]} · `servers_failed` = {serveur: raison}. */
function phePartielle() {
  const tr = (PHERR.truncated && typeof PHERR.truncated === 'object') ? PHERR.truncated : {};
  const ko = (PHERR.servers_failed && typeof PHERR.servers_failed === 'object') ? PHERR.servers_failed : {};
  const srvTr = Object.keys(tr).filter(k => Array.isArray(tr[k]) && tr[k].length);
  const srvKo = Object.keys(ko).filter(k => ko[k] !== null && ko[k] !== undefined && ko[k] !== '');
  const nTr = srvTr.reduce((a, k) => a + tr[k].length, 0);
  if (!nTr && !srvKo.length) return null;
  const bouts = [];
  if (nTr) bouts.push(nTr + ' ' + (nTr > 1 ? 'journaux tronqués' : 'journal tronqué'));
  if (srvKo.length) bouts.push(pluriel(srvKo.length, 'serveur') + ' en échec');
  const ul = h('ul', {});
  srvKo.forEach(k => ul.append(h('li', {}, h('b', { text: k }), ' — serveur non lu : ' + String(ko[k]))));
  srvTr.forEach(k => tr[k].forEach(x => ul.append(h('li', {},
    h('b', { text: k }), ' — ', h('code', { text: (x && x.file) || 'journal' }),
    ' : ' + ((x && x.reason) || 'tronqué')))));
  return h('div', { class: 'warnbox small mt2' },
    iconEl('triangle-alert'), ' ', h('b', { text: 'Analyse partielle' }),
    ' — ' + bouts.join(', ') + '. Des erreurs peuvent manquer dans la liste ci-dessous.', ul);
}

function renderPhe() {
  const body = document.getElementById('phe-body'), cnt = document.getElementById('phe-count');
  if (!body) return;
  if (PHERR.running) {
    mount(body, chipEl('analyse en cours…', 'mut'), ' ',
      h('span', { class: 'muted small', text: PHERR.run_message || '' }));
    cnt.textContent = '';
    return;
  }
  const partielle = phePartielle();
  if (!(PHERR.sites || []).length) {
    mount(body, PHERR.generated_at
      ? chipEl('aucune erreur PHP sur la fenêtre', 'ok')
      : h('span', { class: 'muted', text: 'Analyse jamais lancée — cliquez sur « Relancer l’analyse ».' }),
      partielle);
    cnt.textContent = '';
    return;
  }
  const q = (document.getElementById('phe-q').value || '').toLowerCase().trim();
  const minR = parseInt(document.getElementById('phe-sev').value || '0', 10);
  let n = 0;
  const blocs = [];
  PHERR.sites.forEach(s => {
    let g = (s.groups || []).filter(x => (PHRANK[x.severity] || 0) >= minR);
    if (q) g = g.filter(x => (s.domain + ' ' + x.message + ' ' + (x.short || x.file || '')).toLowerCase().includes(q));
    if (!g.length) return;
    n += g.length;
    const bloc = h('div', { class: 'phe-group' },
      lienSite(s.domain),
      h('span', { class: 'muted small', text: ' ' + pluriel(Number(s.total) || 0, 'occurrence') }));
    g.forEach(x => {
      const r = PHRANK[x.severity] || 0;
      bloc.append(h('div', { class: 'logline' },
        chipEl(x.severity || '?', r >= 4 ? 'err' : r >= 3 ? 'warn' : 'mut'), ' ',
        chipEl('×' + (x.count ?? 1), 'mut'), ' ',
        h('span', { text: x.message || '' }),
        x.short ? h('div', { class: 'muted small phe-loc' },
          h('code', { text: x.short + ':' + (x.line ?? '?') }),
          ' · dernière ' + relTime(x.last)) : null));
    });
    blocs.push(bloc);
  });
  cnt.textContent = n ? pluriel(n, 'groupe') : '';
  mount(body, partielle,
    blocs.length ? blocs : h('span', { class: 'muted', text: 'aucune erreur ne correspond au filtre.' }));
}

async function loadPhe(force) {
  if (cacheFrais('phe', force)) return;
  try {
    PHERR = await api('/api/sec/phperrors');
    const sum = document.getElementById('phe-sum');
    if (PHERR.sites_with_errors) {
      mount(sum, chipEl(
        `${PHERR.sites_with_errors} site(s) · ${PHERR.total} occurrence(s)`
        + (PHERR.fatals ? ` · ${PHERR.fatals} fatale(s)` : ''), PHERR.fatals ? 'err' : 'warn'));
    } else mount(sum, PHERR.generated_at ? chipEl('aucune erreur', 'ok') : null);
    renderPhe();
    majSommaire();
  } catch (e) {
    cacheVider('phe');
    const body = document.getElementById('phe-body');
    if (body) mount(body, h('span', { class: 'muted', text: 'erreur de chargement : ' + e }));
  }
}

async function lancerPhe(b) {
  const heures = document.getElementById('phe-h').value;
  setBusy(b, 'analyse…');
  mount('phe-body', chipEl('lecture des journaux…', 'mut'));
  const fini = () => setIdle(b, null);
  let lancement;
  try { lancement = await api('/api/sec/phperrors/run', { hours: parseInt(heures, 10) }); }
  catch (err) { lancement = { error: String(err) }; }
  if (lancement && lancement.error && !lancement.running) {
    askInfo('Analyse impossible', H(lancement.error));
    fini();
    loadPhe(true);
    return;
  }
  poll('phe', async () => {
    const r = await api('/api/sec/phperrors');
    if (r && !r.running) { loadPhe(true); majCompteurSec(true); return { fini: true }; }
    return { fini: false };
  }, { every: 3000, maxErrors: 5, until: r => !!(r && r.fini), onStop: fini });
}

/* ============================================================================
   4. Extensions à risque
   ========================================================================== */
function sectionRisky() {
  return sectionEl('sec-risky', 'Extensions à risque', null,
    h('p', { class: 'hint' }, "Extensions régulièrement exploitées en incident (gestionnaires de fichiers, "
      + "exécution de PHP arbitraire, outils de migration). À désinstaller dès qu'elles ne servent plus."),
    h('div', { class: 'small', id: 'risky-body' }));
}

function risques() {
  const out = [];
  allSites().forEach(s => (s.plugins_list || []).forEach(p => {
    if (RISKY.includes(String(p.name || '').toLowerCase())) out.push({ s, p });
  }));
  return out;
}

function renderRisky() {
  const box = document.getElementById('risky-body');
  if (!box) return;
  const hits = risques();
  if (!hits.length) { mount(box, chipEl('aucune extension à risque détectée', 'ok')); return; }
  mount(box, hits.map(({ s, p }) => h('div', { class: 'logline' },
    chipEl(p.status === 'active' ? 'active' : (p.status || 'inactive'), p.status === 'active' ? 'err' : 'warn'), ' ',
    lienSite(kName(s) || s.domain), h('span', { class: 'muted', text: ' · ' }),
    h('span', { text: p.name }), ' ',
    h('span', { class: 'muted small', text: p.version || '' }))));
}

/* ============================================================================
   5. PHP obsolète — regroupé par version : une branche se corrige chez
   l'hébergeur, pas site par site.
   ========================================================================== */
function sectionPhp() {
  return sectionEl('sec-php', 'PHP obsolète', null,
    h('p', { class: 'hint', text: 'Sites sous une branche PHP qui ne reçoit plus de correctifs de sécurité. Regroupé par version : la mise à niveau se fait sur le serveur.' }),
    h('div', { class: 'small', id: 'php-body' }));
}

function phpObsoletes(S) {
  const g = new Map();
  S.forEach(s => {
    const v = s.php_version;
    if (!v || parseFloat(v) >= 8.1) return;
    if (!g.has(v)) g.set(v, { version: v, sites: [] });
    g.get(v).sites.push(s);
  });
  return [...g.values()].sort((a, b) => parseFloat(a.version) - parseFloat(b.version));
}

function renderPhp() {
  const box = document.getElementById('php-body');
  if (!box) return;
  const grp = phpObsoletes(allSites());
  if (!grp.length) { mount(box, chipEl('tout le parc en PHP ≥ 8.1', 'ok')); return; }
  mount(box, grp.map(g => {
    const ligne = h('div', { class: 'vulnrow' },
      chipEl('PHP ' + g.version, parseFloat(g.version) < 7.4 ? 'err' : 'warn'),
      h('span', { class: 'muted small', text: pluriel(g.sites.length, 'site') + ' :' }));
    g.sites.forEach(s => { ligne.append(lienSite(kName(s) || s.domain), ' '); });
    return ligne;
  }));
}

/* ============================================================================
   6. Certificats SSL
   ========================================================================== */
function sectionCerts() {
  return sectionEl('sec-certs', 'Certificats SSL', null,
    h('p', { class: 'hint', text: 'Expiration vue par Uptime Kuma, du plus urgent au plus lointain. Alerte sous 21 jours, critique sous 7 jours.' }),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', { text: 'Moniteur' }), h('th', { text: 'Jours restants' }), h('th', { text: 'Expire le' }))),
        h('tbody', { id: 'cert-tb' }))),
    zoneMessage('cert-msg', 'small muted mt2', 'div'));
}

function renderCerts() {
  const tb = document.getElementById('cert-tb'), msg = document.getElementById('cert-msg');
  if (!tb) return;
  const certs = (CERTS || []).slice().sort((a, b) => {
    const x = a.days, y = b.days;
    if (x === null || x === undefined) return 1;
    if (y === null || y === undefined) return -1;
    return Number(x) - Number(y);
  });
  mount(tb, certs.map(x => {
    const d = x.days;
    const niv = (d === null || d === undefined) ? 'mut' : Number(d) < 7 ? 'err' : Number(d) < 21 ? 'warn' : 'ok';
    return h('tr', {},
      h('td', {}, lienSite(x.monitor)),
      h('td', {}, chipEl(d === null || d === undefined ? '?' : d + ' j', niv)),
      h('td', { class: 'sub', text: x.valid_to || '' }));
  }));
  msg.textContent = certs.length ? '' : (CERTMSG || 'aucun certificat remonté.');
}

/* ============================================================================
   7. Intégrité du cœur (checksums)
   ========================================================================== */
function sectionChecksums() {
  const tout = h('button', { type: 'button', class: 'btn sm primary', id: 'verify-all', text: 'Vérifier tout le parc' });
  tout.onclick = async () => {
    const msg = document.getElementById('verify-msg');
    if (!await askConfirm(
      'Lancer <code>wp core verify-checksums</code> sur tout le parc ?'
      + "<br><br>L'opération passe sur chaque site et peut durer plusieurs minutes.",
      { titre: 'Intégrité du cœur', ok: 'Lancer' })) return;
    setBusy(tout, 'lancement…');
    mount(msg, h('span', { class: 'muted', text: 'lancement…' }));
    try {
      const j = await api('/api/sec/checksums/run', {}) || {};
      if (!j.job) {
        mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted', text: j.error || 'aucun job renvoyé' }));
        setIdle(tout, null);
        return;
      }
      mount(msg);
      demarrerJob(j.job, 'Vérification des checksums', 'tout le parc');
      majCompteurSec(true);
    } catch (e) {
      mount(msg, chipEl('échec', 'err'), ' ', h('span', { class: 'muted', text: String(e) }));
    }
    setIdle(tout, null);
  };
  return sectionEl('sec-checksums', 'Intégrité du cœur (checksums)',
    [zoneMessage('verify-msg'), h('span', { class: 'spacer' }), tout],
    h('p', { class: 'hint' }, 'Lance ', h('code', { text: 'wp core verify-checksums' }),
      '. « Vérifier tout le parc » passe sur tous les sites en tâche de fond ; sinon sélectionnez des sites '
      + 'dans le Parc puis « Checksums » dans la barre d’actions, ou lancez ici site par site.'),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {}, h('th', { text: 'Site' }), h('th', { text: 'Dernier contrôle' }))),
        h('tbody', { id: 'verify-tb' }))));
}

function etatChecksum(ck) {
  if (!ck || typeof ck !== 'object') return h('span', { class: 'muted small', text: 'jamais vérifié' });
  return h('span', {},
    chipEl(ck.ok ? 'intègre' : 'anomalie', ck.ok ? 'ok' : 'err',
      { title: String(ck.output_tail ?? '').slice(-400) }), ' ',
    h('span', { class: 'muted small', title: absTime(ck.ts), text: relTime(ck.ts) }));
}

function renderChecksums() {
  const tb = document.getElementById('verify-tb');
  if (!tb) return;
  mount(tb, allSites().filter(s => s.core_version).map(s => {
    const res = h('span', { class: 'small' }, etatChecksum(CKS[s.domain] || CKS[kName(s)]));
    const bt = h('button', { type: 'button', class: 'btn sm', text: 'Vérifier' });
    bt.disabled = s.via === 'rest';
    if (bt.disabled) bt.title = "site géré sans SSH : vérification impossible d'ici";
    else bt.onclick = async () => {
      setBusy(bt);
      let j;
      try { j = await api('/api/sec/verify', { server: s.srv, domain: s.domain }); }
      catch (e) { j = { ok: false, output: String(e) }; }
      setIdle(bt, null);
      mount(res, (j && j.ok)
        ? chipEl('intègre', 'ok')
        : h('span', {}, chipEl('anomalie', 'err'), ' ',
          h('span', { class: 'muted small', text: String((j && (j.output || j.error)) || '').slice(-120) })));
    };
    return h('tr', {},
      h('td', {}, lienSite(kName(s) || s.domain), ' ',
        h('span', { class: 'muted small', text: s.core_version })),
      h('td', {}, bt, ' ', res));
  }));
}

/* ============================================================================
   8. Recherche transversale d'extension
   ========================================================================== */
function sectionRecherche() {
  const q = h('input', {
    class: 'inp w-md', id: 'plug-q', placeholder: 'nom ou slug d’extension…',
    'aria-label': 'Nom ou slug d’extension',
  });
  q.oninput = debounce(renderRecherche, 200);
  return sectionEl('sec-recherche', 'Recherche transversale d’extension', null,
    h('p', { class: 'hint', text: 'Quels sites ont telle extension installée ? (utile en incident : wp-file-manager, etc.)' }),
    h('div', { class: 'filters' }, q, h('span', { class: 'small', id: 'plug-res' })),
    h('div', { class: 'wrap' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', { text: 'Site' }), h('th', { text: 'Extension' }),
          h('th', { text: 'Version' }), h('th', { text: 'Statut' }))),
        h('tbody', { id: 'plug-tb' }))));
}

function renderRecherche() {
  const tb = document.getElementById('plug-tb'), res = document.getElementById('plug-res');
  if (!tb) return;
  const q = (document.getElementById('plug-q').value || '').toLowerCase().trim();
  if (!q) { mount(tb); res.textContent = ''; return; }
  const hits = [];
  allSites().forEach(s => (s.plugins_list || []).forEach(p => {
    if (String(p.name || '').toLowerCase().includes(q)) hits.push({ s, p });
  }));
  res.textContent = `${hits.length} occurrence(s) sur ${new Set(hits.map(x => x.s.domain)).size} site(s)`;
  mount(tb, hits.map(({ s, p }) => h('tr', {},
    h('td', {}, lienSite(kName(s) || s.domain)),
    h('td', { text: p.name }),
    h('td', { text: p.version || '' }),
    h('td', {}, chipEl(p.status || '?', p.status === 'active' ? 'ok' : 'mut')))));
}

/* ============================================================================
   Chargement de l'écran
   ========================================================================== */
async function loadSec(force) {
  monterSec();
  if (cacheFrais('sec', force)) return;
  // `aria-busy` pendant le chargement : une page qui se remplit par morceaux
  // n'est pas une page vide, et une technologie d'assistance doit pouvoir le
  // dire au lieu d'annoncer huit sections encore muettes.
  occupe('page-sec', true);
  loadVulns(force);        // indépendants : l'un ne bloque pas les autres
  loadPhe(force);

  // La référence des admins n'est qu'une des huit sections : son échec ne doit
  // pas emporter les certificats, les extensions à risque et les checksums.
  BLERR = '';
  try { const bl = await api('/api/sec/baseline'); store.baseline = (bl && bl.baseline) || {}; }
  catch (e) { store.baseline = {}; BLERR = String(e); cacheVider('sec'); }
  renderAdmins();
  renderRisky();
  renderPhp();

  try {
    const c = await api('/api/sec/certs');
    CERTS = c.certs || [];
    CERTMSG = c.error || '';
  } catch (e) { CERTS = []; CERTMSG = 'erreur de chargement : ' + e; }
  renderCerts();

  try {
    const c = await api('/api/sec/checksums');
    // La route renvoie {"checksums": {…}} ; on accepte aussi la forme à plat.
    CKS = (c && typeof c === 'object' && !c.error)
      ? ((c.checksums && typeof c.checksums === 'object') ? c.checksums : c) : {};
  } catch (e) { CKS = {}; }
  renderChecksums();
  renderRecherche();
  majSommaire();
  majCompteurSec();
  occupe('page-sec', false);
}

/* Pastille « Sécurité » de la barre latérale : elle vient du MÊME agrégat que
   la file d'incidents (vulnérabilités corrigeables + administrateurs inconnus),
   pour qu'aucun compteur ne contredise un autre. */
export function majCompteurSec(force) { majCompteursServeur(force); }

export { loadSec, sevPill, SEVLABEL, SEVRANK, grouperParExtension };
