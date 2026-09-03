/* Recherche globale (⌘K / Ctrl+K).

   Elle remplace le champ de filtre comme point d'entrée principal : on tape un
   nom de site, d'extension ou d'administrateur, et on arrive directement là où
   il faut agir. Quatre familles de résultats, huit par famille au plus — au
   delà, c'est un filtre qu'il faut, pas une palette.

   Le champ garde le focus en permanence : les flèches déplacent une sélection
   virtuelle (`aria-activedescendant`) plutôt que le focus lui-même, sinon
   chaque flèche vide la saisie en cours dans certains navigateurs. */

import { h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { allSites, kName, st } from '../lib/state.js';
import { libelleKuma, niveauKuma } from './chip.js';
import { registerModalCloser } from './confirm.js';

const MAX = 8;

let MODALE = null, CHAMP = null, LISTE = null;
let RESULTATS = [], SEL = 0;
let CFG = { ouvrirSite: () => {}, filtrerExtension: () => {}, allerA: () => {} };

/** Raccourci affiché : ⌘ sur Mac, Ctrl ailleurs. */
export function raccourciLabel() {
  const mac = /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent || '');
  return mac ? '⌘K' : 'Ctrl K';
}

/* ---- construction de la palette ------------------------------------------ */
function construire() {
  if (MODALE) return MODALE;
  CHAMP = h('input', {
    type: 'search', id: 'search-input', class: 'inp w100',
    placeholder: 'Rechercher un site, une extension, un administrateur…',
    'aria-label': 'Recherche globale', autocomplete: 'off', spellcheck: 'false',
    role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'search-res',
  });
  LISTE = h('div', { id: 'search-res', class: 'sr-list', role: 'listbox', 'aria-label': 'Résultats' });
  MODALE = h('div', { class: 'modal', id: 'searchmodal' },
    h('div', { class: 'box narrow sr-box', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Recherche globale' },
      h('div', { class: 'sr-top' }, iconEl('search', { size: 20 }), CHAMP),
      LISTE,
      h('p', { class: 'hint sr-help' }, 'Flèches pour parcourir, Entrée pour ouvrir, Échap pour fermer.')));
  document.body.append(MODALE);
  MODALE.onclick = e => { if (e.target.id === 'searchmodal') fermerRecherche(); };
  registerModalCloser('searchmodal', fermerRecherche);
  CHAMP.oninput = () => { chercher(CHAMP.value); };
  CHAMP.onkeydown = clavier;
  return MODALE;
}

export function rechercheOuverte() { return !!(MODALE && MODALE.classList.contains('open')); }

export function fermerRecherche() {
  if (!MODALE) return;
  MODALE.classList.remove('open');
  const o = OUVREUR;
  OUVREUR = null;
  if (o && o.isConnected && typeof o.focus === 'function') { try { o.focus(); } catch (e) { /* nœud remplacé */ } }
}

let OUVREUR = null;

export function ouvrirRecherche() {
  construire();
  if (!rechercheOuverte()) OUVREUR = document.activeElement;
  MODALE.classList.add('open');
  CHAMP.value = '';
  chercher('');
  CHAMP.focus();
}

/* ---- recherche ------------------------------------------------------------ */
function siteCle(s) { return kName(s) || s.domain; }

/* Extensions du parc, agrégées : « elementor · 6 sites ». Le calcul est fait à
   chaque frappe mais ne parcourt que les sites, pas leurs CVE : sur 200 sites
   × 25 extensions, c'est quelques millisecondes. */
function extensions(q) {
  const par = new Map();
  allSites().forEach(s => {
    (s.plugins_list || []).forEach(p => {
      const n = String(p.name || '');
      if (!n || !n.toLowerCase().includes(q)) return;
      const e = par.get(n) || { nom: n, sites: 0, maj: 0 };
      e.sites++;
      if (p.update === 'available') e.maj++;
      par.set(n, e);
    });
  });
  return [...par.values()].sort((a, b) => b.maj - a.maj || b.sites - a.sites || a.nom.localeCompare(b.nom));
}

function admins(q) {
  const out = [];
  allSites().forEach(s => {
    (s.admins || []).forEach(a => {
      const l = String((a && a.login) || '');
      if (l && l.toLowerCase().includes(q)) out.push({ login: l, site: s });
    });
  });
  return out.sort((a, b) => a.login.localeCompare(b.login));
}

function actions(q) {
  const L = [
    { label: 'Collecter le parc', ic: 'refresh-cw', run: () => { const b = document.getElementById('collectbtn'); if (b) b.click(); } },
    { label: 'Réglages', ic: 'settings', run: () => CFG.allerA('#reglages') },
    { label: 'Journal des actions', ic: 'scroll-text', run: () => { const b = document.getElementById('logbtn'); if (b) b.click(); } },
    { label: 'Incidents', ic: 'triangle-alert', run: () => CFG.allerA('#incidents') },
    { label: 'Sécurité', ic: 'shield', run: () => CFG.allerA('#securite') },
    { label: 'Gestion', ic: 'server', run: () => CFG.allerA('#gestion') },
  ];
  return L.filter(x => x.label.toLowerCase().includes(q));
}

/* Met en évidence la portion trouvée. Aucun HTML n'est construit : deux nœuds
   texte et un <mark>, donc rien à échapper. */
function surligner(texte, q) {
  const t = String(texte ?? '');
  if (!q) return document.createTextNode(t);
  const i = t.toLowerCase().indexOf(q);
  if (i < 0) return document.createTextNode(t);
  return h('span', {}, t.slice(0, i), h('mark', { text: t.slice(i, i + q.length) }), t.slice(i + q.length));
}

function ligne(res, q, i) {
  const el = h('div', {
    class: 'sr-i', role: 'option', id: 'sr-i-' + i,
    'aria-selected': i === SEL ? 'true' : 'false',
  },
    res.ic ? iconEl(res.ic) : h('span', { class: 'sr-dot' }),
    h('span', { class: 'sr-l' }, surligner(res.titre, q)),
    res.detail ? h('span', { class: 'sr-d', text: res.detail }) : null,
    res.chip ? h('span', { class: 'chip ' + res.chip[1] }, h('span', { class: 'pt' }), res.chip[0]) : null);
  el.onmouseenter = () => { SEL = i; marquer(); };
  el.onclick = () => activer(res);
  return el;
}

function marquer() {
  if (!LISTE) return;
  [...LISTE.querySelectorAll('.sr-i')].forEach((el, i) => {
    el.setAttribute('aria-selected', i === SEL ? 'true' : 'false');
    el.classList.toggle('on', i === SEL);
    if (i === SEL) {
      CHAMP.setAttribute('aria-activedescendant', el.id);
      if (el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
    }
  });
}

function chercher(brut) {
  const q = String(brut || '').trim().toLowerCase();
  RESULTATS = [];
  const groupes = [];

  const S = allSites().filter(s => !q || (s._q || '').includes(q));
  if (S.length) {
    groupes.push(['Sites', S.slice(0, MAX).map(s => ({
      titre: siteCle(s), ic: 'layout-grid',
      detail: siteCle(s) !== s.domain ? s.domain : (s.kuma_group || ''),
      chip: [libelleKuma(st(s)), niveauKuma(st(s))],
      go: () => CFG.ouvrirSite(siteCle(s)),
    })), S.length]);
  }
  if (q) {
    const ex = extensions(q);
    if (ex.length) {
      groupes.push(['Extensions', ex.slice(0, MAX).map(e => ({
        titre: e.nom, ic: 'puzzle',
        detail: e.sites + ' site' + (e.sites > 1 ? 's' : '') + (e.maj ? ' · ' + e.maj + ' à mettre à jour' : ''),
        go: () => CFG.filtrerExtension(e.nom),
      })), ex.length]);
    }
    const ad = admins(q);
    if (ad.length) {
      groupes.push(['Administrateurs', ad.slice(0, MAX).map(a => ({
        titre: a.login, ic: 'shield', detail: siteCle(a.site),
        go: () => CFG.ouvrirSite(siteCle(a.site), 'securite'),
      })), ad.length]);
    }
  }
  const ac = actions(q);
  if (ac.length) {
    groupes.push(['Actions', ac.slice(0, MAX).map(a => ({
      titre: a.label, ic: a.ic, go: a.run,
    })), ac.length]);
  }

  SEL = 0;
  const noeuds = [];
  groupes.forEach(([titre, items, total]) => {
    noeuds.push(h('div', { class: 'sr-g', role: 'presentation' }, titre,
      total > items.length ? h('span', { class: 'muted', text: ` (${items.length} sur ${total})` }) : null));
    items.forEach(r => { noeuds.push(ligne(r, q, RESULTATS.length)); RESULTATS.push(r); });
  });
  if (!RESULTATS.length) noeuds.push(h('div', { class: 'sr-vide', text: 'Aucun résultat.' }));
  mount(LISTE, noeuds);
  marquer();
}

function activer(res) {
  fermerRecherche();
  if (res && res.go) res.go();
}

function clavier(e) {
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); fermerRecherche(); return; }
  if (e.key === 'ArrowDown') { e.preventDefault(); if (RESULTATS.length) { SEL = (SEL + 1) % RESULTATS.length; marquer(); } return; }
  if (e.key === 'ArrowUp') { e.preventDefault(); if (RESULTATS.length) { SEL = (SEL - 1 + RESULTATS.length) % RESULTATS.length; marquer(); } return; }
  if (e.key === 'Home') { e.preventDefault(); SEL = 0; marquer(); return; }
  if (e.key === 'End') { e.preventDefault(); SEL = Math.max(0, RESULTATS.length - 1); marquer(); return; }
  if (e.key === 'Enter') { e.preventDefault(); if (RESULTATS[SEL]) activer(RESULTATS[SEL]); }
}

/**
 * initSearch({ouvrirSite, filtrerExtension, allerA}) — branché une fois par app.js.
 *   ouvrirSite(cle, onglet)   ouvre la page d'un site
 *   filtrerExtension(nom)     ouvre le Parc filtré sur cette extension
 *   allerA(fragment)          navigue vers une destination
 */
export function initSearch(cfg) {
  Object.assign(CFG, cfg || {});
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && !e.altKey && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (rechercheOuverte()) fermerRecherche(); else ouvrirRecherche();
    }
  });
}
