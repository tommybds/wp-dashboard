/* Tableau : tri par colonne, annoncé par `aria-sort`, atteignable au clavier.

   Le collage de l'en-tête est purement CSS (`th{position:sticky;top:0}`) —
   piège connu : c'est `.wrap{overflow-x:auto}` qui sert de référentiel, donc
   `top:0` place l'en-tête à sa position naturelle DANS ce conteneur.
   La densité compacte passe par la variable `--rowh` posée sur <html>. */

import { activeAuClavier } from '../lib/dom.js';

/**
 * bindSortable(racine, {get, set, onChange})
 *   get()      → {k, dir}
 *   set({k,dir}) écrit le nouvel ordre
 *   onChange() redessine
 * Les colonnes triables portent `data-k` dans le HTML.
 */
export function bindSortable(root, { get, set, onChange }) {
  const el = typeof root === 'string' ? document.querySelector(root) : root;
  if (!el) return;
  const ths = [...el.querySelectorAll('th[data-k]')];
  const marquer = () => {
    const { k, dir } = get();
    ths.forEach(th => th.setAttribute('aria-sort',
      th.dataset.k === k ? (dir > 0 ? 'ascending' : 'descending') : 'none'));
  };
  ths.forEach(th => {
    th.tabIndex = 0;
    if (!th.getAttribute('title')) th.title = 'Trier sur cette colonne';
    const act = () => {
      const cur = get();
      set(cur.k === th.dataset.k ? { k: cur.k, dir: cur.dir * -1 } : { k: th.dataset.k, dir: 1 });
      marquer();
      onChange();
    };
    th.onclick = act;
    th.onkeydown = e => activeAuClavier(e, act);
  });
  marquer();
  return marquer;
}

/** Densité : normale (1) ou compacte (.55), comme avant la refonte. */
export function setDensity(compact) {
  document.documentElement.style.setProperty('--rowh', compact ? '.55' : '1');
}

/* ---- colonnes masquables --------------------------------------------------
   La liste MASQUÉE est mémorisée, pas la liste visible : une colonne ajoutée
   plus tard apparaît alors chez tout le monde au lieu de rester invisible chez
   ceux qui avaient déjà enregistré une préférence.
   Le stockage peut être refusé (navigation privée, réglage du navigateur) :
   dans ce cas la préférence vaut pour la session, l'écran fonctionne pareil. */

export function colonnesMasquees(cle, defaut = []) {
  try {
    const brut = localStorage.getItem(cle);
    if (brut === null) return new Set(defaut);
    const l = JSON.parse(brut);
    return new Set(Array.isArray(l) ? l.map(String) : defaut);
  } catch (e) { return new Set(defaut); }
}

export function enregistrerColonnes(cle, masquees) {
  try { localStorage.setItem(cle, JSON.stringify([...masquees])); }
  catch (e) { /* stockage refusé : la préférence vaut pour la session */ }
}

/* ---- débordement horizontal ----------------------------------------------
   Un conteneur plus large que l'écran ne se signale pas tout seul : rien ne
   distingue « la dernière colonne » de « il y en a encore trois à droite ».
   On pose donc `deb-g` / `deb-d` sur ceux qui débordent RÉELLEMENT, et de ce
   côté-là seulement (le CSS y accroche un fondu) : un fondu permanent
   mentirait une fois arrivé au bout.

   Trois déclencheurs, aucun sondage : le défilement du conteneur, le
   redimensionnement de la fenêtre, et les mutations du DOM (un tableau qui se
   remplit change de largeur). Tout est mesuré en une passe, différée. */
const DEBORDANTS = '.wrap,.anchors,.tabs';

function majDebordement(el) {
  const trop = el.scrollWidth - el.clientWidth > 2;
  el.classList.toggle('deb-g', trop && el.scrollLeft > 2);
  el.classList.toggle('deb-d', trop && el.scrollLeft < el.scrollWidth - el.clientWidth - 2);
}

export function initDebordement() {
  const tous = () => document.querySelectorAll(DEBORDANTS).forEach(majDebordement);
  let t = null;
  const differer = () => { clearTimeout(t); t = setTimeout(tous, 120); };
  // Capture : l'évènement `scroll` d'un conteneur ne remonte pas au document.
  document.addEventListener('scroll', e => {
    const el = e.target;
    if (el && el.matches && el.matches(DEBORDANTS)) majDebordement(el);
  }, true);
  window.addEventListener('resize', differer);
  // Les classes posées ici ne relancent pas l'observateur : il ne regarde que
  // les nœuds, pas les attributs.
  if (window.MutationObserver) {
    new MutationObserver(differer).observe(document.body, { childList: true, subtree: true });
  }
  differer();
}
