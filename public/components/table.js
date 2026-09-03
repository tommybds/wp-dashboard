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
