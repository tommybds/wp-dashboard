/* Iconographie : un sprite SVG unique (Lucide, licence ISC), injecté une fois
   dans le document, puis référencé par `<use href="#i-…">`.

   Pourquoi inline et pas `icons.svg#i-x` en référence externe : `<use>` vers un
   autre document n'est pas supporté partout et échoue silencieusement. Le
   sprite est donc récupéré une fois (mis en cache un an grâce au `?v=`) et
   collé dans <body> ; `app.js` attend `initIcons()` avant le premier rendu, il
   n'y a donc jamais de trou visuel.

   `icon()` rend une CHAÎNE : les écrans repris en phase 1 composent encore
   leur HTML avec des gabarits littéraux. `iconEl()` rend un nœud, pour les
   composants construits avec `h()`. */

import { esc } from './dom.js';

let injected = false;
let pending = null;

/** Injecte le sprite dans le document (idempotent). */
export function initIcons(url) {
  if (injected) return Promise.resolve(true);
  if (pending) return pending;
  pending = fetch(url, { credentials: 'same-origin' })
    .then(r => (r.ok ? r.text() : Promise.reject(new Error('sprite ' + r.status))))
    .then(svg => {
      const box = document.createElement('div');
      box.id = 'icon-sprite';
      box.hidden = true;
      box.setAttribute('aria-hidden', 'true');
      box.innerHTML = svg;
      (document.body || document.documentElement).prepend(box);
      injected = true;
      return true;
    })
    .catch(() => false);      // sans sprite l'interface reste utilisable, sans pictogramme
  return pending;
}

/**
 * icon(nom, {size, label, cls, spin}) → chaîne HTML
 *   label absent  → décoratif, `aria-hidden` (le texte voisin porte le sens)
 *   label présent → `role="img"` + `aria-label` (icône seule, ex. bouton)
 */
export function icon(name, opts = {}) {
  const { size = 16, label = '', cls = '', spin = false } = opts;
  const classes = ['ic'];
  if (size === 20) classes.push('ic-20');
  else if (size === 14) classes.push('ic-14');
  if (spin) classes.push('ic-spin');
  if (cls) classes.push(cls);
  const a11y = label
    ? ` role="img" aria-label="${esc(label)}"`
    : ' aria-hidden="true" focusable="false"';
  return `<svg class="${classes.join(' ')}"${a11y}><use href="#i-${esc(name)}"></use></svg>`;
}

/** Même chose, en nœud DOM. */
export function iconEl(name, opts = {}) {
  const tpl = document.createElement('template');
  tpl.innerHTML = icon(name, opts);
  return tpl.content.firstElementChild;
}

/* Correspondance « verbe métier → icône », pour que deux écrans qui parlent de
   la même chose montrent le même pictogramme. */
export const ICON = {
  maj: 'arrow-up',
  rescan: 'refresh-cw',
  install: 'plus',
  viz: 'scan-eye',
  connect: 'link',
  check: 'check',
  safe: 'shield-check',
  bulk: 'list',
  collect: 'refresh-cw',
  cache: 'eraser',
  backup: 'download',
  action: 'diamond',
  ok: 'circle-check',
  warn: 'triangle-alert',
  err: 'circle-x',
  busy: 'loader-circle',
};
