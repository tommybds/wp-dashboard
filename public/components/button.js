/* Boutons : construction, états (focus / désactivé / chargement) et la
   confirmation à deux clics utilisée hors des boutons `data-act`. */

import { esc } from '../lib/dom.js';
import { icon } from '../lib/icons.js';

/**
 * bouton({label, kind, size, icon, iconLabel, title, attrs}) → chaîne HTML
 *   kind : '' (secondaire) | 'primary' | 'danger' | 'icon'
 * Une icône seule EXIGE `iconLabel` : rien d'illisible dans une barre.
 */
export function bouton({ label = '', kind = '', size = '', ic = '', iconLabel = '', title = '', attrs = '' } = {}) {
  const cls = ['btn', kind, size === 'sm' ? 'sm' : ''].filter(Boolean).join(' ');
  const pic = ic ? icon(ic, label ? {} : { label: iconLabel || title || label }) : '';
  return `<button type="button" class="${cls}"${title ? ` title="${esc(title)}"` : ''}`
    + `${!label && (iconLabel || title) ? ` aria-label="${esc(iconLabel || title)}"` : ''}`
    + `${attrs ? ' ' + attrs : ''}>${pic}${label ? esc(label) : ''}</button>`;
}

/* ---- état de chargement ---------------------------------------------------
   Écraser `textContent` détruisait l'icône du bouton et perdait son libellé
   d'origine. `setBusy` mémorise le contenu, `setIdle` le rend — ou le remplace
   quand le libellé doit changer (« Connecter » devient « Vérifier »). */
export function setBusy(btn, label) {
  if (!btn) return;
  if (btn.dataset.busyhtml === undefined) btn.dataset.busyhtml = btn.innerHTML;
  btn.disabled = true;
  btn.classList.add('is-busy');
  btn.innerHTML = icon('loader-circle', { spin: true, label: label || 'en cours' })
    + (label ? ' ' + esc(label) : '');
}

export function setIdle(btn, html) {
  if (!btn) return;
  btn.disabled = false;
  btn.classList.remove('is-busy');
  if (html !== null && html !== undefined) btn.innerHTML = html;
  else if (btn.dataset.busyhtml !== undefined) btn.innerHTML = btn.dataset.busyhtml;
  delete btn.dataset.busyhtml;
}

/* confirmation à 2 clics générique (hors boutons data-act) */
export function confirm2(btn, fn) {
  if (btn.dataset.confirm) {
    delete btn.dataset.confirm;
    btn.classList.remove('danger');
    btn.innerHTML = btn.dataset.label || btn.innerHTML;
    delete btn.dataset.label;
    fn();
    return;
  }
  btn.dataset.confirm = '1';
  btn.dataset.label = btn.innerHTML;
  btn.textContent = 'Confirmer ?';
  btn.classList.add('danger');
  setTimeout(() => {
    if (btn.dataset.confirm) {
      delete btn.dataset.confirm;
      btn.innerHTML = btn.dataset.label;
      delete btn.dataset.label;
      btn.classList.remove('danger');
    }
  }, 4000);
}
