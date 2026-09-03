/* Feuille basse — la couche de choix du mobile.

   Sur un téléphone, un menu flottant ancré à son bouton tombe hors de l'écran
   ou sous le clavier, et une barre d'actions collée en bas de liste n'a pas la
   place d'afficher douze boutons. La feuille répond aux deux : elle monte du
   bas, occupe la largeur, et ses boutons font toute la ligne.

   C'est une vraie couche modale : `role="dialog"` + `aria-modal`, le focus y
   est piégé (la boucle Tab vit dans components/confirm.js, qui connaît l'ordre
   des couches), Échap la ferme, le fond aussi, et le focus revient au bouton
   qui l'a ouverte. Elle se ferme enfin en la faisant GLISSER vers le bas — le
   geste attendu à cet endroit.

   Une seule feuille à la fois : elle est construite une fois puis re-remplie,
   comme `#askmodal`.

   Ce module n'importe PAS components/confirm.js : celui-ci importe déjà le menu
   d'actions, qui importe la feuille — le cycle serait complet. C'est app.js qui
   déclare `fermerFeuille` comme fermeture de la couche `sheetmodal`. */

import { h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';

/** Le mobile, tel que le CSS l'entend (une seule définition pour les deux). */
const MOBILE_Q = '(max-width: 720px)';
export function estMobile() {
  try { return window.matchMedia(MOBILE_Q).matches; } catch (e) { return false; }
}

let MODALE = null, BOITE = null, TITRE = null, CORPS = null;
let OUVREUR = null, ONCLOSE = null;

function construire() {
  if (MODALE) return MODALE;
  TITRE = h('h2', { class: 'sheet-t mt0', id: 'sheet-title' });
  CORPS = h('div', { class: 'sheet-b', id: 'sheet-body' });
  const poignee = h('div', { class: 'sheet-grip', 'aria-hidden': 'true' });
  const fermer = h('button', {
    type: 'button', class: 'btn icon sheet-x', id: 'sheet-close', 'aria-label': 'Fermer',
  }, iconEl('x'));
  fermer.onclick = () => fermerFeuille();
  BOITE = h('div', {
    class: 'box sheet-box', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'sheet-title',
  }, poignee, h('div', { class: 'sheet-h' }, TITRE, fermer), CORPS);
  MODALE = h('div', { class: 'modal sheet', id: 'sheetmodal' }, BOITE);
  MODALE.onclick = e => { if (e.target === MODALE) fermerFeuille(); };
  document.body.append(MODALE);
  brancherGlisser(poignee);
  return MODALE;
}

/* Glisser pour fermer : on suit le doigt, et on ne ferme qu'au-delà de 80 px
   (ou d'un geste franc). En deçà, la feuille revient en place — sinon un
   défilement un peu vif la refermerait par accident. */
function brancherGlisser(poignee) {
  let y0 = null, dy = 0, t0 = 0;
  const debut = e => {
    const t = e.touches ? e.touches[0] : e;
    y0 = t.clientY; dy = 0; t0 = Date.now();
    BOITE.classList.add('drag');
  };
  const bouge = e => {
    if (y0 === null) return;
    const t = e.touches ? e.touches[0] : e;
    dy = Math.max(0, t.clientY - y0);
    BOITE.style.transform = 'translateY(' + dy + 'px)';
  };
  const fin = () => {
    if (y0 === null) return;
    const vite = dy > 30 && (Date.now() - t0) < 300;
    y0 = null;
    BOITE.classList.remove('drag');
    BOITE.style.transform = '';
    if (dy > 80 || vite) fermerFeuille();
  };
  poignee.addEventListener('touchstart', debut, { passive: true });
  poignee.addEventListener('touchmove', bouge, { passive: true });
  poignee.addEventListener('touchend', fin);
  poignee.addEventListener('touchcancel', fin);
  poignee.addEventListener('mousedown', e => { debut(e); e.preventDefault(); });
  window.addEventListener('mousemove', e => { if (y0 !== null) bouge(e); });
  window.addEventListener('mouseup', fin);
}

/** Une feuille est-elle ouverte ? (Échap la ferme avant les autres couches.) */
export function feuilleOuverte() { return !!(MODALE && MODALE.classList.contains('open')); }

export function fermerFeuille() {
  if (!MODALE || !feuilleOuverte()) return;
  MODALE.classList.remove('open');
  mount(CORPS);
  const fn = ONCLOSE; ONCLOSE = null;
  const o = OUVREUR; OUVREUR = null;
  if (o && o.isConnected && typeof o.focus === 'function') {
    try { o.focus(); } catch (e) { /* nœud remplacé entre-temps */ }
  }
  if (fn) try { fn(); } catch (e) { /* un onClose cassé ne bloque pas la fermeture */ }
}

/**
 * ouvrirFeuille({titre, contenu, onClose}) — `contenu` est un nœud, un tableau
 * de nœuds, ou une fonction qui les rend (appelée avec la fonction de
 * fermeture, pour un bouton qui referme après avoir agi).
 */
export function ouvrirFeuille({ titre = '', contenu = null, onClose = null } = {}) {
  construire();
  if (!feuilleOuverte()) OUVREUR = document.activeElement;
  ONCLOSE = onClose;
  TITRE.textContent = titre;
  mount(CORPS, typeof contenu === 'function' ? contenu(fermerFeuille) : contenu);
  MODALE.classList.add('open');
  const f = CORPS.querySelector('button,a[href],input,select,textarea')
    || document.getElementById('sheet-close');
  if (f && f.focus) f.focus();
  return MODALE;
}

/** Bouton pleine largeur d'une feuille : la forme par défaut de ses actions. */
export function boutonFeuille({ label, ic = '', kind = '', onSelect = null, disabled = false, raison = '', title = '' }) {
  const b = h('button', {
    type: 'button',
    class: 'btn sheet-a' + (kind ? ' ' + kind : ''),
    title: disabled ? (raison || 'action indisponible') : (title || null),
    'aria-disabled': disabled ? 'true' : null,
  }, ic ? iconEl(ic) : null, h('span', { class: 'sheet-al', text: label }),
    disabled && raison ? h('span', { class: 'sheet-ar muted small', text: raison }) : null);
  b.onclick = () => {
    if (disabled) return;
    fermerFeuille();
    if (onSelect) onSelect(b);
  };
  return b;
}
