/* Menu d'actions : un bouton, un panneau `role="menu"`, des groupes titrés.

   Il remplace les rangées de boutons du tiroir. Trois choses le distinguent
   d'un `<select>` : les actions sont groupées PAR INTENTION (mettre à jour,
   vérifier, sauvegarder, connecter), celles qui MODIFIENT le site portent un
   trait d'attention, et une action indisponible reste visible avec sa raison
   en infobulle — au lieu de disparaître sans explication.

   Accessibilité : `aria-haspopup="menu"` + `aria-expanded` sur le bouton,
   flèches haut/bas + Début/Fin dans le panneau, Échap ferme et rend le focus
   au bouton, un clic dehors ou une tabulation ferme aussi. Un seul menu
   ouvert à la fois dans le document. */

import { h } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';

/* Menu ouvert : sa fermeture est appelée par le suivant qui s'ouvre, par le
   clic hors du panneau et par Échap. */
let OUVERT = null;

export function fermerMenus() { if (OUVERT) OUVERT(); }

/** Un menu est-il déployé ? (Échap le ferme avant la modale et le reste.) */
export function menuOuvert() { return !!OUVERT; }

let BRANCHE = false;
function brancher() {
  if (BRANCHE) return;
  BRANCHE = true;
  document.addEventListener('click', e => {
    if (!OUVERT) return;
    if (e.target.closest && e.target.closest('.menu')) return;
    fermerMenus();
  });
}

/* Les entrées désactivées restent focusables : c'est là qu'on lit la raison.
   `aria-disabled` plutôt que `disabled` — un bouton `disabled` n'est ni
   atteignable au clavier ni survolable, donc son infobulle est inaccessible. */
function itemEl(it, fermer) {
  const dispo = !it.disabled;
  const el = h('button', {
    type: 'button',
    class: 'menu-i' + (it.danger ? ' danger' : '') + (it.attention ? ' attention' : ''),
    role: 'menuitem',
    tabindex: '-1',
    'aria-disabled': dispo ? null : 'true',
    'data-tip': dispo ? null : (it.raison || 'action indisponible'),
    title: dispo ? (it.title || null) : (it.raison || 'action indisponible'),
  },
    it.ic ? iconEl(it.ic) : h('span', { class: 'menu-ic' }),
    h('span', { class: 'menu-l', text: it.label }),
    it.attention ? h('span', { class: 'menu-mod', title: 'cette action modifie le site', text: 'modifie' }) : null);
  el.onclick = ev => {
    if (!dispo) { ev.preventDefault(); return; }   // l'infobulle s'ouvre, le menu reste
    fermer();
    if (it.onSelect) it.onSelect(el);
  };
  return el;
}

/**
 * menuActions({label, ic, kind, groups, align}) → élément `.menu`
 *   groups : [{titre, items:[{label, ic, onSelect, disabled, raison,
 *                             attention, danger, title}]}]
 * `attention` marque une action qui MODIFIE le site.
 */
export function menuActions({ label = 'Actions', ic = '', kind = '', groups = [], align = 'end', id = null } = {}) {
  brancher();
  const btn = h('button', {
    type: 'button', class: 'btn' + (kind ? ' ' + kind : ''),
    'aria-haspopup': 'menu', 'aria-expanded': 'false', id,
  }, ic ? iconEl(ic) : null, label, h('span', { class: 'caret' }, iconEl('chevron-right', { size: 14 })));

  const panneau = h('div', { class: 'menu-p' + (align === 'start' ? ' start' : ''), role: 'menu', hidden: true });

  const fermer = () => {
    if (panneau.hidden) return;
    panneau.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    if (OUVERT === fermer) OUVERT = null;
  };
  const fermerEtRendre = () => { const etait = !panneau.hidden; fermer(); if (etait) btn.focus(); };

  groups.filter(g => g && (g.items || []).length).forEach((g, i) => {
    if (g.titre) panneau.append(h('div', { class: 'menu-g' + (i ? ' sep' : ''), role: 'presentation', text: g.titre }));
    g.items.forEach(it => panneau.append(itemEl(it, fermerEtRendre)));
  });
  if (!panneau.children.length) {
    panneau.append(h('div', { class: 'menu-vide', role: 'presentation', text: 'aucune action disponible' }));
  }

  const items = () => [...panneau.querySelectorAll('.menu-i')];
  const bouger = (depuis, pas) => {
    const L = items();
    if (!L.length) return;
    const i = L.indexOf(depuis);
    const j = i < 0 ? (pas > 0 ? 0 : L.length - 1) : (i + pas + L.length) % L.length;
    L[j].focus();
  };

  const ouvrir = () => {
    if (OUVERT && OUVERT !== fermer) fermerMenus();
    panneau.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    OUVERT = fermer;
    const L = items();
    if (L.length) L[0].focus();
  };

  btn.onclick = e => { e.stopPropagation(); if (panneau.hidden) ouvrir(); else fermerEtRendre(); };
  btn.onkeydown = e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); if (panneau.hidden) ouvrir(); }
  };
  panneau.onkeydown = e => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); fermerEtRendre(); return; }
    if (e.key === 'Tab') { fermer(); return; }         // la tabulation sort du menu, sans le laisser ouvert
    if (e.key === 'ArrowDown') { e.preventDefault(); bouger(document.activeElement, 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); bouger(document.activeElement, -1); }
    else if (e.key === 'Home') { e.preventDefault(); const L = items(); if (L.length) L[0].focus(); }
    else if (e.key === 'End') { e.preventDefault(); const L = items(); if (L.length) L[L.length - 1].focus(); }
  };

  const box = h('div', { class: 'menu' }, btn, panneau);
  box.dataset.menu = '1';
  return box;
}
