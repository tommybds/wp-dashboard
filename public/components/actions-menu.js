/* Menu d'actions : un bouton, un panneau `role="menu"`, des groupes titrés.

   Il remplace les rangées de boutons du tiroir. Trois choses le distinguent
   d'un `<select>` : les actions sont groupées PAR INTENTION (mettre à jour,
   vérifier, sauvegarder, connecter), celles qui MODIFIENT le site portent un
   trait d'attention, et une action indisponible reste visible avec sa raison
   en infobulle — au lieu de disparaître sans explication.

   Accessibilité : `aria-haspopup="menu"` + `aria-expanded` sur le bouton,
   flèches haut/bas + Début/Fin dans le panneau, Échap ferme et rend le focus
   au bouton, un clic dehors ou une tabulation ferme aussi. Un seul menu
   ouvert à la fois dans le document.

   Sous 720 px, le même menu s'ouvre en FEUILLE BASSE : un panneau ancré à son
   bouton finit hors de l'écran, et ses entrées n'y ont pas la hauteur tactile
   qu'il faut. Les entrées sont décrites une seule fois — seule leur enveloppe
   change. */

import { h } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { estMobile, ouvrirFeuille, fermerFeuille, feuilleOuverte } from './sheet.js';

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

/* Ligne d'ÉTAT en tête d'un groupe : elle ne se clique pas, elle dit où l'on
   en est. « Installer VizProof (grisé, extension déjà présente) » demandait de
   déduire l'état de la liste des actions indisponibles ; on le dit une fois,
   en toutes lettres, et la liste ne garde plus que ce qui a un sens.

   `role="presentation"` comme les titres de groupe : dans un `role="menu"`,
   tout ce qui n'est pas `menuitem` est ignoré du parcours au clavier, et c'est
   exactement ce qu'on veut d'une ligne qu'on ne peut pas activer. */
function etatEl(it) {
  return h('div', { class: 'menu-etat', role: 'presentation', title: it.title || null },
    it.ic ? iconEl(it.ic, { size: 14 }) : null,
    h('span', { class: 'menu-l' },
      h('b', { text: it.label }),
      it.detail ? [' ', h('span', { class: 'menu-d', text: it.detail })] : null));
}

/**
 * menuActions({label, ic, kind, groups, align}) → élément `.menu`
 *   groups : [{titre, items:[{label, ic, onSelect, disabled, raison,
 *                             attention, danger, title} | {etat:true, label, detail, ic}]}]
 * `attention` marque une action qui MODIFIE le site ; `etat` une ligne d'état.
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

  /* Les entrées sont décrites une fois et fabriquées à la demande : le panneau
     de bureau et la feuille du mobile en reçoivent chacun un jeu de nœuds, avec
     leur propre fonction de fermeture. */
  const entrees = quitter => {
    const out = [];
    groups.filter(g => g && (g.items || []).length).forEach((g, i) => {
      if (g.titre) out.push(h('div', { class: 'menu-g' + (i ? ' sep' : ''), role: 'presentation', text: g.titre }));
      g.items.forEach(it => out.push(it.etat ? etatEl(it) : itemEl(it, quitter)));
    });
    if (!out.length) {
      out.push(h('div', { class: 'menu-vide', role: 'presentation', text: 'aucune action disponible' }));
    }
    return out;
  };
  panneau.append(...entrees(fermerEtRendre));

  const items = () => [...panneau.querySelectorAll('.menu-i')];
  const bouger = (depuis, pas) => {
    const L = items();
    if (!L.length) return;
    const i = L.indexOf(depuis);
    const j = i < 0 ? (pas > 0 ? 0 : L.length - 1) : (i + pas + L.length) % L.length;
    L[j].focus();
  };

  /* Mobile : la même liste, dans une feuille qui monte du bas. `OUVERT` est
     renseigné comme pour le panneau, pour qu'Échap et le clic dehors ferment
     la bonne chose, dans le bon ordre. */
  const fermerMobile = () => {
    if (OUVERT === fermerMobile) OUVERT = null;
    if (feuilleOuverte()) fermerFeuille();
    btn.setAttribute('aria-expanded', 'false');
  };
  const ouvrirMobile = () => {
    if (OUVERT && OUVERT !== fermerMobile) fermerMenus();
    OUVERT = fermerMobile;
    btn.setAttribute('aria-expanded', 'true');
    ouvrirFeuille({
      titre: label,
      contenu: () => {
        const noeuds = entrees(fermerMobile);
        // Dans la feuille, les entrées sont atteignables par tabulation : il n'y
        // a pas de bouton parent qui leur passe le focus à la flèche.
        noeuds.forEach(n => { if (n.classList.contains('menu-i')) n.tabIndex = 0; });
        return h('div', { class: 'sheet-menu', role: 'menu', 'aria-label': label }, noeuds);
      },
      onClose: () => { if (OUVERT === fermerMobile) OUVERT = null; btn.setAttribute('aria-expanded', 'false'); },
    });
  };

  const ouvrir = () => {
    if (estMobile()) { ouvrirMobile(); return; }
    if (OUVERT && OUVERT !== fermer) fermerMenus();
    panneau.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    OUVERT = fermer;
    const L = items();
    if (L.length) L[0].focus();
  };
  const basculer = () => {
    if (estMobile()) { if (feuilleOuverte()) fermerMobile(); else ouvrirMobile(); return; }
    if (panneau.hidden) ouvrir(); else fermerEtRendre();
  };

  btn.onclick = e => { e.stopPropagation(); basculer(); };
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
