/* Sections REPLIABLES (accordéon) — Sécurité, Gestion, Réglages.

   Une page de six à neuf sections dépliées, chacune avec ses filtres, ses
   paragraphes et ses listes, ne se lit pas. Repliée, une section tient sur une
   ligne : son titre, et à droite un résumé (un compteur, un état) qui dit s'il
   faut l'ouvrir. Les gestes de la section (`tete`) n'apparaissent qu'ouverte.

   L'état ouvert est mémorisé par écran (une clé localStorage chacun). Une
   ancre (#reglages/alertes, lien d'un incident, cellule de matrice) ouvre sa
   section avant que le routeur n'y fasse défiler : app.js émet l'événement
   'ancre' avec l'id visé, chaque accordéon ouvre celles de son préfixe. */

import { h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';

/**
 * @param {string} cle      clé localStorage des sections ouvertes
 * @param {string} prefixe  préfixe des ids de section de l'écran ('sec-', 'mgmt-'…)
 * @param {string[]} [parDefaut]  sections ouvertes à la première visite
 */
export function accordeon(cle, prefixe, parDefaut = []) {
  let ouvertes;
  try {
    const brut = localStorage.getItem(cle);
    ouvertes = new Set(brut === null ? parDefaut : JSON.parse(brut));
  } catch (e) { ouvertes = new Set(parDefaut); }

  function basculer(id, ouvrir) {
    const sec = document.getElementById(id);
    if (!sec) return;
    const o = ouvrir === undefined ? !sec.classList.contains('ouvert') : !!ouvrir;
    sec.classList.toggle('ouvert', o);
    const corps = document.getElementById(id + '-corps');
    if (corps) corps.hidden = !o;
    const bt = sec.querySelector('.sec-pli');
    if (bt) bt.setAttribute('aria-expanded', o ? 'true' : 'false');
    if (o) ouvertes.add(id); else ouvertes.delete(id);
    try { localStorage.setItem(cle, JSON.stringify([...ouvertes])); } catch (e) { /* refusé */ }
  }

  document.addEventListener('ancre', e => {
    const id = String(e.detail || '');
    if (id.startsWith(prefixe) && document.getElementById(id)?.classList.contains('sec-pliable')) basculer(id, true);
  });

  /** Section repliable : `tete` = gestes visibles une fois ouverte (ou null). */
  function section(id, titre, tete, ...corps) {
    const ouvert = ouvertes.has(id);
    const bt = h('button', {
      type: 'button', class: 'sec-pli', 'aria-expanded': ouvert ? 'true' : 'false', 'aria-controls': id + '-corps',
    }, h('span', { class: 'tlchev' }, iconEl('chevron-right', { size: 14 })),
    h('span', { text: titre }), h('span', { class: 'sec-n', id: id + '-n' }));
    bt.onclick = () => basculer(id);
    return h('section', { class: 'section secsec sec-pliable' + (ouvert ? ' ouvert' : ''), id },
      h('div', { class: 'sechead' }, h('h2', { class: 'sec-titre' }, bt),
        tete ? h('span', { class: 'sec-tete' }, tete) : null),
      h('div', { class: 'sec-corps', id: id + '-corps', hidden: !ouvert }, ...corps));
  }

  /** Résumé d'une ligne affiché à côté du titre (compteur, état). */
  function resumer(id, ...contenu) {
    const n = document.getElementById(id + '-n');
    if (n) mount(n, ...contenu);
  }

  return { section, basculer, resumer };
}
