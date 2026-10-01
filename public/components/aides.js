/* Textes d'aide des sections, repliés sur une ligne.

   Chaque section de Sécurité, Gestion et Réglages s'ouvrait sur deux à quatre
   lignes de documentation avant son contenu. Utile la première fois, du bruit
   ensuite : c'est le contenu qu'on vient voir. Le paragraphe d'aide d'une
   section (`.section > p.hint`) est donc replié sur sa première ligne, avec un
   bouton « lire la suite » qui le déplie — le texte reste dans la page, rien
   n'est caché aux lecteurs d'écran (le repli est purement visuel).

   Les écrans composent leurs sections après coup, et certains réécrivent le
   texte d'une aide (certificats selon que Kuma est branché) : un observateur
   traite chaque paragraphe dès qu'il a du texte. Un texte court (une ligne sur
   bureau) n'est pas replié : un bouton qui ne déplie rien serait un mensonge. */

import { h } from '../lib/dom.js';

const SEUIL = 150;      // caractères — au-delà, le texte passe à la ligne sur bureau

function traiter(p) {
  if (p.dataset.pli) return;
  // Un texte vide ou court n'est pas marqué : il peut être réécrit plus tard,
  // plus long (aide remplie après chargement).
  if ((p.textContent || '').trim().length < SEUIL) return;
  p.dataset.pli = '1';
  p.classList.add('aide-pliee');
  const b = h('button', { type: 'button', class: 'aide-plus', 'aria-expanded': 'false', text: 'lire la suite' });
  b.onclick = () => {
    const ouvrir = p.classList.contains('aide-pliee');
    p.classList.toggle('aide-pliee', !ouvrir);
    b.setAttribute('aria-expanded', ouvrir ? 'true' : 'false');
    b.textContent = ouvrir ? 'replier' : 'lire la suite';
  };
  p.after(b);
  // Le bouton ne se montre que si la ligne est VRAIMENT tronquée : un texte
  // qui tient sur la largeur n'a rien à déplier. La mesure est refaite quand
  // la largeur change — et quand la section, masquée au rendu, apparaît.
  const mesurer = () => {
    if (!p.classList.contains('aide-pliee')) return;
    b.hidden = p.clientWidth > 0 && p.scrollWidth <= p.clientWidth + 1;
  };
  if (window.ResizeObserver) new ResizeObserver(mesurer).observe(p);
  requestAnimationFrame(mesurer);
}

function balayer(racine) {
  (racine || document).querySelectorAll('.section > p.hint, .sec-corps > p.hint').forEach(traiter);
}

export function initAides() {
  const main = document.getElementById('main');
  if (!main) return;
  balayer(main);
  let prevu = false;
  new MutationObserver(() => {
    if (prevu) return;
    prevu = true;
    requestAnimationFrame(() => { prevu = false; balayer(main); });
  }).observe(main, { childList: true, subtree: true, characterData: true });
}
