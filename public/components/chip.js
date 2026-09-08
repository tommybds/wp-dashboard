/* Chip d'état : point + libellé, quatre niveaux et un seul vocabulaire.

   ok       rien à faire                    (vert, réservé à cet état)
   warn     action recommandée, sans urgence
   err      action requise
   mut      inconnu — donnée absente ou périmée (gris, jamais vert par défaut)

   Deux formes de rendu, parce que les écrans de la phase 1 composent encore
   des chaînes : `chip()` rend du HTML, `chipEl()` rend un nœud. */

import { esc } from '../lib/dom.js';

const NIVEAUX = ['ok', 'warn', 'err', 'mut'];

/** Normalise un niveau reçu d'ailleurs (jamais de classe CSS inventée). */
function niveau(n) { return NIVEAUX.includes(n) ? n : 'mut'; }

/**
 * chip(libellé, niveau, {point, title, tip}) → chaîne HTML
 * `point` (défaut vrai) affiche la pastille : la couleur seule ne suffit pas.
 */
export function chip(label, level = 'mut', opts = {}) {
  const { point = true, title = '', tip = '' } = opts;
  const attrs = [`class="chip ${niveau(level)}"`];
  if (title) attrs.push(`title="${esc(title)}"`);
  if (tip) attrs.push(`data-tip="${esc(tip)}" role="button" tabindex="0"`);
  return `<span ${attrs.join(' ')}>${point ? '<span class="pt"></span>' : ''}${esc(label)}</span>`;
}

/** Même chose, en nœud DOM. */
export function chipEl(label, level = 'mut', opts = {}) {
  const tpl = document.createElement('template');
  tpl.innerHTML = chip(label, level, opts);
  return tpl.content.firstElementChild;
}

/* La disponibilité d'un site — libellé, niveau, provenance — n'est PLUS décidée
   ici : elle dépend de la présence d'Uptime Kuma et de la sonde du dashboard,
   deux choses qu'un composant de présentation n'a pas à connaître. La règle
   vit dans `etatSite()` (lib/state.js) ; ce qui suit ne fait que la rendre.

   L'infobulle porte la SOURCE (« d'après Uptime Kuma », « sonde du dashboard,
   il y a 12 min ») : discrète, mais jamais absente — un « en ligne » dont on ne
   sait pas qui l'a mesuré ne vaut pas grand-chose. */
export function chipEtat(e, opts = {}) {
  return chipEl(e.txt, e.niv, { tip: e.tip, ...opts });
}
