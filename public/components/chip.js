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

/* Niveau déduit de l'état Kuma, pour que les écrans ne le ré-inventent pas.
   1 en ligne · 0 down · 2 en attente · undefined pas de monitoring. */
export function niveauKuma(v) {
  if (v === 1) return 'ok';
  if (v === 0) return 'err';
  if (v === 2) return 'warn';
  return 'mut';
}

export function libelleKuma(v) {
  if (v === 1) return 'en ligne';
  if (v === 0) return 'down';
  if (v === 2) return 'en attente';
  return 'inconnu';
}
