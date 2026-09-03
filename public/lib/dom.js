/* Construction de DOM et échappement.
   `h()` remplace progressivement les chaînes HTML : les écrans repris tels
   quels en phase 1 continuent d'utiliser `esc()` (alias `H`) dans leurs
   gabarits, les composants neufs utilisent `h()`. */

/** Échappe les cinq caractères qui changent le sens d'un fragment HTML. */
export const esc = x => String(x ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * h(tag, attrs, ...children) → Element
 *   attrs : { class, id, text, html, dataset:{…}, aria-*, on* (fonction), … }
 *   children : Node | string | tableau | null (ignoré)
 * Une chaîne enfant devient un nœud texte : rien n'est jamais interprété.
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  // Tout `<th>` du front est un en-tête de COLONNE, sans exception : la règle
  // est posée ici plutôt que répétée dans la vingtaine de tableaux des écrans,
  // où elle finirait oubliée dans l'un d'eux. Un appelant qui aurait besoin
  // d'autre chose passe `scope` explicitement.
  if (tag === 'th' && !(attrs && 'scope' in attrs)) el.setAttribute('scope', 'col');
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class' || k === 'className') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'html') el.innerHTML = v;          // appelé avec du HTML construit ici, jamais avec une donnée distante
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el[k.toLowerCase()] = v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
  add(el, children);
  return el;
}

function add(el, kids) {
  for (const c of kids) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) add(el, c);
    else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** Vide une cible (id ou élément) et y place le contenu donné. */
export function mount(target, ...children) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return null;
  el.textContent = '';
  add(el, children);
  return el;
}

/**
 * Zone de message d'un formulaire : « enregistré », « échec »…
 *
 * Elle est déclarée VIDE et en `role="status"` dès le rendu du formulaire : un
 * lecteur d'écran n'annonce le contenu d'une région vivante que si celle-ci
 * existait déjà avant que le texte n'y arrive. Créée au moment du verdict,
 * elle resterait muette — le résultat de l'action serait invisible pour qui
 * n'a pas les yeux sur le bouton.
 */
export function zoneMessage(id, cls = 'small', tag = 'span') {
  return h(tag, { class: cls, id, role: 'status', 'aria-live': 'polite' });
}

/** Marque (ou démarque) une zone en cours de chargement, pour les technologies d'assistance. */
export function occupe(cible, on) {
  const el = typeof cible === 'string' ? document.getElementById(cible) : cible;
  if (!el) return;
  if (on) el.setAttribute('aria-busy', 'true'); else el.removeAttribute('aria-busy');
}

/* Entrée/Espace sur un élément rendu cliquable : un <div>/<tr>/<th> ne le fait
   pas tout seul, contrairement à un <button>. */
export function activeAuClavier(e, fn) {
  if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); fn(); }
}
