/* Construction de DOM et échappement.
   `h()` remplace progressivement les chaînes HTML : les écrans repris tels
   quels en phase 1 continuent d'utiliser `esc()` (alias `H`) dans leurs
   gabarits, les composants neufs utilisent `h()`. */

/** Échappe les cinq caractères qui changent le sens d'un fragment HTML. */
export const esc = x => String(x ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Nom historique de `esc`, gardé pour les gabarits repris tels quels. */
export const H = esc;

/**
 * h(tag, attrs, ...children) → Element
 *   attrs : { class, id, text, html, dataset:{…}, aria-*, on* (fonction), … }
 *   children : Node | string | tableau | null (ignoré)
 * Une chaîne enfant devient un nœud texte : rien n'est jamais interprété.
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
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
 * Délégation d'évènement : le gestionnaire survit aux re-rendus du contenu,
 * contrairement à un `onclick` posé sur chaque nœud après chaque innerHTML.
 */
export function delegate(root, type, selector, fn) {
  const el = typeof root === 'string' ? document.getElementById(root) : root;
  if (!el) return () => {};
  const handler = ev => {
    const hit = ev.target.closest && ev.target.closest(selector);
    if (hit && el.contains(hit)) fn(ev, hit);
  };
  el.addEventListener(type, handler);
  return () => el.removeEventListener(type, handler);
}

/** Raccourci de lecture, pour ne pas répéter `document.getElementById`. */
export const byId = id => document.getElementById(id);

/* Entrée/Espace sur un élément rendu cliquable : un <div>/<tr>/<th> ne le fait
   pas tout seul, contrairement à un <button>. */
export function activeAuClavier(e, fn) {
  if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); fn(); }
}
