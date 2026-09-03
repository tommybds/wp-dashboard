/* Modales génériques : elles remplacent `confirm()`, `alert()` et `prompt()`,
   qui ne savent ni styler, ni afficher du HTML, ni nommer leur bouton d'action.

   Une seule boîte (`#askmodal`) sert aux quatre usages. Elle porte
   `role="dialog"`, Échap la ferme, et le focus revient au bouton qui l'a
   ouverte : sans cela il repart en haut du document et la navigation clavier
   perd sa place.

   La gestion d'Échap vit aussi ici : elle ferme UNE chose, la plus haute —
   la bulle, sinon le menu déployé, sinon la modale du dessus. Les fermetures
   propres à chaque modale sont ENREGISTRÉES par leur écran (pas importées),
   pour que ce composant ne dépende d'aucun d'eux. */

import { esc } from '../lib/dom.js';
import { tipOuverte, fermerTips } from './tip.js';
import { menuOuvert, fermerMenus } from './actions-menu.js';

/* Ordre de fermeture : l'ordre du DOM ne dit pas laquelle est au-dessus (toutes
   les modales partagent z-index 20). Celles qui s'ouvrent PAR-DESSUS une autre
   viennent en tête. */
const MODALES = ['searchmodal', 'askmodal', 'vizmodal', 'rbmodal', 'addmodal',
  'bulkmodal', 'srvmodal', 'jsonmodal', 'logmodal'];

const CLOSERS = {};

/** registerModalCloser('vizmodal', closeViz) — appelé par l'écran propriétaire. */
export function registerModalCloser(id, fn) { CLOSERS[id] = fn; }

function fermerModale(m) {
  if (!m) return;
  const fn = CLOSERS[m.id];
  if (fn) { fn(); return; }
  m.classList.remove('open');
}

/** Branche Échap et le clic sur le fond. Appelé une fois par app.js. */
export function initModals() {
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (tipOuverte()) { fermerTips(); return; }
    if (menuOuvert()) { fermerMenus(); return; }
    const id = MODALES.find(x => { const m = document.getElementById(x); return m && m.classList.contains('open'); });
    if (id) fermerModale(document.getElementById(id));
  });
  document.getElementById('ask-cancel').onclick = askClose;
  document.getElementById('askmodal').onclick = e => {
    if (e.target.id === 'askmodal') document.getElementById('ask-cancel').click();
  };
  registerModalCloser('askmodal', () => document.getElementById('ask-cancel').click());
}

let ASKOPENER = null;

export function askClose() {
  document.getElementById('askmodal').classList.remove('open');
  // Le focus revient au bouton qui a ouvert la modale.
  const o = ASKOPENER;
  ASKOPENER = null;
  if (o && o.isConnected && typeof o.focus === 'function') { try { o.focus(); } catch (e) { /* nœud remplacé entre-temps */ } }
}

export function askOpen(titre, intro, corps, onOk, onCancel) {
  if (!document.getElementById('askmodal').classList.contains('open')) ASKOPENER = document.activeElement;
  document.getElementById('ask-title').textContent = titre;
  document.getElementById('ask-intro').innerHTML = intro || '';
  document.getElementById('ask-body').innerHTML = corps;
  const ok = document.getElementById('ask-ok'), an = document.getElementById('ask-cancel');
  const ok2 = ok.cloneNode(true), an2 = an.cloneNode(true);   // purge des handlers précédents
  ok.replaceWith(ok2); an.replaceWith(an2);
  ok2.textContent = 'Valider'; ok2.className = 'btn primary';   // état neutre : askConfirm le surcharge
  an2.textContent = 'Annuler'; an2.className = 'btn'; an2.hidden = false;
  ok2.onclick = () => { if (!onOk || onOk() !== false) askClose(); };
  an2.onclick = () => { askClose(); if (onCancel) onCancel(); };
  document.getElementById('askmodal').classList.add('open');
  const f = document.querySelector('#ask-body input,#ask-body select') || ok2;
  f.focus();
}

/** Confirmation : le bouton porte le VERBE de l'action, pas « OK ». */
export function askConfirm(msg, { titre = 'Confirmer', ok = 'Valider', danger = false } = {}) {
  return new Promise(res => {
    askOpen(titre, msg, '', () => res(true), () => res(false));
    const b = document.getElementById('ask-ok');
    b.textContent = ok;
    b.className = danger ? 'btn danger' : 'btn primary';
    b.focus();
  });
}

/** Message d'information : un seul bouton. */
export function askInfo(titre, msg) {
  return new Promise(res => {
    askOpen(titre, msg, '', () => res(true), () => res(true));
    const b = document.getElementById('ask-ok'), a = document.getElementById('ask-cancel');
    b.textContent = 'Fermer';
    a.hidden = true;
    b.focus();
  });
}

export function askText(titre, intro, defaut) {
  return new Promise(res => {
    askOpen(titre, intro, `<input class="inp w100" id="ask-input" value="${esc(defaut || '')}">`,
      () => {
        const v = (document.getElementById('ask-input').value || '').trim();
        if (!v) return false;
        res(v);
      },
      () => res(null));
    document.getElementById('ask-input').addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('ask-ok').click();
    });
  });
}

export function askChoice(titre, intro, options, defaut) {
  return new Promise(res => {
    if (!options.length) { res(null); return; }
    const opts = options.map(o => `<option value="${esc(o.value)}"${String(o.value) === String(defaut) ? ' selected' : ''}>${esc(o.label)}</option>`).join('');
    askOpen(titre, intro, `<select class="inp w100" id="ask-select">${opts}</select>`,
      () => res(document.getElementById('ask-select').value), () => res(null));
  });
}
