/* ---- infobulles : ouverture au CLIC ----
   Délégation sur le document : les pastilles « ? » sont souvent créées à la
   volée (tiroir, listes), un binding à l'initialisation les manquerait.

   La bulle vit dans <body> (position:fixed) : ancrée dans le tiroir elle
   passait sous les modales, et le défilement de `.dbody` la rognait. Elle est
   donc positionnée à la main, et refermée dès que la page bouge. */

import { activeAuClavier } from '../lib/dom.js';

let TIPEL = null, TIPFOR = null;

/** Une bulle est-elle ouverte ? (Échap la ferme avant tout le reste.) */
export function tipOuverte() { return !!TIPEL; }

export function fermerTips() {
  if (TIPEL) { TIPEL.remove(); TIPEL = null; }
  if (TIPFOR) { TIPFOR.classList.remove('open'); TIPFOR = null; }
}

function ouvrirTip(p) {
  fermerTips();
  const b = document.createElement('span');
  b.className = 'tipbox';
  b.setAttribute('role', 'tooltip');
  b.textContent = p.dataset.tip || '';
  document.body.appendChild(b);
  const r = p.getBoundingClientRect(), bw = b.offsetWidth, bh = b.offsetHeight;
  let left = r.left - 6;
  if (left + bw > window.innerWidth - 8) left = window.innerWidth - 8 - bw;
  if (left < 8) left = 8;
  let top = r.bottom + 7, haut = false;
  if (top + bh > window.innerHeight - 8 && r.top - 7 - bh > 8) { top = r.top - 7 - bh; haut = true; }
  b.style.left = left + 'px';
  b.style.top = top + 'px';
  b.style.setProperty('--tipx', Math.max(4, Math.min(bw - 14, r.left + r.width / 2 - left - 4.5)) + 'px');
  if (haut) b.classList.add('up');
  TIPEL = b;
  TIPFOR = p;
  p.classList.add('open');
}

/** Branche la délégation. Appelé une fois par app.js. */
export function initTips() {
  document.addEventListener('click', e => {
    const p = e.target.closest('[data-tip]');
    if (!p) { if (!e.target.closest('.tipbox')) fermerTips(); return; }
    e.stopPropagation();
    if (TIPFOR === p) { fermerTips(); return; }
    ouvrirTip(p);
  });
  document.addEventListener('keydown', e => {
    const p = e.target && e.target.closest && e.target.closest('[data-tip][tabindex]');
    if (!p) return;
    activeAuClavier(e, () => { if (TIPFOR === p) fermerTips(); else ouvrirTip(p); });
  });
  /* En position:fixed la bulle ne suit plus son ancre : on la referme. */
  window.addEventListener('scroll', () => { if (TIPEL) fermerTips(); }, true);
  window.addEventListener('resize', () => { if (TIPEL) fermerTips(); });
}
