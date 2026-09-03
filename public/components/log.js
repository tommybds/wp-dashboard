/* Journal des actions — modale transversale.

   Elle reste une MODALE et non une destination : on la consulte en passant,
   depuis n'importe quel écran, pour vérifier ce qu'une action a répondu. La
   chronologie complète (changements, actions, évènements d'agents) vit, elle,
   dans l'écran Changements.

   Les pastilles suivent le langage d'état du reste de l'interface :
     rc 0                       → ok
     rc 2 sur une action viz_*  → avertissement (« anomalies » : l'action a
                                  tourné, c'est le RENDU du site qui a changé)
     tout le reste              → échec */

import { api } from '../lib/api.js';
import { h, mount } from '../lib/dom.js';
import { relTime, absTime } from '../lib/format.js';
import { chipEl } from './chip.js';

/** Verdict d'une ligne du journal : [libellé, niveau]. */
export function verdictAction(rc, action) {
  const n = Number(rc);
  if (n === 0) return ['OK', 'ok'];
  if (n === 2 && /^viz_/.test(String(action || ''))) return ['anomalies', 'warn'];
  return ['échec', 'err'];
}

function ligne(e) {
  const [lib, niv] = verdictAction(e.rc, e.action);
  const sortie = String(e.output_tail || '').slice(-240);
  return h('div', { class: 'logline' },
    h('div', { class: 'tltop' },
      h('b', { text: String(e.domain || '—') }),
      h('span', { class: 'muted', text: String(e.action || '') + (e.arg ? ' ' + e.arg : '') }),
      chipEl(lib, niv),
      h('span', {
        class: 'muted small tlwhen', title: absTime(e.ts),
        text: relTime(e.ts) + (e.duration_s !== undefined && e.duration_s !== null ? ' · ' + e.duration_s + ' s' : ''),
      })),
    e.source ? h('div', { class: 'muted small', text: 'source : ' + e.source }) : null,
    sortie ? h('code', { text: sortie }) : null);
}

export async function ouvrirJournal() {
  document.getElementById('logmodal').classList.add('open');
  mount('loglist', h('span', { class: 'muted small', text: 'chargement…' }));
  let j;
  try { j = await api('/api/actions/log'); }
  catch (e) {
    mount('loglist', chipEl('journal indisponible', 'err'), ' ',
      h('span', { class: 'muted small', text: String(e) }));
    return;
  }
  const log = Array.isArray(j && j.log) ? j.log : [];
  mount('loglist', log.length
    ? log.map(ligne)
    : h('span', { class: 'muted', text: 'Aucune action.' }));
}

/** Branche le bouton de la barre latérale et la fermeture au clic sur le fond. */
export function initJournal() {
  const b = document.getElementById('logbtn');
  if (b) b.onclick = ouvrirJournal;
  const m = document.getElementById('logmodal');
  if (m) {
    m.onclick = e => { if (e.target.id === 'logmodal') m.classList.remove('open'); };
  }
}
