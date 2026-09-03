/* Suivi d'une exécution groupée : la modale, la barre de progression et la
   ligne de notification qui lui correspond.

   Point d'entrée unique des trois lanceurs de job groupé (barre d'actions,
   « mettre à jour cette extension partout », checksums du parc) : ils
   partageaient déjà CURJOB / openBulkModal / pollBulk, ils partagent aussi la
   ligne de notification — sinon un seul des trois aurait été suivi. */

import { api } from '../lib/api.js';
import { esc as H } from '../lib/dom.js';
import { poll } from '../lib/poll.js';
import { store } from '../lib/state.js';
import { loadFleet } from '../lib/state.js';
import { NOTIF } from './toast.js';

let BMTITLE = 'Exécution en masse', LASTJOB = null;

/* Rafraîchissement de l'écran Sécurité après un job : enregistré par app.js
   plutôt qu'importé, pour ne pas lier ce composant à un écran. */
let SEC_REFRESH = null;
export function setSecRefresh(fn) { SEC_REFRESH = fn; }
function refreshSecIfActive() {
  try {
    if (SEC_REFRESH && document.getElementById('page-sec').classList.contains('active')) SEC_REFRESH(true);
  } catch (e) { /* écran absent : rien à rafraîchir */ }
}

export function openBulkModal(title) {
  BMTITLE = title || 'Exécution en masse';
  document.getElementById('bulkmodal').classList.add('open');
}

/* Rouvrir la modale depuis la barre de notifications, y compris après un
   « Fermer » : le job vit côté serveur, seul son identifiant avait été oublié. */
export function reouvrirBulk() {
  if (LASTJOB && !store.curjob) store.curjob = LASTJOB;
  openBulkModal(BMTITLE);
  if (store.curjob) pollBulk();
}

export function demarrerJob(job, titre, detail) {
  store.curjob = LASTJOB = job;
  NOTIF.start({ id: 'bulk', kind: 'bulk', progress: 0, label: titre, detail: detail || 'démarrage…' });
  openBulkModal(titre);
  pollBulk();
}

/** Branche les boutons de la modale. Appelé une fois par app.js. */
export function initJob() {
  document.getElementById('bm-close').onclick = () => {
    document.getElementById('bulkmodal').classList.remove('open');
    // Le sondage n'est PLUS arrêté ici : c'est lui qui alimente la barre de
    // notifications, et une action groupée qui continue côté serveur doit rester
    // visible après la fermeture de la modale. Il s'arrête tout seul à la fin du
    // job (`until`) et remet alors curjob à null.
    store.curjob = null;                 // sinon le rafraîchissement de fond ne repart jamais
    loadFleet();
    refreshSecIfActive();
  };
  document.getElementById('bm-cancel').onclick = () => {
    if (store.curjob) api('/api/actions/bulk_cancel', { job: store.curjob }).catch(() => {});
  };
}

/* verdict VizProof d'une tâche de masse (champ optionnel `viz`) */
export function vizTaskBadge(v) {
  if (v === null || v === undefined || v === '') return '';
  // « anomalies » est un avertissement, pas un échec : le rendu a changé, ce
  // qui n'est pas la même chose qu'un scan qui n'a pas pu tourner.
  const s = String(v);
  const m = { 'ok': ['ok', 'visuel OK'], 'anomalies': ['warn', 'anomalies visuelles'], 'échec': ['err', 'visuel échoué'], 'non configuré': ['mut', 'visuel non configuré'] }[s] || ['mut', s];
  return ` <span class="pill ${m[0]}" title="vérification visuelle VizProof">${H(m[1])}</span>`;
}

export function pollBulk() {
  if (!store.curjob) return;
  const job = store.curjob;
  poll('bulk', async () => {
    const j = await api('/api/actions/bulk_status?job=' + job);
    if (!j || j.error) {
      document.getElementById('bm-title').textContent = BMTITLE + ' — ' + ((j && j.error) || 'suivi indisponible');
      NOTIF.done('bulk', { ok: false, message: (j && j.error) || 'suivi indisponible' });
      return { fini: true, ko: true };
    }
    const tasks = Array.isArray(j.tasks) ? j.tasks : [], done = j.done || 0, total = j.total || 0;
    NOTIF.update('bulk', { progress: total ? done / total : 0, detail: done + '/' + total + (j.running ? ' — en cours' : '') });
    document.getElementById('bm-bar').style.width = (total ? Math.round(100 * done / total) : 0) + '%';
    document.getElementById('bm-title').textContent = `${BMTITLE} — ${done}/${total}` + (j.running ? ' (en cours)' : j.stopped ? ' (arrêtée sur erreur)' : ' (terminée)');
    document.getElementById('bm-list').innerHTML = tasks.map(t => {
      const c = t.status === 'ok' ? 'ok' : t.status === 'échec' ? 'err' : t.status === 'en cours' ? 'warn' : 'mut';
      return `<div class="logline"><span class="pill ${c}">${H(t.status)}</span> <b>${H(t.domain)}</b>${vizTaskBadge(t.viz)} ${t.backup ? `<span class="muted small">backup: ${H(t.backup)}</span>` : ''} ${t.output_tail ? `<br><code>${H(String(t.output_tail).slice(-180))}</code>` : ''}</div>`;
    }).join('') || '<span class="muted small">aucune tâche.</span>';
    if (!j.running) {
      // La remise à null est indispensable : le rafraîchissement de fond
      // (setInterval …if(!curjob) loadFleet()) restait sinon éteint à vie.
      store.curjob = null;
      loadFleet();
      refreshSecIfActive();
      const ko = tasks.filter(t => t.status === 'échec').length;
      const anom = tasks.filter(t => t.viz === 'anomalies').length;
      NOTIF.done('bulk', {
        ok: !ko, warn: !ko && !!anom,
        message: (ko ? ko + ' échec' + (ko > 1 ? 's' : '') + ' sur ' + total
          : done + '/' + total + ' terminée' + (done > 1 ? 's' : ''))
          + (anom ? ' · ' + anom + ' avec anomalies visuelles' : '')
          + (j.stopped ? ' · arrêtée sur erreur' : ''),
      });
    }
    return { fini: !j.running };
  }, { every: 2000, maxErrors: 5, until: r => !!(r && r.fini) });
}
