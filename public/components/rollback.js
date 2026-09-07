/* Rétablir une version antérieure d'une extension OU d'un thème.

   Deux sources, une seule modale (`#rbmodal`) :
     * l'archive locale laissée par une « MAJ sûre » — restitution à l'identique,
       y compris pour une extension premium ;
     * les versions publiées sur wordpress.org.

   Dans les deux cas seuls les FICHIERS sont remplacés : si le composant a migré
   ses tables, la base reste dans son nouvel état. C'est dit dans la modale.

   `type` vaut 'plugin' (défaut) ou 'theme'. Il ne change ni les routes ni le
   déroulé — le backend les sert toutes les deux — seulement le mot employé et
   la source d'archive consultée. Une seconde modale pour les thèmes aurait
   dupliqué les cinq écrans de ce fichier pour un seul mot de différence. */

import { api } from '../lib/api.js';
import { esc as H, h } from '../lib/dom.js';
import { stripPhpNoise } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { askInfo, registerModalCloser } from './confirm.js';

/* Points de restauration du site actuellement affiché, et l'identité de ce
   site : une archive appartient au site qui l'a produite. */
let RBPOINTS = [], RBSITE = { srv: '', dom: '' };

export function setRollbackPoints(points, srv, dom) {
  RBPOINTS = Array.isArray(points) ? points : [];
  RBSITE = { srv, dom };
}
export function rollbackPoints() { return RBPOINTS; }

/* Le mot employé dans la modale, et la clé sous laquelle un point de
   restauration liste ce qu'il contient. Une archive de « MAJ sûre » range les
   extensions sous `plugins` ; si elle range un jour les thèmes, ce sera sous
   `themes` — d'ici là, `archiveDe()` n'en trouve simplement aucune pour un
   thème, et seule la liste wordpress.org est proposée. */
const MOT = { plugin: 'extension', theme: 'thème' };
function mot(type) { return MOT[type] || MOT.plugin; }
function archiveDe(slug, type) {
  const cle = type === 'theme' ? 'themes' : 'plugins';
  return RBPOINTS.find(p => (p[cle] || []).includes(slug)) || null;
}

function closeRb() {
  document.getElementById('rbmodal').classList.remove('open');
  // Remise à zéro du pied : sans elle, une seconde ouverture hériterait de
  // l'état « Fermer » laissé par l'opération précédente.
  const pied = document.getElementById('rb-cancel');
  if (pied) { pied.textContent = 'Annuler'; pied.className = 'btn'; pied.disabled = false; pied.onclick = closeRb; }
  const g = document.getElementById('rb-go');
  if (g) g.remove();
}
document.getElementById('rb-cancel').onclick = closeRb;
document.getElementById('rbmodal').onclick = e => { if (e.target.id === 'rbmodal') closeRb(); };
registerModalCloser('rbmodal', closeRb);

/**
 * Liste des points de restauration, prête à être posée dans la page site.
 * `apres()` est appelé quand un rétablissement a réussi.
 */
export function pointsListeEl(cible, apres) {
  const box = h('div', { class: 'small' });
  RBPOINTS.forEach(pt => {
    const quand = pt.ts ? String(pt.ts).replace(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2}).*$/, '$3/$2 à $4h$5') : '';
    const ligne = h('div', { class: 'vulnrow' }, h('span', { class: 'muted small', text: quand }));
    (pt.plugins || []).forEach(sl => {
      const v = pt.versions && pt.versions[sl];
      const b = h('button', {
        type: 'button', class: 'btn sm',
        title: `Remettre ${sl} dans sa version d'avant cette mise à jour`,
      }, iconEl('rotate-ccw'), sl + (v ? ' → ' + v : ''));
      b.onclick = () => doRollback(sl, { dir: pt.dir }, cible, apres, 'plugin');
      ligne.append(b);
    });
    box.append(ligne);
  });
  return box;
}

async function doRollback(slug, src, cible, apres, type) {
  // Garde-fou : si la page a changé de site entre l'affichage de la liste et le
  // clic, on refuse plutôt que de restaurer les fichiers d'un site sur un autre.
  if (src.dir && (RBSITE.srv !== cible.srv || RBSITE.dom !== cible.dom)) {
    askInfo('Point de restauration périmé',
      `Cette archive appartient à <b>${H(RBSITE.dom || 'un autre site')}</b>, or la page ouverte est
       <b>${H(cible.dom || '—')}</b>. Rouvrez le site concerné pour la rétablir.`);
    return;
  }
  const quoi = src.dir ? "depuis l'archive locale, à l'identique" : `en version ${src.version}`;
  const intro = document.getElementById('rb-intro'), box = document.getElementById('rb-choices');
  const pied = document.getElementById('rb-cancel');
  intro.innerHTML = `Rétablir <b>${H(slug)}</b> ${H(quoi)} ?`;
  box.textContent = '';
  box.append(h('p', { class: 'hint mt2' }, iconEl('triangle-alert'),
    ' Seuls les ', h('b', { text: 'fichiers' }), ' sont remis en place. Si ' + (type === 'theme' ? 'le thème' : 'l’extension')
    + ' a migré ses tables, la base reste dans son nouvel état — vérifiez le site après l’opération.'));
  // Un seul bouton dans le pied, qui change de rôle selon l'étape : avoir
  // « Fermer » et « Annuler » côte à côte ne disait pas lequel faisait quoi.
  pied.textContent = 'Annuler'; pied.className = 'btn';
  const valider = h('button', { type: 'button', class: 'btn primary', id: 'rb-go', text: 'Rétablir' });
  pied.after(valider);
  valider.onclick = async () => {
    valider.remove();
    pied.disabled = true;
    box.innerHTML = '<div class="mt2"><span class="pill mut">opération en cours…</span></div>';
    let r;
    try { r = await api('/api/actions/plugin_rollback', Object.assign({ server: cible.srv, domain: cible.dom, slug, kind: type === 'theme' ? 'theme' : 'plugin' }, src)); }
    catch (e) { r = { ok: false, rc: '—', output: String(e) }; }
    intro.innerHTML = r.ok
      ? `<b>${H(slug)}</b> rétabli${type === 'theme' ? '' : 'e'}.`
      : `Échec du rétablissement de <b>${H(slug)}</b> (rc ${H(r.rc)}).`;
    const sortie = stripPhpNoise(r.output || '');
    box.innerHTML = `<div class="mt2"><span class="pill ${r.ok ? 'ok' : 'err'}">${r.ok ? 'réussi' : 'échec'}</span></div>`
      + (sortie ? `<pre class="tldet mt2">${H(sortie.slice(-800))}</pre>` : '');
    pied.disabled = false; pied.textContent = 'Fermer'; pied.className = 'btn primary';
    pied.onclick = () => {
      closeRb();
      if (r.ok && apres) apres();
    };
  };
  document.getElementById('rbmodal').classList.add('open');
}

/**
 * Choix d'une version : les versions se cliquent, il n'y a rien à saisir.
 * `type` : 'plugin' (défaut) ou 'theme'.
 */
export async function askVersion(slug, btn, cible, apres, type) {
  const t = type === 'theme' ? 'theme' : 'plugin';
  const m = mot(t);
  const lbl = btn.innerHTML;
  btn.disabled = true;
  btn.textContent = '…';
  let r;
  try {
    // `kind` est le mot du protocole, ici comme sur plugin_rollback et le
    // `kind` des vulnérabilités : la traduction se fait à la frontière.
    r = await api('/api/actions/plugin_versions?slug=' + encodeURIComponent(slug)
      + '&kind=' + encodeURIComponent(t));
  } catch (e) { r = null; }
  btn.disabled = false;
  btn.innerHTML = lbl;
  const vs = (r && r.versions) || [], actuelle = (r && r.current) || '';
  const arc = archiveDe(slug, t);
  const intro = document.getElementById('rb-intro'), box = document.getElementById('rb-choices');
  box.textContent = '';
  if (!vs.length && !arc) {
    intro.innerHTML = `Aucune version antérieure disponible pour <b>${H(slug)}</b> : aucune version `
      + `de ce${t === 'theme' ? ' thème' : 'tte extension'} n'est publiée sur wordpress.org `
      + `(${H(m)} premium) et aucune archive locale n'existe. Une archive est créée à chaque « MAJ sûre ».`;
  } else {
    intro.innerHTML = `Choisissez la version à remettre en place pour <b>${H(slug)}</b>.
      Seuls les <b>fichiers</b> sont remplacés — la base n'est pas touchée.`;
    if (arc) {
      box.append(h('div', { class: 'glbl glbl-sep', text: "Archive locale — restitution à l'identique" }));
      const b = h('button', { type: 'button', class: 'btn primary sm' }, iconEl('rotate-ccw'),
        (arc.versions && arc.versions[slug]) || 'version précédente');
      b.onclick = () => { closeRb(); doRollback(slug, { dir: arc.dir }, cible, apres, t); };
      box.append(h('div', { class: 'actions' }, b,
        h('span', { class: 'muted small', text: "telle qu'elle était avant la mise à jour" })));
    }
    if (vs.length) {
      box.append(h('div', { class: 'glbl glbl-sep', text: 'Versions publiées sur wordpress.org' }));
      const acts = h('div', { class: 'actions' });
      vs.slice(0, 24).forEach(v => {
        const b = h('button', { type: 'button', class: 'btn sm' }, v,
          v === actuelle ? h('span', { class: 'muted', text: '(actuelle)' }) : null);
        b.onclick = () => { closeRb(); doRollback(slug, { version: v }, cible, apres, t); };
        acts.append(b);
      });
      box.append(acts);
    }
  }
  document.getElementById('rbmodal').classList.add('open');
}
