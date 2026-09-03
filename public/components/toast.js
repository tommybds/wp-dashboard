/* ---- barre de notifications : le seul endroit qui sait ce qui tourne ----
   Une action lancée depuis le tiroir n'avait de trace que dans la console du
   tiroir, une action groupée que dans sa modale : refermés, plus rien. Le
   registre ci-dessous survit à tout (il vit dans <body>, z-index 1000) et
   RÉSUME ces deux affichages — il ne les remplace pas.
   `start` renvoie l'identifiant à passer à `update`/`done`. Progression :
   un nombre entre 0 et 1 quand le serveur en fournit une (collecte, groupé,
   étapes de la MAJ sûre), `null` = animation indéterminée. */

import { duree } from '../lib/format.js';
import { icon, ICON } from '../lib/icons.js';

/* Ouvrir une ligne renvoie vers l'écran concerné. Les ouvreurs sont ENREGISTRÉS
   par les écrans plutôt qu'importés ici : la barre ne dépend d'aucun écran, et
   il n'y a pas de cycle d'import. */
const OUVREURS = { bulk: null, site: null };

/** setOuvreurs({bulk, site}) — appelé au démarrage par app.js. */
export function setOuvreurs(o) { Object.assign(OUVREURS, o || {}); }

export const NOTIF = (() => {
  const L = new Map();
  let seq = 0, horloge = null;

  /* Le conteneur se pose SOUS l'en-tête d'écran : posé à `top:0` il masquerait
     « Collecter ». La hauteur de l'en-tête change (il passe sur deux lignes en
     étroit), elle est donc mesurée, pas devinée. */
  function placer(el) {
    const h = document.querySelector('.shead');
    el.style.top = ((h ? h.offsetHeight : 0) + 8) + 'px';
  }
  function bac() {
    let el = document.getElementById('notifbar');
    if (!el) {
      el = document.createElement('div');
      el.id = 'notifbar';
      // Ce n'est pas une modale : pas de role dialog, pas de piège au clavier,
      // et Échap continue de fermer la bulle / la modale / le tiroir.
      el.setAttribute('aria-live', 'polite');
      el.setAttribute('aria-atomic', 'false');
      (document.body || document.documentElement).appendChild(el);
      window.addEventListener('resize', () => placer(el));
    }
    placer(el);
    return el;
  }
  function ouvrable(n) { return n.kind === 'bulk' || !!(n.site && n.site.domain); }
  function ouvrir(n) {
    try {
      if (n.kind === 'bulk') { if (OUVREURS.bulk) OUVREURS.bulk(); return; }
      if (n.site && n.site.domain && OUVREURS.site) OUVREURS.site(n.site.srv, n.site.domain);
    } catch (e) { /* un ouvreur cassé ne doit pas figer la barre */ }
  }
  function noeud(n) {
    const d = document.createElement('div');
    d.className = 'ntf';
    d.dataset.id = n.id;
    d.innerHTML = '<span class="ntf-ic"></span>'
      + '<div class="ntf-main"><div class="ntf-lbl"></div><div class="ntf-det" hidden></div>'
      + '<div class="bar wait"><div></div></div></div>'
      + '<span class="ntf-t"></span>'
      + `<button class="ntf-x" type="button" aria-label="Masquer cette notification">${icon('x')}</button>`;
    d.querySelector('.ntf-x').onclick = e => { e.stopPropagation(); retirer(n.id); };
    d.onclick = () => { if (ouvrable(n)) ouvrir(n); };
    return d;
  }
  function peindre(n) {
    const d = n.el;
    if (!d) return;
    d.className = 'ntf' + (n.fini ? ' ' + n.etat : '') + (ouvrable(n) ? ' clic' : '');
    const nom = n.fini
      ? (n.etat === 'ok' ? ICON.ok : n.etat === 'warn' ? ICON.warn : ICON.err)
      : (ICON[n.kind] || ICON.action);
    d.querySelector('.ntf-ic').innerHTML = icon(nom, { spin: !n.fini && n.kind === 'busy' });
    d.querySelector('.ntf-lbl').textContent = n.label;
    const det = d.querySelector('.ntf-det');
    det.textContent = n.detail || '';
    det.hidden = !n.detail;
    const bar = d.querySelector('.bar');
    bar.hidden = !!n.fini;
    bar.classList.toggle('wait', n.progress == null);
    bar.firstElementChild.style.width = n.progress == null ? '40%'
      : Math.round(100 * Math.max(0, Math.min(1, n.progress))) + '%';
    d.querySelector('.ntf-t').textContent = duree((n.fin || Date.now()) - n.debut);
  }
  function battre() {
    const encours = [...L.values()].some(n => !n.fini);
    if (encours && !horloge) horloge = setInterval(() => L.forEach(n => { if (!n.fini) peindre(n); }), 1000);
    if (!encours && horloge) { clearInterval(horloge); horloge = null; }
  }
  /* « Tout effacer » n'apparaît qu'au-delà de 3 lignes : en dessous, la croix de
     chaque ligne suffit et un bouton de plus n'est que du bruit. */
  function majEffacer() {
    const el = bac();
    let b = document.getElementById('notif-clear');
    if (L.size > 3) {
      if (!b) {
        b = document.createElement('button');
        b.id = 'notif-clear';
        b.className = 'btn sm';
        b.type = 'button';
        b.textContent = 'Tout effacer';
        b.onclick = () => [...L.keys()].forEach(retirer);
      }
      el.appendChild(b);
    } else if (b) b.remove();
  }
  function retirer(id) {
    const n = L.get(id);
    if (!n) return;
    if (n.timer) clearTimeout(n.timer);
    if (n.el && n.el.parentNode) n.el.remove();
    L.delete(id);
    majEffacer();
    battre();
  }
  function start(o) {
    o = o || {};
    const id = String(o.id || ('n' + (++seq)));
    retirer(id);                       // relance : une seule ligne par identifiant
    const n = {
      id, label: String(o.label || 'Action en cours'), site: o.site || null,
      kind: String(o.kind || 'action'), detail: String(o.detail || ''),
      progress: (o.progress == null ? null : +o.progress),
      debut: Date.now(), fin: null, fini: false, etat: '', timer: null, el: null,
    };
    n.el = noeud(n);
    const b = document.getElementById('notif-clear');
    if (b) bac().insertBefore(n.el, b); else bac().appendChild(n.el);
    L.set(id, n);
    peindre(n);
    majEffacer();
    battre();
    return id;
  }
  function update(id, o) {
    const n = L.get(id);
    if (!n || n.fini) return;
    o = o || {};
    if (o.label != null) n.label = String(o.label);
    if (o.detail != null) n.detail = String(o.detail);
    if ('progress' in o) n.progress = (o.progress == null ? null : +o.progress);
    peindre(n);
  }
  function done(id, o) {
    const n = L.get(id);
    if (!n || n.fini) return;           // un verdict, pas deux
    o = o || {};
    n.fini = true;
    n.fin = Date.now();
    // `warn` d'abord : une anomalie visuelle n'est PAS un échec (l'action a
    // abouti), et un `ok:false` accompagné de `warn` doit rester orange.
    n.etat = o.warn ? 'warn' : ((o.ok === false) ? 'err' : 'ok');
    if (o.label != null) n.label = String(o.label);
    n.detail = String(o.message || '').replace(/\s+/g, ' ').trim().slice(0, 180);
    peindre(n);
    battre();
    // Un succès s'efface seul ; un échec ou un avertissement attend la croix —
    // c'est précisément ce qu'il ne faut pas rater en changeant d'écran.
    if (n.etat === 'ok') n.timer = setTimeout(() => retirer(id), 8000);
  }
  return {
    start, update, done, remove: retirer,
    encours: id => { const n = L.get(id); return !!n && !n.fini; },
  };
})();
