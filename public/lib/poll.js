/* ---- sondages : un seul endroit qui sait s'arrêter ----
   Chaque `setInterval(...api().catch(()=>null))` dispersé tournait
   indéfiniment quand le backend tombait : l'appel échouait, le garde
   `if(!st) return` rendait la main, et l'intervalle repartait — pour toujours.
   `poll` compte les échecs consécutifs, s'arrête sur `until()`, et se laisse
   arrêter de l'extérieur (fermeture d'une modale, du tiroir, d'un onglet). */

const POLLS = {};

/** Arrête le sondage portant ce nom, s'il tourne. */
export function stopPoll(nom) { const c = POLLS[nom]; if (c) c.stop(); }

/** Sondages en cours, pour diagnostic. */
export function activePolls() { return Object.keys(POLLS); }

/**
 * poll(nom, fn, {every, maxErrors, until, onStop}) → contrôleur {stopped, stop()}
 * Un seul sondage par nom : relancer remplace le précédent.
 */
export function poll(nom, fn, { every = 3000, maxErrors = 5, until = null, onStop = null } = {}) {
  stopPoll(nom);                       // un sondage par nom : jamais deux en parallèle
  let arrete = false, errs = 0, t = null;
  const ctl = {
    get stopped() { return arrete; },
    stop() {
      if (arrete) return;
      arrete = true;
      if (t) clearTimeout(t);
      t = null;
      if (POLLS[nom] === ctl) delete POLLS[nom];
      // `onStop` est appelé QUELLE QUE SOIT la raison (fin normale, abandon sur
      // erreurs, fermeture) : c'est là qu'on réactive un bouton « analyse… ».
      if (onStop) try { onStop(); } catch (e) { /* un onStop cassé n'empêche pas l'arrêt */ }
    },
  };
  POLLS[nom] = ctl;
  const tick = async () => {
    if (arrete) return;
    let r = null, ko = false;
    try { r = await fn(); errs = 0; }
    catch (e) { ko = true; if (++errs >= maxErrors) { ctl.stop(); return; } }
    if (arrete) return;
    if (!ko && until && until(r)) { ctl.stop(); return; }
    t = setTimeout(tick, every);
  };
  tick();
  return ctl;
}
