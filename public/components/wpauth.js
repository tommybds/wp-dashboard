/* Autorisation WordPress (mot de passe d'application), en un clic.

   Le dashboard ne stocke jamais le mot de passe d'un administrateur : il ouvre
   le flux natif `wp-admin/authorize-application.php`, l'utilisateur approuve
   dans SON site, et WordPress renvoie un mot de passe d'application dédié,
   révocable depuis le profil.

   Ce module ne connaît aucun écran : il porte l'appel, le bandeau de retour et
   la lecture de l'état des identifiants. La MISE EN FORME de cet état vit là où
   elle s'affiche (ligne de la liste REST, bandeau de la page site), parce que
   les deux n'ont ni la même place ni les mêmes actions voisines. */

import { api } from '../lib/api.js';
import { esc as H } from '../lib/dom.js';
import { safeUrl } from '../lib/format.js';
import { loadFleet } from '../lib/state.js';
import { setBusy, setIdle } from './button.js';

/* Interrupteur global : il permet de masquer d'un coup tout le parcours
   d'autorisation si le backend correspondant venait à disparaître. */
export const WPAUTH_ENABLED = true;

export const WPAUTH_HELP = "Vous serez redirigé vers l'administration du site pour approuver la "
  + "connexion. WordPress crée alors un mot de passe d'application dédié, révocable à tout moment "
  + 'depuis le profil utilisateur.';

/** État des identifiants d'un site (null si la route est muette). */
export async function wpCredentials(domain) {
  if (!domain) return null;
  try {
    const j = await api('/api/mgmt/wp_credentials?domain=' + encodeURIComponent(domain));
    return (j && typeof j === 'object' && !j.error) ? j : null;
  } catch (e) { return null; }
}

/**
 * Ouvre le flux natif d'autorisation dans un onglet.
 * `after(ok, erreur)` rend la main à l'appelant pour son message d'écran.
 */
export async function wpAuthorize(btn, server, domain, after) {
  const lbl = btn ? btn.innerHTML : '';
  setBusy(btn);
  let j = null;
  try { j = await api('/api/mgmt/wp_authorize', { server: server || '', domain }); }
  catch (e) { j = { error: String(e) }; }
  setIdle(btn, lbl);
  const u = safeUrl(j && j.authorize_url);
  if (!u) {
    if (after) after(false, (j && j.error) || "aucune URL d'autorisation renvoyée");
    return false;
  }
  window.open(u, '_blank', 'noopener');
  if (after) after(true, '');
  return true;
}

/* ---- bandeau de retour : /?wpauth=ok|refuse|expired|invalid|error&domain=… */
const RETOURS = {
  ok: ['ok', 'autorisé', 'Site autorisé — le dashboard peut désormais installer des extensions sur '],
  refuse: ['warn', 'refusé', "Autorisation refusée sur le site : la connexion n'a pas été approuvée dans wp-admin."],
  expired: ['warn', 'expiré', "Lien d'autorisation expiré, relancez la connexion depuis le dashboard."],
  invalid: ['err', 'erreur', "L'autorisation n'a pas pu être validée. Relancez la connexion depuis la page du site."],
  error: ['err', 'erreur', "L'autorisation a échoué. Vérifiez que le site est joignable, puis relancez la connexion."],
};

let WPAUTHTO = null;

export function wpauthBanner() {
  let p;
  try { p = new URLSearchParams(location.search); } catch (e) { return; }
  const stt = p.get('wpauth');
  if (!stt) return;
  const dom = p.get('domain') || '';
  const [cls, tag, txt] = RETOURS[stt] || RETOURS.error;
  const box = document.getElementById('wpauthbox'), msg = document.getElementById('wpauth-msg');
  if (!box || !msg) return;
  msg.innerHTML = `<span class="chip ${cls}"><span class="pt"></span>${H(tag)}</span> `
    + H(txt) + (stt === 'ok' ? (dom ? '<b>' + H(dom) + '</b>.' : 'ce site.') : '');
  box.hidden = false;
  try { history.replaceState(null, '', location.pathname + location.hash); }
  catch (e) { /* historique verrouillé */ }
  loadFleet();
  if (WPAUTHTO) clearTimeout(WPAUTHTO);
  WPAUTHTO = setTimeout(() => { box.hidden = true; WPAUTHTO = null; }, 6000);
}
