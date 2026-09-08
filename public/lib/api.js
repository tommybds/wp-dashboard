/* Accès HTTP : session, en-tête X-Dash, redirection sur 401.

   Un seul point d'entrée pour tout le front. `X-Dash` est l'en-tête qui
   distingue un appel de l'application d'une navigation, côté serveur ; il n'est
   posé que sur les écritures, comme avant. */

/* Slug de la status page Uptime Kuma proxifiée par nginx.

   Ce n'est PLUS une constante exportée : le slug se règle dans les Réglages et
   arrive avec /api/mgmt/state (bloc `kuma`). Figé à la construction, il faisait
   interroger l'ancienne status page dès que la valeur changeait côté serveur.
   Celle qui suit n'est qu'un repli, le temps que /api/mgmt/state réponde. */
let SLUG_COURANT = 'parc-x7k2m9';

/** Slug de la status page à interroger (repli tant que l'état n'est pas lu). */
export function slugKuma() { return SLUG_COURANT; }

/** Enregistre le slug renvoyé par le serveur. Une valeur vide ne l'écrase pas. */
export function setSlugKuma(v) {
  const s = String(v || '').trim();
  if (s) SLUG_COURANT = s;
}

/**
 * api(url)        → GET
 * api(url, corps) → POST JSON
 * 401 (ou redirection vers la page de connexion) → retour à /login.html, et
 * l'erreur levée porte le message 'auth' : le filet de diagnostic l'ignore.
 */
export async function api(u, b) {
  const r = await fetch(u, {
    method: b ? 'POST' : 'GET',
    headers: b ? { 'Content-Type': 'application/json', 'X-Dash': '1' } : {},
    body: b ? JSON.stringify(b) : undefined,
  });
  if (r.status === 401 || (r.redirected && /login\.html/.test(r.url))) {
    location.href = '/login.html';
    throw new Error('auth');
  }
  return r.json();
}

/** Déconnexion : la session est invalidée côté serveur avant la redirection. */
export async function logout() {
  await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-Dash': '1' } });
  location.href = '/login.html';
}
