/* Accès HTTP : session, en-tête X-Dash, redirection sur 401.

   Un seul point d'entrée pour tout le front. `X-Dash` est l'en-tête qui
   distingue un appel de l'application d'une navigation, côté serveur ; il n'est
   posé que sur les écritures, comme avant. */

/** Slug de la status page Uptime Kuma proxifiée par nginx. */
export const SLUG = 'parc-x7k2m9';

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
