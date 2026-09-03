/* Une ligne d'incident dépliable — l'objet partagé par les trois endroits qui
   en montrent : la file « à traiter » du Parc et de la page site, l'écran
   Incidents, et les groupes d'erreurs PHP de Sécurité.

   Pourquoi ce composant existe : la ligne seule ne dit pas quoi faire. Un
   « Uncaught Error: Call to undefined method WP_Error::get_meth… » tronqué à
   78 caractères ne se lit pas, ne se copie pas, et ne dit ni d'où il part, ni
   qui l'a appelé. Le repli garde la liste courte ; l'ouverture donne le message
   entier, le fichier fautif, la fenêtre d'apparition, la pile d'appels quand le
   collecteur a pu la lire, un bouton pour tout copier, et une phrase qui dit
   par quoi commencer.

   Accessibilité : le pli est un vrai <button> (`aria-expanded`, `aria-controls`
   vers l'identifiant du panneau) — Entrée et Espace marchent sans qu'on ait à
   les simuler. Le reste de la ligne bascule aussi à la souris, sauf sur un lien
   ou un bouton, qui gardent leur propre action.

   L'état déplié n'est PAS mémorisé : un rechargement de la file rend des lignes
   repliées. Plusieurs incidents peuvent rester ouverts en même temps — comparer
   deux erreurs fatales est le cas normal, pas l'exception. */

import { h } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { relTime, absTime, dateCourte } from '../lib/format.js';
import { chipEl } from '../components/chip.js';

/* `kind` → ce que la ligne dit à un humain. Un type inconnu garde sa clé :
   mieux vaut un mot technique qu'une ligne muette. */
const KINDS = {
  down: 'site injoignable',
  php_fatal: 'erreur PHP fatale',
  vuln_critical_fixable: 'vulnérabilité critique corrigeable',
  checksums_modified: 'checksums modifiés',
  admin_unknown: 'administrateur inconnu',
  server_stale: 'serveur injoignable',
  backup_late: 'sauvegarde en retard',
  cert_expiring: 'certificat',
  php_eol: 'PHP en fin de support',
};

export const kindLabel = k => KINDS[k] || String(k || 'incident');

const FATALES = /^(Fatal error|Parse error)$/;

/* ---- d'où part l'erreur ----------------------------------------------------
   Le chemin du fichier est le premier indice du coupable : une extension et un
   fichier du cœur n'appellent pas la même réponse. */
function origine(fichier) {
  const s = String(fichier || '');
  const m = s.match(/wp-content\/(plugins|themes)\/([^/]+)/);
  if (m) return { type: m[1] === 'plugins' ? 'plugin' : 'theme', slug: m[2] };
  if (/(^|\/)(wp-includes|wp-admin)\//.test(s) || /\/wp-[a-z-]+\.php$/.test(s)) {
    return { type: 'core', slug: '' };
  }
  return { type: 'autre', slug: '' };
}

/* ---- « Que faire » ---------------------------------------------------------
   Deux à quatre phrases par type, orientées décision : par quoi commencer, et
   ce qu'il ne faut pas conclure trop vite. */
function queFaire(kind, d) {
  if (kind === 'php_fatal' || kind === 'php_warning') return queFairePhp(kind, d);
  return {
    down: "Le moniteur ne joint plus le site. Ouvrez-le d'abord dans un navigateur : "
      + "si la page s'affiche, c'est le moniteur qu'il faut regarder (certificat, "
      + "mot-clé attendu, redirection), pas le site. Sinon, allez voir le serveur — "
      + "service PHP arrêté, disque plein, base injoignable — avant de conclure à une attaque.",
    vuln_critical_fixable: "Une faille publiée touche la version installée, et le "
      + "correctif existe déjà : la mise à jour est le geste attendu, elle est proposée "
      + "sur cette ligne. Si le site est délicat (extension modifiée à la main, "
      + "personnalisations lourdes), passez par « MAJ sûre » depuis la page du site, "
      + "qui sauvegarde et sait revenir en arrière.",
    checksums_modified: "Des fichiers du cœur ne correspondent plus à la version "
      + "officielle de WordPress. C'est un signe classique de compromission, mais une "
      + "mise à jour interrompue donne exactement le même résultat : commencez par "
      + "regarder QUELS fichiers, ci-dessus. Réinstaller le cœur de la même version "
      + "remet les fichiers d'origine sans toucher au contenu.",
    admin_unknown: "Un compte administrateur ne figure pas dans la référence "
      + "enregistrée pour ce site. Ne le supprimez pas tout de suite : notez sa date "
      + "d'inscription, regardez ce qu'il a fait dans l'historique, puis retirez-lui ses "
      + "droits. S'il est légitime, mettez la référence à jour depuis Sécurité pour que "
      + "l'alerte cesse.",
    server_stale: "La dernière collecte n'a pas joint ce serveur : les chiffres de ses "
      + "sites datent de la collecte précédente et peuvent avoir changé. Vérifiez l'accès "
      + "SSH et l'état de la machine ; tant qu'elle ne répond pas, aucune alerte de ses "
      + "sites n'est fiable, y compris son silence.",
    backup_late: "La dernière sauvegarde dépasse le seuil. Lancez-en une depuis cette "
      + "ligne, puis cherchez pourquoi la planification n'a pas tourné : wp-cron affamé, "
      + "destination distante pleine ou refusée, ou sémaphore UpdraftPlus resté en place "
      + "après un échec — dans ce dernier cas rien ne démarre plus, et sans message.",
    cert_expiring: "Le certificat arrive à échéance. Un renouvellement automatique "
      + "échoue presque toujours pour une raison simple : redirection qui casse la "
      + "validation, DNS changé, tâche planifiée arrêtée. Renouvelez à la main si "
      + "l'échéance est proche, puis réparez le renouvellement automatique — sinon "
      + "l'alerte reviendra à l'identique.",
    php_eol: "Ces sites tournent sur une version de PHP qui ne reçoit plus de correctifs "
      + "de sécurité. Le changement se prépare : vérifier la compatibilité des extensions "
      + "et du thème, puis basculer site par site avec une sauvegarde fraîche. Commencez "
      + "par le site le moins exposé.",
  }[kind] || '';
}

function queFairePhp(kind, d) {
  const o = origine(d.file);
  if (kind === 'php_warning') {
    return "Un avertissement n'interrompt pas la page, mais il remplit les journaux et "
      + "finit par masquer les vraies erreurs. Il vient presque toujours d'une extension "
      + "ou d'un thème qui n'a pas suivi une évolution de PHP : une mise à jour le fait "
      + "disparaître. S'il persiste après mise à jour, c'est du code sur mesure à corriger.";
  }
  if (o.type === 'plugin') {
    return `L'extension « ${o.slug} » est en cause : le fichier fautif lui appartient. `
      + "Mettez-la à jour ; si l'erreur persiste, désactivez-la et vérifiez que la page "
      + "redevient normale avant de chercher plus loin.";
  }
  if (o.type === 'theme') {
    return `Le thème « ${o.slug} » est en cause : le fichier fautif lui appartient. `
      + "Mettez-le à jour ; s'il a été retouché à la main, comparez d'abord avec la "
      + "version d'origine — une mise à jour effacerait la retouche sans prévenir.";
  }
  if (o.type === 'core') {
    return "L'erreur part du cœur : c'est presque toujours une extension ou un thème qui "
      + "lui passe une valeur inattendue. Regardez la trace pour le premier fichier hors "
      + "wp-includes, c'est le suspect. Une mise à jour du cœur et des extensions corrige "
      + "la plupart de ces cas.";
  }
  return "Le fichier fautif n'est ni le cœur, ni une extension, ni un thème : c'est du "
    + "code propre à ce site. La trace dit qui l'appelle ; remontez jusqu'à ce qui a "
    + "changé récemment sur le site.";
}

/* ---- les champs de `extra` qui se lisent tels quels ------------------------
   `extra` est un dictionnaire libre, dont les clés dépendent du `kind` : on
   n'affiche que celles qu'on sait nommer, le reste étant déjà dit ailleurs
   (pile, compteur, fenêtre, fichier). Une clé inconnue est ignorée plutôt que
   montrée sous son nom technique. */
const EXTRA_LIB = {
  cve: 'CVE', slug: 'composant', from: 'version installée', to: 'correctif en',
  last_backup: 'dernière sauvegarde', age_h: 'âge (heures)', service: 'destination',
  days_left: 'jours restants', expires: 'expire le',
  msg: 'message du moniteur', error: 'erreur', last_attempt: 'dernière tentative',
  version: 'version', sites: 'sites', files: 'fichiers',
  login: 'compte', email: 'courriel', registered: 'inscrit le',
};

/* Ces valeurs-là sont des horodatages : les rendre telles quelles afficherait
   « 2026-09-09T00:00:00Z » au milieu d'une phrase française. */
const EXTRA_DATES = new Set(['last_backup', 'expires', 'registered', 'last_attempt', 'since']);

function extraEl(extra) {
  const lignes = [];
  for (const [k, lib] of Object.entries(EXTRA_LIB)) {
    const v = extra[k];
    if (v === null || v === undefined || v === '') continue;
    if (Array.isArray(v) && !v.length) continue;
    const txt = Array.isArray(v) ? v.join(', ')
      : (EXTRA_DATES.has(k) ? absTime(v) : String(v));
    lignes.push(h('div', { class: 'incp-x' },
      h('span', { class: 'incp-k', text: lib }), h('span', { text: txt })));
  }
  return lignes.length ? h('div', { class: 'incp-xs' }, lignes) : null;
}

/* ---- le panneau ------------------------------------------------------------ */
function locEl(fichier, ligne) {
  const s = String(fichier || '');
  const code = h('code', { class: 'incp-loc' });
  // La partie « wp-content/plugins/<slug> » est mise en évidence : c'est elle
  // qu'on lit en premier pour savoir à qui parler.
  const m = s.match(/^(.*wp-content\/(?:plugins|themes)\/)([^/]+)(.*)$/);
  if (m) code.append(m[1], h('b', { text: m[2] }), m[3]);
  else code.append(s);
  if (ligne) code.append(':' + ligne);
  return code;
}

function fenetreTexte(count, first, last) {
  const n = Number(count) || 0;
  if (!n) return '';
  const fois = n + ' fois';
  const a = dateCourte(first), b = dateCourte(last);
  if (a && b && a !== b) return `${fois} entre le ${a} et le ${b}`;
  if (b || a) return `${fois}, la dernière le ${b || a}`;
  return fois;
}

/** Copie dans le presse-papiers, avec le repli des navigateurs sans API. */
async function copier(texte, bt, dire) {
  let ok = false;
  try {
    await navigator.clipboard.writeText(texte);
    ok = true;
  } catch (e) {
    ok = copieDeSecours(texte);
  }
  bt.textContent = ok ? 'Copié' : 'Échec';
  dire.textContent = ok ? 'copié dans le presse-papiers' : 'copie impossible';
  setTimeout(() => { bt.textContent = 'Copier'; dire.textContent = ''; }, 2000);
}

function copieDeSecours(texte) {
  const ta = document.createElement('textarea');
  ta.value = texte;
  ta.setAttribute('readonly', '');
  ta.setAttribute('aria-hidden', 'true');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  document.body.append(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  ta.remove();
  return ok;
}

/**
 * Le contenu déplié, à partir d'un descripteur normalisé :
 *   { kind, message, file, line, count, first, last, trace, tronquee, extra }
 */
function panneau(d) {
  const trace = Array.isArray(d.trace) ? d.trace.filter(Boolean) : [];
  const fen = fenetreTexte(d.count, d.first, d.last);
  const aide = queFaire(d.kind, d);

  const bt = h('button', { type: 'button', class: 'btn sm', text: 'Copier' });
  const dire = h('span', { class: 'muted small', role: 'status', 'aria-live': 'polite' });
  bt.onclick = e => {
    e.stopPropagation();
    const bouts = [d.message];
    if (d.file) bouts.push(d.file + (d.line ? ':' + d.line : ''));
    if (trace.length) bouts.push('', 'Stack trace:', ...trace);
    copier(bouts.join('\n'), bt, dire);
  };

  return h('div', { class: 'incp' },
    h('p', { class: 'incp-msg', text: d.message || 'sans message' }),
    d.file ? h('div', { class: 'small mt1' }, locEl(d.file, d.line)) : null,
    fen ? h('div', { class: 'muted small mt1', text: fen }) : null,
    extraEl(d.extra && typeof d.extra === 'object' ? d.extra : {}),
    trace.length
      ? h('div', { class: 'mt2' },
        h('div', { class: 'muted small incp-t' }, 'Trace d’appel',
          d.tronquee ? h('span', { class: 'incp-cut', text: ' — tronquée par le journal' }) : null),
        h('pre', { class: 'incp-tr', text: trace.join('\n') }))
      : null,
    aide ? h('div', { class: 'incp-do' },
      h('b', { class: 'small', text: 'Que faire' }),
      h('p', { class: 'small', text: aide })) : null,
    h('div', { class: 'incp-b' }, bt, dire));
}

/* ---- l'ossature repliable -------------------------------------------------- */
let SEQ = 0;

function depliable(classe, resume, corps, libelle) {
  const id = 'incp-' + (++SEQ);
  corps.id = id;
  corps.hidden = true;
  const bt = h('button', {
    type: 'button', class: 'inc-x', 'aria-expanded': 'false', 'aria-controls': id,
    'aria-label': 'Détails — ' + String(libelle || 'incident'),
  }, h('span', { class: 'tlchev' }, iconEl('chevron-right', { size: 14 })));
  const bascule = () => {
    const ouvrir = corps.hidden;
    corps.hidden = !ouvrir;
    bt.setAttribute('aria-expanded', ouvrir ? 'true' : 'false');
  };
  bt.onclick = e => { e.stopPropagation(); bascule(); };
  const ligne = h('div', { class: classe }, bt, resume, corps);
  // Confort à la souris : la ligne entière bascule, sauf sur un lien, un bouton
  // ou le panneau lui-même (où l'on sélectionne du texte). Le clavier, lui,
  // passe par le vrai bouton ci-dessus : rien n'est simulé ici.
  ligne.onclick = e => { if (!e.target.closest('a,button,input,.incp')) bascule(); };
  return ligne;
}

/* ---- ancienneté ------------------------------------------------------------ */
function anciennete(inc) {
  if (inc.since) return relTime(inc.since).replace(/^il y a /, 'depuis ');
  const age = Number(inc.age_h) || 0;
  if (!age) return '';
  return age < 48 ? 'depuis ' + Math.round(age) + ' h' : 'depuis ' + Math.round(age / 24) + ' j';
}

/**
 * Une ligne de la file « à traiter », dépliable.
 *   siteEl   nœud qui nomme le site (lien ou gras), ou null
 *   chipKind pastille du type d'incident (écran Incidents seulement)
 *   actions  bloc `.inc-b` construit par l'écran — lui seul sait quoi lancer
 */
export function incidentEl(inc, { siteEl = null, chipKind = false, actions = null } = {}) {
  const quand = anciennete(inc);
  const x = (inc.extra && typeof inc.extra === 'object') ? inc.extra : {};
  const corps = panneau({
    kind: inc.kind, message: inc.detail || inc.title || '',
    file: String(x.file || ''), line: x.line || 0,
    count: x.count || 0, first: x.first || '', last: x.last || '',
    trace: x.trace, tronquee: !!x.trace_truncated, extra: x,
  });
  const resume = [
    h('div', { class: 'inc-m' },
      h('div', { class: 'inc-t' },
        chipKind ? chipEl(kindLabel(inc.kind), 'mut') : null,
        siteEl,
        h('span', { class: 'inc-h', text: inc.title || '' })),
      inc.detail ? h('div', { class: 'muted small inc-d', text: inc.detail }) : null),
    quand ? h('span', {
      class: 'muted small inc-a', title: inc.since ? absTime(inc.since) : '', text: quand,
    }) : null,
    actions,
  ];
  return depliable('inc ' + (inc.severity === 'critical' ? 'err' : 'warn'),
    resume, corps, inc.title || kindLabel(inc.kind));
}

/**
 * Un groupe d'erreurs PHP de la section Sécurité, dépliable — même panneau que
 * les incidents : le message tronqué de la liste n'était pas plus exploitable ici.
 */
export function erreurPhpEl(g, chips) {
  const fatale = FATALES.test(String(g.severity || ''));
  const ou = String(g.short || g.file || '');
  const corps = panneau({
    kind: fatale ? 'php_fatal' : 'php_warning', message: String(g.message || ''),
    file: ou, line: g.line || 0, count: g.count || 0,
    first: g.first || '', last: g.last || '',
    trace: g.trace, tronquee: !!g.trace_truncated, extra: {},
  });
  const resume = [
    h('div', { class: 'inc-m' },
      h('div', { class: 'inc-t' }, chips, h('span', { class: 'inc-h', text: g.message || '' })),
      ou ? h('div', { class: 'muted small inc-d' },
        h('code', { text: ou + ':' + (g.line ?? '?') }),
        g.last ? ' · dernière ' + relTime(g.last) : '') : null),
  ];
  return depliable('inc ' + (fatale ? 'err' : 'warn'), resume, corps, g.message || 'erreur PHP');
}
