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

import { api } from '../lib/api.js';
import { esc, h } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { relTime, absTime, dateCourte, tsMs } from '../lib/format.js';
import { chipEl } from '../components/chip.js';
import { askInfo, askOpen } from '../components/confirm.js';
import { NOTIF } from '../components/toast.js';

/* `kind` → ce que la ligne dit à un humain. Un type inconnu (backend plus
   récent que l'interface) se lit « autre » : sa clé technique (`type_inconnu`)
   n'apprenait rien à l'écran — elle reste dans l'infobulle de la chip. */
const KINDS = {
  down: 'site injoignable',
  php_fatal: 'erreur PHP fatale',
  // La gravité a sa propre pastille : le type ne la répète pas.
  vuln_critical_fixable: 'faille corrigeable',
  vuln_critical_unfixed: 'faille sans correctif',
  checksums_modified: 'checksums modifiés',
  admin_unknown: 'administrateur inconnu',
  server_stale: 'serveur injoignable',
  backup_late: 'sauvegarde en retard',
  cert_expiring: 'certificat',
  php_eol: 'PHP en fin de support',
  scan_suspect: 'fichier suspect',
  viz_auto_update: 'écart visuel après MAJ auto',
  viz_not_scanned: 'MAJ auto sans contrôle visuel',
  auto_update_noop: 'MAJ auto sans effet',
  auto_rollback: 'MAJ auto annulée',
  auto_update_blocked: 'MAJ auto en attente',
  auto_update_failed: 'MAJ auto non faite',
};

export const kindLabel = k => KINDS[k] || (k ? 'autre' : 'incident');

/* ---- le titre sans le nom du site ------------------------------------------
   Le serveur écrit des titres autonomes (« Sauvegarde en retard sur
   site-03.fr »), lisibles dans une alerte Telegram. Dans une ligne qui NOMME
   déjà le site juste avant, ou sur la page de ce site, le domaine se lisait
   deux fois. On le retire des tournures connues ; une tournure inconnue garde
   son titre entier plutôt que d'être mutilée. */
function echapRe(t) { return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function titreSansCible(titre, cible) {
  const brut = String(titre || ''), c = String(cible || '');
  if (!c || !brut.includes(c)) return brut;
  const e = echapRe(c);
  const t = brut
    .replace(new RegExp('^(Serveur|Site)\\s+' + e + '\\s+'), '$1 ')
    .replace(new RegExp('^' + e + '\\s*(?::|—|-)?\\s*'), '')
    .replace(new RegExp('\\s*(?:—|-|:)\\s*' + e + '$'), '')
    .replace(new RegExp('\\s+(?:sur|de|du site|pour)\\s+' + e + '(?=\\s|$)'), '')
    .trim();
  if (!t || t.includes(c)) return brut;
  return t.charAt(0).toUpperCase() + t.slice(1);
}

/* ---- une source de la file qui n'a pas répondu ----------------------------
   Elle se DIT — une file vide n'a pas le même sens si l'une de ses sources n'a
   pas répondu — mais en français : « certs : RuntimeError: docker exec:
   conteneur uptime-kuma absent » s'affichait tel quel. L'exception reste
   lisible dans la bulle « ? », pour qui doit la diagnostiquer. */
const SOURCES = {
  fleet: 'inventaire du parc', disponibilite: 'disponibilité des sites',
  php_errors: 'erreurs PHP', vulns: 'vulnérabilités', vulns_sans_correctif: 'vulnérabilités',
  checksums: 'intégrité du cœur', scan: 'scan des fichiers', admins: 'administrateurs',
  fleet_servers: 'serveurs', updraft: 'sauvegardes', viz_nuit: 'contrôle visuel de la nuit',
  certs: 'certificats', php_eol: 'versions de PHP', counters: 'compteurs', 'réseau': 'réseau',
};

function causeLisible(err) {
  const e = String(err || '');
  if (/uptime-kuma|kuma/i.test(e) && /absent|no such container|not running|introuvable/i.test(e)) {
    return 'Uptime Kuma ne répond pas (conteneur introuvable)';
  }
  if (/file indisponible/.test(e)) return 'le serveur du dashboard ne répond pas';
  if (/timed? ?out|timeout|délai/i.test(e)) return 'délai de réponse dépassé';
  if (/FileNotFoundError|No such file/i.test(e)) return 'fichier de données absent (analyse jamais lancée ?)';
  if (/JSONDecodeError|Expecting value/i.test(e)) return 'fichier de données illisible';
  if (/Permission denied|PermissionError/i.test(e)) return 'accès refusé au fichier de données';
  if (/ConnectionRefused|Connection refused/i.test(e)) return 'connexion refusée';
  return 'lecture impossible';
}

export function sourceIncompleteEl(e) {
  const src = String((e && e.source) || '');
  const brut = String((e && e.error) || '');
  return h('p', { class: 'hint hint-tight' },
    chipEl('source incomplète', 'warn'), ' ',
    h('span', { class: 'muted small', text: (SOURCES[src] || src || 'source inconnue') + ' : ' + causeLisible(brut) }),
    brut ? h('span', {
      class: 'info', role: 'button', tabindex: '0', 'data-tip': brut,
      'aria-label': 'Erreur technique', text: '?',
    }) : null);
}

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
      + "personnalisations lourdes), passez par « MAJ contrôlée » depuis la page du site, "
      + "qui sauvegarde et sait revenir en arrière.",
    vuln_critical_unfixed: "Une faille critique est publiée et AUCUNE version "
      + "corrigée n'existe : la mise à jour ne réglera rien. Trois issues, dans cet "
      + "ordre de préférence — désactiver le composant s'il n'est pas indispensable, "
      + "le remplacer par un équivalent maintenu, ou le garder en connaissance de "
      + "cause après avoir lu la faille (elle est souvent conditionnée à un rôle "
      + "précis, ou à une fonction que vous n'utilisez pas). Dans le doute, "
      + "désactiver coûte moins cher qu'une remise en état.",
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
    scan_suspect: "Un ou plusieurs fichiers APPARUS depuis la référence répondent à un "
      + "motif de porte dérobée. Ne les supprimez pas d'abord : regardez la date de "
      + "modification et le contenu cité ci-dessus, puis comparez avec ce qui s'est passé "
      + "ce jour-là (mise à jour d'extension, import, dépôt de fichier). Si c'est "
      + "légitime, acceptez-le dans la référence depuis Sécurité pour que l'alerte cesse ; "
      + "sinon, sortez le fichier du docroot avant d'effacer quoi que ce soit — c'est la "
      + "seule copie que vous aurez pour comprendre par où c'est entré.",
    cert_expiring: "Le certificat arrive à échéance. Un renouvellement automatique "
      + "échoue presque toujours pour une raison simple : redirection qui casse la "
      + "validation, DNS changé, tâche planifiée arrêtée. Renouvelez à la main si "
      + "l'échéance est proche, puis réparez le renouvellement automatique — sinon "
      + "l'alerte reviendra à l'identique.",
    auto_rollback: "La mise à jour de la nuit a cassé quelque chose (page en échec pour "
      + "VizProof, accueil en erreur, WordPress tombé) et le site a été remis dans son état "
      + "d'avant. Les versions refusées ne seront pas retentées : la mise à jour repartira "
      + "d'elle-même à la version suivante de l'éditeur. Regardez le rapport VizProof pour "
      + "comprendre ce qui cassait ; pour forcer cette version-là malgré tout, faites une "
      + "mise à jour contrôlée depuis la page du site. Le retour arrière remet les fichiers, "
      + "pas les données : une extension qui a migré ses tables peut demander une vérification.",
    auto_update_blocked: "Le site est en mise à jour automatique, mais le dernier rapport "
      + "VizProof montre des pages en échec. Mettre à jour par-dessus prendrait l'état cassé "
      + "comme nouvelle référence : la nuit attend. Ouvrez le rapport : si l'écart est voulu "
      + "(contenu modifié, carrousel), acceptez-le comme référence dans VizProof ; sinon, "
      + "réparez la page. Les mises à jour reprennent la nuit suivante.",
    auto_update_failed: "La mise à jour de la nuit s'est arrêtée avant de toucher au site : "
      + "site déjà en erreur au départ, référence VizProof impossible alors qu'elle est "
      + "exigée, ou erreur du dashboard. Rien n'a changé sur le site ; la cause est ci-dessus. "
      + "La nuit suivante retentera d'elle-même.",
    php_eol: "Ces sites tournent sur une version de PHP qui ne reçoit plus de correctifs "
      + "de sécurité. Le changement se prépare : vérifier la compatibilité des extensions "
      + "et du thème, puis basculer site par site avec une sauvegarde fraîche. Commencez "
      + "par le site le moins exposé.",
  }[kind] || '';
}

/* Familles calculées par le collecteur (phperrors.famille_bruit) : une fatale
   déclenchée de l'extérieur, qui ne dit rien de l'état du site. Le texte par
   défaut accusait « une extension ou un thème » — faux, et coûteux : on cherche
   un coupable qui n'existe pas. */
const PHP_BRUIT = {
  acces_direct:
    "Personne n'a cassé quoi que ce soit : un robot a demandé ce fichier PHP "
    + "DIRECTEMENT par son adresse (un fichier du cœur, un gabarit de thème), sans "
    + "passer par WordPress. Hors de son contexte, ABSPATH n'existe pas, aucune "
    + "fonction n'est chargée, et PHP s'arrête — la page publique, elle, n'a jamais "
    + "été touchée. Rien à corriger dans le site. Pour faire taire le bruit, refusez "
    + "l'accès direct à ces fichiers au niveau du serveur web (wp-includes/, "
    + "wp-admin/includes/ et les .php des thèmes n'ont aucune raison d'être appelés "
    + "depuis l'extérieur).",
  maj_en_cours:
    "Erreur passagère d'une mise à jour : WordPress remplace une extension fichier par "
    + "fichier, et une visite arrivée pendant ces quelques secondes a demandé un fichier "
    + "pas encore reposé. Une mise à jour de ce composant est journalisée au même moment, "
    + "et l'erreur ne s'est pas répétée. Rien à corriger ; vérifiez seulement que le site "
    + "s'affiche. Si le compteur grimpe aux relevés suivants, ce n'est plus passager : "
    + "la mise à jour a laissé l'extension incomplète, réinstallez-la.",
  rest_batch:
    "Un robot sonde la route REST /batch/v1. Le cœur lui renvoie une erreur, puis la "
    + "traite comme une requête — d'où la fatale. Elle vient de l'extérieur : le site "
    + "n'a rien à corriger. Si le volume gêne, fermez /wp-json/batch/v1 aux visiteurs "
    + "non connectés ; aucune extension courante n'en a besoin.",
};

function queFairePhp(kind, d) {
  const bruit = PHP_BRUIT[String((d.extra || {}).famille || '')];
  if (bruit) return bruit;
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
  chemin_complet: 'chemin complet', modifie_le: 'modifié le', taille: 'taille',
  proprietaire: 'propriétaire', extrait: 'extrait',
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
    // `files` arrive tantôt en liste de chemins (checksums), tantôt en liste
    // d'objets (scan structurel : chemin + règle + ligne). Sans ce cas, la
    // seconde forme s'affichait « [object Object] ».
    const txt = Array.isArray(v)
      ? v.map(x => (x && typeof x === 'object'
        ? String(x.path || '') + (x.line ? ':' + x.line : '')
        : String(x))).join(', ')
      : (EXTRA_DATES.has(k) ? absTime(v) : String(v));
    lignes.push(h('div', { class: 'incp-x' },
      h('span', { class: 'incp-k', text: lib }), h('span', { text: txt })));
  }
  return lignes.length ? h('div', { class: 'incp-xs' }, lignes) : null;
}

/* ---- acquitter une alerte ---------------------------------------------------
   Une file dont RIEN ne peut disparaître n'est plus lue : le PHP en fin de
   support, le moniteur en pause depuis dix jours et la sauvegarde d'un site
   abandonné y restaient indéfiniment, et finissaient par masquer les quatre
   lignes qui se règlent d'un clic.

   Trois gestes, une seule modale : deux veilles datées et un « jusqu'à ce que
   ça change » qui s'appuie sur l'empreinte calculée par le serveur — si la
   situation bouge (autre version vulnérable, autre fichier en erreur), l'alerte
   revient d'elle-même avec un bandeau qui le dit. */

/** Une ligne « à traiter » (le reste est « à planifier »). */
export const estNow = inc => !inc || inc.bucket !== 'plan';

const ACK_CHOIX = [
  ['7', '7 jours'],
  ['30', '30 jours'],
  ['ignore', 'jusqu’à ce que la situation change'],
];

/** « 3 sept. » — de quoi situer une décision, sans l'heure qui n'y apprend rien. */
function jourCourt(v) {
  const t = tsMs(v);
  return t === null ? '' : new Date(t).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' });
}

/** La modale de choix → {mode, days, reason} ou null si l'on renonce. */
function demanderAcquittement(inc) {
  return new Promise(res => {
    const opts = ACK_CHOIX.map(([v, lbl], i) =>
      `<label class="ackopt"><input type="radio" name="ackmode" value="${v}"`
      + `${i ? '' : ' checked'}> <span>${esc(lbl)}</span></label>`).join('');
    askOpen('Ne plus signaler cette alerte',
      esc(inc.title || kindLabel(inc.kind)),
      `<div class="ackopts" role="radiogroup" aria-label="Ne plus signaler pendant">${opts}</div>`
      + '<label class="small muted ackl" for="ack-reason">Raison (facultative)</label>'
      + '<input class="inp w100" id="ack-reason" maxlength="300" '
      + 'placeholder="ce que vous avez décidé, pour vous en souvenir">',
      () => {
        const coche = document.querySelector('#ask-body input[name="ackmode"]:checked');
        const v = coche ? coche.value : 'ignore';
        const raison = (document.getElementById('ack-reason').value || '').trim();
        res(v === 'ignore' ? { mode: 'ignore', reason: raison }
          : { mode: 'snooze', days: Number(v), reason: raison });
      },
      () => res(null));
    document.getElementById('ask-ok').textContent = 'Confirmer';
  });
}

/** Réactive une alerte acquittée → vrai si le serveur a bien repris la main. */
async function reactiverIncident(id) {
  let j = null;
  try { j = await api('/api/incidents/unack', { id }); } catch (e) { j = null; }
  if (!j || !j.ok) {
    askInfo('Réactivation impossible',
      esc((j && j.error) || "le serveur n'a pas répondu"));
    return false;
  }
  return true;
}

/**
 * Ouvre la modale, acquitte, annonce le résultat — et laisse l'écran redessiner.
 * `recharger()` est appelé après l'acquittement ET après une annulation :
 * l'écran seul sait ce qu'il doit relire.
 */
async function acquitterIncident(inc, recharger) {
  const choix = await demanderAcquittement(inc);
  if (!choix) return false;
  const corps = { id: inc.id, mode: choix.mode, reason: choix.reason };
  if (choix.days) corps.days = choix.days;
  let j = null;
  try { j = await api('/api/incidents/ack', corps); } catch (e) { j = null; }
  if (!j || !j.ok) {
    askInfo('Acquittement impossible',
      esc((j && j.error) || "le serveur n'a pas répondu"));
    return false;
  }
  if (recharger) recharger();
  NOTIF.toast({
    label: choix.mode === 'snooze'
      ? 'Alerte mise en veille (' + choix.days + ' jours)'
      : 'Alerte écartée jusqu’à ce que la situation change',
    detail: inc.title || '',
    action: 'Annuler',
    onAction: async () => {
      if (await reactiverIncident(inc.id) && recharger) recharger();
    },
  });
  return true;
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
function panneau(d, boutons) {
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
    h('div', { class: 'incp-b' }, bt, boutons || null, dire));
}

/* « Ne plus signaler… » et « Réactiver » : le geste qui vide la file. Ils vivent
   dans le PLI et non sur la ligne — écarter une alerte demande de l'avoir lue,
   et la ligne repliée porte déjà l'action qui la corrige. */
function boutonsAcquittement(inc, opts) {
  if (!opts.onAck) return null;
  if (opts.acquitte) {
    const b = h('button', { type: 'button', class: 'btn sm', text: 'Réactiver' });
    b.onclick = async e => {
      e.stopPropagation();
      b.disabled = true;
      const ok = await reactiverIncident(inc.id);
      b.disabled = false;
      if (ok) opts.onAck();
    };
    return b;
  }
  const b = h('button', { type: 'button', class: 'btn sm', text: 'Ne plus signaler…' });
  b.onclick = e => { e.stopPropagation(); acquitterIncident(inc, opts.onAck); };
  return b;
}

/* Bandeau discret d'une alerte REVENUE : elle avait été écartée, mais
   l'empreinte de la situation a changé depuis. Sans lui, on ne comprend pas
   pourquoi une ligne qu'on croyait rangée reparaît. */
function bandeauAck(inc) {
  const a = inc.acked;
  if (!a) return null;
  if (a.stale_fingerprint) {
    return h('div', { class: 'muted small inc-ack' },
      'écartée le ' + jourCourt(a.ts) + ' — la situation a changé depuis'
      + (a.reason ? ' · ' + a.reason : ''));
  }
  const quand = a.mode === 'snooze' && a.until
    ? 'en veille jusqu’au ' + jourCourt(a.until)
    : 'écartée le ' + jourCourt(a.ts);
  return h('div', { class: 'muted small inc-ack' },
    quand + (a.reason ? ' · ' + a.reason : '') + (a.by ? ' · ' + a.by : ''));
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
/* `since_min` : date posée à la création du suivi des premières apparitions —
   le problème existait déjà, depuis au moins ce moment-là. */
function anciennete(inc) {
  if (inc.since) return relTime(inc.since).replace(/^il y a /, inc.since_min ? 'depuis ≥ ' : 'depuis ');
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
export function incidentEl(inc, {
  siteEl = null, chipKind = false, actions = null, onAck = null, acquitte = false,
} = {}) {
  const quand = anciennete(inc);
  const x = (inc.extra && typeof inc.extra === 'object') ? inc.extra : {};
  const corps = panneau({
    kind: inc.kind, message: inc.detail || inc.title || '',
    file: String(x.file || ''), line: x.line || 0,
    count: x.count || 0, first: x.first || '', last: x.last || '',
    trace: x.trace, tronquee: !!x.trace_truncated, extra: x,
  }, boutonsAcquittement(inc, { onAck, acquitte }));
  // Le site (ou le serveur) est nommé avant le titre, ou c'est la page du site :
  // le titre n'a pas à le répéter. Sur l'écran Incidents, la chip de type dit
  // souvent déjà tout le titre (« sauvegarde en retard ») : on ne l'écrit
  // alors qu'une fois.
  let titre = titreSansCible(inc.title || '', inc.site || inc.server || '');
  const kl = kindLabel(inc.kind).toLowerCase(), tl = titre.toLowerCase();
  if (chipKind && tl && (tl === kl || kl.endsWith(tl))) titre = '';
  const resume = [
    h('div', { class: 'inc-m' },
      h('div', { class: 'inc-t' },
        chipKind ? chipEl(kindLabel(inc.kind), 'mut', { title: KINDS[inc.kind] ? '' : String(inc.kind || '') }) : null,
        siteEl,
        titre ? h('span', { class: 'inc-h', text: titre }) : null),
      inc.detail ? h('div', { class: 'muted small inc-d', text: inc.detail }) : null,
      bandeauAck(inc)),
    quand ? h('span', {
      class: 'muted small inc-a', title: inc.since ? absTime(inc.since) : '', text: quand,
    }) : null,
    actions,
  ];
  // Une ligne « à planifier » n'est pas une urgence : elle garde la même forme,
  // mais pas le trait rouge — sinon la section entière crie comme la file.
  const ton = inc.bucket === 'plan' ? 'plan' : (inc.severity === 'critical' ? 'err' : 'warn');
  return depliable('inc ' + ton, resume, corps, inc.title || kindLabel(inc.kind));
}

/**
 * Un incident en LIGNE DE TABLEAU (écran Incidents) → [ligne, ligne de détail].
 *
 * Mêmes données et même panneau que `incidentEl`, mais rangés en colonnes
 * (gravité · type · site · problème · depuis · actions) : la liste en texte
 * libre ne se parcourait pas du regard, et ses boutons tombaient à des
 * endroits différents selon la longueur de la ligne. Le détail est une
 * seconde ligne pleine largeur, ouverte par le chevron ou un clic sur la ligne.
 */
export function incidentLigneTableau(inc, {
  siteEl = null, actions = null, onAck = null, acquitte = false, nbCols = 7,
} = {}) {
  const x = (inc.extra && typeof inc.extra === 'object') ? inc.extra : {};
  const corps = panneau({
    kind: inc.kind, message: inc.detail || inc.title || '',
    file: String(x.file || ''), line: x.line || 0,
    count: x.count || 0, first: x.first || '', last: x.last || '',
    trace: x.trace, tronquee: !!x.trace_truncated, extra: x,
  }, boutonsAcquittement(inc, { onAck, acquitte }));
  const id = 'incp-' + (++SEQ);
  const detail = h('tr', { class: 'inc-detail', id, hidden: true },
    h('td', { colspan: String(nbCols) }, corps));

  const plan = inc.bucket === 'plan';
  const grave = inc.severity === 'critical';
  const gravite = acquitte ? chipEl('acquitté', 'mut')
    : plan ? chipEl(grave ? 'critique' : 'avertissement', 'mut')
      : chipEl(grave ? 'critique' : 'avertissement', grave ? 'err' : 'warn');

  // Le titre sans le site (il a sa colonne) ; s'il ne fait que redire le type,
  // c'est le détail qui devient la ligne principale.
  const kl = kindLabel(inc.kind);
  let titre = titreSansCible(inc.title || '', inc.site || inc.server || '');
  const tl = titre.toLowerCase();
  let sous = inc.detail || '';
  if (!tl || tl === kl.toLowerCase() || kl.toLowerCase().endsWith(tl)) { titre = sous; sous = ''; }
  // « gravityforms 2.10.2 · faille critique corrigeable » : la seconde moitié
  // redit le type et la gravité, déjà dans leurs colonnes.
  if (/^vuln_/.test(inc.kind || '') && titre.includes(' · ')) titre = titre.split(' · ')[0];

  const bt = h('button', {
    type: 'button', class: 'inc-x', 'aria-expanded': 'false', 'aria-controls': id,
    'aria-label': 'Détails — ' + String(inc.title || kl),
  }, h('span', { class: 'tlchev' }, iconEl('chevron-right', { size: 14 })));
  const bascule = () => {
    const ouvrir = detail.hidden;
    detail.hidden = !ouvrir;
    bt.setAttribute('aria-expanded', ouvrir ? 'true' : 'false');
    tr.classList.toggle('ouvert', ouvrir);
  };
  bt.onclick = e => { e.stopPropagation(); bascule(); };

  const quand = anciennete(inc).replace(/^depuis /, '');
  const tr = h('tr', { class: 'inc-row ' + (acquitte || plan ? 'plan' : grave ? 'err' : 'warn') },
    h('td', { class: 'inc-c-x' }, bt),
    h('td', { 'data-l': 'Gravité' }, gravite),
    h('td', { 'data-l': 'Type', class: 'inc-c-type' },
      h('span', { title: KINDS[inc.kind] ? '' : String(inc.kind || ''), text: kl })),
    h('td', { 'data-l': 'Site', class: 'inc-c-site' }, siteEl),
    h('td', { 'data-l': 'Problème', class: 'inc-c-pb' },
      h('div', { class: 'inc-pb', text: titre }),
      sous ? h('div', { class: 'muted small inc-d', text: sous }) : null,
      bandeauAck(inc)),
    h('td', { 'data-l': 'Depuis', class: 'muted small inc-c-quand',
      title: inc.since ? (inc.since_min ? 'déjà présent le ' : '') + absTime(inc.since) : '', text: quand }),
    h('td', { class: 'inc-c-act' }, actions));
  // La ligne entière bascule à la souris, sauf sur un lien ou un bouton.
  tr.onclick = e => { if (!e.target.closest('a,button,input')) bascule(); };
  return [tr, detail];
}

/**
 * Un fichier signalé par le scan structurel, dépliable — même panneau que les
 * incidents et les erreurs PHP.
 *
 * `regle` vient du serveur (scan_found.json → `rules`) et porte le POURQUOI :
 * sans lui, « chr_chain sur mpdf.php » ne se décide pas. La date de dernière
 * modification est mise en avant parce que c'est souvent elle qui tranche — un
 * fichier de plugin touché hors mise à jour n'a pas d'explication innocente.
 */
export function fichierSuspectEl(f, regle, chips) {
  const r = regle || {};
  const sev = String(f.sev || r.sev || '');
  const quand = f.mtime ? new Date(Number(f.mtime) * 1000).toISOString().slice(0, 16).replace('T', ' ') : '';
  const corps = panneau({
    kind: 'scan_suspect', message: r.why || r.label || String(f.rule || ''),
    file: String(f.short || f.path || ''), line: f.line || 0,
    count: 0, first: '', last: '',
    extra: {
      chemin_complet: f.path && f.path !== f.short ? f.path : '',
      modifie_le: quand, taille: f.size ? f.size + ' octets' : '',
      proprietaire: f.owner || '', extrait: f.excerpt || '',
    },
  });
  const resume = [
    h('div', { class: 'inc-m' },
      h('div', { class: 'inc-t' }, chips,
        h('span', { class: 'inc-h', text: r.label || String(f.rule || 'signalement') })),
      h('div', { class: 'muted small inc-d' },
        h('code', { text: String(f.short || f.path || '') + (f.line ? ':' + f.line : '') }),
        quand ? ' · modifié le ' + quand : '')),
  ];
  return depliable('inc ' + (sev === 'critical' ? 'err' : sev === 'low' ? 'plan' : 'warn'),
                   resume, corps, r.label || 'fichier suspect');
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
    trace: g.trace, tronquee: !!g.trace_truncated, extra: { famille: g.famille || '' },
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
