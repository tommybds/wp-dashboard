/* Écran Aide — « comment marche ce dashboard ».

   Une page à ancres, comme Sécurité, Gestion et Réglages : un sommaire, puis
   une section par question qu'on se pose vraiment devant l'écran. Le texte est
   STATIQUE et vit ici, à côté du code qu'il décrit : quand un comportement
   change, c'est le même commit qui corrige son explication.

   Règle d'écriture : dire ce que fait le dashboard, pas ce qu'il pourrait
   faire. Les horaires sont ceux du cron livré (deploy/wp-dashboard.cron) ; la
   cadence de collecte, elle, se règle, et le texte renvoie au réglage. */

import { h, mount } from '../lib/dom.js';

let MONTE = false;

const ANCRES = [
  ['aide-demarrer', 'demarrer', 'Vue d’ensemble'],
  ['aide-maj', 'mises-a-jour', 'Mettre à jour'],
  ['aide-vizproof', 'vizproof', 'VizProof'],
  ['aide-sauvegardes', 'sauvegardes', 'Sauvegardes'],
  ['aide-alertes', 'alertes', 'Incidents et alertes'],
  ['aide-liaisons', 'liaisons', 'Liaisons'],
  ['aide-taches', 'taches', 'Tâches automatiques'],
  ['aide-glossaire', 'glossaire', 'Glossaire'],
];

/* Petits constructeurs : la page est faite de paragraphes et de listes, rien
   de plus. `b()` met en gras un terme défini dans la phrase. */
const p = (...c) => h('p', {}, ...c);
const b = t => h('b', { text: t });
const lien = (href, t) => h('a', { href, text: t });
const liste = (...items) => h('ul', {}, items.map(i => h('li', {}, ...(Array.isArray(i) ? i : [i]))));
const terme = (t, ...def) => [h('dt', { text: t }), h('dd', {}, ...def)];

function section(id, titre, ...corps) {
  return h('section', { class: 'section secsec aide', id },
    h('div', { class: 'sechead' }, h('h2', { text: titre })),
    ...corps);
}

function demarrer() {
  return section('aide-demarrer', 'Vue d’ensemble',
    p('Le dashboard ', b('inventorie'), ' chaque WordPress du parc (versions, extensions, thèmes, '
      + 'administrateurs, sauvegardes, PHP), croise cet inventaire avec les vulnérabilités connues, '
      + 'et affiche la disponibilité relevée par Uptime Kuma ou, à défaut, par sa propre sonde.'),
    p('Il ne modifie ', b('rien'), ' sans un clic : aucune mise à jour n’est lancée par le dashboard '
      + 'de lui-même. Les seules mises à jour qui se font seules sont celles que WordPress applique '
      + 'la nuit quand ses mises à jour automatiques sont activées (voir ',
      lien('#aide/mises-a-jour', 'Mettre à jour'), ').'),
    h('h3', { text: 'Les écrans' }),
    liste(
      [b('Parc'), ' — tous les sites, leur état, et la file de ce qui demande une action.'],
      [b('Incidents'), ' — la file complète : ce qui se règle maintenant, et ce qui est à planifier.'],
      [b('Sécurité'), ' — vulnérabilités, administrateurs inconnus, erreurs PHP, certificats, fichiers suspects.'],
      [b('Changements'), ' — chronologie de tout ce qui a bougé sur le parc, et la tendance.'],
      [b('Gestion'), ' — serveurs, installations suivies, moniteurs Kuma, préprods.'],
      [b('Réglages'), ' — cadence de collecte, alertes Telegram, VizProof, clés SSH, apparence.']),
    h('h3', { text: 'La page d’un site' }),
    p('Un clic sur un site ouvre sa page. L’en-tête porte l’action principale (la ',
      b('MAJ sûre'), ' s’il y a des mises à jour, sinon le re-scan) ; chaque autre geste est dans '
      + 'l’onglet qui en parle :'),
    liste(
      [b('Aperçu'), ' — ce qui est à traiter sur ce site, et sa fiche.'],
      [b('Extensions et thèmes'), ' — mises à jour une par une ou en lot, cœur WordPress, gel, retour à une version.'],
      [b('Sécurité'), ' — vulnérabilités, administrateurs, intégrité du cœur, erreurs PHP.'],
      [b('VizProof'), ' — contrôle visuel : liaison, pages surveillées, baseline, scan, dernier rapport.'],
      [b('Sauvegardes'), ' — UpdraftPlus, et les archives laissées par les MAJ sûres.'],
      [b('Historique'), ' — tout ce qui s’est passé sur ce site.'],
      [b('Réglages'), ' — mises à jour automatiques, agent Dash, identifiants WordPress, caches.']));
}

function maj() {
  return section('aide-maj', 'Mettre à jour',
    p('Trois façons de mettre à jour, de la plus prudente à la plus directe.'),
    h('h3', { text: 'MAJ sûre' }),
    p('Le bouton bleu de l’en-tête, ou « sûre » sur une ligne. Dans l’ordre : ',
      b('référence VizProof'), ' du rendu actuel, ', b('sauvegarde UpdraftPlus'), ', ',
      b('archive'), ' des fichiers qui vont changer et de la base, mise à jour ',
      b('sous maintenance'), ' (les visiteurs voient une page d’attente de quelques secondes), '
      + 'contrôle de santé, puis ', b('scan VizProof'), ' comparé à la référence. Si le site '
      + 'casse, le ', b('retour arrière'), ' est automatique. Comptez une à deux minutes.'),
    h('h3', { text: 'MAJ simple' }),
    p('Le bouton « MAJ » d’une ligne, ou « Tout mettre à jour ». Immédiat, ', b('sans sauvegarde ni archive'),
      ' : rien à rétablir si le site casse. Si le site est relié à VizProof, une référence est prise '
      + 'avant et un scan après — pour information, il n’annule rien.'),
    h('h3', { text: 'Mises à jour automatiques de WordPress' }),
    p('Activées dans l’onglet ', b('Réglages'), ' d’un site. WordPress applique alors lui-même les '
      + 'nouvelles versions, la nuit, sans passer par le dashboard. Si VizProof est relié, chaque '
      + 'mise à jour automatique est suivie d’un scan visuel ; sinon, aucun contrôle après coup.'),
    h('h3', { text: 'Geler, revenir en arrière' }),
    liste(
      [b('Geler'), ' une extension ou un thème : le dashboard ne le mettra plus jamais à jour, ni par '
        + 'un bouton, ni en lot, ni par la MAJ sûre. Utile quand une version casse le site.'],
      [b('Rétablir'), ' : onglet Sauvegardes (archive d’une MAJ sûre) ou bouton Rétablir d’une extension '
        + '(version publiée sur wordpress.org). Seuls les ', b('fichiers'), ' sont remplacés : si la mise '
        + 'à jour a migré la base, seule la sauvegarde UpdraftPlus la rétablit.']));
}

function vizproof() {
  return section('aide-vizproof', 'VizProof',
    p('Les autres volets disent ce que le site ', b('contient'), '. VizProof dit ce qu’un visiteur ',
      b('voit'), ' : une mise à jour peut réussir sans une ligne d’erreur et vider une page.'),
    liste(
      [b('Baseline'), ' — photo de référence de chaque page surveillée.'],
      [b('Scan'), ' — nouvelle photo, comparée à la baseline : ', b('ok'), ', ', b('à vérifier'),
        ' (écart visuel ou balises SEO changées) ou ', b('critique'), '.'],
      [b('Pages en erreur'), ' — une page qui répond 404 ou 500 est signalée en rouge (« HTTP 404 ») '
        + 'et ne devient jamais une référence : VizProof refuse de la promouvoir.'],
      [b('Relier un site'), ' — onglet VizProof du site : installer l’extension, relier, choisir les '
        + 'pages. Le jeton de compte se règle une fois dans ', lien('#reglages/vizproof', 'Réglages › VizProof'), '.']));
}

function sauvegardes() {
  return section('aide-sauvegardes', 'Sauvegardes',
    p('Le dashboard lit la configuration ', b('UpdraftPlus'), ' de chaque site et la date de sa dernière '
      + 'sauvegarde réussie. Au-delà du seuil (48 h par défaut, réglable dans ',
      lien('#reglages/incidents', 'Réglages › Règles d’incidents'), '), le site passe en incident et '
      + 'une alerte part.'),
    p('Politique commune du parc : base ', b('chaque jour'), ' (6 semaines), fichiers ', b('chaque semaine'),
      ' (6 semaines), puis un jeu par mois sur environ un an, envoyés sur la Storage Box.'),
    p('UpdraftPlus dépend du cron de WordPress, qui ne tourne que si le site reçoit des visites : '
      + 'un site suspendu ou jamais visité ', b('ne se sauvegarde plus'), '.'));
}

function alertes() {
  return section('aide-alertes', 'Incidents et alertes',
    h('h3', { text: 'La file d’incidents' }),
    liste(
      [b('À traiter'), ' — ce qui se règle maintenant, souvent en un clic : site injoignable, faille '
        + 'critique corrigeable, sauvegarde en retard, certificat qui expire, administrateur inconnu.'],
      [b('À planifier'), ' — les chantiers : PHP en fin de support, moniteur volontairement en pause…'],
      [b('Ne plus signaler…'), ' — acquitte un incident pour un temps ou pour de bon. Il revient s’il change.']),
    h('h3', { text: 'Telegram' }),
    liste(
      [b('Alertes immédiates'), ' — nouvel administrateur, intégrité du cœur, sauvegarde périmée, '
        + 'certificat, anomalie VizProof, collecte arrêtée. Choisies dans ',
        lien('#reglages/alertes', 'Réglages › Alertes'), '.'],
      [b('Bilan du matin'), ' (8 h) — les problèmes ', b('apparus'), ' depuis la veille, ceux qui sont ',
        b('réglés'), ', ce qui reste ouvert, et un résumé des changements. Les préprods tiennent en une '
        + 'ligne et n’envoient jamais de bilan à elles seules. Rien de neuf : pas de message.']));
}

function liaisons() {
  return section('aide-liaisons', 'Liaisons',
    liste(
      [b('Via SSH'), ' — le cas normal : le dashboard lit et agit directement sur le serveur (wp-cli).'],
      [b('Via REST'), ' — site sans accès SSH : c’est l’', b('agent Dash'), ' qui pousse l’inventaire. '
        + 'Les actions passent alors par les ', b('identifiants WordPress'), ' (un mot de passe '
        + 'd’application), et restent limitées : pas de mise à jour, ni de sauvegarde, ni de contrôle '
        + 'd’intégrité d’ici.'],
      [b('Agent Dash'), ' — petite extension (mu-plugin) qui prévient en temps réel : nouvel '
        + 'administrateur, activation d’extension. Sans lui, ces événements se voient à la collecte suivante.'],
      [b('Préprod'), ' — un sous-domaine dev., preprod., staging., test.… est reconnu tout seul ; '
        + 'le marquage se force dans ', lien('#gestion/installs', 'Gestion'), '. Une préprod a sa puce, '
        + 'et le bilan du matin la replie.']));
}

function taches() {
  return section('aide-taches', 'Tâches automatiques',
    p('Ce qui tourne tout seul sur le serveur du dashboard (heure de Paris) :'),
    liste(
      [b('Collecte'), ' de l’inventaire — toutes les 30 min par défaut, réglable dans ',
        lien('#reglages/collecte', 'Réglages › Collecte'), '.'],
      [b('Erreurs PHP'), ' — lecture des journaux des serveurs, toutes les 2 h.'],
      [b('Scan des fichiers'), ' — recherche de portes dérobées, chaque nuit à 3 h 20.'],
      [b('Vulnérabilités'), ' — mise à jour de la base publique et croisement, chaque jour à 6 h.'],
      [b('Bilan Telegram'), ' — chaque jour à 8 h.'],
      [b('Rotation des journaux'), ' — le dimanche à 4 h 30.']),
    p('Aucune de ces tâches ne modifie un site.'));
}

function glossaire() {
  return section('aide-glossaire', 'Glossaire',
    h('dl', {},
      terme('Baseline', 'Photo de référence VizProof d’une page, à laquelle les scans sont comparés.'),
      terme('Docroot', 'Répertoire d’un site sur le serveur. Un abonnement Plesk peut en contenir plusieurs, '
        + 'donc plusieurs WordPress ; ils s’ajoutent dans Gestion.'),
      terme('Gel', 'Interdiction faite au dashboard de mettre à jour une extension ou un thème précis.'),
      terme('Maintenance', 'Page d’attente que WordPress montre aux visiteurs pendant une mise à jour lancée '
        + 'par le dashboard. Elle est retirée à la fin, même en cas d’échec.'),
      terme('mu-plugin', 'Extension « must-use » : chargée d’office par WordPress, sans activation. '
        + 'L’agent Dash en est une.'),
      terme('Sonde', 'Contrôle de disponibilité fait par le dashboard lui-même, quand Kuma ne surveille pas le site.')));
}

export function loadAide() {
  if (MONTE) return;
  MONTE = true;
  mount('page-aide',
    h('nav', { class: 'anchors', 'aria-label': 'Sections de l’aide' },
      ANCRES.map(([, slug, lbl]) => h('a', { class: 'anchor', href: '#aide/' + slug }, h('span', { text: lbl })))),
    demarrer(), maj(), vizproof(), sauvegardes(), alertes(), liaisons(), taches(), glossaire());
}
