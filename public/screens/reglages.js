/* Écran Réglages — « comment le dashboard se comporte ».

   Phase 4 : ce n'était qu'une modale, c'est maintenant UNE page à ancres, sur
   le modèle de Sécurité et de Gestion. Huit sections, chacune avec son bouton
   d'enregistrement et son message de résultat : rien ne s'enregistre à l'insu
   de l'utilisateur, et un échec ne se confond jamais avec un autre.

     1. Collecte             cadence du cron, dernier relevé, collecte manuelle
     2. Alertes Telegram     jeton, chat, interrupteur général, déclencheurs
     3. VizProof             jeton de compte, base API
     4. Contrôle visuel      les quatre cases qui pilotent les mises à jour
     5. Règles d'incidents   seuils de la file « à traiter »
     6. Clés SSH             liste, génération, affectation, test
     7. Apparence            thème, densité des tableaux
     8. Session              qui est connecté, déconnexion

   Les SECRETS (jeton Telegram, jeton VizProof) ne sont jamais réinjectés dans
   un champ : l'API n'en renvoie qu'un témoin et les derniers caractères. Un
   champ laissé vide veut dire « inchangé » ; effacer est un geste explicite. */

import { api, logout } from '../lib/api.js';
import { esc as H, h, mount } from '../lib/dom.js';
import { relTime, absTime } from '../lib/format.js';
import { iconEl } from '../lib/icons.js';
import { store } from '../lib/state.js';
import { askConfirm } from '../components/confirm.js';
import { setBusy, setIdle } from '../components/button.js';
import { chipEl } from '../components/chip.js';
import { setDensity } from '../components/table.js';
import { loadSched, applyTheme, themeCourant } from '../components/shell.js';

/* ---- état du module -------------------------------------------------------- */
let MONTE = false;
let KEYS = null;
let SETTINGSLU = false;

const ANCRES = [
  ['set-collecte', 'collecte', 'Collecte'],
  ['set-alertes', 'alertes', 'Alertes'],
  ['set-vizproof', 'vizproof', 'VizProof'],
  ['set-visuel', 'controle-visuel', 'Contrôle visuel'],
  ['set-incidents', 'incidents', 'Règles d’incidents'],
  ['set-cles', 'cles-ssh', 'Clés SSH'],
  ['set-apparence', 'apparence', 'Apparence'],
  ['set-session', 'session', 'Session'],
];

/* Message de résultat d'une section : il s'efface tout seul quand il est
   positif, reste quand il ne l'est pas — une erreur qui disparaît est une
   erreur qu'on n'a pas lue. */
function dire(id, niveau, libelle, detail) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!libelle) { mount(el); return; }
  mount(el, chipEl(libelle, niveau), detail ? [' ', h('span', { class: 'muted small', text: detail })] : null);
  if (niveau === 'ok') {
    setTimeout(() => {
      const e2 = document.getElementById(id);
      if (e2 && e2.firstChild && e2.textContent.includes(libelle)) mount(e2);
    }, 2500);
  }
}

function attendre(id) {
  const el = document.getElementById(id);
  if (el) mount(el, h('span', { class: 'muted small', text: '…' }));
}

function sectionEl(id, titre, tete, ...corps) {
  return h('section', { class: 'section secsec', id },
    h('div', { class: 'sechead' }, h('h2', { text: titre }), tete),
    ...corps);
}

/** Ligne « bouton(s) + message » qui ferme une section. */
function piedSection(msgId, ...boutons) {
  return h('div', { class: 'filters mt3' }, ...boutons, h('span', { class: 'small', id: msgId }));
}

/* ============================================================================
   Squelette
   ========================================================================== */
function monterReglages() {
  if (MONTE) return;
  MONTE = true;
  mount('page-reglages',
    h('nav', { class: 'anchors', 'aria-label': 'Sections de la page Réglages' },
      ANCRES.map(([, slug, lbl]) => h('a', { class: 'anchor', href: '#reglages/' + slug },
        h('span', { text: lbl })))),
    sectionCollecte(),
    sectionAlertes(),
    sectionVizproof(),
    sectionVisuel(),
    sectionIncidents(),
    sectionCles(),
    sectionApparence(),
    sectionSession());
}

/* ============================================================================
   1. Collecte
   ========================================================================== */
const SCHED_LABELS = {
  0: 'désactivée (manuelle uniquement)', 15: 'toutes les 15 minutes', 30: 'toutes les 30 minutes',
  60: 'toutes les heures', 120: 'toutes les 2 heures', 180: 'toutes les 3 heures',
  360: 'toutes les 6 heures', 720: 'toutes les 12 heures', 1440: 'une fois par jour (3h17)',
};

function sectionCollecte() {
  const collecte = h('button', { type: 'button', class: 'btn sm', id: 'set-collectnow' },
    iconEl('refresh-cw'), ' Collecter maintenant');
  collecte.onclick = () => {
    const b = document.getElementById('collectbtn');
    if (b) b.click();
  };
  return sectionEl('set-collecte', 'Collecte',
    [h('span', { class: 'small', id: 'sched-sum' }), h('span', { class: 'spacer' }), collecte],
    h('p', { class: 'hint', text: 'Cadence du cron qui inventorie le parc. Une collecte complète prend '
      + 'environ 1 min 30 ; le bouton « Collecter » de l’en-tête reste disponible à tout moment.' }),
    h('div', { id: 'sched-body' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

async function loadSchedule() {
  const bd = document.getElementById('sched-body');
  if (!bd) return;
  let s;
  try { s = await api('/api/mgmt/schedule'); }
  catch (e) { mount(bd, chipEl('cadence indisponible', 'mut'), ' ', h('span', { class: 'muted small', text: String(e) })); return; }
  const choix = s.choices || [0, 60];
  const sel = h('select', { id: 'sched-sel', 'aria-label': 'Cadence de collecte' },
    choix.map(v => h('option', { value: String(v), text: SCHED_LABELS[v] || v + ' min' })));
  sel.value = String(s.interval_minutes);
  const save = h('button', { type: 'button', class: 'btn primary sm', id: 'sched-save', text: 'Enregistrer' });
  save.onclick = async () => {
    attendre('sched-msg');
    setBusy(save);
    try {
      const r = await api('/api/mgmt/schedule', { interval_minutes: parseInt(sel.value, 10) }) || {};
      loadSched();
      if (r.ok) dire('sched-msg', 'ok', 'enregistré', 'cron : ' + (r.cron || 'désactivé'));
      else dire('sched-msg', 'err', 'échec', r.error || 'inconnu');
    } catch (e) { dire('sched-msg', 'err', 'échec', String(e)); }
    setIdle(save, null);
  };
  mount(bd,
    h('div', { class: 'field' },
      h('label', { for: 'sched-sel', text: 'Cadence' }),
      sel,
      h('div', { class: 'aide' }, 'Cron actuel : ',
        h('code', { text: s.cron || '(désactivé)' }))),
    piedSection('sched-msg', save));
  const gen = store.fleet && store.fleet.generated_at;
  mount('sched-sum', gen
    ? chipEl('collecté ' + relTime(gen), 'mut', { title: absTime(gen) })
    : chipEl('jamais collecté', 'warn'));
}

/* ============================================================================
   2. Alertes Telegram
   ========================================================================== */
const AL_CHK = [
  ['new_admin', 'nouvel administrateur'],
  ['checksum_fail', 'checksums en anomalie'],
  ['viz_anomaly', 'anomalie visuelle VizProof'],
  ['site_down', 'site down (Kuma)'],
];
const AL_NUM = [
  ['backup_stale_h', 'sauvegarde plus vieille que (h)', 48],
  ['cert_days', 'certificat expirant sous (j)', 21],
  ['collect_dead_h', 'collecte muette depuis (h)', 6],
];

function sectionAlertes() {
  return sectionEl('set-alertes', 'Alertes Telegram',
    [h('span', { class: 'small', id: 'al-sum' })],
    h('p', { class: 'hint' },
      'Créez le bot avec ', h('b', { text: '@BotFather' }), ' (commande ', h('code', { text: '/newbot' }),
      ') pour obtenir le ', h('code', { text: 'bot_token' }), ' ; écrivez ensuite un message au bot et relevez '
      + 'votre ', h('code', { text: 'chat_id' }), ' via ', h('b', { text: '@userinfobot' }), '.'),
    h('div', { id: 'alert-body' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

async function loadAlerts() {
  const bd = document.getElementById('alert-body');
  if (!bd) return;
  let a;
  try { a = await api('/api/mgmt/alerts'); }
  catch (e) { mount(bd, chipEl('alertes indisponibles', 'mut'), ' ', h('span', { class: 'muted small', text: String(e) })); return; }
  if (!a || typeof a !== 'object' || a.error) {
    mount(bd, chipEl('alertes indisponibles', 'mut'), ' ',
      h('span', { class: 'muted small', text: (a && a.error) || 'réponse vide' }));
    return;
  }
  const r = (a.rules && typeof a.rules === 'object') ? a.rules : {};

  const actif = h('input', { type: 'checkbox', id: 'al-enabled' });
  actif.checked = !!a.enabled;
  const token = h('input', {
    class: 'inp w100', id: 'al-token', type: 'password', autocomplete: 'new-password',
    placeholder: a.token_set
      ? 'jeton enregistré (…' + (a.token_tail || '') + ') — laisser vide pour le conserver'
      : 'bot_token (ex. 123456789:AA…)',
  });
  const chat = h('input', { class: 'inp w100', id: 'al-chat', placeholder: '-1001234567890' });
  chat.value = a.chat_id ?? '';

  const cases = AL_CHK.map(([k, l]) => {
    const c = h('input', { type: 'checkbox', 'data-arule': k });
    c.checked = !!r[k];
    return h('label', { class: 'fld' }, c, ' ' + l);
  });
  const nums = AL_NUM.map(([k, l, d]) => {
    const c = h('input', { class: 'inp w-num', type: 'number', min: '0', step: '1', 'data-arule': k });
    c.value = String(r[k] ?? d);
    return h('label', { class: 'fld' }, l + ' ', c);
  });

  const save = h('button', { type: 'button', class: 'btn primary sm', id: 'al-save', text: 'Enregistrer' });
  save.onclick = async () => {
    attendre('al-msg');
    setBusy(save);
    const rules = {};
    bd.querySelectorAll('[data-arule]').forEach(el => {
      if (el.type === 'checkbox') rules[el.dataset.arule] = el.checked;
      else { const v = el.value.trim(); rules[el.dataset.arule] = v === '' ? null : Number(v); }
    });
    try {
      const j = await api('/api/mgmt/alerts', {
        enabled: actif.checked, token: token.value, chat_id: chat.value.trim(), rules,
      }) || {};
      if (j.ok === false || j.error) dire('al-msg', 'err', 'échec', j.error || '');
      else {
        token.value = '';                     // un secret ne revient jamais dans un champ
        dire('al-msg', 'ok', 'enregistré');
        mount('al-sum', chipEl(j.enabled ? 'actives' : 'désactivées', j.enabled ? 'ok' : 'mut'));
      }
    } catch (e) { dire('al-msg', 'err', 'échec', String(e)); }
    setIdle(save, null);
  };
  const test = h('button', { type: 'button', class: 'btn sm', id: 'al-test', text: 'Envoyer un test' });
  test.onclick = async () => {
    attendre('al-msg');
    setBusy(test);
    try {
      const j = await api('/api/mgmt/alerts/test', {}) || {};
      if (j.ok) dire('al-msg', 'ok', 'message envoyé');
      else dire('al-msg', 'err', 'échec', j.error || '');
    } catch (e) { dire('al-msg', 'err', 'échec', String(e)); }
    setIdle(test, null);
  };

  mount(bd,
    h('div', { class: 'field' },
      h('label', { class: 'fld' }, actif, ' alertes activées'),
      h('div', { class: 'aide', text: 'Interrupteur général : décoché, plus rien n’est envoyé, les règles sont conservées.' })),
    h('div', { class: 'fieldrow' },
      h('div', { class: 'field' },
        h('label', { for: 'al-token', text: 'Jeton du bot' }), token,
        h('div', { class: 'aide', text: a.token_set
          ? 'Un jeton est enregistré. Laisser vide pour le conserver.'
          : 'Aucun jeton enregistré : les alertes ne partiront pas.' })),
      h('div', { class: 'field' },
        h('label', { for: 'al-chat', text: 'chat_id' }), chat,
        h('div', { class: 'aide', text: 'Destinataire : votre compte, ou un groupe (identifiant négatif).' }))),
    h('h3', { text: 'Déclencheurs' }),
    h('div', {}, cases),
    h('div', { class: 'mt1' }, nums),
    piedSection('al-msg', save, test),
    h('p', { class: 'hint hint-loose', text: 'Le test utilise la configuration ENREGISTRÉE : pensez à enregistrer avant.' }));
  mount('al-sum', chipEl(a.enabled ? 'actives' : 'désactivées', a.enabled ? 'ok' : 'mut'));
}

/* ============================================================================
   3. VizProof
   ========================================================================== */
function sectionVizproof() {
  return sectionEl('set-vizproof', 'VizProof',
    [h('span', { class: 'small', id: 'viz-sum' })],
    h('p', { class: 'hint' },
      'Le jeton de compte se crée dans ', h('b', { text: 'VizProof → Réglages → API' }),
      '. Il sert à retrouver (ou créer) le site VizProof d’après son URL, puis à relier le plugin.'),
    h('div', { id: 'viz-body' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

function renderVizSettings(cfg) {
  const bd = document.getElementById('viz-body');
  if (!bd) return;
  cfg = cfg || {};
  const pose = !!cfg.vizproof_token_set;
  const token = h('input', {
    class: 'inp w100', id: 'viz-token', type: 'password', autocomplete: 'off', spellcheck: 'false',
    placeholder: pose
      ? 'jeton enregistré (…' + (cfg.vizproof_token_tail || '') + ') — laisser vide pour le conserver'
      : 'vrt_…',
  });
  const base = h('input', {
    class: 'inp w100', id: 'viz-base', autocomplete: 'off', spellcheck: 'false',
    placeholder: 'https://vizproof.com',
  });
  base.value = cfg.vizproof_api_base || '';

  const maj = j => {
    if (j && j.settings) { store.settings = j.settings; SETTINGSLU = true; renderVizSettings(store.settings); }
  };
  const save = h('button', { type: 'button', class: 'btn primary sm', id: 'viz-save', text: 'Enregistrer' });
  save.onclick = async () => {
    const v = token.value.trim(), b = base.value.trim();
    if (!v && b === String(cfg.vizproof_api_base || '')) {
      dire('viz-msg', 'mut', 'rien à enregistrer', 'saisissez un jeton ou changez la base API.');
      return;
    }
    attendre('viz-msg');
    setBusy(save);
    const patch = {};
    if (v) patch.vizproof_token = v;
    if (b !== String(cfg.vizproof_api_base || '')) patch.vizproof_api_base = b;
    try {
      const j = await api('/api/mgmt/settings', { settings: patch }) || {};
      if (j.error || !j.settings) { dire('viz-msg', 'err', 'échec', j.error || 'réponse vide'); setIdle(save, null); return; }
      maj(j);
      dire('viz-msg', 'ok', 'enregistré');
    } catch (e) { dire('viz-msg', 'err', 'échec', String(e)); }
    setIdle(save, null);
  };
  const test = h('button', { type: 'button', class: 'btn sm', id: 'viz-test', text: 'Tester' });
  test.disabled = !pose;
  test.onclick = async () => {
    attendre('viz-msg');
    setBusy(test);
    try {
      const j = await api('/api/mgmt/vizproof/test', {}) || {};
      if (j.ok) dire('viz-msg', 'ok', (j.total ?? '?') + ' site(s) accessible(s)', j.api_base || '');
      else dire('viz-msg', 'err', 'échec', j.error || '');
    } catch (e) { dire('viz-msg', 'err', 'échec', String(e)); }
    setIdle(test, null);
  };
  const oubli = h('button', { type: 'button', class: 'btn sm danger', id: 'viz-forget', text: 'Effacer' });
  oubli.disabled = !pose;
  oubli.onclick = async () => {
    if (!await askConfirm(
      'Effacer le jeton VizProof enregistré ?<br><br>Les connexions « en un clic » redemanderont un jeton.',
      { titre: 'Effacer le jeton VizProof', ok: 'Effacer', danger: true })) return;
    attendre('viz-msg');
    try {
      const j = await api('/api/mgmt/settings',
        { settings: { vizproof_token: '' }, vizproof_token_clear: true }) || {};
      maj(j);
      dire('viz-msg', 'ok', 'effacé');
    } catch (e) { dire('viz-msg', 'err', 'échec', String(e)); }
  };

  mount(bd,
    h('div', { class: 'fieldrow' },
      h('div', { class: 'field' },
        h('label', { for: 'viz-token', text: 'Jeton de compte' }), token,
        h('div', { class: 'aide', text: pose
          ? 'Un jeton est enregistré. Laisser vide pour le conserver.'
          : 'Aucun jeton : la connexion d’un site demandera un jeton à chaque fois.' })),
      h('div', { class: 'field' },
        h('label', { for: 'viz-base', text: 'Base de l’API' }), base,
        h('div', { class: 'aide', text: 'https exigé. Vide = https://vizproof.com.' }))),
    piedSection('viz-msg', save, test, oubli));
  mount('viz-sum', pose
    ? chipEl('jeton enregistré · …' + (cfg.vizproof_token_tail || ''), 'ok')
    : chipEl('aucun jeton', 'mut'));
}

/* ============================================================================
   4. Contrôle visuel (les quatre cases)
   ========================================================================== */
const CASES_VIZ = [
  ['set-vizrb', 'viz_anomaly_rollback', false,
    'Retour arrière automatique sur anomalie visuelle',
    'Décoché (défaut) : pendant une MAJ sûre, une anomalie détectée par VizProof est SIGNALÉE et la mise à '
    + 'jour est conservée — le verdict devient « réussie avec anomalies visuelles ». Coché : la mise à jour '
    + 'est ANNULÉE. Un rendu qui change n’est pas toujours un rendu cassé (bandeau de cookies, carrousel, '
    + 'publicité), d’où le défaut prudent côté « avertir ».'],
  ['set-vizscan', 'viz_scan_after_update', true,
    'Contrôle visuel VizProof après chaque mise à jour',
    'Coché (défaut) : après une mise à jour lancée depuis la page d’un site (cœur, extensions, thèmes), le '
    + 'dashboard récupère en arrière-plan le verdict visuel des sites reliés. L’extension scanne d’elle-même '
    + 'après une mise à jour quand son option est active : on attend SON scan plutôt que d’en lancer un '
    + 'second. Ce contrôle INFORME seulement — le bouton unitaire n’archive rien, il n’y a rien à annuler.'],
  ['set-vizbase', 'viz_baseline_before_update', true,
    'Baseline VizProof avant chaque mise à jour unitaire',
    'Coché (défaut) : sur un site relié, la mise à jour part dans un déroulé suivi — baseline, mise à jour, '
    + 'verdict visuel, inventaire. Sans baseline, le contrôle d’après compare au dernier état connu de '
    + 'VizProof, qui peut dater de la veille et mêler d’autres changements.'],
  ['set-vizbasereq', 'viz_baseline_required', false,
    'Exiger la baseline : ne pas mettre à jour si elle échoue',
    'Décoché (défaut) : une baseline ratée est un avertissement et la mise à jour se fait quand même — '
    + 'VizProof est un filet, pas une condition. Coché : la mise à jour est annulée tant qu’aucun témoin '
    + 'd’avant n’a pu être pris.'],
];

function sectionVisuel() {
  return sectionEl('set-visuel', 'Contrôle visuel des mises à jour', null,
    h('p', { class: 'hint', text: 'Ces quatre réglages pilotent ce qui se passe autour d’une mise à jour '
      + 'lancée depuis le dashboard. Chacun s’enregistre à la volée.' }),
    h('div', { id: 'mset-body' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

function renderVisuel() {
  const bd = document.getElementById('mset-body');
  if (!bd) return;
  mount(bd, CASES_VIZ.map(([id, cle, defaut, titre, aide]) => {
    const c = h('input', { type: 'checkbox', id });
    c.checked = store.settings[cle] === undefined ? defaut : !!store.settings[cle];
    c.onchange = async e => {
      const v = e.target.checked;
      attendre(id + 'msg');
      try {
        const r = await api('/api/mgmt/settings', { settings: { [cle]: v } }) || {};
        if (r && r.settings) store.settings = r.settings;
        dire(id + 'msg', 'ok', 'enregistré');
      } catch (err) {
        e.target.checked = !v;               // ne jamais afficher un réglage qui n'a pas été écrit
        dire(id + 'msg', 'err', 'échec', String(err));
      }
    };
    return h('div', { class: 'field' },
      h('label', { class: 'fld' }, c, ' ' + titre, ' ', h('span', { class: 'small', id: id + 'msg' })),
      h('div', { class: 'aide', text: aide }));
  }));
}

/* ============================================================================
   5. Règles d'incidents
   ========================================================================== */
function sectionIncidents() {
  return sectionEl('set-incidents', 'Règles d’incidents',
    [h('span', { class: 'small', id: 'inc-sum' })],
    h('p', { class: 'hint', text: 'Seuils de la file « à traiter » : ils pilotent l’écran Incidents, les '
      + 'pastilles de la barre latérale ET les colonnes du Parc. Un seuil changé ici change les trois d’un coup.' }),
    h('div', { id: 'inc-body' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

/* Un champ = une clé de `incident_rules`. Le backend recompose TOUT le
   sous-dictionnaire à partir de ses valeurs par défaut : une clé absente du
   corps envoyé reviendrait au défaut, jamais à la valeur enregistrée. On
   renvoie donc toujours les cinq clés ensemble. */
const REGLES_NUM = [
  ['backup_max_age_h', 'inc-backup', 'Sauvegarde en retard au-delà de (heures)', 48,
    'Une sauvegarde UpdraftPlus plus ancienne devient un incident « avertissement ».'],
  ['cert_warn_days', 'inc-certw', 'Certificat signalé sous (jours)', 21,
    'Nombre de jours restants en dessous duquel un certificat TLS est signalé.'],
  ['cert_critical_days', 'inc-certc', 'Certificat critique sous (jours)', 7,
    'En dessous, l’incident passe en « critique ».'],
];

function renderIncidentRules() {
  const bd = document.getElementById('inc-body');
  if (!bd) return;
  const r = (store.settings && store.settings.incident_rules) || {};
  const champs = {};
  const blocs = REGLES_NUM.map(([cle, id, lbl, defaut, aide]) => {
    const inp = h('input', { class: 'inp w-num', id, type: 'number', min: '0', step: '1' });
    inp.value = String(r[cle] ?? defaut);
    champs[cle] = inp;
    return h('div', { class: 'field' },
      h('label', { for: id, text: lbl }), inp, h('div', { class: 'aide', text: aide }));
  });
  const high = h('input', { type: 'checkbox', id: 'inc-high' });
  high.checked = !!r.vuln_high_is_incident;
  const php = h('input', { class: 'inp w100', id: 'inc-php', placeholder: '7.0, 7.4, 8.0' });
  php.value = (Array.isArray(r.php_eol_versions) ? r.php_eol_versions : []).join(', ');

  const save = h('button', { type: 'button', class: 'btn primary sm', id: 'inc-save', text: 'Enregistrer' });
  save.onclick = async () => {
    const regles = { vuln_high_is_incident: high.checked };
    let mauvais = null;
    REGLES_NUM.forEach(([cle, , lbl]) => {
      const v = champs[cle].value.trim();
      const n = /^\d+$/.test(v) ? parseInt(v, 10) : null;
      if (n === null) mauvais = mauvais || lbl;
      regles[cle] = n === null ? undefined : n;
    });
    if (mauvais) { dire('inc-msg', 'err', 'valeur invalide', mauvais + ' : un nombre entier positif est attendu.'); return; }
    const versions = php.value.split(/[,\s]+/).map(x => x.trim()).filter(Boolean);
    const horsForme = versions.find(x => !/^\d+\.\d+$/.test(x));
    if (horsForme) {
      dire('inc-msg', 'err', 'version invalide', '« ' + horsForme + ' » — forme attendue : majeure.mineure (7.4, 8.0).');
      return;
    }
    regles.php_eol_versions = versions;
    attendre('inc-msg');
    setBusy(save);
    try {
      const j = await api('/api/mgmt/settings', { settings: { incident_rules: regles } }) || {};
      if (j.error || !j.settings) { dire('inc-msg', 'err', 'échec', j.error || 'réponse vide'); setIdle(save, null); return; }
      store.settings = j.settings;
      SETTINGSLU = true;
      renderIncidentRules();
      dire('inc-msg', 'ok', 'enregistré');
    } catch (e) { dire('inc-msg', 'err', 'échec', String(e)); }
    setIdle(save, null);
  };

  mount(bd,
    h('div', { class: 'fieldrow' }, blocs),
    h('div', { class: 'field' },
      h('label', { class: 'fld' }, high, ' Une vulnérabilité « élevée » corrigeable est un incident critique'),
      h('div', { class: 'aide', text: 'Décoché (défaut) : seules les « critiques » remontent dans la file, '
        + 'sinon elle devient illisible — l’écran Sécurité montre déjà tout.' })),
    h('div', { class: 'field' },
      h('label', { for: 'inc-php', text: 'Versions PHP en fin de support' }), php,
      h('div', { class: 'aide', text: 'Majeure.mineure, séparées par des virgules. Un serveur sous l’une de '
        + 'ces branches remonte en incident et le Parc marque ses sites.' })),
    piedSection('inc-msg', save));
  // Trois chips courtes plutôt qu'une longue : une chip ne se coupe pas
  // (white-space:nowrap), et une seule ligne de 50 caractères déborderait en
  // étroit. Le sens complet est dans l'infobulle.
  const n = (Array.isArray(r.php_eol_versions) ? r.php_eol_versions : []).length;
  mount('inc-sum',
    chipEl('sauvegarde ' + (r.backup_max_age_h ?? 48) + ' h', 'mut',
      { title: 'âge maximal d’une sauvegarde avant incident' }), ' ',
    chipEl('certificat ' + (r.cert_warn_days ?? 21) + '/' + (r.cert_critical_days ?? 7) + ' j', 'mut',
      { title: 'seuils d’avertissement et de criticité d’un certificat' }), ' ',
    chipEl(n + ' branche(s) PHP', 'mut', { title: 'versions PHP considérées en fin de support' }));
}

/* ============================================================================
   6. Clés SSH
   ========================================================================== */
function sectionCles() {
  return sectionEl('set-cles', 'Clés SSH',
    [h('span', { class: 'small', id: 'k-sum' })],
    h('p', { class: 'hint' },
      'La clé publique sert à l’enrôlement manuel sur les serveurs (',
      h('code', { text: '~/.ssh/authorized_keys' }), '). ',
      h('b', { text: 'Toujours tester avant d’assigner' }),
      ' : une clé non enrôlée casse la collecte du serveur concerné.'),
    h('div', { id: 'set-body' }, h('span', { class: 'muted small', text: 'chargement…' })));
}

function optionsCle(courante) {
  return (KEYS && KEYS.keys || []).map(k =>
    h('option', { value: k.path, text: k.name, selected: k.path === courante }));
}

async function loadKeys() {
  const bd = document.getElementById('set-body');
  if (!bd) return;
  try { KEYS = await api('/api/mgmt/sshkeys'); }
  catch (e) {
    mount(bd, chipEl('erreur de chargement', 'err'), ' ', h('span', { class: 'muted small', text: String(e) }));
    return;
  }
  const keys = KEYS.keys || [], asg = {};
  (KEYS.assignments || []).forEach(a => { asg[a.server] = a.key; });
  const noms = [...new Set([...(store.fleet?.servers || []).map(s => s.name),
    ...(KEYS.assignments || []).map(a => a.server)])].sort();

  /* --- liste des clés --- */
  const lignes = [];
  if (!keys.length) {
    lignes.push(h('tr', {}, h('td', { colspan: '4' }, h('span', { class: 'muted small', text: 'aucune clé détectée' }))));
  }
  keys.forEach(k => {
    const pub = h('tr', { hidden: true }, h('td', { colspan: '4' },
      h('textarea', { class: 'code short', readonly: true, 'aria-label': 'Clé publique ' + k.name })));
    pub.firstChild.firstChild.value = k.pub || '';
    const b = h('button', { type: 'button', class: 'btn sm', text: 'voir la clé publique' });
    b.onclick = () => {
      pub.hidden = !pub.hidden;
      b.textContent = pub.hidden ? 'voir la clé publique' : 'masquer la clé publique';
    };
    lignes.push(h('tr', {},
      h('td', {}, h('b', { text: k.name }), h('div', { class: 'sub', text: k.path || '' })),
      h('td', {}, chipEl(k.type || '?', 'mut')),
      h('td', {}, h('span', { class: 'sub', text: k.fingerprint || '' })),
      h('td', {}, b)), pub);
  });

  /* --- génération --- */
  const nom = h('input', { class: 'inp w-sm', id: 'k-name', placeholder: 'dashboard', 'aria-label': 'Nom de la clé' });
  const gen = h('button', { type: 'button', class: 'btn sm', id: 'k-gen', text: 'Générer' });
  const sortie = h('div', { id: 'k-genout' });
  gen.onclick = async () => {
    const n = (nom.value || 'dashboard').trim();
    attendre('k-genmsg');
    mount(sortie);
    setBusy(gen);
    try {
      const j = await api('/api/mgmt/sshkeys/generate', { name: n }) || {};
      if (!j.ok) dire('k-genmsg', 'err', 'échec', j.error || 'cette clé existe déjà ?');
      else {
        dire('k-genmsg', 'ok', 'créée');
        const ta = h('textarea', { class: 'code short', readonly: true, 'aria-label': 'Clé publique générée' });
        ta.value = j.pub || '';
        mount(sortie,
          h('p', { class: 'hint', text: 'Clé publique à enrôler sur les serveurs (~/.ssh/authorized_keys), '
            + 'puis à assigner ci-dessous.' }),
          ta, h('div', { class: 'muted small', text: j.path || '' }));
        KEYS.keys = [...(KEYS.keys || []), { name: n, path: j.path, type: '', pub: j.pub, fingerprint: '' }];
      }
    } catch (e) { dire('k-genmsg', 'err', 'échec', String(e)); }
    setIdle(gen, null);
  };

  /* --- affectation par serveur --- */
  const affect = noms.length ? noms.map(n => {
    const sel = h('select', { 'aria-label': 'Clé du serveur ' + n }, optionsCle(asg[n]));
    if (asg[n]) sel.value = asg[n];
    const res = h('span', { class: 'small' });
    const test = h('button', { type: 'button', class: 'btn sm', text: 'Tester' });
    test.onclick = async () => {
      setBusy(test);
      mount(res);
      try {
        const j = await api('/api/mgmt/sshkeys/test', { server: n, key: sel.value }) || {};
        mount(res, chipEl(j.ok ? 'joignable' : 'échec', j.ok ? 'ok' : 'err'), ' ',
          h('span', { class: 'muted small', text: String(j.output || j.error || '').slice(-160) }));
      } catch (e) { mount(res, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) })); }
      setIdle(test, 'Tester');
    };
    const ass = h('button', { type: 'button', class: 'btn sm', text: 'Assigner' });
    ass.onclick = async () => {
      const k = sel.value;
      if (!k) return;
      if (!await askConfirm(
        `Assigner cette clé au serveur <b>${H(n)}</b> ?<br><br>Si elle n'y est pas enrôlée, la collecte de ce serveur cassera.`,
        { titre: 'Assigner une clé', ok: 'Assigner', danger: true })) return;
      setBusy(ass);
      try {
        const j = await api('/api/mgmt/sshkeys/assign', { server: n, key: k }) || {};
        if (j.ok) mount(res, chipEl('assignée', 'ok'));
        else mount(res, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: j.error || '' }));
      } catch (e) { mount(res, chipEl('échec', 'err'), ' ', h('span', { class: 'muted small', text: String(e) })); }
      setIdle(ass, 'Assigner');
    };
    return h('tr', {}, h('td', {}, h('b', { text: n })), h('td', {}, sel), h('td', {}, test, ' ', ass, ' ', res));
  }) : h('tr', {}, h('td', { colspan: '3' }, h('span', { class: 'muted small', text: 'aucun serveur' })));

  /* --- assignation globale --- */
  const tous = h('select', { id: 'k-allsel', 'aria-label': 'Clé à assigner partout' }, optionsCle(''));
  const btnTous = h('button', {
    type: 'button', class: 'btn sm danger', id: 'k-all', text: 'Assigner cette clé à TOUS les serveurs',
  });
  btnTous.onclick = async () => {
    const k = tous.value;
    if (!k) return;
    const kn = (KEYS.keys || []).find(x => x.path === k);
    if (!await askConfirm(
      `Assigner la clé <b>${H(kn ? kn.name : k)}</b> à <b>TOUS</b> les serveurs ?<br><br>`
      + "Tout serveur où elle n'est pas enrôlée deviendra injoignable.",
      { titre: 'Assigner à tous les serveurs', ok: 'Assigner partout', danger: true })) return;
    attendre('k-allmsg');
    try {
      const j = await api('/api/mgmt/sshkeys/assign', { server: '*', key: k }) || {};
      if (j.ok) { dire('k-allmsg', 'ok', 'assignée partout'); setTimeout(loadKeys, 1500); }
      else dire('k-allmsg', 'err', 'échec', j.error || '');
    } catch (e) { dire('k-allmsg', 'err', 'échec', String(e)); }
  };

  mount(bd,
    h('h3', { text: 'Clés disponibles' }),
    h('div', { class: 'wrap' }, h('table', {},
      h('thead', {}, h('tr', {},
        h('th', { text: 'Nom' }), h('th', { text: 'Type' }), h('th', { text: 'Empreinte' }),
        h('th', {}, h('span', { class: 'sr-only', text: 'Clé publique' })))),
      h('tbody', {}, lignes))),
    h('h3', { text: 'Générer une clé dédiée' }),
    h('div', { class: 'filters' }, nom, gen, h('span', { class: 'small', id: 'k-genmsg' })),
    sortie,
    h('h3', { text: 'Affectation par serveur' }),
    h('div', { class: 'wrap' }, h('table', {},
      h('thead', {}, h('tr', {},
        h('th', { text: 'Serveur' }), h('th', { text: 'Clé' }),
        h('th', {}, h('span', { class: 'sr-only', text: 'Actions' })))),
      h('tbody', {}, affect))),
    h('div', { class: 'filters mt3' }, tous, btnTous, h('span', { class: 'small', id: 'k-allmsg' })));
  mount('k-sum', chipEl(keys.length + ' clé(s) · ' + noms.length + ' serveur(s)', 'mut'));
}

/* ============================================================================
   7. Apparence
   ========================================================================== */
const DENS_CLE = 'dashDensite';

function densiteMemorisee() {
  try { return localStorage.getItem(DENS_CLE) === 'compacte' ? 'compacte' : 'normale'; }
  catch (e) { return 'normale'; }
}

/** Appliquée au démarrage (ce module est importé par app.js). */
export function appliquerPreferences() {
  const compacte = densiteMemorisee() === 'compacte';
  store.filt.compact = compacte;
  setDensity(compacte);
}

function sectionApparence() {
  const theme = h('select', { id: 'set-theme', 'aria-label': 'Thème' },
    h('option', { value: 'auto', text: 'Auto (préférence du système)' }),
    h('option', { value: 'light', text: 'Clair' }),
    h('option', { value: 'dark', text: 'Sombre' }));
  theme.value = themeCourant();
  theme.onchange = () => { applyTheme(theme.value); dire('app-msg', 'ok', 'thème appliqué'); };

  const dens = h('select', { id: 'set-dens', 'aria-label': 'Densité des tableaux' },
    h('option', { value: 'normale', text: 'Normale' }),
    h('option', { value: 'compacte', text: 'Compacte' }));
  dens.value = densiteMemorisee();
  dens.onchange = () => {
    const compacte = dens.value === 'compacte';
    try { localStorage.setItem(DENS_CLE, dens.value); } catch (e) { /* stockage refusé : vaut pour la session */ }
    store.filt.compact = compacte;
    setDensity(compacte);
    dire('app-msg', 'ok', 'densité appliquée');
  };

  return sectionEl('set-apparence', 'Apparence', null,
    h('p', { class: 'hint', text: 'Préférences de CE navigateur : elles ne partent pas au serveur et ne '
      + 'concernent pas les autres postes.' }),
    h('div', { class: 'fieldrow' },
      h('div', { class: 'field' },
        h('label', { for: 'set-theme', text: 'Thème' }), theme,
        h('div', { class: 'aide', text: 'Le bouton « Thème » de la barre latérale fait tourner les trois états.' })),
      h('div', { class: 'field' },
        h('label', { for: 'set-dens', text: 'Densité des tableaux' }), dens,
        h('div', { class: 'aide', text: 'Compacte : lignes resserrées, plus de sites à l’écran.' }))),
    h('div', { class: 'small', id: 'app-msg' }));
}

/* ============================================================================
   8. Session
   ========================================================================== */
function sectionSession() {
  const qui = document.getElementById('nav-user');
  const bt = h('button', { type: 'button', class: 'btn sm danger', id: 'set-logout' },
    iconEl('log-out'), ' Se déconnecter');
  bt.onclick = () => logout();
  return sectionEl('set-session', 'Session', null,
    h('div', { class: 'kv' },
      h('span', { class: 'k', text: 'Utilisateur' }),
      h('span', { text: (qui && qui.textContent) || 'session ouverte' }),
      h('span', { class: 'k', text: 'Dashboard' }),
      h('span', {}, h('code', { text: location.origin }))),
    h('p', { class: 'hint hint-loose', text: 'La déconnexion invalide la session côté serveur avant de '
      + 'renvoyer à la page de connexion.' }),
    h('div', { class: 'actions mt2' }, bt));
}

/* ============================================================================
   Réglages lus paresseusement (hors écran)
   ========================================================================== */
/* La modale de confirmation de la MAJ sûre a besoin des réglages même si
   personne n'a jamais ouvert cette page. Un seul appel par session. */
export async function ensureSettings() {
  if (SETTINGSLU) return store.settings;
  try {
    const j = await api('/api/mgmt/settings');
    if (j && j.settings && typeof j.settings === 'object') store.settings = j.settings;
    SETTINGSLU = true;
  } catch (e) { /* réglages inaccessibles : les valeurs par défaut du store servent */ }
  return store.settings;
}

async function loadSettings() {
  let j;
  try { j = await api('/api/mgmt/settings'); }
  catch (e) {
    const bd = document.getElementById('mset-body');
    if (bd) mount(bd, chipEl('réglages indisponibles', 'mut'), ' ', h('span', { class: 'muted small', text: String(e) }));
    renderVizSettings(store.settings);
    renderIncidentRules();
    return;
  }
  if (j && j.settings && typeof j.settings === 'object') { store.settings = j.settings; SETTINGSLU = true; }
  renderVisuel();
  renderVizSettings(store.settings);
  renderIncidentRules();
}

/* ============================================================================
   Chargement de l'écran
   ========================================================================== */
export function loadReglages() {
  monterReglages();
  loadSchedule();
  loadAlerts();
  loadSettings();
  loadKeys();
}

appliquerPreferences();

export { loadKeys, loadSettings, loadAlerts, loadSchedule };
