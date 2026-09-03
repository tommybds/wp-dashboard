/* Mises en forme partagées : dates, durées, URL, cadences UpdraftPlus, bruit
   PHP. Aucune de ces fonctions ne touche au DOM ni au réseau. */

/* ---- dates & liens — helpers tolérants (epoch s/ms, ISO, "2026-08-25 10:00:00") */
export function tsMs(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'number') return isFinite(v) ? (v > 1e12 ? v : v * 1000) : null;
  const s = String(v).trim();
  if (/^\d+(\.\d+)?$/.test(s)) { const n = Number(s); return n > 1e12 ? n : n * 1000; }
  const d = Date.parse(s.replace(' ', 'T'));
  return isNaN(d) ? null : d;
}

export function relTime(v) {
  const t = tsMs(v);
  if (t === null) return String(v ?? '');
  const h = (Date.now() - t) / 3600000;
  if (h < 0.02) return "à l'instant";
  if (h < 1) return 'il y a ' + Math.max(1, Math.round(h * 60)) + ' min';
  if (h < 48) return 'il y a ' + Math.round(h) + ' h';
  return 'il y a ' + Math.round(h / 24) + ' j';
}

export function absTime(v) {
  const t = tsMs(v);
  return t === null ? String(v ?? '') : new Date(t).toLocaleString('fr-FR');
}

/** Durée courte, pour la barre de notifications. */
export function duree(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? s + ' s' : Math.floor(s / 60) + ' min ' + String(s % 60).padStart(2, '0');
}

/** URL affichable telle quelle : bloque `javascript:` et consorts. */
export function safeUrl(u) {
  const s = String(u ?? '').trim();
  return /^(https?:\/\/|\/)[^\s]*$/i.test(s) ? s : '';
}

/* domaine normalisé d'une URL (comparaisons site ↔ inventaire) */
export function hostOf(u) {
  const s = String(u ?? '').trim();
  if (!s) return '';
  try { return new URL(/^https?:\/\//i.test(s) ? s : 'https://' + s).hostname.replace(/^www\./i, '').toLowerCase(); }
  catch (e) { return s.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split(/[/?#]/)[0].toLowerCase(); }
}

/* Anti-rafale sur les champs de filtre : sans lui, chaque frappe redessine
   l'intégralité du tableau (40 sites × leurs extensions). */
export function debounce(fn, ms = 200) {
  let t = null;
  return function (...a) { clearTimeout(t); t = setTimeout(() => fn.apply(this, a), ms); };
}

/* ---- lisibilité UpdraftPlus ---------------------------------------------- */
export function udIntervalFr(v) {
  const m = { everyhour: 'toutes les heures', every2hours: 'toutes les 2 h', every4hours: 'toutes les 4 h', every8hours: 'toutes les 8 h', every12hours: 'toutes les 12 h', daily: 'quotidienne', weekly: 'hebdomadaire', fortnightly: 'tous les 15 jours', monthly: 'mensuelle' };
  return m[v] || v || '?';
}
function udIntervalDays(v) {
  const m = { everyhour: 1 / 24, every2hours: 2 / 24, every4hours: 4 / 24, every8hours: 8 / 24, every12hours: 12 / 24, daily: 1, weekly: 7, fortnightly: 14, monthly: 30 };
  return m[v] || null;
}
export function udHorizon(retain, interval) {
  const d = udIntervalDays(interval), n = parseInt(retain, 10);
  if (!d || !n) return null;
  const days = n * d;
  if (days >= 365) return '≈ ' + (Math.round(days / 365 * 10) / 10 + '').replace('.0', '') + ' an(s)';
  if (days >= 60) return '≈ ' + Math.round(days / 30) + ' mois';
  if (days >= 14) return '≈ ' + Math.round(days / 7) + ' semaines';
  return '≈ ' + Math.round(days) + ' jour(s)';
}
function udPeriod(n, s) {
  if (s === 604800) return n + ' sem';
  if (s === 86400) return n + ' j';
  const d = n * s / 86400;
  if (d >= 1) return Math.round(d) + ' j';
  return Math.round(n * s / 3600) + ' h';
}
export function udRulesFr(rules) {
  if (!rules || !rules.length) return null;
  return rules.map(r => {
    const everyDays = r.every_n * r.every_s / 86400;
    const evTxt = everyDays > 730 ? 'archive conservée sans purge' : '1 backup toutes les ' + udPeriod(r.every_n, r.every_s);
    return 'au-delà de ' + udPeriod(r.after_n, r.after_s) + ' : ' + evTxt;
  }).join(' · ');
}

/* ---- évènements poussés par les agents ------------------------------------
   L'agent envoie du JSON brut (`{"login":"admin","ip":"10.0.0.9"}`) : illisible
   tel quel dans une chronologie. On le rend en une phrase, par type
   d'évènement, avec un repli « clé : valeur » pour les types inconnus — un
   agent plus récent que l'interface reste lisible.

   Une seule copie depuis la phase 5 : l'écran Changements ET l'onglet
   Historique de la page site (`tlDetail`) passent par ici. */
export function detailEvenement(label, brut) {
  if (brut === null || brut === undefined || brut === '') return '';
  let d;
  try { d = JSON.parse(brut); } catch (err) { return stripPhpNoise(String(brut)).slice(0, 220); }
  if (!d || typeof d !== 'object') return String(brut).slice(0, 220);
  const slug = f => String(f).split('/')[0];
  const lab = String(label || '');
  if (lab === 'upgrader_process_complete') {
    const items = (d.items || []).map(slug).filter(Boolean);
    const quoi = { plugin: 'extension', theme: 'thème', core: 'cœur', translation: 'traduction' }[d.type]
      || d.type || 'élément';
    if (!items.length) return `${quoi} · ${d.action || 'mise à jour'}`;
    return `${quoi}${items.length > 1 ? 's' : ''} : ${items.join(', ')}`;
  }
  if (lab === 'wp_login') return `${d.login || '?'}${d.ip ? ' · depuis ' + d.ip : ''}`;
  if (lab === 'user_register' || lab === 'set_user_role' || lab === 'grant_super_admin') {
    return `${d.login || '?'}${d.email ? ' <' + d.email + '>' : ''}`
      + `${(d.roles || []).length ? ' · ' + d.roles.join(', ') : ''}`;
  }
  if (lab === 'deleted_user') return `${d.login || d.id || '?'}`;
  if (lab === 'activated_plugin' || lab === 'deactivated_plugin') return slug(d.plugin || d.file || '?');
  if (lab === 'switch_theme') return d.name || d.stylesheet || '?';
  return Object.entries(d).filter(([, v]) => v !== null && v !== '' && v !== undefined)
    .map(([k, v]) => `${k} : ${Array.isArray(v) ? v.map(slug).join(', ') : v}`).join(' · ').slice(0, 220);
}

/* Évènements considérés comme une alerte immédiate : mêmes que côté serveur
   (CRITICAL_EVENTS), plus un changement de rôle vers administrateur. */
const EVT_ALERTE = ['user_register', 'activated_plugin'];

export function evenementAlerte(label, detail) {
  const l = String(label || '');
  if (EVT_ALERTE.includes(l)) return true;
  return l === 'set_user_role' && /administrator/i.test(String(detail || ''));
}

/* Retire le bruit PHP des sorties wp-cli : ces lignes noient l'information utile. */
export function stripPhpNoise(s) {
  return String(s ?? '').split('\n').filter(l => {
    const t = l.trim();
    return t && !/^(PHP\s+)?(Warning|Notice|Deprecated|Strict Standards)\s*:/i.test(t)
             && !/is deprecated|Implicitly marking parameter|already defined in phar|^\s*in .+ on line \d+/i.test(t);
  }).join('\n').trim();
}
