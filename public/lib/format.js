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
export function udIntervalDays(v) {
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
export function udPeriod(n, s) {
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

/* Retire le bruit PHP des sorties wp-cli : ces lignes noient l'information utile. */
export function stripPhpNoise(s) {
  return String(s ?? '').split('\n').filter(l => {
    const t = l.trim();
    return t && !/^(PHP\s+)?(Warning|Notice|Deprecated|Strict Standards)\s*:/i.test(t)
             && !/is deprecated|Implicitly marking parameter|already defined in phar|^\s*in .+ on line \d+/i.test(t);
  }).join('\n').trim();
}
