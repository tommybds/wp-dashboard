#!/usr/bin/env python3
"""Contrôle des mises à jour automatiques de la nuit.

WordPress applique ses mises à jour automatiques vers 5 h, et l'extension
VizProof des sites reliés lance alors un scan de toutes les pages surveillées.
Le verdict restait sur le site : la collecte ne retient que le DERNIER scan, qui
porte sur une seule page — souvent une page sans écart. Une page cassée à 5 h
ne se voyait nulle part (ecuriestemel, page Contact, du 25 au 28/09).

Ce script passe après les mises à jour (cron 6 h 45, avant le bilan de 8 h) et,
pour chaque site suivi, relié à VizProof et joignable en SSH :

  1. lit dans l'historique de l'extension les mises à jour des dernières 26 h ;
  2. repère les mises à jour SANS EFFET : un élément « mis à jour » dont la
     version n'a pas changé dans changes.jsonl (licence expirée, paquet
     refusé : WordPress retente chaque nuit, VizProof scanne pour rien) ;
  3. lit le rapport VizProof agrégé (toutes les pages) et en retient les pages
     en écart ou en erreur HTTP.

Le résultat va dans data/viz_nuit.json, que lit la file d'incidents
(`inc_viz_nuit`), donc aussi le bilan du matin ; un écart part en alerte
Telegram (règle `viz_anomaly`, comme les autres anomalies visuelles).

FILET DE SÉCURITÉ (01/10). La nuit du 30/09 au 01/10, wp-mail-smtp s'est mis à
jour sur huit sites reliés et seuls trois ont scanné : sur les autres, le
plugin n'a jamais appelé VizProof. Le script ne se contente donc plus de LIRE
ce que le plugin a fait : il compare aux mises à jour que la collecte a
journalisées (changes.jsonl), et si l'une d'elles n'est suivie d'aucun scan,
il lance lui-même `wp vizproof scan --wait --after-update` sur le site
(« rattrapage »). Le verdict est le même que celui d'un scan du plugin.

ÉCART PERSISTANT. Un écart ne disparaît plus du bilan au bout de 48 h parce
que plus personne n'a regardé : tant que le dernier rapport du site montre
encore les pages en échec, l'écart est reconfirmé chaque matin ; il ne part
que quand un scan plus récent ne les montre plus.

Lecture seule sur les sites, hormis le scan de rattrapage. `--dry-run` affiche
sans écrire, sans alerter et sans lancer de scan.
"""
import os, re, sys, json, time, base64, datetime

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA, load_json, save_json  # noqa: E402
import actions_server as A  # noqa: E402

PATH = os.path.join(DATA, "viz_nuit.json")
CHANGES_PATH = os.path.join(DATA, "changes.jsonl")
MAJ_NUIT = os.path.join(DATA, "maj_nuit.json")
FENETRE_H = 26
# Un scan du plugin « couvre » une mise à jour journalisée s'il a eu lieu au plus
# tard 3 h avant la ligne de journal : la collecte (toutes les 30 min) relève la
# nouvelle version APRÈS la mise à jour, jamais avant.
COUVERTURE_S = 3 * 3600
RATTRAPAGE_SOURCE = "rattrapage-nuit"
RETOUR_SOURCE = "retour-auto"
RE_MAJ = re.compile(r"^(\S+) (\S+) → (\S+)$")

# Historique de l'extension : les événements « update » récents, sans rien
# d'autre (ni jeton, ni réglage). JSON sur une ligne, repérée par son préfixe.
PHP = r'''
$h = array_values((array) get_option('vizproof_timeline_history', array()));
$out = array();
foreach (array_slice($h, 0, 12) as $e) {
  $e = (array) $e;
  if (($e['source'] ?? '') !== 'update') continue;
  $u = (array) ($e['update'] ?? array());
  // Les slugs d'abord (`rollbackCandidates`) : depuis VizProof 1.3.16, `items`
  // porte le NOM affiché des extensions (« WP Mail SMTP »), que rien ne relie
  // au journal des versions, qui ne connaît que les slugs.
  $items = array();
  foreach ((array) ($u['rollbackCandidates'] ?? array()) as $c) {
    $c = (array) $c; $sl = (string) ($c['slug'] ?? ''); $pf = (string) ($c['plugin'] ?? '');
    $items[] = $sl !== '' ? $sl : ($pf !== '' && dirname($pf) !== '.' ? dirname($pf) : basename($pf, '.php'));
  }
  $items = array_values(array_filter($items));
  if (!$items) $items = array_values(array_map('strval', (array) ($u['items'] ?? array())));
  $out[] = array('at' => (string) ($e['createdAt'] ?? ''), 'type' => (string) ($u['type'] ?? ''),
                 'items' => $items,
                 'status' => (string) ($e['status'] ?? ''));
}
echo 'VIZNUIT:' . json_encode($out) . PHP_EOL;
'''


def iso_epoch(v):
    try:
        return datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def evenements(srv, site):
    """Mises à jour relevées par l'extension, les plus récentes d'abord."""
    ligne = 'eval(base64_decode("%s"));' % base64.b64encode(PHP.encode()).decode()
    rc, out = A.run_wp_remote(srv, site, "eval " + A.sq(A.sq(ligne)) + " --skip-plugins --skip-themes", timeout=60)
    m = re.search(r"VIZNUIT:(\[.*\])", out or "")
    if rc != 0 or not m:
        return None
    try:
        ev = json.loads(m.group(1))
    except ValueError:
        return None
    return [e for e in ev if isinstance(e, dict)]


def elements_changes(domaine, depuis):
    """Slugs dont la version a VRAIMENT changé sur ce site depuis `depuis`."""
    vus = set()
    try:
        fh = open(CHANGES_PATH)
    except OSError:
        return vus
    with fh:
        for l in fh:
            try:
                c = json.loads(l)
                t = time.mktime(time.strptime(c["ts"], "%Y-%m-%d %H:%M"))
            except (ValueError, KeyError, TypeError):
                continue
            if c.get("domain") != domaine or t < depuis:
                continue
            k, det = c.get("kind"), str(c.get("detail") or "")
            if k in ("plugin_update", "theme_update"):
                vus.add(det.split(" ", 1)[0])
            elif k == "core":
                vus.add("wordpress-core")
    return vus


def maj_journalisees(domaine, depuis):
    """[(slug, genre, instant, version d'avant)] des mises à jour relevées par
    la collecte (version d'avant = "" quand le journal ne la donne pas).

    genre ∈ plugin, theme, core. Un retrait suivi d'un ajout sous le même nom
    est une mise à jour surprise en cours (WordPress supprime l'ancien dossier
    avant de poser le nouveau) : elle compte comme une mise à jour."""
    out, retraits = [], set()
    try:
        fh = open(CHANGES_PATH)
    except OSError:
        return out
    with fh:
        for l in fh:
            try:
                c = json.loads(l)
                t = time.mktime(time.strptime(c["ts"], "%Y-%m-%d %H:%M"))
            except (ValueError, KeyError, TypeError):
                continue
            if c.get("domain") != domaine or t < depuis:
                continue
            k, det = c.get("kind"), str(c.get("detail") or "")
            if k in ("plugin_update", "theme_update"):
                m = RE_MAJ.match(det)
                out.append((det.split(" ", 1)[0], "plugin" if k == "plugin_update" else "theme", t,
                            m.group(2) if m else ""))
            elif k == "core":
                out.append(("wordpress-core", "core", t, ""))
            elif k == "plugin_remove":
                retraits.add(det.replace("− extension ", "", 1).strip())
            elif k == "plugin_add":
                nom = det.replace("+ extension ", "", 1).strip().split(" ")[0]
                if nom in retraits:
                    out.append((nom, "plugin", t, ""))
    return out


def scan_rattrapage(srv_name, s, srv, site, majs):
    """Scan d'après mise à jour lancé PAR LE DASHBOARD → {rc, report, …}.

    Même commande que la fin d'une MAJ sûre : purge des caches, stabilisation,
    captures de toutes les pages suivies, verdict. Les composants mis à jour
    sont passés pour que VizProof leur attribue les écarts."""
    plugins = sorted({m for m, g, *_ in majs if g == "plugin"})
    themes = sorted({m for m, g, *_ in majs if g == "theme"})
    t0 = time.time()
    cmd = (A.viz_scan_after_update_cmd(plugins, themes) if A.viz_scan_after_supported(s)
           else "run vizproof scan --wait --format=json")
    rc, out = A.remote_bash(srv, site, cmd, timeout=600, max_out=None)
    if rc != 0 and A.VIZ_SCAN_AFTER_UPDATE_RE.search(out or ""):
        rc, out = A.remote_bash(srv, site, "run vizproof scan --wait --format=json",
                                timeout=600, max_out=None)
    A.append_log({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "source": RATTRAPAGE_SOURCE,
                  "server": srv_name, "domain": s.get("domain"), "action": "viz_scan",
                  "arg": ",".join(plugins + themes)[:200] or None, "rc": rc,
                  "duration_s": round(time.time() - t0, 1),
                  "output_tail": str(out or "")[-800:]})
    j = A.viz_json_tail(out) or {}
    return {"rc": rc, "report": A.viz_report_payload(j), "items": plugins + themes}


def retour_arriere(srv_name, s, majs, items):
    """Annule les mises à jour de la nuit que le scan en échec a suivies.

    Cibles : les éléments du scan (`items`) dont le journal donne la version
    d'avant. Chaque composant rétabli est RETIRÉ des mises à jour automatiques —
    sinon la même version repasserait la nuit suivante, casserait de nouveau, et
    serait annulée de nouveau. Le cœur ne se rétablit pas (migrations de base).
    → {"retablis": [...], "impossibles": [...]}"""
    dernier = {}
    for slug, genre, t, de in majs:
        if slug in items and (slug not in dernier or t >= dernier[slug][1]):
            dernier[slug] = (genre, t, de)
    retablis, impossibles = [], []
    for slug, (genre, _t, de) in sorted(dernier.items()):
        if genre == "core":
            impossibles.append({"slug": slug, "raison": "le cœur ne se rétablit pas automatiquement"})
            continue
        if not de:
            impossibles.append({"slug": slug, "raison": "version d'avant inconnue"})
            continue
        t0 = time.time()
        rc, out = A.plugin_rollback(srv_name, s.get("domain"), slug, version=de, kind=genre)
        A.append_log({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "source": RETOUR_SOURCE,
                      "server": srv_name, "domain": s.get("domain"),
                      "action": "theme_rollback" if genre == "theme" else "plugin_rollback",
                      "arg": f"{slug} {de}", "rc": rc, "duration_s": round(time.time() - t0, 1),
                      "output_tail": str(out or "")[-800:]})
        if rc != 0:
            raison = ("introuvable sur wordpress.org (extension premium ?)"
                      if re.search(r"not found|introuvable|could not|404", str(out or ""), re.I)
                      else str(out or "échec").strip().splitlines()[-1][:120] if str(out or "").strip() else "échec")
            impossibles.append({"slug": slug, "raison": raison})
            continue
        rcs, _ = A.auto_maj_suspendre(srv_name, s.get("domain"), slug, genre)
        retablis.append({"slug": slug, "genre": genre, "version": de, "suspendu": rcs == 0})
    return {"retablis": retablis, "impossibles": impossibles}


def pages_en_ecart(rapport):
    """[(page, formats, http)] des pages en échec ou en erreur HTTP."""
    par_page = {}
    for it in (rapport or {}).get("items") or []:
        if not isinstance(it, dict):
            continue
        http = it.get("http_status")
        if it.get("status") != "fail" and not (isinstance(http, int) and http >= 400):
            continue
        p = par_page.setdefault(str(it.get("page") or "?"), {"formats": [], "http": None})
        if it.get("viewport"):
            p["formats"].append(str(it["viewport"]))
        if isinstance(http, int) and http >= 400:
            p["http"] = http
    return [(n, sorted(set(v["formats"])), v["http"]) for n, v in par_page.items()]


def lire_rapport(srv_name, domaine):
    """Dernier rapport VizProof agrégé du site (dict) ou None."""
    try:
        _rc, j = A.viz_report_read(srv_name, domaine)
        rapport = (j or {}).get("report") if isinstance(j, dict) else None
    except Exception:
        rapport = None
    return rapport if isinstance(rapport, dict) else None


def examiner(srv_name, s, now, rattraper=False):
    """Bilan de la nuit pour un site, ou None s'il n'y a rien eu."""
    srv, site = A.find_site(srv_name, s.get("domain"))
    if not site:
        return None
    ev = evenements(srv, site) or []
    recents = [e for e in ev if (iso_epoch(e.get("at")) or 0) >= now - FENETRE_H * 3600]

    # Filet : une mise à jour journalisée que AUCUN scan du plugin n'a suivie.
    majs = maj_journalisees(s.get("domain"), now - FENETRE_H * 3600)
    rattrapage, non_couvertes = None, []
    if majs:
        premiere = min(t for _, _, t, _ in majs)
        couvert = any((iso_epoch(e.get("at")) or 0) >= premiere - COUVERTURE_S for e in recents)
        if not couvert:
            non_couvertes = sorted({m for m, *_ in majs})
            if rattraper:
                rattrapage = scan_rattrapage(srv_name, s, srv, site, majs)
    if not recents and not non_couvertes:
        return None

    items = sorted({i for e in recents for i in e.get("items") or []} | set(non_couvertes))
    sans_effet = []
    if recents:
        # Toute la fenêtre, pas « une heure avant le premier scan » : un scan
        # lancé APRÈS la mise à jour (rattrapage du dashboard, scan manuel)
        # ouvrait la comparaison après elle, et l'extension bel et bien mise à
        # jour sortait « sans effet ».
        changes = elements_changes(s.get("domain"), now - FENETRE_H * 3600)
        sans_effet = sorted({i for e in recents for i in e.get("items") or []} - changes)

    rapport = (rattrapage or {}).get("report") or lire_rapport(srv_name, s.get("domain"))
    ecarts = []
    if isinstance(rapport, dict) and not rapport.get("is_baseline"):
        ecarts = pages_en_ecart(rapport)

    # Retour arrière automatique (mode automatique, réglage du site) : seulement
    # sur une page en ÉCHEC ou en erreur HTTP, jamais sur une simple différence
    # « à vérifier » ; puis un scan de contrôle dit si le site est revenu.
    retour = None
    if ecarts and rattraper and A.auto_rollback_actif(s.get("domain")):
        retour = retour_arriere(srv_name, s, majs, set(items))
        if retour["retablis"]:
            apres = scan_rattrapage(srv_name, s, srv, site,
                                    [m for m in majs if m[0] in {x["slug"] for x in retour["retablis"]}])
            rapp2 = apres.get("report")
            retour["ecarts_apres"] = (len(pages_en_ecart(rapp2)) if isinstance(rapp2, dict)
                                      and not rapp2.get("is_baseline") else None)
    quand = [e["at"] for e in recents]
    if non_couvertes:
        quand.append(datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat())
    return {
        "site": s.get("kuma") or s.get("domain"), "domain": s.get("domain"), "server": srv_name,
        "at": max(quand), "nuits": len(recents),
        "items": items, "sans_effet": sans_effet,
        # Mises à jour que le plugin n'a pas scannées : rattrapées par le
        # dashboard (`rattrapage` = son code retour), ou seulement constatées
        # (`--dry-run`, plugin absent).
        "non_couvertes": non_couvertes,
        "rattrapage": (rattrapage or {}).get("rc"),
        "ecarts": [{"page": p, "formats": f, "http": h} for p, f, h in ecarts],
        "retour": retour,
        "run_id": (rapport or {}).get("run_id") if isinstance(rapport, dict) else None,
        "report_url": (rapport or {}).get("report_url") if isinstance(rapport, dict) else None,
    }


def reconfirmer(srv_name, ancien, now):
    """Écart d'un bilan précédent : toujours là ? → bilan reconduit, ou None.

    L'écart reste tant que le dernier rapport du site montre ENCORE des pages
    en échec. Un rapport plus récent sans échec (scan suivant, nouvelle
    référence acceptée) le lève."""
    rapport = lire_rapport(srv_name, ancien.get("domain"))
    if not isinstance(rapport, dict) or rapport.get("is_baseline"):
        return None
    ecarts = pages_en_ecart(rapport)
    if not ecarts:
        return None
    r = dict(ancien)
    r["ecarts"] = [{"page": p, "formats": f, "http": h} for p, f, h in ecarts]
    r["confirme"] = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()
    r["sans_effet"] = []          # la nuit d'origine est passée : seul l'écart reste
    return r


def texte_retour(r):
    """Alerte d'une mise à jour automatique ANNULÉE (retour arrière automatique)."""
    t = r.get("retour") or {}
    e = A.esc_html
    lignes = [f"↩️ <b>{e(r['domain'] or r['site'])}</b> — mise à jour automatique annulée",
              "VizProof a vu : " + ", ".join(e(x["page"]) for x in r["ecarts"])]
    for x in t.get("retablis") or []:
        lignes.append(f"• {e(x['slug'])} rétabli en {e(x['version'])}"
                      + (" · MAJ auto suspendue pour ce composant" if x.get("suspendu") else ""))
    for x in t.get("impossibles") or []:
        lignes.append(f"• {e(x['slug'])} : retour impossible — {e(x['raison'])}")
    ea = t.get("ecarts_apres")
    if t.get("retablis"):
        lignes.append("Après retour : " + ("plus aucune page en échec ✅" if ea == 0
                                            else f"{ea} page(s) encore en échec ⚠️" if ea
                                            else "contrôle impossible, à vérifier"))
    return "\n".join(lignes)


def texte_alerte(r):
    pages = [e["page"] + " : " + (f"HTTP {e['http']}" if e.get("http") else "écart")
             + (f" ({', '.join(f.lower() for f in e.get('formats') or [])})" if e.get("formats") else "")
             for e in r["ecarts"]]
    return A.texte_ecart_visuel(r["domain"] or r["site"], "écart visuel après la mise à jour automatique de la nuit",
                                mises_a_jour=r["items"], pages=pages, report_url=r.get("report_url") or "")


def main():
    dry = "--dry-run" in sys.argv[1:]
    now = time.time()
    precedent = (load_json(PATH, {}) or {}).get("sites") or {}
    # Sites que le dashboard a mis à jour lui-même cette nuit (maj_nuit.py,
    # 4 h) : la chaîne Contrôlée a déjà scanné, jugé et, au besoin, annulé.
    # Repasser derrière ferait un second retour arrière et une seconde alerte.
    faits = {d for d, r in ((load_json(MAJ_NUIT, {}) or {}).get("sites") or {}).items()
             if isinstance(r, dict) and now - (r.get("ts") or 0) < 12 * 3600
             and r.get("verdict") not in ("rien à faire", "bloqué", "simulation")}
    resultats = {}
    for srv_name, s in A.visible_sites():
        if s.get("via") == "rest" or s.get("preprod"):
            continue
        v = s.get("vizproof") or {}
        if not (v.get("connected") and v.get("has_cli")):
            continue
        cle = s.get("kuma") or s.get("domain")
        if s.get("domain") in faits:
            continue
        try:
            r = examiner(srv_name, s, now, rattraper=not dry)
            if not r and isinstance(precedent.get(cle), dict) and precedent[cle].get("ecarts"):
                r = reconfirmer(srv_name, precedent[cle], now)
        except Exception as e:           # un site en panne n'arrête pas les autres
            print(f"{s.get('domain')} : {type(e).__name__}: {e}")
            continue
        if r:
            resultats[r["site"]] = r
            rat = ""
            if r.get("non_couvertes"):
                rat = (f" · NON SCANNÉ par le plugin : {', '.join(r['non_couvertes'])}"
                       + (f" → rattrapage rc={r['rattrapage']}" if r.get("rattrapage") is not None else ""))
            print(f"{r['site']:28} {', '.join(r['items']):30} sans effet : {', '.join(r['sans_effet']) or '-':20} "
                  f"écarts : {', '.join(e['page'] for e in r['ecarts']) or '-'}{rat}"
                  + (" (reconduit)" if r.get("confirme") else ""))
    if dry:
        return
    save_json(PATH, {"generated_at": time.strftime("%Y-%m-%d %H:%M"), "sites": resultats})
    for r in resultats.values():
        if r["ecarts"] and not r.get("confirme"):
            A.alert(f"viz_nuit:{r['site']}:{r['at'][:10]}", "viz_anomaly",
                    texte_retour(r) if r.get("retour") else texte_alerte(r))
    A.attendre_envois()
    print(f"{len(resultats)} site(s) mis à jour cette nuit.")


if __name__ == "__main__":
    main()
