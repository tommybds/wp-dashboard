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

Lecture seule sur les sites. `--dry-run` affiche sans écrire ni alerter.
"""
import os, re, sys, json, time, base64, datetime

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA, load_json, save_json  # noqa: E402
import actions_server as A  # noqa: E402

PATH = os.path.join(DATA, "viz_nuit.json")
CHANGES_PATH = os.path.join(DATA, "changes.jsonl")
FENETRE_H = 26

# Historique de l'extension : les événements « update » récents, sans rien
# d'autre (ni jeton, ni réglage). JSON sur une ligne, repérée par son préfixe.
PHP = r'''
$h = array_values((array) get_option('vizproof_timeline_history', array()));
$out = array();
foreach (array_slice($h, 0, 12) as $e) {
  $e = (array) $e;
  if (($e['source'] ?? '') !== 'update') continue;
  $u = (array) ($e['update'] ?? array());
  $out[] = array('at' => (string) ($e['createdAt'] ?? ''), 'type' => (string) ($u['type'] ?? ''),
                 'items' => array_values(array_map('strval', (array) ($u['items'] ?? array()))),
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


def examiner(srv_name, s, now):
    """Bilan de la nuit pour un site, ou None s'il n'y a rien eu."""
    srv, site = A.find_site(srv_name, s.get("domain"))
    if not site:
        return None
    ev = evenements(srv, site)
    if not ev:
        return None
    recents = [e for e in ev if (iso_epoch(e.get("at")) or 0) >= now - FENETRE_H * 3600]
    if not recents:
        return None
    depuis = min(iso_epoch(e["at"]) for e in recents) - 3600
    changes = elements_changes(s.get("domain"), depuis)
    items = sorted({i for e in recents for i in e.get("items") or []})
    sans_effet = [i for i in items if i not in changes]

    rapport, ecarts = None, []
    try:
        _rc, j = A.viz_report_read(srv_name, s.get("domain"))
        rapport = (j or {}).get("report") if isinstance(j, dict) else None
    except Exception:
        rapport = None
    if isinstance(rapport, dict) and not rapport.get("is_baseline"):
        ecarts = pages_en_ecart(rapport)
    return {
        "site": s.get("kuma") or s.get("domain"), "domain": s.get("domain"), "server": srv_name,
        "at": max(e["at"] for e in recents), "nuits": len(recents),
        "items": items, "sans_effet": sans_effet,
        "ecarts": [{"page": p, "formats": f, "http": h} for p, f, h in ecarts],
        "report_url": (rapport or {}).get("report_url") if isinstance(rapport, dict) else None,
    }


def texte_alerte(r):
    pages = [e["page"] + " : " + (f"HTTP {e['http']}" if e.get("http") else "écart")
             + (f" ({', '.join(f.lower() for f in e.get('formats') or [])})" if e.get("formats") else "")
             for e in r["ecarts"]]
    return A.texte_ecart_visuel(r["domain"] or r["site"], "écart visuel après la mise à jour automatique de la nuit",
                                mises_a_jour=r["items"], pages=pages, report_url=r.get("report_url") or "")


def main():
    dry = "--dry-run" in sys.argv[1:]
    now = time.time()
    resultats = {}
    for srv_name, s in A.visible_sites():
        if s.get("via") == "rest" or s.get("preprod"):
            continue
        v = s.get("vizproof") or {}
        if not (v.get("connected") and v.get("has_cli")):
            continue
        try:
            r = examiner(srv_name, s, now)
        except Exception as e:           # un site en panne n'arrête pas les autres
            print(f"{s.get('domain')} : {type(e).__name__}: {e}")
            continue
        if r:
            resultats[r["site"]] = r
            print(f"{r['site']:28} {', '.join(r['items']):30} sans effet : {', '.join(r['sans_effet']) or '-':20} "
                  f"écarts : {', '.join(e['page'] for e in r['ecarts']) or '-'}")
    if dry:
        return
    save_json(PATH, {"generated_at": time.strftime("%Y-%m-%d %H:%M"), "sites": resultats})
    for r in resultats.values():
        if r["ecarts"]:
            A.alert(f"viz_nuit:{r['site']}:{r['at'][:10]}", "viz_anomaly", texte_alerte(r))
    print(f"{len(resultats)} site(s) mis à jour cette nuit.")


if __name__ == "__main__":
    main()
