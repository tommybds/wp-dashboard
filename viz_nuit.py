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
FENETRE_H = 26
# Un scan du plugin « couvre » une mise à jour journalisée s'il a eu lieu au plus
# tard 3 h avant la ligne de journal : la collecte (toutes les 30 min) relève la
# nouvelle version APRÈS la mise à jour, jamais avant.
COUVERTURE_S = 3 * 3600
RATTRAPAGE_SOURCE = "rattrapage-nuit"

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


def maj_journalisees(domaine, depuis):
    """[(slug, genre, instant)] des mises à jour relevées par la collecte.

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
                out.append((det.split(" ", 1)[0], "plugin" if k == "plugin_update" else "theme", t))
            elif k == "core":
                out.append(("wordpress-core", "core", t))
            elif k == "plugin_remove":
                retraits.add(det.replace("− extension ", "", 1).strip())
            elif k == "plugin_add":
                nom = det.replace("+ extension ", "", 1).strip().split(" ")[0]
                if nom in retraits:
                    out.append((nom, "plugin", t))
    return out


def scan_rattrapage(srv_name, s, srv, site, majs):
    """Scan d'après mise à jour lancé PAR LE DASHBOARD → {rc, report, …}.

    Même commande que la fin d'une MAJ sûre : purge des caches, stabilisation,
    captures de toutes les pages suivies, verdict. Les composants mis à jour
    sont passés pour que VizProof leur attribue les écarts."""
    plugins = sorted({m for m, g, _ in majs if g == "plugin"})
    themes = sorted({m for m, g, _ in majs if g == "theme"})
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
        premiere = min(t for _, _, t in majs)
        couvert = any((iso_epoch(e.get("at")) or 0) >= premiere - COUVERTURE_S for e in recents)
        if not couvert:
            non_couvertes = sorted({m for m, _, _ in majs})
            if rattraper:
                rattrapage = scan_rattrapage(srv_name, s, srv, site, majs)
    if not recents and not non_couvertes:
        return None

    items = sorted({i for e in recents for i in e.get("items") or []} | set(non_couvertes))
    sans_effet = []
    if recents:
        depuis = min(iso_epoch(e["at"]) for e in recents) - 3600
        changes = elements_changes(s.get("domain"), depuis)
        sans_effet = sorted({i for e in recents for i in e.get("items") or []} - changes)

    rapport = (rattrapage or {}).get("report") or lire_rapport(srv_name, s.get("domain"))
    ecarts = []
    if isinstance(rapport, dict) and not rapport.get("is_baseline"):
        ecarts = pages_en_ecart(rapport)
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
    resultats = {}
    for srv_name, s in A.visible_sites():
        if s.get("via") == "rest" or s.get("preprod"):
            continue
        v = s.get("vizproof") or {}
        if not (v.get("connected") and v.get("has_cli")):
            continue
        cle = s.get("kuma") or s.get("domain")
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
            A.alert(f"viz_nuit:{r['site']}:{r['at'][:10]}", "viz_anomaly", texte_alerte(r))
    print(f"{len(resultats)} site(s) mis à jour cette nuit.")


if __name__ == "__main__":
    main()
