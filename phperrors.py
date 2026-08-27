#!/usr/bin/env python3
"""Surveillance des erreurs PHP du parc — lecture des journaux existants.

Aucune modification des sites : on lit les journaux que le serveur écrit déjà.

  * Plesk : /var/log/plesk-php<XX>-fpm/error.log, chaque ligne étant étiquetée
    « [pool <domaine>] » — un seul fichier porte donc les erreurs de tous les
    sites d'une même version de PHP.
  * WordOps / VPS : /var/log/nginx/<domaine>.error.log, où PHP-FPM renvoie ses
    messages via « FastCGI sent in stderr ».
  * Repli : le proxy_error_log du vhost, et wp-content/debug.log s'il existe.

Un seul passage par SERVEUR (et non par site) : lire un journal de 11 Mo une
fois pour 35 sites, plutôt que 35 fois.

Usage :
    python3 phperrors.py            # collecte + agrégation → data/php_errors.json
    python3 phperrors.py --print    # idem avec un résumé lisible
    python3 phperrors.py --hours 48 # fenêtre d'analyse (défaut 24 h)
"""
import os, sys, re, json, datetime, collections
import concurrent.futures

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
OUT_PATH = os.path.join(DATA, "php_errors.json")
FLEET_PATH = os.path.join(DATA, "fleet.json")

sys.path.insert(0, BASE)
import actions_server as A  # import sûr : le serveur HTTP ne démarre que sous __main__

TAIL_LINES = 60000   # profondeur de lecture par journal
MAX_PER_SITE = 60    # groupes d'erreurs conservés par site
DEFAULT_HOURS = 24

# Gravités, de la plus grave à la plus anodine.
SEV_RANK = {"Fatal error": 4, "Parse error": 4, "Warning": 3,
            "Deprecated": 2, "Notice": 1, "Strict Standards": 1}

# Plesk : [27-Aug-2026 00:00:54] WARNING: [pool elwave.fr] child 123 said into
# stderr: "PHP message: PHP Warning:  msg in /chemin/fichier.php on line 42"
RE_PLESK = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\w+:\s+\[pool (?P<dom>[^\]]+)\].*?"
    r"PHP message:\s*PHP\s+(?P<sev>Fatal error|Parse error|Warning|Notice|Deprecated|Strict Standards):\s*"
    r"(?P<msg>.*?)(?:\s+in\s+(?P<file>/[^\s]+?)\s+on line\s+(?P<line>\d+))?[\"']?\s*$")

# nginx : 2026/08/20 19:11:42 [error] 5172#5172: *47 FastCGI sent in stderr:
# "PHP message: PHP Warning:  msg in /chemin/fichier.php on line 42" while ...
RE_NGINX = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?"
    r"PHP message:\s*PHP\s+(?P<sev>Fatal error|Parse error|Warning|Notice|Deprecated|Strict Standards):\s*"
    r"(?P<msg>.*?)(?:\s+in\s+(?P<file>/[^\s]+?)\s+on line\s+(?P<line>\d+))?(?:\"|\s+while\s|$)")


def parse_ts(raw, mode):
    """Horodatage du journal → datetime, ou None si illisible."""
    raw = (raw or "").strip()
    try:
        if mode == "nginx":
            return datetime.datetime.strptime(raw, "%Y/%m/%d %H:%M:%S")
        # Plesk : « 27-Aug-2026 00:00:54 », mois en anglais quelle que soit la locale
        jour, mois, reste = raw.split("-", 2)
        mois_num = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].index(mois[:3]) + 1
        annee, heure = reste.split(" ", 1)
        h, m, sec = heure.split(":")
        return datetime.datetime(int(annee), mois_num, int(jour), int(h), int(m), int(sec))
    except (ValueError, IndexError):
        return None


def normalise(msg):
    """Neutralise ce qui varie d'une occurrence à l'autre, pour regrouper.

    Sans cela, « Undefined array key 417 » et « ... 993 » comptent pour deux
    erreurs distinctes alors que c'est le même défaut.
    """
    m = str(msg or "").strip().strip('"')
    m = re.sub(r"\b\d{3,}\b", "N", m)
    m = re.sub(r"0x[0-9a-f]+", "0xN", m, flags=re.I)
    m = re.sub(r"\s+", " ", m)
    return m[:300]


def remote_scan(server, domains, hours):
    """Extrait les lignes d'erreur PHP d'un serveur → liste de dicts."""
    since = datetime.datetime.now() - datetime.timedelta(hours=hours)
    # Un seul script par serveur : il déverse les journaux pertinents avec un
    # préfixe indiquant leur format, l'analyse se fait ensuite côté dashboard.
    script = f"""#!/bin/bash
T={TAIL_LINES}
for f in /var/log/plesk-php*-fpm/error.log; do
  [ -f "$f" ] || continue
  tail -n $T "$f" 2>/dev/null | grep -F "PHP message" | sed 's/^/@@PLESK@@/'
done
for f in /var/log/nginx/*.error.log /var/www/vhosts/system/*/logs/proxy_error_log; do
  [ -f "$f" ] || continue
  base=$(basename "$f" .error.log)
  case "$f" in
    */vhosts/system/*) base=$(basename "$(dirname "$(dirname "$f")")") ;;
  esac
  tail -n $T "$f" 2>/dev/null | grep -F "PHP message" | sed "s|^|@@NGINX@@$base\\t|"
done
echo "@@FIN@@"
"""
    rc, out = A.run_remote_script(server, script, timeout=300)
    if rc != 0 and "@@FIN@@" not in (out or ""):
        return [], f"lecture impossible (rc {rc})"

    connus = set(domains)
    lignes = []
    for brut in (out or "").splitlines():
        if brut.startswith("@@PLESK@@"):
            m = RE_PLESK.match(brut[9:])
            if not m:
                continue
            dom, mode = m.group("dom"), "plesk"
        elif brut.startswith("@@NGINX@@"):
            reste = brut[9:]
            dom, _, contenu = reste.partition("\t")
            m = RE_NGINX.match(contenu)
            if not m:
                continue
            mode = "nginx"
        else:
            continue
        if dom not in connus:
            continue
        ts = parse_ts(m.group("ts"), mode)
        if ts is None or ts < since:
            continue
        msg, fichier = m.group("msg") or "", m.group("file") or ""
        ligne_no = int(m.group("line") or 0)
        # Le groupe « in <fichier> on line <n> » étant optionnel, le message
        # absorbe parfois le chemin : on le retire pour ne pas le voir deux fois
        # et pour que deux occurrences du même défaut se regroupent.
        if not fichier:
            m2 = re.search(r"\s+in\s+(/[^\s]+?)\s+on line\s+(\d+)", msg)
            if m2:
                fichier, ligne_no = m2.group(1), int(m2.group(2))
        if not fichier:
            # Exceptions non capturées (PHP 7+) : « ... in /chemin/f.php:123 »,
            # avec deux-points et non « on line N », suivi de la pile d'appels.
            m3 = re.search(r"\s+in\s+(/[^\s:]+):(\d+)", msg)
            if m3:
                fichier, ligne_no = m3.group(1), int(m3.group(2))
                msg = msg[:m3.start()]
        if fichier:
            msg = re.sub(r"\s+in\s+" + re.escape(fichier) + r"\s+on line\s+\d+.*$", "", msg)
            msg = re.sub(r"\s+Stack trace:.*$", "", msg, flags=re.S)
        lignes.append({
            "domain": dom, "ts": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": m.group("sev"), "message": normalise(msg),
            "file": fichier, "line": ligne_no,
        })
    return lignes, None


def agrege(lignes):
    """Regroupe par (site, fichier, ligne, message) avec compteur et bornes."""
    par_site = collections.defaultdict(dict)
    for e in lignes:
        cle = (e["file"], e["line"], e["message"], e["severity"])
        g = par_site[e["domain"]].get(cle)
        if g is None:
            par_site[e["domain"]][cle] = {
                "severity": e["severity"], "message": e["message"],
                "file": e["file"], "line": e["line"],
                "count": 1, "first": e["ts"], "last": e["ts"],
            }
        else:
            g["count"] += 1
            g["first"] = min(g["first"], e["ts"])
            g["last"] = max(g["last"], e["ts"])
    sites = []
    for dom, groupes in par_site.items():
        lst = sorted(groupes.values(),
                     key=lambda g: (-SEV_RANK.get(g["severity"], 0), -g["count"]))
        sites.append({
            "domain": dom, "total": sum(g["count"] for g in lst),
            "groups": lst[:MAX_PER_SITE],
            "worst": lst[0]["severity"] if lst else "",
            "fatals": sum(g["count"] for g in lst
                          if g["severity"] in ("Fatal error", "Parse error")),
        })
    sites.sort(key=lambda s: (-SEV_RANK.get(s["worst"], 0), -s["total"]))
    return sites


def shorten(path, docroots):
    """Chemin raccourci pour l'affichage : wp-content/plugins/x/y.php."""
    for d in docroots:
        if d and path.startswith(d):
            return path[len(d):].lstrip("/")
    i = path.find("/wp-content/")
    return path[i + 1:] if i >= 0 else path


def main():
    hours = DEFAULT_HOURS
    args = sys.argv[1:]
    if "--hours" in args:
        try:
            hours = max(1, min(720, int(args[args.index("--hours") + 1])))
        except (IndexError, ValueError):
            pass

    fleet = A.load_json(FLEET_PATH, {"servers": []})
    servers = {s["name"]: s for s in A.servers_list()}
    # Domaines visibles par serveur, et docroots pour raccourcir les chemins.
    par_serveur, docroots = collections.defaultdict(list), []
    for srv in fleet.get("servers", []):
        for site in srv.get("sites", []):
            if not A.site_visible(site) or srv.get("name") not in servers:
                continue
            par_serveur[srv["name"]].append(site.get("domain"))
            if site.get("path"):
                docroots.append(site["path"])

    resultats, erreurs = [], {}

    def un_serveur(nom):
        return nom, remote_scan(servers[nom], par_serveur[nom], hours)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(par_serveur)))) as pool:
        for nom, (lignes, err) in pool.map(un_serveur, list(par_serveur)):
            if err:
                erreurs[nom] = err
            resultats.extend(lignes)

    sites = agrege(resultats)
    for s in sites:
        for g in s["groups"]:
            g["short"] = shorten(g["file"], docroots)

    res = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "window_hours": hours,
        "sites_with_errors": len(sites),
        "total": sum(s["total"] for s in sites),
        "fatals": sum(s["fatals"] for s in sites),
        "servers_failed": erreurs,
        "sites": sites,
    }
    A.save_json(OUT_PATH, res)
    print(f"{res['sites_with_errors']} site(s) avec erreurs sur {hours} h — "
          f"{res['total']} occurrence(s), dont {res['fatals']} fatale(s)"
          + (f" | serveurs en échec : {list(erreurs)}" if erreurs else ""))
    if "--print" in args:
        for s in sites[:15]:
            print(f"\n  {s['domain']} — {s['total']} occurrence(s)")
            for g in s["groups"][:5]:
                print(f"    [{g['severity']:13}] ×{g['count']:<5} {g['message'][:70]}")
                if g["short"]:
                    print(f"                   {g['short']}:{g['line']}")


if __name__ == "__main__":
    main()
