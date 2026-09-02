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

Le tri (fenêtre de temps, domaines demandés) est fait CÔTÉ SERVEUR : la borne
est calculée par `date` dans le fuseau du serveur, et seules les lignes utiles
remontent. Chaque journal est plafonné à 20 000 lignes après filtrage ; le
dépassement est remonté dans `truncated` de data/php_errors.json, pour que
l'interface puisse indiquer une analyse partielle.

Usage :
    python3 phperrors.py            # collecte + agrégation → data/php_errors.json
    python3 phperrors.py --print    # idem avec un résumé lisible
    python3 phperrors.py --hours 48 # fenêtre d'analyse (défaut 24 h)
"""
import os, sys, re, inspect, datetime, collections
import concurrent.futures

# BASE reste calculé ici : il doit exister AVANT le sys.path.insert qui rend le
# dépôt importable (dashlib et actions_server en dépendent).
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA          # noqa: E402
from dashlib import save_json as _save_json   # noqa: E402
import actions_server as A  # noqa: E402  — import sûr : le serveur HTTP ne démarre que sous __main__

OUT_PATH = os.path.join(DATA, "php_errors.json")
FLEET_PATH = os.path.join(DATA, "fleet.json")

RAW_LINES = 400000   # borne de LECTURE par journal (avant filtrage)
CAP_LINES = 20000    # plafond de lignes REMONTÉES par journal (après filtrage)
MAX_PER_SITE = 60    # groupes d'erreurs conservés par site
DEFAULT_HOURS = 24
# Le filtrage par date se fait sur le serveur distant (fuseau du serveur). Le
# filtre local n'est qu'un garde-fou : on lui laisse 3 h de tolérance pour ne
# pas jeter des lignes légitimes à cause d'un décalage de fuseau ou d'horloge.
TZ_TOLERANCE_HOURS = 3
DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")

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


def save_json_atomic(path, obj, mode=0o600):
    """Écriture atomique en 0600 : php_errors.json cite des chemins de fichiers
    et des messages d'erreur du parc, il n'a rien à faire en lecture publique."""
    _save_json(path, obj, mode=mode, indent=None, fsync=True)


def parse_log_ts(raw, mode):
    """Horodatage d'un journal PHP → datetime, ou None si illisible.

    À ne pas confondre avec actions_server.parse_ts, qui lit un tout autre
    format (les horodatages des journaux du dashboard) : d'où le nom distinct."""
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


def build_script(domains, hours):
    """Script bash de collecte des journaux, filtré CÔTÉ SERVEUR.

    Trois filtres, dans cet ordre de sélectivité : « PHP message », les
    domaines demandés (motif « [pool <dom>] » sur Plesk, nom de fichier sur
    nginx), puis la fenêtre de temps. Celle-ci est construite par `date` SUR LE
    SERVEUR : ses journaux sont horodatés dans SON fuseau, calculer la borne
    depuis le fuseau du dashboard décalait la fenêtre d'autant.

    La sortie est plafonnée à CAP_LINES lignes par journal APRÈS filtrage ; le
    dépassement est signalé par « @@TRONQUE@@<fichier>|<raison> » pour que
    l'interface puisse dire que l'analyse est partielle.
    """
    liste = "\n".join(d for d in domains if DOMAIN_RE.match(str(d or "")))
    return f"""#!/bin/bash
RAW={RAW_LINES}
CAP={CAP_LINES}
HOURS={int(hours)}
TMP=$(mktemp -d /tmp/.wpdash-log.XXXXXX) || exit 91
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
find /tmp -maxdepth 1 -name '.wpdash-log.*' -mmin +1440 -exec rm -rf {{}} + 2>/dev/null

cat > "$TMP/doms" <<'@@DOMS@@'
{liste}
@@DOMS@@

# Fenêtre de temps : un motif ancré par heure, dans le fuseau DU SERVEUR.
# LC_ALL=C : php-fpm écrit le mois en anglais quelle que soit la locale.
TSOK=1
if LC_ALL=C date -d "-1 hours" +%Y >/dev/null 2>&1; then
  i=0
  while [ "$i" -le "$HOURS" ]; do
    LC_ALL=C date -d "-$i hours" "+^\\[%d-%b-%Y %H:" >> "$TMP/ts"
    LC_ALL=C date -d "-$i hours" "+^%Y/%m/%d %H:" >> "$TMP/ts"
    i=$((i+1))
  done
else
  TSOK=0            # date(1) sans -d : filtrage de date laissé au dashboard
fi
echo "@@FENETRE@@$TSOK"

fenetre() {{ if [ "$TSOK" = "1" ]; then grep -f "$TMP/ts"; else cat; fi; }}

# $1 = fichier, $2 = commande de filtrage supplémentaire, $3 = préfixe de sortie
extraire() {{
  local f="$1" pfx="$3"
  tail -n "$RAW" "$f" 2>/dev/null | grep -F "PHP message" | eval "$2" | fenetre > "$TMP/cur"
  local n
  n=$(wc -l < "$TMP/cur" 2>/dev/null || echo 0)
  if [ "$n" -gt "$CAP" ]; then
    printf '@@TRONQUE@@%s|%s lignes retenues, plafond %s\\n' "$f" "$n" "$CAP"
    tail -n "$CAP" "$TMP/cur" | sed "s|^|$pfx|"
  else
    sed "s|^|$pfx|" "$TMP/cur"
  fi
}}

# Plesk : un journal par version de PHP, chaque ligne étiquetée [pool <domaine>].
sed -e 's/^/[pool /' -e 's/$/]/' "$TMP/doms" | grep -v '^\\[pool \\]$' > "$TMP/pools"
if [ -s "$TMP/pools" ]; then
  for f in /var/log/plesk-php*-fpm/error.log; do
    [ -f "$f" ] || continue
    extraire "$f" 'grep -F -f "$TMP/pools"' '@@PLESK@@'
  done
fi

# nginx / proxy Plesk : un journal par domaine — on n'ouvre que ceux demandés.
while IFS= read -r d; do
  [ -n "$d" ] || continue
  for f in "/var/log/nginx/$d.error.log" "/var/log/nginx/www.$d.error.log" \\
           "/var/www/vhosts/system/$d/logs/proxy_error_log"; do
    [ -f "$f" ] || continue
    extraire "$f" cat "@@NGINX@@$d\\t"
  done
done < "$TMP/doms"
echo "@@FIN@@"
"""


def _run_remote(server, script, timeout=300):
    """Exécute le script distant SANS troncature de la sortie.

    `actions_server.run_remote_script` tronque par défaut à 6000 caractères —
    soit une trentaine de lignes de journal, silencieusement, le marqueur
    « @@FIN@@ » survivant à la coupe. On demande donc explicitement une sortie
    entière (max_out=None) ; le repli couvre une version antérieure du module.
    """
    try:
        supporte = "max_out" in inspect.signature(A.run_remote_script).parameters
    except (TypeError, ValueError):
        supporte = True
    if supporte:
        return A.run_remote_script(server, script, timeout=timeout, max_out=None)
    return A.run_remote_script(server, script, timeout=timeout)


def remote_scan(server, domains, hours):
    """Extrait les lignes d'erreur PHP d'un serveur → (lignes, erreur, tronqués)."""
    # Le tri par date est fait sur le serveur ; ce filtre local n'est qu'un
    # garde-fou, d'où la tolérance de TZ_TOLERANCE_HOURS (fuseaux, horloges).
    since = (datetime.datetime.now()
             - datetime.timedelta(hours=hours + TZ_TOLERANCE_HOURS))
    rc, out = _run_remote(server, build_script(domains, hours), timeout=300)
    out = out or ""
    if "@@FIN@@" not in out:
        # Sans le marqueur final, la sortie est partielle (script interrompu,
        # sortie tronquée en amont…) : mieux vaut le dire que compter à moitié.
        return [], f"sortie incomplète, marqueur @@FIN@@ absent (rc {rc}, {len(out)} caractères)", []
    if rc != 0:
        return [], f"lecture impossible (rc {rc})", []

    if "@@FENETRE@@0" in out:
        # `date -d` absent (BusyBox…) : le filtrage de date retombe sur le
        # dashboard, avec la tolérance de fuseau ci-dessus.
        print(f"[{server.get('name')}] date(1) sans -d : fenêtre filtrée localement", flush=True)

    connus = set(domains)
    tronques = []
    lignes = []
    for brut in out.splitlines():
        if brut.startswith("@@TRONQUE@@"):
            fichier, _, raison = brut[11:].partition("|")
            tronques.append({"file": fichier, "reason": raison})
            continue
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
        ts = parse_log_ts(m.group("ts"), mode)
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
    return lignes, None, tronques


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

    resultats, erreurs, tronques = [], {}, {}

    def un_serveur(nom):
        """Ne lève jamais : un serveur lent (subprocess.TimeoutExpired) ou en
        erreur ne doit pas emporter la passe entière — même règle que
        collect.ssh_collect."""
        try:
            return nom, remote_scan(servers[nom], par_serveur[nom], hours)
        except Exception as e:
            return nom, ([], f"{type(e).__name__}: {e}"[:300], [])

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(par_serveur)))) as pool:
        for nom, (lignes, err, coupes) in pool.map(un_serveur, list(par_serveur)):
            if err:
                erreurs[nom] = err
            if coupes:
                tronques[nom] = coupes
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
        # {serveur: [{file, reason}]} — journaux dont l'analyse est partielle
        # (plafond de lignes atteint) : l'interface peut le signaler.
        "truncated": tronques,
        "sites": sites,
    }
    save_json_atomic(OUT_PATH, res)
    print(f"{res['sites_with_errors']} site(s) avec erreurs sur {hours} h — "
          f"{res['total']} occurrence(s), dont {res['fatals']} fatale(s)"
          + (f" | serveurs en échec : {list(erreurs)}" if erreurs else "")
          + (f" | analyse partielle : {list(tronques)}" if tronques else ""))
    if "--print" in args:
        for s in sites[:15]:
            print(f"\n  {s['domain']} — {s['total']} occurrence(s)")
            for g in s["groups"][:5]:
                print(f"    [{g['severity']:13}] ×{g['count']:<5} {g['message'][:70]}")
                if g["short"]:
                    print(f"                   {g['short']}:{g['line']}")


if __name__ == "__main__":
    main()
