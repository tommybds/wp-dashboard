#!/usr/bin/env python3
"""Collecteur parc WordPress — inventaire wp-cli en SSH.

Écrit data/fleet.json (+ copie public/). Sécurité : wp-cli en su utilisateur du
site (jamais root sauf docroot root), --skip-plugins --skip-themes en lecture.

Serveurs sans root (mutualisés type Infomaniak) : entrée servers.json avec
"user": "<login>" et "no_su": true — wp-cli tourne alors directement sous
l'utilisateur SSH (pas de su, pas de --allow-root).

Sites sans aucun accès SSH : listés dans data/rest_sites.json et interrogés via
l'agent (mu-plugin) sur /wp-json/sumotori-dash/v1/inventory, requête signée HMAC.
Ils sont rangés dans un serveur virtuel « rest » et portent via="rest".
"""
import json, subprocess, sys, os, re, time, datetime, socket, hmac, hashlib
import concurrent.futures
import urllib.error, urllib.parse, urllib.request
from urllib.parse import urlparse

# Briques communes à tous les scripts du dépôt (cf. dashlib.py). PATTERN_RE
# n'est plus utilisé directement ici (valid_pattern s'en charge) mais reste un
# attribut du module, comme avant la mise en commun.
from dashlib import (BASE, DATA_DIR as DATA, PUBLIC_DIR as PUB,  # noqa: F401
                     PATH_PATTERN_RE as PATTERN_RE, load_json, norm_domain,
                     site_key, sq, valid_path_pattern as valid_pattern)
from dashlib import save_json as _save_json
from dashboard_config import CONFIG
KEY = CONFIG["ssh_key"]                # clé SSH par défaut (surchargée par serveur dans servers.json)
KUMA_STATUS = CONFIG["kuma_status_url"]  # JSON de la status page Kuma du parc
KUMA_CONTAINER = CONFIG["kuma_container"]
DEFAULT_PARALLEL = 4   # sites collectés simultanément sur un même serveur
MAX_SERVERS_PARALLEL = 8  # serveurs interrogés simultanément
KUMA_DB = CONFIG["kuma_db"]  # chemin de la base Kuma DANS le conteneur
# ---- collecte REST (agent distant, aucun SSH) ----
REST_SITES_PATH = os.path.join(DATA, "rest_sites.json")
SECRETS_PATH = os.path.join(DATA, "site_secrets.json")
AGENT_NS = "sumotori-dash/v1"
USER_AGENT = "SumotoriDashboard/1.0"
REST_TIMEOUT = 20
MAX_SUBSITES = 50  # plafond de sous-sites collectés par réseau multisite

REMOTE_SCRIPT = r'''#!/bin/bash
limit="${1:-0}"; match="${2:-}"; NOSU="${3:-0}"; PAR="${4:-4}"; shift 4 || true
WPBIN=$(command -v wp || true)
count=0
# `wait -n` (attente d'UN job) n'existe qu'à partir de bash 4.3 ; sinon on vide le lot.
HAVE_WAITN=0
if [ -n "${BASH_VERSINFO[0]:-}" ]; then
  if [ "${BASH_VERSINFO[0]}" -gt 4 ] 2>/dev/null; then HAVE_WAITN=1
  elif [ "${BASH_VERSINFO[0]}" -eq 4 ] 2>/dev/null && [ "${BASH_VERSINFO[1]:-0}" -ge 3 ] 2>/dev/null; then HAVE_WAITN=1
  fi
fi

# Exécute une commande shell côté site : directement quand l'utilisateur SSH est
# déjà le propriétaire du site (mutualisé, NOSU=1), sinon via su vers OWN.
asuser() {
  if [ "$NOSU" = "1" ]; then
    timeout 75 bash -c "$1" 2>&1
  else
    timeout 75 su -s /bin/bash "$OWN" -c "$1" 2>&1
  fi
}

# Répertoire de cache wp-cli du compte $1.
#
# Sécurité : surtout PAS un chemin prévisible dans /tmp partagé (un voisin du
# mutualisé pourrait l'y créer d'avance et empoisonner ce que wp-cli y lit).
# On privilégie le HOME du compte ; à défaut, un répertoire créé par mktemp
# (nom imprévisible) pour la durée de l'exécution.
wp_cache_dir() {
  local own="$1" home=""
  if [ "$NOSU" = "1" ]; then
    home="${HOME:-}"
  else
    home=$(getent passwd "$own" 2>/dev/null | cut -d: -f6)
    [ -n "$home" ] || home=$(awk -F: -v u="$own" '$1==u{print $6}' /etc/passwd 2>/dev/null)
  fi
  if [ -n "$home" ] && [ -d "$home" ]; then
    printf '%s/.wp-cli/cache' "$home"
  elif [ -n "$CACHEROOT" ]; then
    printf '%s/%s' "$CACHEROOT" "$own"
  else
    printf '%s/cache' "$OUTDIR"
  fi
}

# $1 = options de chargement (--skip-plugins --skip-themes, ou vide), puis la commande wp.
wp_call() {
  [ -n "$WPBIN" ] || { echo "wp-cli absent du serveur"; return 90; }
  local skips="$1"; shift
  local args="$*"
  local extra=""
  [ "$NOSU" != "1" ] && [ "$OWN" = "root" ] && extra="--allow-root"
  local base="cd '$D' && env WP_CLI_CACHE_DIR='$CACHE' WP_CLI_PHP_ARGS='-d display_errors=0 -d error_reporting=0' HTTP_HOST='$DOM' SERVER_NAME='$DOM'"
  local out rc
  out=$(asuser "$base wp $args $extra $skips --no-color"); rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qiE 'requires PHP|PHP version|Parse error|syntax error, unexpected'; then
    local php
    for php in /opt/plesk/php/7.4/bin/php /opt/plesk/php/8.0/bin/php /opt/plesk/php/8.1/bin/php /opt/plesk/php/8.2/bin/php /opt/plesk/php/8.3/bin/php; do
      [ -x "$php" ] || continue
      out=$(asuser "$base $php -d display_errors=0 -d error_reporting=0 $WPBIN $args $extra $skips --no-color"); rc=$?
      [ $rc -eq 0 ] && break
    done
  fi
  printf '%s' "$out"; return $rc
}

# lecture d'inventaire : plugins et thèmes non chargés (rapide et insensible aux fatals)
run_wp() { wp_call "--skip-plugins --skip-themes" "$@"; }
# variante sans skip : indispensable pour une commande CLI fournie par un plugin
run_wp_plugins() { wp_call "" "$@"; }

# emitfield <nom> <commande wp…> ; un nom préfixé par « + » charge les plugins.
emitfield() {
  local name="$1"; shift
  local withplugins=0
  case "$name" in
    +*) withplugins=1; name="${name#+}" ;;
  esac
  printf '@@F@@%s\n' "$name"
  local out rc
  if [ "$withplugins" = "1" ]; then out=$(run_wp_plugins "$@"); else out=$(run_wp "$@"); fi
  rc=$?
  printf '%s\n' "$out"
  printf '@@ENDF@@%s\n' "$rc"
}

# Inventaire d'UN site. Les variables locales sont visibles des fonctions appelées
# (portée dynamique bash), ce qui permet d'exécuter plusieurs sites en parallèle,
# chacun dans son propre sous-shell écrivant dans son propre fichier.
emit_site() {
  local D="$1" DOM="$2" OWN="$3"
  local CACHE
  CACHE=$(wp_cache_dir "$OWN")
    # Séparateur \037 (unit separator) : un nom de répertoire peut contenir « | ».
    printf '@@SITE@@%s\037%s\037%s\n' "$DOM" "$D" "$OWN"
    emitfield core_version core version
    emitfield core_update core check-update --format=json --fields=version,update_type
    emitfield siteurl option get siteurl
    emitfield blogname option get blogname
    emitfield plugins plugin list --format=json --fields=name,status,version,update_version,update
    emitfield themes theme list --format=json --fields=name,status,version,update_version,update
    emitfield auto_update_plugins option get auto_update_plugins --format=json
    emitfield admins user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=json
    emitfield updraft_interval option get updraft_interval
    emitfield updraft_interval_db option get updraft_interval_database
    emitfield updraft_retain option get updraft_retain
    emitfield updraft_retain_db option get updraft_retain_db
    emitfield updraft_service option get updraft_service --format=json
    emitfield updraft_extrarules option get updraft_retain_extrarules --format=json
    emitfield updraft_last option get updraft_last_backup --format=json
    emitfield +vizproof vizproof status --format=json
    emitfield cliinfo cli info
}

# Collecte des sites : PAR en parallèle, chacun dans un fichier temporaire pour que
# les blocs @@SITE@@ ne s'entrelacent jamais ; concaténés dans l'ordre à la fin.

# Ménage : un timeout côté dashboard coupe la session SSH (SIGHUP) et peut
# laisser des répertoires derrière lui. On balaie ceux de plus de 24 h.
find /tmp -maxdepth 1 -name '.wpdash.*' -mmin +1440 -exec rm -rf {} + 2>/dev/null
find /tmp -maxdepth 1 -name '.wpdash-cache.*' -mmin +1440 -exec rm -rf {} + 2>/dev/null

OUTDIR=$(mktemp -d /tmp/.wpdash.XXXXXX) || exit 91
# Cache wp-cli de repli, partagé entre les comptes sans HOME utilisable : nom
# imprévisible (mktemp) et bit collant, comme /tmp.
CACHEROOT=$(mktemp -d /tmp/.wpdash-cache.XXXXXX 2>/dev/null) || CACHEROOT=""
[ -n "$CACHEROOT" ] && chmod 1777 "$CACHEROOT" 2>/dev/null
# HUP/INT/TERM en plus de EXIT : sans cela une session SSH coupée laisse le
# répertoire temporaire sur le serveur distant.
trap 'rm -rf "$OUTDIR" ${CACHEROOT:+"$CACHEROOT"}' EXIT HUP INT TERM
jobs_running=0

for pat in "$@"; do
  for cfg in $pat/wp-load.php; do
    [ -f "$cfg" ] || continue
    D=$(dirname "$cfg"); DOM=$(basename "$(dirname "$D")"); OWN=$(stat -c %U "$D" 2>/dev/null || echo root)
    [ -n "$match" ] && [ "$DOM" != "$match" ] && continue
    if [ "$limit" != "0" ] && [ "$count" -ge "$limit" ]; then break 2; fi
    count=$((count+1))
    emit_site "$D" "$DOM" "$OWN" > "$OUTDIR/$(printf '%04d' "$count").out" 2>/dev/null &
    jobs_running=$((jobs_running+1))
    if [ "$jobs_running" -ge "$PAR" ]; then
      if [ "$HAVE_WAITN" = "1" ]; then
        wait -n 2>/dev/null
        jobs_running=$((jobs_running-1))
      else
        wait            # bash < 4.3 : pas de wait -n, on vide le lot
        jobs_running=0
      fi
    fi
  done
done
wait

for f in "$OUTDIR"/*.out; do
  [ -f "$f" ] || continue
  cat "$f"
done
echo '@@DONE@@'
'''

CORE_FIELDS = {"core_version", "siteurl", "plugins"}


# load_json, sq (quotage shell : sans lui, un motif contenant une apostrophe
# s'exécute en root sur les serveurs du parc), PATTERN_RE et valid_pattern
# viennent de dashlib — l'API valide les motifs de docroot avec la MÊME règle.


def effective_patterns(server, extra):
    """Motifs de docroots du serveur, filtrés : tout ce qui sort de la forme
    attendue est rejeté (et signalé) plutôt que transmis au shell distant."""
    pats = list(server.get("patterns") or [])
    pats += [d.get("path") for d in extra
             if isinstance(d, dict) and d.get("server") == server.get("name")]
    out = []
    for p in pats:
        if valid_pattern(p):
            out.append(str(p))
        else:
            print(f"[{server.get('name')}] motif de docroot rejeté : {p!r}", flush=True)
    return out


def ssh_user(server):
    """Utilisateur SSH du serveur (root par défaut ; login du site sur les mutualisés)."""
    return str(server.get("user") or "root")


def ssh_collect(server, extra, limit=0, match=""):
    pats = " ".join(sq(p) for p in effective_patterns(server, extra))
    nosu = "1" if server.get("no_su") else "0"  # mutualisé : pas de su, pas de --allow-root
    # Sites collectés en parallèle sur le serveur distant. Volontairement modéré :
    # ces machines hébergent de la production, on ne veut pas saturer leur CPU.
    par = to_int(server.get("parallel"), DEFAULT_PARALLEL) or DEFAULT_PARALLEL
    remote_cmd = f"bash -s -- {sq(to_int(limit, 0) or 0)} {sq(match)} {sq(nosu)} {sq(par)} {pats}"
    key = server.get("key") or KEY  # clé dédiée au serveur si définie, sinon la clé par défaut
    cmd = ["ssh", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=12", "-o", "StrictHostKeyChecking=accept-new",
           "-p", str(server.get("port") or 22), f"{ssh_user(server)}@{server['host']}", remote_cmd]
    try:
        r = subprocess.run(cmd, input=REMOTE_SCRIPT, capture_output=True, text=True, timeout=2400)
        return r.stdout, r.returncode
    except subprocess.TimeoutExpired:
        return "", -1


def split_site_header(raw):
    """« domaine<sep>chemin<sep>propriétaire » → triplet.

    Le script distant sépare par \\037 (unit separator) : un nom de répertoire
    contenant « | » décalait les champs. Le repli sur « | » reste accepté pour
    lire une sortie produite par une version antérieure du script — le chemin,
    au milieu, y est recomposé à partir des champs intermédiaires.
    """
    if "\x1f" in raw:
        parts = raw.split("\x1f")
    else:
        parts = raw.split("|")
        if len(parts) > 3:
            parts = [parts[0], "|".join(parts[1:-1]), parts[-1]]
    parts = (parts + ["", ""])[:3]
    return parts[0], parts[1], parts[2]


def parse_sites(text):
    sites, cur, field, buf = [], None, None, []
    for line in text.splitlines():
        if line.startswith("@@SITE@@"):
            if cur:
                sites.append(cur)
            dom, path, own = split_site_header(line[8:])
            cur = {"domain": dom, "path": path, "owner": own, "fields": {}, "rcs": {}}
            field = None
        elif line.startswith("@@F@@"):
            field, buf = line[5:], []
        elif line.startswith("@@ENDF@@"):
            if cur is not None and field:
                cur["fields"][field] = "\n".join(buf).strip()
                try:
                    cur["rcs"][field] = int(line[8:])
                except ValueError:
                    cur["rcs"][field] = 99
            field = None
        elif field is not None:
            buf.append(line)
    if cur:
        sites.append(cur)
    return sites


MAX_JSON_CANDIDATES = 500  # lignes candidates examinées par extract_json


def extract_json(s):
    """JSON produit par wp-cli, extrait d'une sortie qui peut être polluée.

    wp-cli écrit son JSON en DERNIER ; ce qui précède (avertissements PHP,
    « Deprecated: … [foo] … ») peut contenir des crochets, ce qui piégeait le
    repli find("[")…rfind("]"). On repart donc de la dernière ligne qui commence
    par « [ » ou « { » et on remonte, en essayant à chaque fois le bloc complet
    (JSON indenté sur plusieurs lignes) puis la ligne seule (JSON compact).
    """
    if not s:
        return None
    lines = s.splitlines()
    tried = 0
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].lstrip()[:1] not in ("[", "{"):
            continue
        tried += 1
        if tried > MAX_JSON_CANDIDATES:
            break
        for cand in ("\n".join(lines[i:]).strip(), lines[i].strip()):
            try:
                return json.loads(cand)
            except (ValueError, TypeError):
                pass
    for opener, closer in (("[", "]"), ("{", "}")):
        i, j = s.find(opener), s.rfind(closer)
        if i != -1 and j > i:
            try:
                return json.loads(s[i:j + 1])
            except (ValueError, TypeError):
                continue
    return None


def to_int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def has_update(item):
    """Un plugin/thème est-il à mettre à jour ? (format wp-cli ou booléen de l'agent)"""
    if not isinstance(item, dict):
        return False
    return item.get("update") in ("available", True, "true", 1)


def apply_plugins(site, plugins):
    """Remplit les champs plugins d'un site — format identique en SSH et en REST."""
    if isinstance(plugins, list):
        plugins = [p for p in plugins if isinstance(p, dict)]
        site["plugins_total"] = len(plugins)
        site["plugins_active"] = sum(1 for p in plugins if p.get("status") in ("active", "active-network"))
        upd = [p for p in plugins if has_update(p)]
        site["plugins_updates"] = len(upd)
        site["plugins_updates_list"] = [{"name": p.get("name"), "from": p.get("version"),
                                         "to": p.get("update_version")} for p in upd]
        site["plugins_list"] = [{"name": p.get("name"), "status": p.get("status"), "version": p.get("version"),
                                 "update": p.get("update"), "to": p.get("update_version")} for p in plugins]
    else:
        site["plugins_total"] = site["plugins_active"] = site["plugins_updates"] = None
        site["plugins_updates_list"] = []
        site["plugins_list"] = []
    return site


def map_admins(admins):
    """Liste d'administrateurs (clés wp-cli ou clés courtes de l'agent) → format du parc."""
    if not isinstance(admins, list):
        return None
    out = []
    for a in admins:
        if not isinstance(a, dict):
            continue
        out.append({"id": a.get("ID", a.get("id")), "login": a.get("user_login", a.get("login")),
                    "email": a.get("user_email", a.get("email")),
                    "registered": a.get("user_registered", a.get("registered"))})
    return out


def vizproof_summary(data):
    """Résumé vizproof à partir d'un objet JSON déjà décodé (SSH ou REST)."""
    if not isinstance(data, dict):
        return None
    connected = data.get("connected")
    if connected is None:
        connected = data.get("dashboard_connected")
    if connected is None:
        connected = bool(data.get("endpoint"))
    pages = data.get("pages")
    if pages is None:
        pages = data.get("pages_count")
    if isinstance(pages, list):
        pages = len(pages)
    last = data.get("last_run") or data.get("last_scan") or data.get("last")
    return {
        "version": str(data.get("version") or data.get("plugin_version") or "") or None,
        "connected": bool(connected),
        "pages": to_int(pages, 0) or 0,
        "last_run": last if isinstance(last, dict) else None,
    }


def postprocess(raw):
    f, rcs = raw["fields"], raw["rcs"]
    ok = lambda k: rcs.get(k, 99) == 0

    def scalar(k, maxlen=200):
        if not ok(k):
            return None
        lines = [l.strip() for l in (f.get(k) or "").splitlines() if l.strip()]
        return lines[-1][:maxlen] if lines else None

    site = {
        "domain": raw["domain"], "path": raw["path"], "owner": raw["owner"],
        "collected_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "core_version": scalar("core_version", 30),
        "siteurl": scalar("siteurl"),
        "blogname": scalar("blogname", 120),
        "via": "ssh",  # collecté en wp-cli par SSH (voir via="rest" pour l'agent distant)
    }
    cu = extract_json(f.get("core_update", "")) if ok("core_update") else None
    # `cu` vient d'une sortie distante : rien ne garantit une liste de dicts.
    site["core_update"] = (cu[0].get("version")
                           if isinstance(cu, list) and cu and isinstance(cu[0], dict) else None)

    apply_plugins(site, extract_json(f.get("plugins", "")) if ok("plugins") else None)

    themes = extract_json(f.get("themes", "")) if ok("themes") else None
    site["themes_updates"] = sum(1 for t in themes if has_update(t)) if isinstance(themes, list) else None

    aup = extract_json(f.get("auto_update_plugins", "")) if ok("auto_update_plugins") else None
    site["plugins_auto_update"] = len(aup) if isinstance(aup, list) else 0

    site["admins"] = map_admins(extract_json(f.get("admins", "")) if ok("admins") else None)

    site["updraft"] = None
    if scalar("updraft_interval"):
        last = extract_json(f.get("updraft_last", "")) if ok("updraft_last") else None
        bt = suc = None
        if isinstance(last, dict):
            bt = last.get("backup_time")
            suc = last.get("success")
        svc = extract_json(f.get("updraft_service", "")) if ok("updraft_service") else None
        if isinstance(svc, list):
            svc = ",".join(str(x) for x in svc)
        # règles de rétention longue durée (GFS, Premium) : {"files":{"1":{after-howmany,...}},"db":{...}}
        extr = extract_json(f.get("updraft_extrarules", "")) if ok("updraft_extrarules") else None
        rules = None
        if isinstance(extr, dict):
            rules = {}
            for kind in ("files", "db"):
                part = extr.get(kind)
                if isinstance(part, dict):
                    lst = []
                    for r in part.values():
                        try:
                            lst.append({"after_n": int(r["after-howmany"]), "after_s": int(r["after-period"]),
                                        "every_n": int(r["every-howmany"]), "every_s": int(r["every-period"])})
                        except (KeyError, TypeError, ValueError):
                            continue
                    if lst:
                        rules[kind] = sorted(lst, key=lambda x: x["after_n"] * x["after_s"])
            rules = rules or None
        site["updraft"] = {
            "interval": scalar("updraft_interval", 30),
            "interval_db": scalar("updraft_interval_db", 30),
            "retain": scalar("updraft_retain", 10),
            "retain_db": scalar("updraft_retain_db", 10),
            "service": svc, "last_backup_ts": bt, "last_success": suc,
            "extrarules": rules,
        }

    # vizproof-timeline : collecté avec les plugins chargés (champ « +vizproof »)
    site["vizproof"] = vizproof_summary(extract_json(f.get("vizproof", ""))) if ok("vizproof") else None

    m = re.search(r"PHP version:\s*([0-9][0-9.]*)", f.get("cliinfo", ""))
    site["php_version"] = m.group(1) if m else None

    errs = {}
    for k in CORE_FIELDS:
        if not ok(k):
            raw_err = f.get(k) or ""
            lines = [l for l in raw_err.splitlines()
                     if l.strip() and "Deprecated:" not in l and "Warning:" not in l and "Notice:" not in l]
            errs[k] = ("\n".join(lines) or raw_err)[-400:]
    site["errors"] = errs
    return site


# ---------- collecte via l'agent REST (sites sans accès SSH) ----------
def agent_get(url, path, secret, params=None, timeout=REST_TIMEOUT):
    """Appel signé de l'agent : HMAC sha256 de « <ts>.<chemin> » avec le secret du site."""
    ts = str(int(time.time()))
    sig = hmac.new(str(secret).encode(), f"{ts}.{path}".encode(), hashlib.sha256).hexdigest()
    full = str(url).rstrip("/") + "/wp-json/" + AGENT_NS + path
    if params:
        full += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(full, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json", "X-Viz-Site": str(url),
        "X-Viz-Timestamp": ts, "X-Viz-Signature": sig})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(4 * 1024 * 1024).decode("utf-8", "replace") or "{}")


def agent_error(exc):
    """Message court et lisible pour une erreur d'appel de l'agent."""
    if isinstance(exc, urllib.error.HTTPError):
        hint = " (signature refusée ou agent non appairé ?)" if exc.code in (401, 403) else ""
        return f"agent : HTTP {exc.code}{hint}"
    return f"agent injoignable : {type(exc).__name__}: {exc}"[:300]


def normalize_updraft(raw):
    """Aligne le bloc UpdraftPlus de l'agent sur le format de la collecte SSH :
    `service` en chaîne (l'agent renvoie un tableau) et `extrarules` à None
    quand il est vide, pour que l'affichage soit identique dans les deux modes."""
    if not isinstance(raw, dict):
        return None
    u = dict(raw)
    svc = u.get("service")
    if isinstance(svc, list):
        u["service"] = ",".join(str(x) for x in svc if x) or None
    rules = u.get("extrarules")
    if not rules:
        u["extrarules"] = None
    return u


def map_rest_inventory(entry, data, url=None, blog_id=None):
    """Inventaire de l'agent → exactement la même structure de site que la collecte SSH."""
    d = data if isinstance(data, dict) else {}
    core = d.get("core") if isinstance(d.get("core"), dict) else {}
    url = str(url or entry.get("url") or "").rstrip("/")
    site = {
        "domain": site_key(d.get("home") or url or entry.get("domain")),
        "path": str(d.get("path") or ""), "owner": str(d.get("owner") or ""),
        "collected_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "core_version": str(core.get("version") or d.get("core_version") or "") or None,
        "siteurl": str(d.get("siteurl") or d.get("home") or url or "") or None,
        "blogname": str(d.get("name") or d.get("blogname") or entry.get("name") or "") or None,
        "via": "rest", "url": url, "blog_id": blog_id, "multisite": bool(d.get("multisite")),
    }
    site["core_update"] = str(core.get("update") or d.get("core_update") or "") or None
    apply_plugins(site, d.get("plugins"))
    # L'agent renvoie déjà des compteurs ; la collecte SSH, elle, part de listes.
    themes = d.get("themes")
    if isinstance(themes, list):
        site["themes_updates"] = sum(1 for t in themes if has_update(t))
    else:
        site["themes_updates"] = to_int(d.get("themes_updates"))
    aup = d.get("auto_update_plugins")
    if isinstance(aup, list):
        site["plugins_auto_update"] = len(aup)
    else:
        site["plugins_auto_update"] = to_int(d.get("plugins_auto_update"), 0)
    site["admins"] = map_admins(d.get("admins"))
    site["updraft"] = normalize_updraft(d.get("updraft"))
    site["vizproof"] = vizproof_summary(d.get("vizproof"))
    site["php_version"] = str(d.get("php") or d.get("php_version") or "") or None
    site["errors"] = dict(d["errors"]) if isinstance(d.get("errors"), dict) else {}
    return site


def rest_error_site(entry, message, url=None, blog_id=None):
    """Site REST injoignable : il figure quand même au parc, avec l'erreur en clair."""
    site = map_rest_inventory(entry, {}, url=url, blog_id=blog_id)
    site["errors"] = {"rest": str(message)[:400]}
    return site


def subsite_entries(entry, secret):
    """Sous-sites d'un réseau multisite → ([(url, blog_id, nom)], erreur)."""
    try:
        listing = agent_get(entry["url"], "/sites", secret)
    except Exception as e:
        return [], f"liste des sous-sites indisponible — {agent_error(e)}"
    rows = listing.get("sites") if isinstance(listing, dict) else listing
    if not isinstance(rows, list):
        return [], "liste des sous-sites illisible"
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or r.get("home") or "").rstrip("/")
        if url:
            out.append((url, r.get("blog_id") or r.get("id"), r.get("name")))
    return out, None


def collect_rest_sites(match=""):
    """Sites gérés par l'agent distant. Ne lève jamais : toute erreur devient un champ."""
    entries = load_json(REST_SITES_PATH, [])
    if not isinstance(entries, list) or not entries:
        return []
    store = load_json(SECRETS_PATH, {})
    if not isinstance(store, dict):
        store = {}
    sites = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("url"):
            continue
        key = entry.get("domain") or site_key(entry["url"])
        if match and match not in (key, norm_domain(key)):
            continue
        secret = store.get(key) or store.get(norm_domain(key))
        if not secret:
            sites.append(rest_error_site(entry, "aucun secret enregistré : appairez le site"))
            continue
        try:
            data = agent_get(entry["url"], "/inventory",
                             secret, {"blog_id": entry["blog_id"]} if entry.get("blog_id") else None)
        except Exception as e:
            sites.append(rest_error_site(entry, agent_error(e)))
            continue
        site = map_rest_inventory(entry, data, blog_id=entry.get("blog_id"))
        sites.append(site)
        if not (isinstance(data, dict) and data.get("multisite")) or entry.get("blog_id"):
            continue
        # réseau multisite : une entrée par sous-site, collectée avec ?blog_id=<id>
        subs, err = subsite_entries(entry, secret)
        if err:
            site["errors"]["rest_sites"] = err
        if len(subs) > MAX_SUBSITES:
            print(f"[rest] {key} : {len(subs)} sous-sites, tronqué à {MAX_SUBSITES}", flush=True)
            site["errors"]["rest_sites_tronques"] = f"{len(subs)} sous-sites, {MAX_SUBSITES} collectés"
            subs = subs[:MAX_SUBSITES]
        for sub_url, blog_id, name in subs:
            if site_key(sub_url) == site["domain"]:
                continue  # site principal du réseau : déjà collecté
            child = {"domain": site_key(sub_url), "url": entry["url"], "name": name, "blog_id": blog_id}
            try:
                cdata = agent_get(entry["url"], "/inventory", secret,
                                  {"blog_id": blog_id} if blog_id else None)
            except Exception as e:
                sites.append(rest_error_site(child, agent_error(e), url=sub_url, blog_id=blog_id))
                continue
            sites.append(map_rest_inventory(child, cdata, url=sub_url, blog_id=blog_id))
    return sites


def kuma_folder_map():
    """{nom monitor: dossier} via la base Kuma (docker exec).

    Pas d'injection possible ici : la commande est passée en argv, la requête
    est constante. La sortie, elle, reste du texte à analyser prudemment — d'où
    le try englobant et le test de code retour.
    """
    try:
        r = subprocess.run(
            ["docker", "exec", KUMA_CONTAINER, "sqlite3", KUMA_DB,
             "SELECT m.name||char(9)||COALESCE(g.name,'') FROM monitor m "
             "LEFT JOIN monitor g ON g.id=m.parent WHERE m.type!='group';"],
            capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            print(f"kuma : lecture de la base impossible ({(r.stderr or '').strip()[:120]})")
            return {}
        out = r.stdout
        d = {}
        for line in out.splitlines():
            if "\t" in line:
                n, g = line.split("\t", 1)
                d[n] = g or None
        return d
    except Exception:
        return {}


def annotate_kuma(fleet):
    overrides = load_json(os.path.join(DATA, "overrides.json"), {})
    aliases = {k: v.get("alias") for k, v in overrides.items() if v.get("alias")}
    folders = kuma_folder_map()
    try:
        cfg = json.load(urllib.request.urlopen(KUMA_STATUS, timeout=10))
        mon = set()
        for g in cfg.get("publicGroupList", []):
            for m in g.get("monitorList", []):
                mon.add(m["name"])
    except Exception as e:
        print(f"annotation kuma sautée ({e})")
        for srv in fleet["servers"]:
            for s in srv["sites"]:
                s.setdefault("kuma", None)
                s.setdefault("kuma_group", None)
                s.setdefault("visible", None)
        return

    def match(site):
        if aliases.get(site["domain"]) in mon:
            return aliases[site["domain"]]
        if site["domain"] in mon:
            return site["domain"]
        try:
            h = urlparse(site.get("siteurl") or "").hostname or ""
        except ValueError:
            h = ""
        if h.startswith("www."):
            h = h[4:]
        if h and h in mon:
            return h
        if h and "www." + h in mon:
            return "www." + h
        return None

    cand = {}
    for srv in fleet["servers"]:
        for s in srv["sites"]:
            s["kuma"] = None
            ov = overrides.get(s["domain"], {})
            s["visible"] = ov.get("visible")  # True/False/None(auto)
            n = match(s)
            if n:
                cand.setdefault(n, []).append((srv, s))
    # Un même domaine peut exister sur deux serveurs (migration en cours…) :
    # à défaut de résolution DNS tranchante, on retient le serveur de plus forte
    # « priority » (clé optionnelle de servers.json, entier, défaut 2).
    prio = {s.get("name"): (to_int(s.get("priority"), 2) if isinstance(s, dict) else 2)
            for s in load_json(os.path.join(BASE, "servers.json"), []) if isinstance(s, dict)}
    for name, lst in cand.items():
        chosen = None
        if len(lst) > 1:
            try:
                ips = set(socket.gethostbyname_ex(name)[2])
            except OSError:
                ips = set()
            hits = [t for t in lst if t[0].get("host") in ips]
            if len(hits) == 1:
                chosen = hits[0]
        if chosen is None:
            chosen = sorted(lst, key=lambda t: (prio.get(t[0].get("name")) if
                                                prio.get(t[0].get("name")) is not None else 2),
                            reverse=True)[0]
        chosen[1]["kuma"] = name
        chosen[1]["kuma_group"] = folders.get(name)


def save_json_atomic(path, obj, mode=0o600):
    """Écrit un JSON de façon atomique (dashlib.save_json, avec fsync).

    fleet.json est lu en concurrence par l'API, vulns.py, phperrors.py et le
    navigateur : un `open(…, "w")` les expose à un fichier tronqué. Les fichiers
    de `data/` sont en 0600 (ils contiennent logins et e-mails d'administrateurs),
    la copie publique servie par nginx en 0644 — d'où un mode toujours explicite
    ici, jamais déduit du chemin.
    """
    _save_json(path, obj, mode=mode, fsync=True)


def append_line(path, text, mode=0o600):
    """Ajoute une ligne à un journal, en le créant en 0600 s'il n'existe pas."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, mode)
    with os.fdopen(fd, "a") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def write_fleet(fleet, rotate=False):
    annotate_kuma(fleet)
    if rotate and os.path.exists(os.path.join(DATA, "fleet.json")):
        try:
            os.replace(os.path.join(DATA, "fleet.json"), os.path.join(DATA, "fleet.prev.json"))
        except OSError:
            pass
    save_json_atomic(os.path.join(DATA, "fleet.json"), fleet, 0o600)
    save_json_atomic(os.path.join(PUB, "fleet.json"), fleet, 0o644)


def merge_stale(entry, previous, ts):
    """Serveur injoignable → on conserve sa photo précédente, marquée « stale ».

    Écrire l'entrée vide telle quelle avait trois effets en cascade : les sites
    du serveur disparaissaient du dashboard, `append_history` enregistrait un
    point de tendance effondré, et fleet.prev.json devenait cette photo vide —
    si bien que le diff de la collecte suivante ne voyait plus rien (prev None
    → `continue`) et perdait les changements réels. En conservant les sites, la
    rotation de fleet.prev reste sans danger : le diff ne compare que des
    données réelles.
    """
    if entry.get("complete"):
        return entry
    prev = previous.get(entry.get("name")) if isinstance(previous, dict) else None
    if not isinstance(prev, dict) or not prev.get("sites"):
        return entry
    kept = dict(prev)
    kept["host"] = entry.get("host") or prev.get("host")
    kept["complete"] = False
    kept["stale"] = True          # données de la collecte précédente
    kept["last_attempt"] = ts     # date de la tentative qui a échoué
    kept["error"] = entry.get("error") or "serveur injoignable"
    print(f"[{entry.get('name')}] injoignable — {len(kept['sites'])} site(s) conservés "
          f"de la collecte précédente (stale)", flush=True)
    return kept


def append_history(fleet):
    servers = fleet.get("servers") or []
    sites = [(s, x) for s in servers for x in (s.get("sites") or [])]
    # Un serveur injoignable conserve sa photo précédente (voir merge_stale) :
    # ses sites comptent donc normalement, la courbe ne plonge pas à zéro. On
    # note simplement combien de serveurs sont dans cet état.
    line = {"ts": fleet.get("generated_at"),
            "sites": len(sites),
            "core_updates": sum(1 for _, x in sites if x.get("core_update")),
            "plugin_updates": sum((x.get("plugins_updates") or 0) for _, x in sites),
            "errors": sum(1 for _, x in sites if x.get("errors")),
            "stale_servers": sum(1 for s in servers if s.get("stale"))}
    append_line(os.path.join(DATA, "collect_history.jsonl"), json.dumps(line))


# --------------------------------------------------------------------------- #
#  Détection de changements entre deux collectes → data/changes.jsonl         #
#                                                                             #
#  On journalise les changements d'ÉTAT RÉEL (la version installée a bougé,   #
#  un admin est apparu), jamais « une mise à jour est devenue disponible » :  #
#  ce dernier chiffre fluctue à chaque heure et noierait tout signal utile.   #
#  Pour les sites SSH sans agent, ce diff est le seul moyen de savoir qu'un   #
#  changement a eu lieu (les sites avec agent poussent déjà events.jsonl).    #
# --------------------------------------------------------------------------- #
CHANGES_PATH = os.path.join(DATA, "changes.jsonl")
# Pas de rotation ici : c'est rotate.py qui applique la rétention différenciée
# (90 j pour le tout-venant, 400 j pour les lignes « warn » qui ont valeur de
# preuve). Une coupe aux N dernières lignes à chaque collecte — 48 fois par
# jour — effaçait précisément ce que rotate.py cherche à conserver.

def _index_sites(fleet):
    """domaine (clé Kuma de préférence) -> site, en écartant les doublons.

    Un même domaine peut exister sur deux serveurs (mutu + legacy) : on retient
    l'install rattaché à Kuma, celui que l'UI affiche — même logique que le
    reste du dashboard, pour ne pas differ deux copies l'une contre l'autre.
    """
    out = {}
    for s in fleet.get("servers", []):
        for site in s.get("sites", []):
            dom = site.get("kuma") or site.get("domain")
            if not dom:
                continue
            if dom in out and not site.get("kuma"):
                continue
            out[dom] = site
    return out

def _plugin_map(site):
    return {p.get("name"): p for p in (site.get("plugins_list") or []) if p.get("name")}

def _admin_map(site):
    return {a.get("login"): a for a in (site.get("admins") or []) if a.get("login")}

def diff_fleets(old, new, ts):
    """Liste de changements structurés {ts, domain, kind, severity, detail}."""
    changes = []
    oi, ni = _index_sites(old), _index_sites(new)

    def mk(dom, kind, sev, detail):
        changes.append({"ts": ts, "domain": dom, "kind": kind,
                        "severity": sev, "detail": detail})

    for dom, ns in ni.items():
        prev = oi.get(dom)
        if prev is None:
            continue  # site nouveau dans l'inventaire : pas un « changement »
        # Une collecte en erreur donne des champs peu fiables (plugins_list vide,
        # etc.) : on ne diffe pas, sinon flot de faux « + / − plugin ».
        if ns.get("errors") or prev.get("errors"):
            continue

        ov, nv = prev.get("core_version"), ns.get("core_version")
        if ov and nv and ov != nv:
            mk(dom, "core", "info", f"cœur WordPress {ov} → {nv}")

        ov, nv = prev.get("php_version"), ns.get("php_version")
        if ov and nv and ov != nv:
            mk(dom, "php", "info", f"PHP {ov} → {nv}")

        op, np_ = _plugin_map(prev), _plugin_map(ns)
        if op and np_:  # les deux inventaires présents
            for name, p in np_.items():
                if name not in op:
                    v = p.get("version") or ""
                    mk(dom, "plugin_add", "warn", f"+ extension {name} {v}".rstrip())
                    continue
                pv, nvv = op[name].get("version"), p.get("version")
                if pv and nvv and pv != nvv:
                    mk(dom, "plugin_update", "info", f"{name} {pv} → {nvv}")
                if p.get("status") != op[name].get("status"):
                    verb = "activée" if p.get("status") == "active" else "désactivée"
                    mk(dom, "plugin_status", "info", f"extension {name} {verb}")
            for name in op:
                if name not in np_:
                    mk(dom, "plugin_remove", "info", f"− extension {name}")

        oa, na = _admin_map(prev), _admin_map(ns)
        if oa and na:
            for login, a in na.items():
                if login not in oa:
                    email = a.get("email") or ""
                    mk(dom, "admin_add", "warn", f"+ admin {login} <{email}>".replace(" <>", ""))
            for login in oa:
                if login not in na:
                    mk(dom, "admin_remove", "warn", f"− admin {login}")

        ou, nu = prev.get("updraft") or {}, ns.get("updraft") or {}
        # Même garde que pour les extensions et les admins : un `wp option get`
        # qui échoue une fois met `updraft` à None et ferait osciller le journal
        # (« daily → None » puis « None → daily ») à chaque incident passager.
        if ou and nu and isinstance(ou, dict) and isinstance(nu, dict):
            for k, lbl in (("interval", "sauvegarde fichiers"), ("interval_db", "sauvegarde BDD"),
                           ("retain", "rétention fichiers"), ("retain_db", "rétention BDD")):
                a, b = ou.get(k), nu.get(k)
                if (a or b) and str(a) != str(b):
                    mk(dom, "updraft", "info", f"Updraft {lbl} {a} → {b}")
    return changes

def append_changes(changes):
    if not changes:
        return
    for c in changes:
        append_line(CHANGES_PATH, json.dumps(c, ensure_ascii=False))


def main():
    limit, only, match = 0, None, ""
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--limit":
            limit = int(args.pop(0))
        elif a == "--only":
            only = args.pop(0)
        elif a == "--match":
            match = args.pop(0)
    servers = [s for s in load_json(os.path.join(BASE, "servers.json"), []) if isinstance(s, dict)]
    extra = [d for d in load_json(os.path.join(DATA, "extra_docroots.json"), []) if isinstance(d, dict)]
    now_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    # --only sur un nom absent de servers.json : on s'arrête AVANT toute écriture.
    # (`next(...)` sans défaut levait StopIteration, message illisible.)
    srv_only = None
    if only and only != "rest":
        srv_only = next((s for s in servers if s.get("name") == only), None)
        if srv_only is None:
            connus = ", ".join(sorted(str(s.get("name")) for s in servers)) or "aucun"
            print(f"[{only}] serveur inconnu de servers.json (connus : {connus}, plus « rest »)",
                  file=sys.stderr)
            sys.exit(2)

    # Inventaire précédent : sert à conserver les serveurs devenus injoignables.
    previous = load_json(os.path.join(DATA, "fleet.json"), None)
    prev_srv = {s.get("name"): s for s in (previous or {}).get("servers", [])
                if isinstance(s, dict) and s.get("name")}

    if match and only:
        fleet = load_json(os.path.join(DATA, "fleet.json"), {"servers": []})
        fleet.setdefault("servers", [])
        if only == "rest":
            # re-scan d'un seul site géré par l'agent distant
            sites = collect_rest_sites(match)
        else:
            out, rc = ssh_collect(srv_only, extra, 0, match)
            sites = [postprocess(s) for s in parse_sites(out)]
            if not sites and "@@DONE@@" not in out:
                print(f"[{only}] échec du scan de {match} (rc={rc})")
                sys.exit(1)
        # Le serveur peut ne pas encore figurer dans fleet.json (première collecte
        # ciblée) : on crée son entrée, sinon les sites étaient jetés en silence.
        fs = next((x for x in fleet["servers"] if x.get("name") == only), None)
        if fs is None:
            fs = {"name": only, "host": "-" if only == "rest" else (srv_only or {}).get("host", "-"),
                  "complete": True, "sites": []}
            fleet["servers"].append(fs)
        fs["sites"] = [s for s in (fs.get("sites") or []) if s.get("domain") != match] + sites
        fs["sites"].sort(key=lambda s: s.get("domain") or "")
        write_fleet(fleet)
        print(f"[{only}] {match} " + ("re-scanné." if sites else "disparu — retiré de la liste."))
        return

    # Avec --only on ne recollecte qu'un serveur : on repart de l'inventaire existant
    # et on remplace la seule entrée concernée, sinon les autres serveurs seraient perdus.
    if only:
        fleet = load_json(os.path.join(DATA, "fleet.json"), None) or {"servers": []}
        fleet["generated_at"] = now_ts
        fleet["servers"] = [s for s in fleet.get("servers", []) if s.get("name") != only]
    else:
        fleet = {"generated_at": now_ts, "servers": []}
    targets = [s for s in servers if not only or s.get("name") == only]

    def collect_one(srv):
        """Un serveur : renvoie son entrée de flotte. Exécuté dans un thread.

        Ne lève jamais : une exception (champ manquant dans servers.json, sortie
        distante inattendue…) avortait `pool.map` et donc la collecte de TOUS
        les serveurs. L'échec devient une entrée incomplète, traitée ensuite
        comme un serveur injoignable.
        """
        nom = str(srv.get("name") or "?")
        t0 = time.time()
        try:
            out, rc = ssh_collect(srv, extra, limit)
            sites = [postprocess(s) for s in parse_sites(out)]
            sites.sort(key=lambda s: s.get("domain") or "")
            complete = "@@DONE@@" in out
            print(f"[{nom}] {len(sites)} sites, rc={rc}, complet={complete}, {time.time()-t0:.0f}s", flush=True)
            entry = {"name": nom, "host": srv.get("host", ""), "complete": complete, "sites": sites}
            if not complete:
                entry["error"] = f"collecte incomplète (rc={rc})"
            return entry
        except Exception as e:
            err = f"{type(e).__name__}: {e}"[:300]
            print(f"[{nom}] ÉCHEC de la collecte — {err}", flush=True)
            return {"name": nom, "host": srv.get("host", ""), "complete": False,
                    "error": err, "sites": []}

    if targets:
        # Serveurs interrogés en parallèle : la durée totale devient celle du plus lent.
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_SERVERS_PARALLEL, len(targets))) as pool:
            results = [merge_stale(e, prev_srv, now_ts) for e in pool.map(collect_one, targets)]
        order = {s.get("name"): i for i, s in enumerate(servers)}
        fleet["servers"].extend(sorted(results, key=lambda e: order.get(e["name"], 99)))
    # sites sans SSH, interrogés via l'agent : serveur virtuel « rest »
    if not only or only == "rest":
        t0 = time.time()
        rest = collect_rest_sites()
        if rest or only == "rest":
            rest.sort(key=lambda s: s["domain"])
            fleet["servers"].append({"name": "rest", "host": "-", "complete": True, "sites": rest})
            failed = sum(1 for s in rest if s.get("errors"))
            print(f"[rest] {len(rest)} sites via l'agent ({failed} en erreur), {time.time()-t0:.0f}s", flush=True)
    write_fleet(fleet, rotate=not only)
    if not only:
        append_history(fleet)
        # write_fleet(rotate=True) vient de basculer l'ancienne photo en
        # fleet.prev.json : on la compare à la nouvelle pour tracer les changements.
        prev = load_json(os.path.join(DATA, "fleet.prev.json"), None)
        if prev:
            changes = diff_fleets(prev, fleet, fleet["generated_at"])
            append_changes(changes)
            if changes:
                warn = sum(1 for c in changes if c["severity"] == "warn")
                print(f"{len(changes)} changement(s) détecté(s)"
                      + (f", dont {warn} à surveiller." if warn else "."))
    print(f"OK — {sum(len(s['sites']) for s in fleet['servers'])} sites.")


if __name__ == "__main__":
    main()
