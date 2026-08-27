#!/usr/bin/env python3
"""API du dashboard parc WordPress (127.0.0.1:8090, derrière nginx + basic auth).

Regroupe : actions wp-cli whitelistées, collecte manuelle, gestion de la liste
(overrides / serveurs / docroots / moniteurs Kuma), édition en masse (file
d'attente), volet sécurité (checksums, diff, référence admins), alertes
Telegram, ingestion d'évènements signés HMAC et timeline par site.
Toute action wp-cli tourne en su utilisateur du site — sauf sur les serveurs
déclarés "no_su" (mutualisés), où l'utilisateur SSH est déjà le propriétaire.
Aucun shell libre exposé.
"""
import json, subprocess, os, re, sys, time, datetime, threading, itertools, hashlib, hmac, base64, secrets, tempfile, http.cookies
import io, ipaddress, socket, urllib.error, urllib.request, urllib.parse, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dashboard_config import CONFIG

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
PUB = os.path.join(BASE, "public")
KEY = CONFIG["ssh_key"]              # clé SSH par défaut (surchargée par serveur dans servers.json)
LOG = os.path.join(DATA, "actions.log")
KUMA_DB = CONFIG["kuma_db"]          # chemin de la base Kuma DANS le conteneur
KUMA_CONTAINER = CONFIG["kuma_container"]
SLUG = CONFIG["kuma_slug"]           # slug de la status page Kuma du parc
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,80}$")
SERVER_RE = re.compile(r"^[a-z0-9-]{1,40}$")
FLEET_PATH = os.path.join(DATA, "fleet.json")
# ---- vizproof (produit public : lecture seule, scan visuel et statut) ----
VIZ_ANOMALY_RC = 2  # code de sortie « anomalies visuelles détectées » : pas une erreur technique
VIZ_ACTIONS = ("viz_baseline", "viz_scan")
# ---- agent privé de liaison au dashboard (mu-plugin distinct de vizproof) ----
DASH_BASE = CONFIG["dashboard_url"]              # racine publique du dashboard
DASH_ENDPOINT = DASH_BASE + "/api/ingest"        # où les agents poussent leurs évènements
AGENT_NAME = "sumotori-dash-agent.php"
AGENT_SLUG = "sumotori-dash-agent"
# Paquet complet (readme, licence, traductions) depuis la mise en conformité wordpress.org ;
# l'ancien fichier isolé reste accepté en repli.
AGENT_DIR = os.path.join(BASE, "agent", AGENT_SLUG)
AGENT_FILE = os.path.join(AGENT_DIR, AGENT_NAME)
if not os.path.exists(AGENT_FILE):
    AGENT_DIR = os.path.join(BASE, "agent")
    AGENT_FILE = os.path.join(AGENT_DIR, AGENT_NAME)
AGENT_NS = "sumotori-dash/v1"
AGENT_INVENTORY_ROUTE = f"/wp-json/{AGENT_NS}/inventory"  # inventaire REST sans SSH
AGENT_TIMEOUT = 60  # installer un plugin est lent : marge large
VIZ_SLUG = "vizproof-timeline"  # seul slug accepté par l'agent (liste blanche côté site)
# actions impossibles sans SSH : l'agent est en lecture seule (hors installation de vizproof)
FROZEN_RC = 96  # extension gelée par la politique de mise à jour du site
REST_UNSUPPORTED_RC = 97
REST_UNSUPPORTED_MSG = "action indisponible : site géré sans SSH (l'agent est en lecture seule)"
AGENT_OLD_RC = 99
AGENT_OLD_MSG = "agent trop ancien : réinstallez-le depuis Gestion"
VIZ_NS = "vizproof-timeline/v1"
# ---- sondage d'URL, appairage et sites gérés en REST (sans SSH) ----
USER_AGENT = "SumotoriDashboard/1.0"
DISCOVER_TIMEOUT = 12
DISCOVER_REDIRECTS = 3
REST_SITES_PATH = os.path.join(DATA, "rest_sites.json")
PAIRINGS_PATH = os.path.join(DATA, "pairings.json")
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # sans caractères ambigus (0/O, 1/I/L)
PAIR_TTL = 30 * 60
PAIR_RATE_MAX = 20      # tentatives d'appairage par heure et par IP
PAIR_RATE_WINDOW = 3600
PAIR_CODE_RE = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}$")
# ---- alertes / sécurité / évènements ----
ALERTS_PATH = os.path.join(DATA, "alerts.json")
ALERTS_STATE_PATH = os.path.join(DATA, "alerts_state.json")
ALERTS_LOG = os.path.join(DATA, "alerts.log")
ALERT_COOLDOWN = 24 * 3600  # une même clé d'alerte n'est renvoyée qu'après 24 h
CHECKSUMS_PATH = os.path.join(DATA, "checksums.json")
VULNS_FOUND_PATH = os.path.join(DATA, "vulns_found.json")
# Politique de mise à jour par extension : liste d'exclusions PAR SITE. Une
# extension gelée (parce qu'une version casse le site, ou qu'un client valide
# avant) reste installée mais n'est jamais mise à jour par le dashboard.
UPDATE_POLICY_PATH = os.path.join(DATA, "update_policy.json")
CHECKSUM_SOURCES = ("securite", "bulk", "manuel")  # sources dont on mémorise le résultat
SECRETS_PATH = os.path.join(DATA, "site_secrets.json")
EVENTS_PATH = os.path.join(DATA, "events.jsonl")
CHANGES_PATH = os.path.join(DATA, "changes.jsonl")
# Libellés courts par type de changement (data/changes.jsonl), partagés UI/API.
CHANGE_LABELS = {
    "core": "cœur WordPress", "php": "PHP",
    "plugin_add": "extension ajoutée", "plugin_remove": "extension retirée",
    "plugin_update": "extension mise à jour", "plugin_status": "extension activée/désactivée",
    "admin_add": "admin ajouté", "admin_remove": "admin retiré", "updraft": "réglage sauvegarde",
}
EVENTS_MAX_BYTES = 5 * 1024 * 1024  # au-delà : rotation vers events.jsonl.1
INGEST_MAX_BYTES = 16 * 1024
INGEST_SKEW = 300  # tolérance d'horodatage, en secondes
# ---- clés SSH ----
SSH_DIR = "/root/.ssh"
SSH_SKIP_EXACT = {"config", "authorized_keys", "environment"}  # fichiers non-clés du répertoire
SSH_KEYNAME_RE = re.compile(r"^[a-z0-9_-]{1,30}$")

ACTIONS = {
    "core_update":        ("Mise à jour du core", False, "core update && WPRUN core update-db"),
    "plugins_update_all": ("MAJ de tous les plugins", False, "plugin update --all"),
    "plugins_update_except": ("MAJ plugins sauf {arg}", True, "plugin update --all --exclude={arg}"),
    "plugin_update":      ("MAJ du plugin {arg}", True,  "plugin update {arg}"),
    "themes_update_all":  ("MAJ de tous les thèmes", False, "theme update --all"),
    "updraft_backup":     ("Backup UpdraftPlus", False, "updraftplus backup"),
    "cache_flush":        ("Vider caches + rewrite", False, "cache flush && WPRUN rewrite flush"),
    "autoupdate_on":      ("Activer auto-updates plugins", False, "plugin auto-updates enable --all"),
    "autoupdate_off":     ("Désactiver auto-updates plugins", False, "plugin auto-updates disable --all"),
    "verify_checksums":   ("Vérifier checksums du core", False, "core verify-checksums"),
    "vizproof_install":   ("Installer vizproof-timeline", False, "plugin install vizproof-timeline --activate"),
    "viz_baseline":       ("Baseline visuelle VizProof", False, "vizproof baseline --wait --format=json"),
    "viz_scan":           ("Scan visuel VizProof", False, "vizproof scan --wait --format=json"),
}
# actions bulk qui doivent d'abord backuper si UpdraftPlus est présent
BACKUP_FIRST = {"core_update", "plugins_update_all", "plugins_update_except", "themes_update_all"}

REMOTE_TEMPLATE = r'''#!/bin/bash
D={docroot}
DOM={domain}
OWN={owner}
NOSU={nosu}
WPBIN=$(command -v wp || true)
[ -n "$WPBIN" ] || {{ echo "wp-cli absent"; exit 90; }}
extra=""
[ "$NOSU" != "1" ] && [ "$OWN" = "root" ] && extra="--allow-root"
base="cd '$D' && env WP_CLI_CACHE_DIR=/tmp/.wpcli-cache-$OWN WP_CLI_PHP_ARGS='-d display_errors=0 -d error_reporting=0' HTTP_HOST='$DOM' SERVER_NAME='$DOM'"
# Exécution côté site : directe quand l'utilisateur SSH possède déjà le site
# (mutualisé, NOSU=1), sinon bascule vers le propriétaire du docroot via su.
asuser() {{
  if [ "$NOSU" = "1" ]; then
    timeout {timeout} bash -c "$1" 2>&1
  else
    timeout {timeout} su -s /bin/bash "$OWN" -c "$1" 2>&1
  fi
}}
run() {{
  local out rc
  out=$(asuser "$base wp $* $extra --no-color"); rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qiE 'requires PHP|PHP version'; then
    local php
    for php in /opt/plesk/php/7.4/bin/php /opt/plesk/php/8.0/bin/php /opt/plesk/php/8.1/bin/php /opt/plesk/php/8.2/bin/php /opt/plesk/php/8.3/bin/php; do
      [ -x "$php" ] || continue
      out=$(asuser "$base $php -d display_errors=0 -d error_reporting=0 $WPBIN $* $extra --no-color"); rc=$?
      [ $rc -eq 0 ] && break
    done
  fi
  printf '%s\n' "$out"; return $rc
}}
{body}
'''

# Dépôt du mu-plugin de liaison : le contenu voyage dans l'entrée standard de ssh
# (document ici), puis est écrit sous l'utilisateur du site (su ou direct si no_su).
REMOTE_DEPLOY_TEMPLATE = r'''#!/bin/bash
D={docroot}
OWN={owner}
NOSU={nosu}
MU="$D/wp-content/mu-plugins"
F="$MU/{fname}"
[ -d "$D" ] || {{ echo "docroot introuvable"; exit 98; }}
TMP=$(mktemp /tmp/dash-agent.XXXXXX) || {{ echo "mktemp impossible"; exit 96; }}
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<'{marker}'
{content}
{marker}
[ -s "$TMP" ] || {{ echo "contenu de l'agent vide"; exit 97; }}
asuser() {{
  if [ "$NOSU" = "1" ]; then
    timeout {timeout} bash -c "$1" 2>&1
  else
    timeout {timeout} su -s /bin/bash "$OWN" -c "$1" 2>&1
  fi
}}
out=$(asuser "mkdir -p '$MU' && cat > '$F' && chmod 0644 '$F'" < "$TMP"); rc=$?
[ $rc -eq 0 ] || {{ printf '%s\n' "$out"; echo "dépôt du mu-plugin impossible"; exit $rc; }}
if [ "$NOSU" != "1" ]; then
  GRP=$(stat -c %G "$D" 2>/dev/null || echo "$OWN")
  chown "$OWN":"$GRP" "$F" 2>/dev/null
  chmod 0755 "$MU" 2>/dev/null
fi
echo "mu-plugin déposé: $F"
'''

REMOTE_REMOVE_TEMPLATE = r'''#!/bin/bash
D={docroot}
OWN={owner}
NOSU={nosu}
F="$D/wp-content/mu-plugins/{fname}"
asuser() {{
  if [ "$NOSU" = "1" ]; then
    timeout {timeout} bash -c "$1" 2>&1
  else
    timeout {timeout} su -s /bin/bash "$OWN" -c "$1" 2>&1
  fi
}}
[ -f "$F" ] || {{ echo "mu-plugin déjà absent"; exit 0; }}
out=$(asuser "rm -f '$F'"); rc=$?
[ $rc -eq 0 ] || {{ printf '%s\n' "$out"; exit $rc; }}
echo "mu-plugin supprimé"
'''


def load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


# ---------- cadence de la collecte automatique (cron) ----------
CRON_PATH = "/etc/cron.d/wp-dashboard"
CRON_MINUTE = 17          # décalé de l'heure pile : évite les pics de charge
SCHEDULE_CHOICES = [0, 15, 30, 60, 120, 180, 360, 720, 1440]


def cron_expr(minutes):
    """Expression cron pour un intervalle en minutes (0 = désactivé)."""
    if minutes < 60:
        return f"*/{minutes} * * * *"
    if minutes == 60:
        return f"{CRON_MINUTE} * * * *"
    if minutes < 1440:
        return f"{CRON_MINUTE} */{minutes // 60} * * *"
    return f"{CRON_MINUTE} 3 * * *"   # quotidien : 3h17 du matin


def read_schedule():
    """Intervalle courant lu depuis le fichier cron."""
    interval, expr = 0, None
    try:
        with open(CRON_PATH) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "collect.py" not in line:
                    continue
                expr = " ".join(line.split()[:5])
                m, h = line.split()[0], line.split()[1]
                if m.startswith("*/"):
                    interval = int(m[2:])
                elif h.startswith("*/"):
                    interval = int(h[2:]) * 60
                elif h == "*":
                    interval = 60
                else:
                    interval = 1440
                break
    except OSError:
        pass
    return {"interval_minutes": interval, "cron": expr, "choices": SCHEDULE_CHOICES}


def write_schedule(minutes):
    """Réécrit /etc/cron.d/wp-dashboard. 0 désactive la collecte automatique."""
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return False, "intervalle invalide"
    if minutes not in SCHEDULE_CHOICES:
        return False, "intervalle non autorisé"
    header = "# Collecte du parc WordPress — géré depuis le dashboard (Réglages)\n"
    if minutes == 0:
        body = "# collecte automatique désactivée\n"
    else:
        body = (f"{cron_expr(minutes)} root cd {BASE} && /usr/bin/python3 collect.py "
                f">> /var/log/wp-dashboard.log 2>&1\n")
    try:
        tmp = CRON_PATH + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(header + body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, CRON_PATH)
    except OSError as e:
        return False, f"écriture impossible : {e}"
    return True, None


# ---------- authentification (session par cookie signé) ----------
SESSION_SECRET_PATH = os.path.join(DATA, ".session_secret")
AUTH_PATH = os.path.join(DATA, "auth.json")
AUTH_FAIL_LOG = os.path.join(DATA, "auth_fail.log")
SESSION_TTL = 7 * 24 * 3600  # 7 jours


def session_secret():
    try:
        with open(SESSION_SECRET_PATH, "rb") as fh:
            return fh.read()
    except OSError:
        sec = os.urandom(32)
        with open(SESSION_SECRET_PATH, "wb") as fh:
            fh.write(sec)
        os.chmod(SESSION_SECRET_PATH, 0o600)
        return sec


def verify_password(user, password):
    creds = load_json(AUTH_PATH, {})
    if not creds or user != creds.get("user"):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(creds["salt"]), creds.get("iters", 200000))
    return hmac.compare_digest(dk.hex(), creds.get("hash", ""))


def make_token(user):
    payload = base64.urlsafe_b64encode(json.dumps({"u": user, "exp": int(time.time()) + SESSION_TTL}).encode()).decode()
    sig = hmac.new(session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def check_token(token):
    try:
        payload, sig = token.split(".", 1)
        good = hmac.new(session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("u")
    except Exception:
        return None


def cookie_user(headers):
    raw = headers.get("Cookie", "")
    try:
        c = http.cookies.SimpleCookie(raw)
        if "dash_session" in c:
            return check_token(c["dash_session"].value)
    except http.cookies.CookieError:
        return None
    return None


def log_auth_fail(user, ip):
    with open(AUTH_FAIL_LOG, "a") as fh:
        fh.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} LOGIN FAILED user={user} ip={ip}\n")


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def servers_list():
    return load_json(os.path.join(BASE, "servers.json"), [])


def find_site(server_name, domain):
    srv = next((s for s in servers_list() if s["name"] == server_name), None)
    fleet = load_json(os.path.join(DATA, "fleet.json"), {"servers": []})
    fsrv = next((s for s in fleet["servers"] if s["name"] == server_name), None)
    if not srv or not fsrv:
        return None, None
    site = next((s for s in fsrv["sites"] if s["domain"] == domain), None)
    return srv, site


def sq(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def ssh_target(srv):
    """Cible ssh du serveur : root@host par défaut, <user>@host sur un mutualisé."""
    return f"{srv.get('user') or 'root'}@{srv['host']}"


def norm_domain(value):
    """Normalise un hôte en domaine : minuscule, sans schéma, sans port, sans www."""
    h = str(value or "").strip().lower()
    if "//" in h:
        h = h.split("//", 1)[1]
    h = h.split("/")[0].split("@")[-1].split(":")[0]
    return h[4:] if h.startswith("www.") else h


def site_key(value):
    """Clé d'un site : le domaine, suivi du chemin pour une installation en sous-répertoire.

    Deux WordPress peuvent partager un hôte (exemple.fr et exemple.fr/boutique) :
    le chemin fait donc partie de la clé. Pour un site à la racine, la clé reste
    strictement le domaine — compatible avec tout ce qui existe déjà.
    """
    raw = str(value or "").strip()
    if raw and "//" not in raw:
        raw = "https://" + raw
    try:
        u = urllib.parse.urlsplit(raw)
    except ValueError:
        return norm_domain(value)
    host = norm_domain(u.hostname or u.netloc or value)
    path = re.sub(r"/+$", "", (u.path or "")).lower()
    return host + path if path else host


# ---------- clés SSH (jamais de clé privée renvoyée) ----------
def ssh_pub_text(path):
    """Partie publique d'une clé : <path>.pub s'il existe, sinon dérivée par ssh-keygen -y."""
    try:
        with open(path + ".pub") as fh:
            txt = fh.read().strip()
        if txt:
            return txt
    except OSError:
        pass
    try:
        r = subprocess.run(["ssh-keygen", "-y", "-f", path], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None  # clé chiffrée par passphrase, fichier non-clé, ou ssh-keygen absent


def ssh_fingerprint(path, pub):
    """Empreinte via ssh-keygen -lf sur le .pub, ou sur le pub dérivé écrit en fichier temporaire."""
    target, tmp = path + ".pub", None
    if not os.path.exists(target):
        if not pub:
            return None
        fd, tmp = tempfile.mkstemp(prefix="dash_pub_")
        with os.fdopen(fd, "w") as fh:
            fh.write(pub + "\n")
        target = tmp
    try:
        r = subprocess.run(["ssh-keygen", "-lf", target], capture_output=True, text=True, timeout=5)
        return (r.stdout.strip() or None) if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def ssh_key_type(pub):
    head = (pub or "").split()[0] if (pub or "").split() else ""
    return {"ssh-ed25519": "ed25519", "ssh-rsa": "rsa"}.get(head, "?")


def ssh_keys_list():
    """Clés privées présentes dans SSH_DIR (on exclut les fichiers de service et les .pub)."""
    keys = []
    try:
        names = sorted(os.listdir(SSH_DIR))
    except OSError:
        return keys
    for n in names:
        if n.startswith(".") or n.startswith("known_hosts") or n.endswith(".pub") or n in SSH_SKIP_EXACT:
            continue
        path = os.path.join(SSH_DIR, n)
        if not os.path.isfile(path):
            continue
        pub = ssh_pub_text(path)
        keys.append({"name": n, "path": path, "type": ssh_key_type(pub),
                     "pub": pub, "fingerprint": ssh_fingerprint(path, pub)})
    return keys


def ssh_key_assignments():
    return [{"server": s.get("name"), "key": s.get("key") or KEY} for s in servers_list()]


def valid_key_path(key):
    """Chemin de clé acceptable : sous /root/.ssh, sans .., et le fichier existe."""
    key = str(key or "")
    return key.startswith(SSH_DIR + "/") and ".." not in key and os.path.isfile(key)


# ---------- wp-cli action ----------
def run_remote_script(srv, script, timeout=300):
    """Exécute un script bash sur le serveur : transmis à `bash -s` sur l'entrée standard."""
    cmd = ["ssh", "-i", srv.get("key") or KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=12", "-p", str(srv["port"]), ssh_target(srv), "bash -s"]
    r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout + 40)
    return r.returncode, (r.stdout + r.stderr).strip()[-6000:]


def run_wp_remote(srv, site, wp_args, timeout=300):
    """Construit le script distant (chaînage « && WPRUN ») et l'exécute en ssh."""
    parts = [p.strip() for p in wp_args.split("&& WPRUN")]
    body = "\n".join(f"run {p} || exit $?" for p in parts)
    script = REMOTE_TEMPLATE.format(docroot=sq(site["path"]), domain=sq(site["domain"]),
                                    owner=sq(site["owner"] or "root"),
                                    nosu="1" if srv.get("no_su") else "0",
                                    timeout=timeout, body=body)
    return run_remote_script(srv, script, timeout)


def update_policy():
    d = load_json(UPDATE_POLICY_PATH, {})
    return d if isinstance(d, dict) else {}


def frozen_plugins(domain):
    """Extensions gelées pour ce site (jamais mises à jour automatiquement)."""
    entry = update_policy().get(str(domain or "")) or {}
    out = [str(x) for x in (entry.get("frozen") or []) if SLUG_RE.match(str(x))]
    return sorted(set(out))


def set_frozen_plugin(domain, slug, frozen):
    """Gèle ou dégèle une extension. → nouvelle liste pour ce site."""
    pol = update_policy()
    entry = pol.setdefault(str(domain), {})
    cur = set(entry.get("frozen") or [])
    if frozen:
        cur.add(str(slug))
    else:
        cur.discard(str(slug))
    entry["frozen"] = sorted(cur)
    entry["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    if not entry["frozen"]:
        pol.pop(str(domain), None)
    save_json(UPDATE_POLICY_PATH, pol)
    return sorted(cur)


def run_action(server_name, domain, action, arg):
    if action == "rescan":
        r = subprocess.run(["/usr/bin/python3", os.path.join(BASE, "collect.py"),
                            "--only", server_name, "--match", domain],
                           capture_output=True, text=True, timeout=240)
        return r.returncode, (r.stdout + r.stderr).strip()
    if action not in ACTIONS:
        return 1, "action inconnue"
    # Politique par extension : une extension gelée n'est jamais mise à jour,
    # que la demande vienne d'un bouton, d'une action groupée ou de la MAJ sûre.
    gelees = frozen_plugins(domain)
    if gelees:
        if action == "plugin_update" and str(arg or "") in gelees:
            return FROZEN_RC, f"extension gelée pour ce site : {arg}"
        if action == "plugins_update_all":
            action, arg = "plugins_update_except", ",".join(gelees)
    label, needs_arg, wp_args = ACTIONS[action]
    if needs_arg:
        arg = str(arg or "")
        arg_ok = re.match(r"^[a-z0-9][a-z0-9,_-]{0,200}$", arg) if action == "plugins_update_except" else SLUG_RE.match(arg)
        if not arg_ok:
            return 91, "argument invalide"
        wp_args = wp_args.format(arg=arg)
    srv, site = find_site(server_name, domain)
    if not srv or not site:
        # site géré sans SSH : message explicite, et installation de vizproof via l'agent
        rest = rest_target(server_name, domain)
        if rest:
            if action != "vizproof_install":
                return REST_UNSUPPORTED_RC, REST_UNSUPPORTED_MSG
            # Voie officielle quand le site est autorisé (mot de passe d'application,
            # API REST native de WordPress) ; sinon on retente via l'agent.
            _, cred = wp_cred_for(domain, rest.get("siteurl") or rest.get("url") or "")
            if cred:
                rc, out = wp_install_plugin(rest)
            else:
                rc, out = rest_install_plugin(rest)
            if rc == 0:
                try:  # inventaire rafraîchi pour que le plugin apparaisse tout de suite
                    run_action(server_name, domain, "rescan", None)
                except Exception as e:
                    out += f"\n(re-scan à refaire : {e})"
            return rc, out
        return 92, "site inconnu"
    # rc 2 sur une action vizproof = anomalies visuelles, remonté tel quel à l'appelant
    return run_wp_remote(srv, site, wp_args)


def append_log(entry):
    with open(LOG, "a") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_log(n=120):
    try:
        with open(LOG) as fh:
            lines = fh.readlines()[-n:]
        out = []
        for l in lines:
            try:
                out.append(json.loads(l))
            except ValueError:
                continue  # ligne tronquée par une écriture concurrente : ignorée
        return out[::-1]
    except FileNotFoundError:
        return []


# ---------- checksums mémorisés (C2) ----------
CHECKSUMS_LOCK = threading.Lock()


def record_checksum(domain, rc, out):
    """Mémorise le dernier résultat de `core verify-checksums` pour un domaine."""
    with CHECKSUMS_LOCK:
        store = load_json(CHECKSUMS_PATH, {})
        store[domain] = {"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         "ok": rc == 0, "output_tail": (out or "")[-1200:]}
        save_json(CHECKSUMS_PATH, store)


# ---------- vizproof : lecture du couple (rc, sortie) ----------
VIZ_NOT_CONFIGURED_RE = re.compile(
    r"not a registered|n'est pas une commande|pas configur|non configur|not configured|"
    r"dash-connect|no baseline|aucune baseline|aucune page|no pages|plugin.{0,20}(absent|inactif)",
    re.I)


def viz_status(rc, out):
    """Traduit une exécution vizproof en statut : ok / anomalies / non configuré / échec."""
    if rc == 0:
        return "ok"
    if rc == VIZ_ANOMALY_RC:
        return "anomalies"
    if rc == REST_UNSUPPORTED_RC:
        return "non configuré"  # site sans SSH : baseline et scan visuels indisponibles
    if VIZ_NOT_CONFIGURED_RE.search(out or ""):
        return "non configuré"
    return "échec"


def logged_action(server, domain, action, arg, source="manuel"):
    t0 = time.time()
    try:
        rc, out = run_action(server, domain, action, arg)
    except subprocess.TimeoutExpired:
        rc, out = 93, "timeout"
    except Exception as e:
        rc, out = 94, f"erreur interne: {e}"
    # rc conservé tel quel : sur une action vizproof, 2 signifie « anomalies », pas une erreur
    entry = {"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source": source,
             "server": server, "domain": domain, "action": action, "arg": arg,
             "rc": rc, "duration_s": round(time.time() - t0, 1), "output_tail": out[-2000:]}
    append_log(entry)
    if action == "verify_checksums" and source in CHECKSUM_SOURCES:
        record_checksum(domain, rc, out)
    return rc, out


# --------------------------------------------------------------------------- #
#  Mise à jour sûre : archive → met à jour → contrôle → restaure si cassé      #
#                                                                             #
#  Le retour arrière remet en place le DOSSIER de l'extension archivé juste    #
#  avant, et non une restauration complète UpdraftPlus : restaurer tout le     #
#  site ferait perdre ce qui a été écrit depuis la sauvegarde (commandes,      #
#  entrées de formulaire, commentaires) pour un simple plantage d'extension.   #
#  L'archive fonctionne en outre pour les extensions premium, que              #
#  `wp plugin install --version=` ne sait pas retélécharger.                   #
#                                                                             #
#  Le contrôle de santé s'appuie sur des signaux toujours disponibles (page    #
#  d'accueil servie, WordPress fonctionnel). Le contrôle visuel VizProof n'est #
#  utilisé QUE là où la commande `wp vizproof` existe réellement.              #
# --------------------------------------------------------------------------- #
SAFE = {"running": False, "domain": "", "steps": [], "verdict": "", "started": None,
        "finished": None}
SAFE_LOCK = threading.Lock()
SAFE_ROLLBACK_PARENT = "/tmp"
SAFE_ROLLBACK_DIR = SAFE_ROLLBACK_PARENT + "/.wpdash-rollback"
SAFE_KEEP_DAYS = 7          # archives conservées 7 jours (purge par date)
SAFE_KEEP_SETS = 3          # et au plus 3 jeux par site (purge par nombre)
SAFE_DISK_MARGIN_MB = 500   # marge exigée en plus du double du volume à archiver
BODY_MIN_RATIO = 0.5   # une page qui perd plus de la moitié de son poids = suspecte


def safe_step(label, ok, detail=""):
    SAFE["steps"].append({"label": label, "ok": ok, "detail": str(detail or "")[:600],
                          "ts": datetime.datetime.now().strftime("%H:%M:%S")})


def site_home_url(site):
    return (site.get("siteurl") or ("https://" + site.get("domain", ""))).rstrip("/") + "/"


def health_probe(site):
    """(ok, statut, taille, message) — la page d'accueil est-elle servie normalement ?"""
    st, body, _final, err = http_get(site_home_url(site), timeout=25,
                                     headers={"Accept": "text/html"})
    if err:
        return False, None, 0, f"injoignable : {err}"
    size = len(body or b"")
    return (st == 200), st, size, f"HTTP {st}, {size} octets"


def remote_bash(srv, site, body, timeout=300):
    """Exécute du bash arbitraire côté site (helpers `asuser`/`run` disponibles)."""
    script = REMOTE_TEMPLATE.format(docroot=sq(site["path"]), domain=sq(site["domain"]),
                                    owner=sq(site["owner"] or "root"),
                                    nosu="1" if srv.get("no_su") else "0",
                                    timeout=timeout, body=body)
    return run_remote_script(srv, script, timeout)


def viz_available(srv, site):
    rc, _ = remote_bash(srv, site, 'asuser "$base wp vizproof --help $extra --no-color" >/dev/null 2>&1'
                                  ' && echo oui || exit 1', timeout=60)
    return rc == 0


def safe_update_run(server_name, domain, slugs=None, do_backup=True, use_viz=True,
                    with_core=False):
    """Orchestration complète.

    `slugs` None = toutes les extensions ayant une mise à jour en attente.
    `with_core` inclut le cœur WordPress : ses fichiers sont archivés et
    restaurables, MAIS les migrations de base de données déclenchées par
    `core update-db` ne sont PAS annulées par le retour arrière — c'est la
    sauvegarde UpdraftPlus qui sert de recours pour la base.
    """
    SAFE.update({"running": True, "domain": domain, "steps": [], "verdict": "",
                 "started": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "finished": None})
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    arc = f"{SAFE_ROLLBACK_DIR}/{re.sub(r'[^a-zA-Z0-9._-]', '_', domain)}-{stamp}"
    try:
        srv, site = find_site(server_name, domain)
        if not srv or not site:
            safe_step("Site introuvable", False,
                      "site géré sans SSH : la mise à jour sûre exige un accès SSH")
            SAFE["verdict"] = "impossible"
            return

        # 1. état de départ
        ok, st, size_before, msg = health_probe(site)
        # Référence WP-CLI : certains sites ont déjà des extensions qui échouent en
        # CLI (revslider sur ffhbi.fr). On mémorise l'état AVANT pour ne pas
        # imputer à la mise à jour un défaut qui préexistait.
        rcw0, _ = remote_bash(srv, site, 'run option get siteurl', timeout=90)
        wp_ok_before = (rcw0 == 0)
        safe_step("Contrôle avant mise à jour", ok,
                  msg + ("" if wp_ok_before else " — WP-CLI déjà en erreur avant l'opération"))
        if not ok:
            safe_step("Interrompu", False,
                      "le site est déjà en erreur avant toute intervention — "
                      "on ne met pas à jour un site cassé")
            SAFE["verdict"] = "annulé"
            return

        # 2. liste réelle des extensions à mettre à jour.
        #    --skip-plugins/--skip-themes : lire l'inventaire n'exige pas de charger
        #    le code des extensions, et l'une d'elles peut être en erreur fatale
        #    (revslider sur ffhbi.fr fait échouer la commande sans ces options).
        rc, out = remote_bash(srv, site,
                              'asuser "$base wp plugin list --update=available --field=name '
                              '--format=csv --skip-plugins --skip-themes $extra --no-color"', timeout=120)
        if rc != 0:
            safe_step("Liste des mises à jour", False,
                      "impossible d'obtenir la liste des extensions à mettre à jour : "
                      + (out or "")[-300:])
            SAFE["verdict"] = "annulé"
            return
        pending = [l.strip() for l in (out or "").splitlines()
                   if l.strip() and re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", l.strip())]
        if slugs:
            pending = [p for p in pending if p in slugs]
        gelees = frozen_plugins(domain)
        if gelees:
            ecartees = [p for p in pending if p in gelees]
            pending = [p for p in pending if p not in gelees]
            if ecartees:
                safe_step("Extensions gelées, écartées", True, ", ".join(ecartees))

        # Cœur : présent seulement si une mise à jour est réellement disponible.
        core_target = ""
        if with_core:
            rcc, outc = remote_bash(srv, site,
                                    'asuser "$base wp core check-update --field=version '
                                    '--format=csv --skip-plugins --skip-themes $extra --no-color"',
                                    timeout=120)
            cand = [l.strip() for l in (outc or "").splitlines()
                    if re.match(r"^\d+\.\d+(\.\d+)?$", l.strip())]
            core_target = cand[0] if rcc == 0 and cand else ""
            with_core = bool(core_target)

        if not pending and not with_core:
            safe_step("Rien à mettre à jour", True, "aucune extension ni cœur en attente")
            SAFE["verdict"] = "rien à faire"
            return
        quoi = []
        if pending:
            quoi.append(f"{len(pending)} extension(s) : " + ", ".join(pending[:20]))
        if with_core:
            quoi.append(f"cœur WordPress → {core_target}")
        safe_step("À mettre à jour", True, " | ".join(quoi))
        # Versions actuelles : sans elles, une archive ne dit pas vers quoi on
        # reviendrait. Le manifeste est écrit à côté des .tgz.
        versions_avant = {}
        rcv, outv = remote_bash(srv, site,
                                'asuser "$base wp plugin list --fields=name,version --format=csv '
                                '--skip-plugins --skip-themes $extra --no-color"', timeout=120)
        for ligne in (outv or "").splitlines():
            bout = ligne.strip().split(",")
            if len(bout) == 2 and bout[0] in pending:
                versions_avant[bout[0]] = bout[1]
        if with_core:
            safe_step("Avertissement sur le cœur", True,
                      "les fichiers du cœur sont archivés et restaurables, mais les migrations "
                      "de base de données (core update-db) ne sont PAS annulées par le retour "
                      "arrière — la sauvegarde UpdraftPlus est le recours pour la base")

        # 3. sauvegarde UpdraftPlus (filet distant, hors mécanisme de retour arrière)
        if do_backup:
            rc, out = logged_action(server_name, domain, "updraft_backup", None, source="maj-sure")
            safe_step("Sauvegarde UpdraftPlus", rc == 0,
                      (out or "")[-300:] if rc else "sauvegarde lancée")

        # 4. archivage des dossiers concernés (+ contrôle d'espace et purge)
        #    On archive UNIQUEMENT les extensions réellement mises à jour, jamais
        #    tout le dossier plugins : sur un gros site c'est 400 Mo contre 30.
        lst = " ".join(sq(p) for p in pending)
        core_arch = "oui" if with_core else "non"
        manifest = json.dumps({"domain": domain, "ts": stamp, "core_before": core if with_core else None,
                               "core_target": core_target if with_core else None,
                               "plugins": versions_avant}, ensure_ascii=False)
        body = f'''
set -o pipefail
PLUGDIR=$(asuser "$base wp plugin path $extra --no-color" 2>/dev/null | tail -1)
[ -d "$PLUGDIR" ] || PLUGDIR="$D/wp-content/plugins"
echo "PLUGDIR=$PLUGDIR"

# Purge des archives d'anciennes exécutions (retour arrière conservé 7 jours).
find {sq(SAFE_ROLLBACK_DIR)} -maxdepth 1 -type d -mtime +{SAFE_KEEP_DAYS} -exec rm -rf {{}} + 2>/dev/null

# Volume à archiver, puis contrôle d'espace : on refuse de commencer si /tmp
# ne peut pas absorber les archives avec une marge confortable.
besoin=0
for s in {lst}; do
  [ -d "$PLUGDIR/$s" ] || continue
  besoin=$((besoin + $(du -sm "$PLUGDIR/$s" 2>/dev/null | cut -f1)))
done
if [ "{core_arch}" = "oui" ]; then
  besoin=$((besoin + $(du -sm --exclude=wp-content "$D" 2>/dev/null | cut -f1)))
fi
# La base est dumpée elle aussi : --skip-plugins évite qu'une extension en
# erreur (fatale au chargement) empêche le dump, comme c'est le cas sur ffhbi.
# On ne retient qu'une ligne entièrement numérique : la sortie peut être
# précédée d'avertissements PHP contenant eux-mêmes des chiffres.
dbmo=$(asuser "$base wp db size --size_format=mb --skip-plugins --skip-themes $extra --no-color" 2>/dev/null \
       | grep -Eo '^[0-9]+([.][0-9]+)?$' | tail -1 | cut -d. -f1)
[ -n "$dbmo" ] || dbmo=200
echo "DB_MO=$dbmo"
besoin=$((besoin + dbmo))
libre=$(df -Pm {sq(SAFE_ROLLBACK_PARENT)} | awk 'NR==2{{print $4}}')
echo "BESOIN_MO=$besoin"; echo "LIBRE_MO=$libre"
if [ "$libre" -lt $((besoin * 2 + {SAFE_DISK_MARGIN_MB})) ]; then
  echo "ESPACE_INSUFFISANT"; exit 83
fi

mkdir -p {sq(arc)} && chmod 700 {sq(arc)} || exit 81
# Le script tourne en root mais `wp` tourne sous l'utilisateur du site :
# sans ce chown, `wp db export` ne peut pas ecrire dans l'archive.
[ "$NOSU" = "1" ] || chown "$OWN" {sq(arc)} 2>/dev/null
for s in {lst}; do
  if [ -d "$PLUGDIR/$s" ]; then
    tar czf {sq(arc)}/plugin__"$s".tgz -C "$PLUGDIR" "$s" || exit 82
    echo "archivé $s"
  else
    echo "absent $s"
  fi
done
if [ "{core_arch}" = "oui" ]; then
  # Le cœur = tout le docroot SAUF wp-content (extensions, thèmes, médias) :
  # on ne duplique ni les médias ni les extensions déjà archivées à part.
  tar czf {sq(arc)}/core__.tgz -C "$D" --exclude=./wp-content . || exit 84
  echo "archivé (coeur)"
fi
# Dump de la base : symétrique de l'archive des fichiers. Indispensable pour le
# cœur (core update-db migre le schéma, la restauration de fichiers ne l'annule
# pas) et utile pour les extensions qui migrent leurs tables (WooCommerce,
# Yoast, ACF, Gravity Forms…). --skip-plugins : le dump doit aboutir même quand
# une extension est en erreur fatale.
dump_ok=0
if asuser "$base wp db export {sq(arc)}/db__.sql --skip-plugins --skip-themes --add-drop-table $extra --no-color" >/dev/null 2>&1 \
   && [ -s {sq(arc)}/db__.sql ]; then
  dump_ok=1
else
  # Repli : sur un serveur ou wp-cli 2.12 cherche `mariadb-dump` alors que seul
  # `mysqldump` existe (cas de plesk-mutu), l'export echoue. On appelle donc
  # mysqldump directement, avec les identifiants lus dans wp-config.
  # Le mot de passe transite par un fichier 600, jamais par la ligne de commande
  # (il serait visible dans `ps`) ni par la sortie standard.
  DUMPBIN=$(command -v mysqldump || command -v mariadb-dump || true)
  if [ -n "$DUMPBIN" ]; then
    cfg() {{ asuser "$base wp config get $1 --skip-plugins --skip-themes $extra --no-color" 2>/dev/null | tail -1; }}
    DBN=$(cfg DB_NAME); DBU=$(cfg DB_USER); DBH=$(cfg DB_HOST)
    CNF={sq(arc)}/.my.cnf
    ( umask 077; printf '[client]\npassword=%s\n' "$(cfg DB_PASSWORD)" > "$CNF" )
    # DB_HOST peut valoir « hote », « hote:port » ou « hote:/chemin/socket » :
    # passe tel quel a -h, mysqldump le prend pour un nom d'hote et echoue.
    DBPORT=""; DBSOCK=""
    case "$DBH" in
      *:/*) DBSOCK="${{DBH#*:}}"; DBH="${{DBH%%:*}}" ;;
      *:*)  DBPORT="${{DBH#*:}}"; DBH="${{DBH%%:*}}" ;;
    esac
    set -- --defaults-extra-file="$CNF" -h "${{DBH:-localhost}}" -u "$DBU"
    [ -n "$DBPORT" ] && set -- "$@" -P "$DBPORT"
    [ -n "$DBSOCK" ] && set -- "$@" --socket="$DBSOCK"
    if [ -n "$DBN" ] && [ -n "$DBU" ]; then
      "$DUMPBIN" "$@" --add-drop-table --single-transaction --quick "$DBN" \
        > {sq(arc)}/db__.sql 2>/dev/null \
        && [ -s {sq(arc)}/db__.sql ] && dump_ok=1
    fi
    rm -f "$CNF"
  fi
fi
if [ "$dump_ok" = "1" ]; then
  gzip -f {sq(arc)}/db__.sql 2>/dev/null
  echo "BDD_MO=$(du -sm {sq(arc)}/db__.sql.gz 2>/dev/null | cut -f1)"
  echo "archivé (base)"
else
  echo "BDD_ECHEC"
fi
cat > {sq(arc)}/manifest.json <<'MANIFEST'
{manifest}
MANIFEST
echo "TAILLE_ARCHIVES_MO=$(du -sm {sq(arc)} 2>/dev/null | cut -f1)"
'''
        rc, out = remote_bash(srv, site, body, timeout=900)
        if "ESPACE_INSUFFISANT" in (out or ""):
            besoin = next((l.split("=")[1] for l in out.splitlines() if l.startswith("BESOIN_MO=")), "?")
            libre = next((l.split("=")[1] for l in out.splitlines() if l.startswith("LIBRE_MO=")), "?")
            safe_step("Espace disque insuffisant", False,
                      f"{besoin} Mo à archiver, {libre} Mo libres sur {SAFE_ROLLBACK_PARENT} — "
                      "mise à jour annulée avant toute modification")
            SAFE["verdict"] = "annulé"
            return
        plugdir = next((l.split("=", 1)[1] for l in (out or "").splitlines()
                        if l.startswith("PLUGDIR=")), "")
        n_arc = sum(1 for l in (out or "").splitlines()
                    if l.startswith("archivé") and "(base)" not in l)
        db_ok = "archivé (base)" in (out or "")
        db_mo = next((l.split("=")[1] for l in (out or "").splitlines() if l.startswith("BDD_MO=")), "?")
        safe_step("Archivage des fichiers", rc == 0 and n_arc > 0,
                  f"{n_arc} élément(s) archivé(s) dans {arc}" if rc == 0 else (out or "")[-300:])
        safe_step("Sauvegarde locale de la base", db_ok,
                  f"{arc}/db__.sql.gz ({db_mo} Mo) — restauration : "
                  f"gunzip -c db__.sql.gz | wp db import -" if db_ok
                  else "le dump de la base a échoué")
        if rc != 0 or n_arc == 0:
            safe_step("Interrompu", False, "sans archive, aucun retour arrière possible")
            SAFE["verdict"] = "annulé"
            return
        if with_core and not db_ok:
            # Le cœur migre le schéma : sans dump, un retour arrière laisserait
            # d'anciens fichiers sur une base déjà migrée. On refuse.
            safe_step("Interrompu", False,
                      "mise à jour du cœur sans sauvegarde de base : refusé "
                      "(core update-db migre le schéma, la restauration de fichiers ne l'annule pas)")
            SAFE["verdict"] = "annulé"
            return

        # 5. mise à jour (cœur d'abord : les extensions s'adaptent au cœur, l'inverse est faux)
        rc = 0
        if with_core:
            rcc, outc = remote_bash(srv, site,
                                    'run core update\nrun core update-db', timeout=900)
            safe_step(f"Mise à jour du cœur → {core_target}", rcc == 0, (outc or "")[-400:])
            rc = rc or rcc
        if pending:
            rcp, outp = remote_bash(srv, site, f'run plugin update {lst}', timeout=900)
            safe_step("Mise à jour des extensions", rcp == 0, (outp or "")[-500:])
            rc = rc or rcp

        # 6. contrôles après
        ok2, st2, size_after, msg2 = health_probe(site)
        shrunk = bool(size_before and size_after < size_before * BODY_MIN_RATIO)
        safe_step("Page d'accueil", ok2 and not shrunk,
                  msg2 + (f" — page effondrée ({size_before} → {size_after})" if shrunk else ""))
        rcw, outw = remote_bash(srv, site, 'run option get siteurl', timeout=90)
        # On ne retient une régression que si WP-CLI fonctionnait AVANT.
        wp_regression = wp_ok_before and rcw != 0
        safe_step("WordPress fonctionnel", not wp_regression,
                  (outw or "")[-200:] if wp_regression
                  else ("ok" if rcw == 0 else "en erreur, mais déjà avant l'opération — non imputé"))

        viz_ok, viz_used = True, False
        if use_viz and viz_available(srv, site):
            viz_used = True
            rcv, outv = remote_bash(srv, site,
                                    'run vizproof scan --wait --format=json', timeout=600)
            viz_ok = (rcv == 0)
            safe_step("Contrôle visuel VizProof", viz_ok,
                      "anomalies visuelles détectées" if rcv == VIZ_ANOMALY_RC else (outv or "")[-300:])
        elif use_viz:
            safe_step("Contrôle visuel VizProof", True,
                      "indisponible sur ce site (commande wp vizproof absente) — ignoré")

        sain = (rc == 0) and ok2 and not shrunk and not wp_regression and viz_ok

        # 7. retour arrière si nécessaire
        if sain:
            # Les archives sont CONSERVÉES : c'est ce qui permet de rétablir une
            # version précédente plus tard, y compris pour une extension premium.
            # Purge bornée : au plus SAFE_KEEP_SETS jeux par site.
            prefixe = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
            remote_bash(srv, site,
                        f'ls -1dt {sq(SAFE_ROLLBACK_DIR)}/{prefixe}-* 2>/dev/null '
                        f'| tail -n +{SAFE_KEEP_SETS + 1} | xargs -r rm -rf', timeout=60)
            safe_step("Terminé", True,
                      f"mise à jour conservée · point de restauration gardé ({arc})")
            SAFE["verdict"] = "réussi"
        else:
            rb = f'''
PLUGDIR={sq(plugdir or "$D/wp-content/plugins")}
for f in {sq(arc)}/plugin__*.tgz; do
  [ -f "$f" ] || continue
  s=$(basename "$f" .tgz); s=${{s#plugin__}}
  rm -rf "$PLUGDIR/$s" && tar xzf "$f" -C "$PLUGDIR" && echo "restauré $s" || echo "ECHEC $s"
done
if [ -f {sq(arc)}/core__.tgz ]; then
  # On remet les fichiers du cœur par-dessus (wp-content n'a jamais été touché).
  tar xzf {sq(arc)}/core__.tgz -C "$D" && echo "restauré (coeur)" || echo "ECHEC (coeur)"
fi
'''
            rcr, outr = remote_bash(srv, site, rb, timeout=900)
            n_res = sum(1 for l in (outr or "").splitlines() if l.startswith("restauré"))
            safe_step("Retour arrière (fichiers)", rcr == 0 and n_res > 0,
                      f"{n_res} élément(s) remis en version précédente")
            # La base n'est JAMAIS restaurée automatiquement : elle contient ce
            # qui a été écrit pendant la mise à jour (commande, formulaire,
            # commentaire). La rejouer ferait perdre ces données. On donne la
            # commande exacte pour que ce soit une décision, pas un effet de bord.
            if db_ok:
                safe_step("Base de données : décision à prendre", True,
                          "la base n'a PAS été restaurée (elle contient ce qui a été écrit "
                          f"pendant l'opération). Dump disponible : {arc}/db__.sql.gz — "
                          f"pour l'appliquer : cd {site['path']} && gunzip -c {arc}/db__.sql.gz "
                          "| wp db import -")
            ok3, _st3, size3, msg3 = health_probe(site)
            safe_step("Contrôle après retour arrière", ok3, msg3)
            SAFE["verdict"] = "annulé (retour arrière)" if ok3 else "ÉCHEC — intervention requise"
            alert(f"safeupdate:{domain}", None,
                  f"⛔ <b>{esc_html(domain)}</b> — mise à jour annulée automatiquement "
                  f"({n_res} extension(s) remise(s) en arrière). Verdict : {esc_html(SAFE['verdict'])}")
        append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "maj-sure", "server": server_name, "domain": domain,
                    "action": "safe_update", "arg": ",".join(pending),
                    "rc": 0 if sain else 2, "duration_s": 0,
                    "output_tail": f"verdict={SAFE['verdict']}"})
    except Exception as e:
        safe_step("Erreur interne", False, f"{type(e).__name__}: {e}")
        SAFE["verdict"] = "erreur"
    finally:
        SAFE["running"] = False
        SAFE["finished"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def rollback_points(server_name, domain):
    """Points de restauration disponibles pour un site → liste décroissante.

    Chaque entrée décrit un jeu d'archives laissé par une mise à jour sûre :
    quand, et quelle version chaque extension avait AVANT.
    """
    srv, site = find_site(server_name, domain)
    if not srv or not site:
        return []
    prefixe = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    rc, out = remote_bash(srv, site,
                          f'for d in $(ls -1dt {sq(SAFE_ROLLBACK_DIR)}/{prefixe}-* 2>/dev/null); do '
                          f'  echo "@@DIR@@$d"; cat "$d/manifest.json" 2>/dev/null; echo; '
                          f'  ls -1 "$d" | grep "^plugin__" | sed "s/^plugin__/@@P@@/;s/\\.tgz$//"; '
                          f'done', timeout=120)
    if rc != 0:
        return []
    points, cur = [], None
    for ligne in (out or "").splitlines():
        ligne = ligne.rstrip()
        if ligne.startswith("@@DIR@@"):
            cur = {"dir": ligne[7:], "plugins": [], "versions": {}, "ts": ""}
            points.append(cur)
        elif cur is None:
            continue
        elif ligne.startswith("@@P@@"):
            cur["plugins"].append(ligne[5:])
        elif ligne.startswith("{"):
            try:
                m = json.loads(ligne)
                cur["versions"] = m.get("plugins") or {}
                cur["ts"] = m.get("ts") or ""
            except ValueError:
                pass
    return [p for p in points if p["plugins"]]


def wporg_versions(slug, limit=40):
    """Versions publiées d'une extension sur wordpress.org, de la plus récente
    à la plus ancienne. C'est la source qu'utilise WP Rollback : le dépôt
    conserve tous les tags, donc n'importe quelle version reste installable.
    Renvoie [] pour une extension premium (absente du dépôt public)."""
    if not SLUG_RE.match(str(slug or "")):
        return []
    url = f"https://api.wordpress.org/plugins/info/1.0/{urllib.parse.quote(str(slug))}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read(2 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception:
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    brutes = [v for v in (data.get("versions") or {}) if v and v != "trunk"]
    # Tri décroissant à la sémantique PHP : on réutilise le comparateur déjà
    # validé contre version_compare() (1.10 > 1.9, et beta2 > beta1).
    import functools
    from vulns import version_compare
    brutes.sort(key=functools.cmp_to_key(version_compare), reverse=True)
    return {"current": data.get("version"), "versions": brutes[:limit]}


def plugin_rollback(server_name, domain, slug, arc_dir=None, version=None):
    """Rétablit une extension. → (rc, message).

    Deux sources, dans cet ordre de fiabilité :
      1. une archive locale — restitution à l'identique, fonctionne aussi pour
         les extensions premium que wordpress.org ne peut pas resservir ;
      2. une version publiée sur wordpress.org, en repli.
    La base n'est jamais touchée : une extension qui a migré ses tables peut
    nécessiter une intervention manuelle, c'est signalé à l'appelant.
    """
    srv, site = find_site(server_name, domain)
    if not srv or not site:
        return 92, "site inconnu"
    if not SLUG_RE.match(str(slug or "")):
        return 91, "extension invalide"

    if arc_dir:
        if not re.match(r"^/tmp/\.wpdash-rollback/[A-Za-z0-9._-]+$", str(arc_dir)):
            return 91, "point de restauration invalide"
        body = f'''
PLUGDIR=$(asuser "$base wp plugin path $extra --no-color" 2>/dev/null | tail -1)
[ -d "$PLUGDIR" ] || PLUGDIR="$D/wp-content/plugins"
F={sq(str(arc_dir))}/plugin__{sq(str(slug))}.tgz
[ -f "$F" ] || {{ echo "ARCHIVE_ABSENTE"; exit 2; }}
rm -rf "$PLUGDIR"/{sq(str(slug))} && tar xzf "$F" -C "$PLUGDIR" && echo "RESTAURE"
'''
        rc, out = remote_bash(srv, site, body, timeout=600)
        if "ARCHIVE_ABSENTE" in (out or ""):
            return 2, "aucune archive pour cette extension dans ce point de restauration"
        if rc != 0 or "RESTAURE" not in (out or ""):
            return rc or 1, (out or "")[-300:]
        return 0, f"{slug} rétabli depuis l'archive"

    if not version or not re.match(r"^[0-9][0-9A-Za-z._-]{0,20}$", str(version)):
        return 91, "version invalide"
    rc, out = remote_bash(srv, site,
                          f'run plugin install {sq(str(slug))} --version={sq(str(version))} --force',
                          timeout=600)
    return rc, (out or "")[-400:]


# ---------- collecte complète ----------
COLLECT = {"running": False, "lines": [], "rc": None, "started": None, "done_servers": 0, "total_servers": 0}
COLLECT_LOCK = threading.Lock()

# ---------- veille de vulnérabilités (vulns.py, croisement local) ----------
VULNS = {"running": False, "message": "", "finished": None}


def vulns_worker(refresh=True):
    """Rafraîchit la base publique puis recroise l'inventaire, hors requête HTTP."""
    VULNS.update({"running": True, "message": "analyse en cours…", "finished": None})
    try:
        cmd = [sys.executable, os.path.join(BASE, "vulns.py")]
        cmd += ["--fetch", "--scan"] if refresh else ["--scan"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200, cwd=BASE)
        out = (r.stdout or "").strip().splitlines()
        VULNS["message"] = out[-1] if out else ((r.stderr or "").strip()[-200:] or "terminé")
    except subprocess.TimeoutExpired:
        VULNS["message"] = "délai dépassé (l'analyse a été interrompue)"
    except Exception as e:
        VULNS["message"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        VULNS["running"] = False
        VULNS["finished"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def collect_worker():
    try:
        p = subprocess.Popen(["/usr/bin/python3", os.path.join(BASE, "collect.py")],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in p.stdout:
            line = line.rstrip()
            if not line:
                continue
            COLLECT["lines"] = (COLLECT["lines"] + [line])[-100:]
            if line.startswith("["):
                COLLECT["done_servers"] += 1
        p.wait()
        COLLECT["rc"] = p.returncode
        if p.returncode == 0:
            # collecte complète réussie : on évalue les règles d'alerte sur les données fraîches
            try:
                evaluate_alerts()
            except Exception as e:
                alerts_log(f"evaluate_alerts: {e}")
    except Exception as e:
        COLLECT["lines"] = COLLECT["lines"] + [f"erreur: {e}"]
        COLLECT["rc"] = 95
    finally:
        COLLECT["running"] = False


def start_collect():
    with COLLECT_LOCK:
        if COLLECT["running"]:
            return False
        COLLECT.update({"running": True, "lines": [], "rc": None, "done_servers": 0,
                        # + le serveur virtuel « rest » quand des sites sont collectés sans SSH
                        "total_servers": len(servers_list()) + (1 if rest_sites() else 0),
                        "started": datetime.datetime.now().strftime("%H:%M:%S")})
        threading.Thread(target=collect_worker, daemon=True).start()
        return True


# ---------- file d'attente de masse ----------
JOBS = {}
JOB_SEQ = itertools.count(1)
JOB_LOCK = threading.Lock()


def bulk_worker(job):
    try:
        _bulk_worker(job)
    except Exception as e:   # un bug ne doit jamais laisser un job « en cours » indéfiniment
        for t in job["tasks"]:
            if t["status"] in ("en attente", "en cours"):
                t["status"] = "échec"
                t["output_tail"] = f"interruption du traitement : {e}"
        job["stopped"] = True
    finally:
        job["running"] = False
        job["finished"] = datetime.datetime.now().strftime("%H:%M:%S")


def _bulk_worker(job):
    for task in job["tasks"]:
        if job["cancel"]:
            task["status"] = "annulé"
            continue
        task["status"] = "en cours"
        srv, site = find_site(task["server"], task["domain"])
        # Installation de l'agent : dépôt du fichier + appairage, pas une commande wp-cli
        if task["action"] == "dash_connect":
            try:
                rc, out = dash_connect(task["server"], task["domain"])  # secret déjà masqué en interne
            except Exception as e:
                rc, out = 94, f"erreur interne : {e}"
            task["rc"] = rc
            task["output_tail"] = str(out or "")[-1500:]
            task["status"] = "ok" if rc == 0 else "échec"
            job["done"] += 1
            if rc != 0 and job["mode"] == "stop":
                job["stopped"] = True
                for t in job["tasks"]:
                    if t["status"] == "en attente":
                        t["status"] = "ignoré"
                break
            continue
        # backup préalable si demandé et UpdraftPlus présent
        if job["backup_first"] and task["action"] in BACKUP_FIRST and site and site.get("updraft"):
            rcb, _ = logged_action(task["server"], task["domain"], "updraft_backup", None, source="bulk-backup")
            task["backup"] = "ok" if rcb == 0 else f"échec (rc {rcb})"
        # MAJ vérifiée visuellement : baseline avant la MAJ, scan après
        viz_ready = False
        if job.get("viz_verify") and task["action"] in BACKUP_FIRST:
            rcv, outv = logged_action(task["server"], task["domain"], "viz_baseline", None, source="bulk-viz")
            task["viz"] = viz_status(rcv, outv)
            viz_ready = rcv == 0
        rc, out = logged_action(task["server"], task["domain"], task["action"], task.get("arg"), source="bulk")
        task["rc"] = rc
        task["output_tail"] = out[-1500:]
        task["status"] = "ok" if rc == 0 else "échec"
        if viz_ready and rc == 0:
            rcs, outs = logged_action(task["server"], task["domain"], "viz_scan", None, source="bulk-viz")
            task["viz"] = viz_status(rcs, outs)
            # les anomalies visuelles ne font pas échouer la tâche : elles alertent
            if task["viz"] == "anomalies":
                alert(f"viz_anomaly:{task['domain']}", "viz_anomaly",
                      f"👁 <b>Anomalies visuelles</b> après « {ACTIONS.get(task['action'], (task['action'],))[0]} »"
                      f"\nSite : <b>{esc_html(task['domain'])}</b> ({esc_html(task['server'])})")
        job["done"] += 1
        if rc != 0 and job["mode"] == "stop":
            job["stopped"] = True
            for t in job["tasks"]:
                if t["status"] == "en attente":
                    t["status"] = "ignoré"
            break
        # re-scan léger après une action mutante réussie
        if rc == 0 and task["action"] not in ("verify_checksums", "rescan"):
            logged_action(task["server"], task["domain"], "rescan", None, source="bulk-rescan")
    # running/finished sont posés par bulk_worker (bloc finally)


def start_bulk(tasks, mode, backup_first, viz_verify=False):
    jid = next(JOB_SEQ)
    job = {"id": jid, "running": True, "cancel": False, "stopped": False,
           "mode": mode, "backup_first": backup_first, "viz_verify": bool(viz_verify),
           "done": 0, "total": len(tasks),
           "started": datetime.datetime.now().strftime("%H:%M:%S"), "finished": None,
           "tasks": [{"server": t["server"], "domain": t["domain"], "action": t["action"],
                      "arg": t.get("arg"), "status": "en attente", "rc": None,
                      "output_tail": "", "backup": None, "viz": None} for t in tasks]}
    JOBS[jid] = job
    # purge des vieux jobs terminés
    old = [k for k, v in JOBS.items() if not v["running"] and k < jid - 8]
    for k in old:
        JOBS.pop(k, None)
    threading.Thread(target=bulk_worker, args=(job,), daemon=True).start()
    return jid


# ---------- Kuma (manipulation directe SQLite + redémarrage) ----------
def kuma_sql(sql):
    r = subprocess.run(["docker", "exec", KUMA_CONTAINER, "sqlite3", "-cmd", ".timeout 8000", KUMA_DB, sql],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stdout + r.stderr).strip()


def kuma_restart():
    subprocess.run(["docker", "restart", KUMA_CONTAINER], capture_output=True, text=True, timeout=90)


def kuma_state():
    rc, out = kuma_sql("SELECT id||char(9)||name||char(9)||type||char(9)||COALESCE(parent,'')||char(9)||active FROM monitor ORDER BY type!='group', name;")
    groups, monitors = [], []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 5:
            continue
        row = {"id": int(p[0]), "name": p[1], "type": p[2],
               "parent": int(p[3]) if p[3] else None, "active": p[4] == "1"}
        (groups if row["type"] == "group" else monitors).append(row)
    return groups, monitors


def kuma_create(domain, monitor_name, group_id, url, mtype, keyword):
    name = monitor_name or domain
    esc = lambda s: str(s).replace('"', '""')
    gid = int(group_id)
    if mtype == "keyword":
        sql = (f'INSERT INTO monitor (name,active,user_id,`interval`,url,type,keyword,maxretries,'
               f'ignore_tls,upside_down,maxredirects,accepted_statuscodes_json,retry_interval,method,'
               f'expiry_notification,resend_interval,parent,invert_keyword,timeout,conditions) '
               f'SELECT "{esc(name)}",1,user_id,`interval`,"{esc(url)}","keyword","{esc(keyword)}",'
               f'maxretries,ignore_tls,upside_down,maxredirects,accepted_statuscodes_json,retry_interval,'
               f'method,expiry_notification,resend_interval,{gid},invert_keyword,timeout,conditions '
               f'FROM monitor WHERE type!="group" ORDER BY id LIMIT 1;')
    else:
        sql = (f'INSERT INTO monitor (name,active,user_id,`interval`,url,type,maxretries,'
               f'ignore_tls,upside_down,maxredirects,accepted_statuscodes_json,retry_interval,method,'
               f'expiry_notification,resend_interval,parent,invert_keyword,timeout,conditions) '
               f'SELECT "{esc(name)}",1,user_id,`interval`,"{esc(url)}","http",'
               f'maxretries,ignore_tls,upside_down,maxredirects,accepted_statuscodes_json,retry_interval,'
               f'method,expiry_notification,resend_interval,{gid},invert_keyword,timeout,conditions '
               f'FROM monitor WHERE type!="group" ORDER BY id LIMIT 1;')
    rc, out = kuma_sql(sql)
    if rc != 0:
        return rc, out
    # rattacher à la status page pour le statut live
    kuma_sql('INSERT INTO monitor_group (monitor_id, group_id, weight) '
             'SELECT (SELECT MAX(id) FROM monitor), '
             '(SELECT id FROM `group` WHERE status_page_id=(SELECT id FROM status_page WHERE slug="' + SLUG + '")), '
             '(SELECT MAX(id) FROM monitor);')
    kuma_restart()
    return 0, "moniteur créé"


# ---------- sécurité : diff et référence admins ----------
def compute_diff():
    cur = load_json(os.path.join(DATA, "fleet.json"), {"servers": []})
    prev = load_json(os.path.join(DATA, "fleet.prev.json"), None)
    if prev is None:
        return {"available": False}

    def index(fl):
        d = {}
        for srv in fl["servers"]:
            for s in srv["sites"]:
                d[(srv["name"], s["domain"])] = s
        return d
    ci, pi = index(cur), index(prev)
    changes = []
    for key, s in ci.items():
        if key not in pi:
            changes.append({"domain": s["domain"], "type": "nouveau site", "detail": f"{key[0]}"})
            continue
        p = pi[key]
        if s.get("core_version") != p.get("core_version"):
            changes.append({"domain": s["domain"], "type": "core", "detail": f"{p.get('core_version')} → {s.get('core_version')}"})
        if (s.get("plugins_updates") or 0) != (p.get("plugins_updates") or 0):
            changes.append({"domain": s["domain"], "type": "MAJ plugins en attente", "detail": f"{p.get('plugins_updates')} → {s.get('plugins_updates')}"})
        if (s.get("plugins_total") or 0) != (p.get("plugins_total") or 0):
            changes.append({"domain": s["domain"], "type": "nombre de plugins", "detail": f"{p.get('plugins_total')} → {s.get('plugins_total')}"})
        if s.get("php_version") != p.get("php_version"):
            changes.append({"domain": s["domain"], "type": "PHP", "detail": f"{p.get('php_version')} → {s.get('php_version')}"})
        na = {a["login"] for a in (s.get("admins") or [])}
        oa = {a["login"] for a in (p.get("admins") or [])}
        for login in na - oa:
            changes.append({"domain": s["domain"], "type": "⚠ nouvel admin", "detail": login})
        for login in oa - na:
            changes.append({"domain": s["domain"], "type": "admin supprimé", "detail": login})
    for key, p in pi.items():
        if key not in ci:
            changes.append({"domain": p["domain"], "type": "site disparu", "detail": f"{key[0]}"})
    return {"available": True, "prev": prev.get("generated_at"), "cur": cur.get("generated_at"), "changes": changes}


def set_baseline(domain=None):
    """Fige les administrateurs actuels comme référence.

    Un même domaine peut exister sur plusieurs serveurs (copie legacy à côté de
    la prod). Seul l'install RÉELLEMENT géré — celui rattaché à un moniteur Kuma,
    donc celui affiché — fait foi : sinon on enregistrerait les comptes d'une
    vieille copie et les vrais admins resteraient signalés en rouge.
    """
    fleet = load_json(os.path.join(DATA, "fleet.json"), {"servers": []})
    base = load_json(os.path.join(DATA, "admins_baseline.json"), {})
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    retenus = {}
    for srv in fleet["servers"]:
        for s in srv["sites"]:
            if s.get("admins") is None:
                continue
            cle = s.get("kuma") or s.get("domain")
            if domain and domain not in (s.get("domain"), s.get("kuma")):
                continue
            # priorité à l'install rattaché à Kuma (celui que l'interface affiche)
            if cle in retenus and not s.get("kuma"):
                continue
            retenus[cle] = s
    for cle, s in retenus.items():
        base[cle] = {"logins": sorted(a["login"] for a in s["admins"]), "set_at": now}
    save_json(os.path.join(DATA, "admins_baseline.json"), base)
    return base


# ---------- sécurité : certificats SSL (info TLS relevée par Kuma) ----------
def ssl_certs():
    sql = ("SELECT m.name||'|||'||t.info_json FROM monitor_tls_info t "
           "JOIN monitor m ON m.id=t.monitor_id;")
    try:
        r = subprocess.run(["docker", "exec", KUMA_CONTAINER, "sqlite3", KUMA_DB, sql],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return {"certs": [], "error": f"docker exec: {e}"}
    if r.returncode != 0:
        return {"certs": [], "error": ((r.stdout + r.stderr).strip() or f"rc={r.returncode}")[-400:]}

    certs = []
    for line in r.stdout.splitlines():
        if "|||" not in line:
            continue
        name, raw = line.split("|||", 1)
        try:
            info = json.loads(raw)
        except (ValueError, TypeError):
            continue  # ligne illisible : on l'ignore
        if not isinstance(info, dict):
            continue
        # structure habituelle {"valid":true,"certInfo":{"daysRemaining":…,"validTo":…}},
        # mais certaines versions posent les champs à la racine
        ci = info.get("certInfo") if isinstance(info.get("certInfo"), dict) else {}
        days = ci.get("daysRemaining", info.get("daysRemaining"))
        valid_to = ci.get("validTo", info.get("validTo"))
        if days is None and valid_to is None:
            continue
        try:
            days = int(days) if days is not None else None
        except (TypeError, ValueError):
            days = None
        certs.append({"monitor": name, "days": days, "valid_to": valid_to})
    # les plus urgents d'abord ; les jours inconnus finissent la liste
    certs.sort(key=lambda c: c["days"] if c["days"] is not None else 10 ** 6)
    return {"certs": certs}


# ---------- alertes Telegram (C1) ----------
ALERT_DEFAULTS = {
    "enabled": False, "bot_token": "", "chat_id": "",
    "rules": {"new_admin": True, "checksum_fail": True, "backup_stale_h": 48,
              "cert_days": 7, "collect_dead_h": 3, "viz_anomaly": True, "site_down": False},
}
ALERTS_LOCK = threading.Lock()


def esc_html(s):
    """Échappe un texte pour le parse_mode HTML de Telegram."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_number(v):
    """Valeur numérique d'un seuil de règle, ou None si inutilisable/désactivé."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def parse_ts(value):
    """Horodatage « YYYY-MM-DD HH:MM[:SS] » → epoch, ou None."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.datetime.strptime(str(value), fmt).timestamp()
        except (TypeError, ValueError):
            continue
    return None


def alerts_cfg():
    """Configuration d'alertes, complétée par les valeurs par défaut."""
    raw = load_json(ALERTS_PATH, {})
    cfg = dict(ALERT_DEFAULTS)
    rules = dict(ALERT_DEFAULTS["rules"])
    if isinstance(raw, dict):
        cfg.update({k: v for k, v in raw.items() if k != "rules"})
        if isinstance(raw.get("rules"), dict):
            rules.update(raw["rules"])
    cfg["rules"] = rules
    return cfg


def coerce_rule(key, value):
    """Normalise une règle selon son type par défaut : booléen ou seuil numérique."""
    ref = ALERT_DEFAULTS["rules"].get(key)
    if isinstance(ref, bool):
        return bool(value)
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ref
    return int(n) if n.is_integer() else n


def alerts_log(msg):
    """Journal dédié aux alertes : une erreur d'envoi ne remonte jamais à l'appelant."""
    try:
        with open(ALERTS_LOG, "a") as fh:
            fh.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


def telegram_send_sync(text):
    """Envoi synchrone via l'API Bot → (ok, erreur). Le token est masqué dans l'erreur."""
    cfg = alerts_cfg()
    token, chat = str(cfg.get("bot_token") or ""), str(cfg.get("chat_id") or "")
    if not token or not chat:
        return False, "bot_token ou chat_id manquant"
    data = urllib.parse.urlencode({"chat_id": chat, "text": str(text)[:3900],
                                   "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace") or "{}")
        if body.get("ok"):
            return True, None
        return False, str(body.get("description") or "réponse Telegram inattendue")[:300]
    except Exception as e:
        return False, f"{type(e).__name__}: {e}".replace(token, "***")[:300]


def send_telegram(text):
    """Envoi non bloquant : l'appelant n'attend pas, les erreurs partent dans alerts.log."""
    def worker():
        ok, err = telegram_send_sync(text)
        short = " ".join(str(text).split())[:200]
        alerts_log(("envoyé: " if ok else f"échec ({err}): ") + short)
    threading.Thread(target=worker, daemon=True).start()


def alert(key, rule, text):
    """Alerte Telegram : alertes activées + règle active + anti-spam de 24 h sur la clé."""
    cfg = alerts_cfg()
    if not cfg.get("enabled"):
        return False
    if rule and not cfg["rules"].get(rule):
        return False
    now = time.time()
    with ALERTS_LOCK:
        state = load_json(ALERTS_STATE_PATH, {})
        if not isinstance(state, dict):
            state = {}
        try:
            last = float(state.get(key) or 0)
        except (TypeError, ValueError):
            last = 0
        if now - last < ALERT_COOLDOWN:
            return False
        state[key] = now
        # purge des clés devenues inutiles (plus de 7 jours)
        state = {k: v for k, v in state.items()
                 if isinstance(v, (int, float)) and now - v < 7 * ALERT_COOLDOWN}
        save_json(ALERTS_STATE_PATH, state)
    send_telegram(text)
    return True


def site_visible(site):
    """Règle d'affichage du dashboard : masqué si override False, ou sans moniteur Kuma
    quand l'affichage n'est pas forcé. Un site ajouté en REST est visible d'office :
    il a été déclaré explicitement, même s'il n'est pas encore supervisé par Kuma."""
    if site.get("visible") is False:
        return False
    if site.get("via") == "rest":
        return True
    if site.get("visible") is not True and "kuma" in site and not site.get("kuma"):
        return False
    return True


def visible_sites():
    """[(nom du serveur, site)] pour les sites affichés du parc."""
    fleet = load_json(FLEET_PATH, {"servers": []})
    out = []
    for srv in fleet.get("servers", []):
        for s in srv.get("sites", []):
            if site_visible(s):
                out.append((srv.get("name"), s))
    return out


def evaluate_alerts():
    """Évalue les règles après une collecte complète et envoie ce qui doit l'être."""
    cfg = alerts_cfg()
    if not cfg.get("enabled"):
        return {"enabled": False, "sent": 0}
    rules, now, sent = cfg["rules"], time.time(), 0

    # 1) nouveaux administrateurs (issus du diff de collecte)
    if rules.get("new_admin"):
        diff = compute_diff()
        for ch in (diff.get("changes") or []):
            if "nouvel admin" not in str(ch.get("type", "")):
                continue
            sent += alert(f"new_admin:{ch.get('domain')}:{ch.get('detail')}", "new_admin",
                          "🛑 <b>Nouvel administrateur</b>"
                          f"\nSite : <b>{esc_html(ch.get('domain'))}</b>"
                          f"\nCompte : <code>{esc_html(ch.get('detail'))}</code>")

    # 2) sauvegardes UpdraftPlus périmées
    stale_h = to_number(rules.get("backup_stale_h"))
    if stale_h:
        for server, s in visible_sites():
            up = s.get("updraft")
            if not up:
                continue  # pas d'UpdraftPlus configuré : rien à comparer
            ts = to_number(up.get("last_backup_ts"))
            age_h = (now - ts) / 3600 if ts else None
            if age_h is not None and age_h <= stale_h:
                continue
            detail = f"il y a {age_h:.0f} h" if age_h is not None else "aucune sauvegarde connue"
            sent += alert(f"backup_stale:{s.get('domain')}", "backup_stale_h",
                          "💾 <b>Sauvegarde périmée</b>"
                          f"\nSite : <b>{esc_html(s.get('domain'))}</b> ({esc_html(server)})"
                          f"\nDernière : {esc_html(detail)} — seuil {stale_h:g} h")

    # 3) checksums du core en échec (data/checksums.json)
    if rules.get("checksum_fail"):
        for dom, rec in (load_json(CHECKSUMS_PATH, {}) or {}).items():
            if not isinstance(rec, dict) or rec.get("ok") is not False:
                continue
            sent += alert(f"checksum_fail:{dom}", "checksum_fail",
                          "🧬 <b>Checksums du core en échec</b>"
                          f"\nSite : <b>{esc_html(dom)}</b>"
                          f"\n<code>{esc_html((rec.get('output_tail') or '')[-300:])}</code>")

    # 4) certificats TLS proches de l'expiration (info relevée par Kuma)
    cert_days = to_number(rules.get("cert_days"))
    if cert_days:
        for c in (ssl_certs().get("certs") or []):
            days = c.get("days")
            if days is None or days > cert_days:
                continue
            sent += alert(f"cert:{c.get('monitor')}", "cert_days",
                          "🔐 <b>Certificat proche de l'expiration</b>"
                          f"\nMoniteur : <b>{esc_html(c.get('monitor'))}</b>"
                          f"\nExpire dans {days} jour(s)")

    # 5) collecteur muet (dernière ligne de collect_history.jsonl)
    dead_h = to_number(rules.get("collect_dead_h"))
    if dead_h:
        last = None
        try:
            with open(os.path.join(DATA, "collect_history.jsonl")) as fh:
                lines = [l for l in fh.readlines() if l.strip()]
            if lines:
                last = parse_ts(json.loads(lines[-1]).get("ts"))
        except (OSError, ValueError):
            last = None
        age_h = (now - last) / 3600 if last else None
        if age_h is None or age_h > dead_h:
            detail = f"il y a {age_h:.0f} h" if age_h is not None else "aucun historique"
            sent += alert("collect_dead", "collect_dead_h",
                          "🕳 <b>Collecteur muet</b>"
                          f"\nDernière collecte : {esc_html(detail)} — seuil {dead_h:g} h")
    return {"enabled": True, "sent": sent}


# ---------- évènements poussés par les sites (B1) ----------
EVENTS_LOCK = threading.Lock()
SECRETS_LOCK = threading.Lock()
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
CRITICAL_EVENTS = ("user_register", "activated_plugin")


def site_secrets():
    store = load_json(SECRETS_PATH, {})
    return store if isinstance(store, dict) else {}


def set_site_secret(domain, secret):
    """Enregistre le secret HMAC d'un site (fichier réservé à root).

    La clé retient le chemin pour un WordPress en sous-répertoire ; pour un site
    à la racine elle vaut le domaine, comme avant.
    """
    with SECRETS_LOCK:
        store = site_secrets()
        store[site_key(domain)] = secret
        save_json(SECRETS_PATH, store)
        try:
            os.chmod(SECRETS_PATH, 0o600)
        except OSError:
            pass
    return secret


def append_event(entry):
    """Ajoute une ligne à data/events.jsonl, avec rotation au-delà de 5 Mo."""
    with EVENTS_LOCK:
        try:
            if os.path.getsize(EVENTS_PATH) > EVENTS_MAX_BYTES:
                os.replace(EVENTS_PATH, EVENTS_PATH + ".1")
        except OSError:
            pass
        with open(EVENTS_PATH, "a") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_events(n=400, domain=None):
    try:
        with open(EVENTS_PATH) as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        return []
    out = []
    for l in lines:
        try:
            e = json.loads(l)
        except ValueError:
            continue  # ligne illisible : ignorée
        if domain and e.get("domain") != domain:
            continue
        out.append(e)
    return out


def read_changes(n=1500, domain=None):
    """Historique persistant des changements de collecte (data/changes.jsonl).

    Produit par collect.py : chaque ligne est un changement d'état réel (version
    installée qui bouge, admin/extension ajouté), déjà dédoublonné par domaine
    Kuma. C'est l'historique complet — au-delà de la seule dernière collecte que
    donne compute_diff(). Renvoyé du plus récent au plus ancien.
    """
    try:
        with open(CHANGES_PATH) as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        return []
    out = []
    for l in lines:
        try:
            c = json.loads(l)
        except ValueError:
            continue
        if domain and c.get("domain") != domain:
            continue
        out.append(c)
    out.reverse()
    return out


def event_is_critical(event, detail):
    """Évènement justifiant une alerte immédiate (création d'admin, plugin activé)."""
    if event in CRITICAL_EVENTS:
        return True
    return event == "set_user_role" and "administrator" in str(detail or "").lower()


def verify_ingest(headers, raw):
    """Contrôle HMAC d'un POST /api/ingest → (clé du site, None) ou (None, erreur)."""
    raw_site = headers.get("X-Viz-Site", "")
    site, keyed = norm_domain(raw_site), site_key(raw_site)
    ts = str(headers.get("X-Viz-Timestamp", "") or "").strip()
    sig = str(headers.get("X-Viz-Signature", "") or "").strip().lower()
    try:
        tsi = int(ts)
    except ValueError:
        return None, "horodatage invalide"
    if abs(time.time() - tsi) > INGEST_SKEW:
        return None, "horodatage périmé"
    store = site_secrets()
    # domaine seul d'abord (historique), puis domaine+chemin pour un WP en sous-répertoire
    secret = store.get(site) if site else None
    if not secret and keyed != site:
        secret, site = store.get(keyed), keyed
    if not secret:
        return None, "site inconnu"
    good = hmac.new(str(secret).encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig):
        return None, "signature invalide"
    return site, None


def ingest_event(domain, body):
    """Journalise un évènement validé et alerte si l'évènement est critique."""
    event = str(body.get("event") or "inconnu")[:60]
    detail = body.get("detail")
    if not isinstance(detail, str):
        detail = "" if detail is None else json.dumps(detail, ensure_ascii=False)
    detail = detail[:500]
    entry = {"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "domain": domain, "event": event, "detail": detail}
    append_event(entry)
    if event_is_critical(event, detail):
        alert(f"event:{domain}:{event}:{detail[:60]}", "new_admin",
              "🚨 <b>Évènement critique</b>"
              f"\nSite : <b>{esc_html(domain)}</b>"
              f"\nÉvènement : <code>{esc_html(event)}</code>"
              f"\n{esc_html(detail[:300])}")
    return entry


# ---------- liaison d'un site au dashboard (mu-plugin privé sumotori-dash-agent) ----------
def forget_site_secret(domain):
    """Retire le secret HMAC d'un site."""
    with SECRETS_LOCK:
        store = site_secrets()
        removed = store.pop(site_key(domain), None) is not None
        save_json(SECRETS_PATH, store)
        try:
            os.chmod(SECRETS_PATH, 0o600)
        except OSError:
            pass
    return removed


def mask_secret(text, secret):
    """Le secret ne doit apparaître nulle part : ni en sortie, ni en journal, ni en alerte."""
    text = str(text or "")
    return text.replace(secret, "***") if secret else text


def agent_source():
    """Contenu du mu-plugin de liaison → (contenu, erreur). Le fichier est fourni hors d'ici."""
    try:
        with open(AGENT_FILE, encoding="utf-8") as fh:
            content = fh.read()
    except OSError as e:
        return None, f"fichier agent introuvable ({AGENT_FILE}) : {e.strerror or e}"
    if not content.strip():
        return None, f"fichier agent vide ({AGENT_FILE})"
    return content, None


def deploy_agent(srv, site, content, timeout=60):
    """Dépose le mu-plugin dans <docroot>/wp-content/mu-plugins (0644, propriétaire du site)."""
    marker = "SUMOTORI_AGENT_" + secrets.token_hex(8)
    if re.search(rf"^{marker}$", content, re.M):  # collision impossible en pratique
        return 96, "marqueur de transfert en collision avec le contenu"
    script = REMOTE_DEPLOY_TEMPLATE.format(docroot=sq(site["path"]), owner=sq(site["owner"] or "root"),
                                           nosu="1" if srv.get("no_su") else "0",
                                           fname=AGENT_NAME, marker=marker,
                                           content=content.rstrip("\n"), timeout=timeout)
    return run_remote_script(srv, script, timeout)


def remove_agent(srv, site, timeout=60):
    """Supprime le mu-plugin de liaison du site."""
    script = REMOTE_REMOVE_TEMPLATE.format(docroot=sq(site["path"]), owner=sq(site["owner"] or "root"),
                                           nosu="1" if srv.get("no_su") else "0",
                                           fname=AGENT_NAME, timeout=timeout)
    return run_remote_script(srv, script, timeout)


def dash_connect(server_name, domain):
    """Liaison privée : secret HMAC + dépôt du mu-plugin + `wp dash-agent connect`.

    Le secret n'apparaît jamais en clair : masqué par « *** » dans la sortie
    renvoyée, dans actions.log et dans toute alerte.
    """
    srv, site = find_site(server_name, domain)
    if not srv or not site:
        return 92, "site inconnu"
    content, err = agent_source()
    if err:
        return 96, err
    secret = secrets.token_urlsafe(32)
    if not SECRET_RE.match(secret):  # garde-fou : rien d'inattendu ne part dans le shell
        return 91, "secret invalide"
    prev = site_secrets().get(site_key(domain))
    set_site_secret(domain, secret)
    t0 = time.time()
    try:
        rc, out = deploy_agent(srv, site, content)
        if rc == 0:
            rc, out2 = run_wp_remote(srv, site,
                                     f"dash-agent connect --endpoint={DASH_ENDPOINT} --secret={secret}")
            out = (out + "\n" + out2).strip()
    except subprocess.TimeoutExpired:
        rc, out = 93, "timeout"
    except Exception as e:
        rc, out = 94, f"erreur interne: {e}"
    out = mask_secret(out, secret)
    if rc != 0:
        # échec : on rétablit l'état précédent plutôt que de garder un secret orphelin
        if prev:
            set_site_secret(domain, prev)
        else:
            forget_site_secret(domain)
    append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source": "dashboard",
                "server": server_name, "domain": domain, "action": "dash_connect", "arg": "***",
                "rc": rc, "duration_s": round(time.time() - t0, 1), "output_tail": out[-2000:]})
    return rc, out


def dash_disconnect(server_name, domain):
    """Débranche le site : `wp dash-agent disconnect`, suppression du mu-plugin, oubli du secret."""
    srv, site = find_site(server_name, domain)
    if not srv or not site:
        return 92, "site inconnu"
    t0, parts = time.time(), []
    try:
        _, out_cli = run_wp_remote(srv, site, "dash-agent disconnect", timeout=120)
        parts.append(out_cli)  # un échec ici (mu-plugin déjà retiré) n'est pas bloquant
        rc, out_rm = remove_agent(srv, site)
        parts.append(out_rm)
    except subprocess.TimeoutExpired:
        rc = 93
        parts.append("timeout")
    except Exception as e:
        rc = 94
        parts.append(f"erreur interne: {e}")
    forget_site_secret(domain)
    out = "\n".join(p for p in parts if p).strip()
    append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source": "dashboard",
                "server": server_name, "domain": domain, "action": "dash_disconnect", "arg": None,
                "rc": rc, "duration_s": round(time.time() - t0, 1), "output_tail": out[-2000:]})
    return rc, out


# ---------- sondage d'une URL (garde anti-SSRF) ----------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Empêche urllib de suivre seul : chaque saut doit repasser la garde anti-SSRF."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_site_url(raw):
    """URL de site normalisée : https par défaut, chemin conservé, sans slash final."""
    s = str(raw or "").strip()
    if not s:
        return None, "url vide"
    if "://" not in s:
        # « javascript: », « file: », « data: »… : un schéma sans // ne devient pas du https
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(?!\d)", s)
        if m:
            return None, f"schéma non autorisé ({m.group(1)})"
        s = "https://" + s
    try:
        u = urllib.parse.urlsplit(s)
    except ValueError:
        return None, "url invalide"
    if u.scheme not in ("http", "https"):
        return None, f"schéma non autorisé ({u.scheme or '?'})"
    if not u.hostname:
        return None, "hôte manquant"
    if "@" in (u.netloc or ""):
        return None, "identifiants interdits dans l'url"
    path = re.sub(r"/+$", "", u.path or "")
    return urllib.parse.urlunsplit((u.scheme, u.netloc, path, "", "")), None


def public_ips(host, port):
    """IP publiques de l'hôte → (liste, erreur). Refuse loopback, privé, lien-local, réservé."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError, ValueError) as e:
        return None, f"hôte injoignable ({e})"
    ips = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return None, f"adresse non autorisée ({ip})"
        ips.append(str(ip))
    if not ips:
        return None, "aucune adresse exploitable"
    return ips, None


def validate_public_url(url):
    """Contrôle schéma + résolution DNS publique d'une URL (appliqué à chaque redirection)."""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return None, "url invalide"
    if u.scheme not in ("http", "https"):
        return None, f"schéma non autorisé ({u.scheme or '?'})"
    if not u.hostname:
        return None, "hôte manquant"
    if "@" in (u.netloc or ""):
        return None, "identifiants interdits dans l'url"
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return None, "port invalide"
    ips, err = public_ips(u.hostname, port)
    if err:
        return None, err
    return u, None


def http_get(url, timeout=DISCOVER_TIMEOUT, max_redirects=DISCOVER_REDIRECTS,
             headers=None, max_bytes=512 * 1024):
    """GET avec suivi manuel des redirections → (status, corps, url finale, erreur).

    Un 403/404 n'est pas une erreur de transport : le statut est renvoyé tel quel.
    """
    cur, hops = str(url), 0
    opener = urllib.request.build_opener(NoRedirect)
    while True:
        _, err = validate_public_url(cur)
        if err:
            return None, None, cur, err
        req = urllib.request.Request(cur, headers=dict({"User-Agent": USER_AGENT,
                                                        "Accept": "application/json"}, **(headers or {})))
        try:
            with opener.open(req, timeout=timeout) as resp:
                return getattr(resp, "status", resp.getcode()), resp.read(max_bytes), cur, None
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and hops < max_redirects:
                loc = e.headers.get("Location") if e.headers else None
                if not loc:
                    return e.code, None, cur, "redirection sans en-tête Location"
                cur, hops = urllib.parse.urljoin(cur, loc), hops + 1
                continue
            try:
                body = e.read(max_bytes)
            except Exception:
                body = None
            return e.code, body, cur, None
        except Exception as e:
            return None, None, cur, f"{type(e).__name__}: {e}"[:200]


def known_domains():
    """Domaines déjà gérés : sites SSH de fleet.json + sites REST."""
    known = set()
    for srv in load_json(FLEET_PATH, {"servers": []}).get("servers", []):
        for s in srv.get("sites", []):
            known.add(str(s.get("domain") or ""))
            if s.get("siteurl"):
                known.add(site_key(s["siteurl"]))
                known.add(norm_domain(s["siteurl"]))
            # nom du moniteur Kuma rattaché : couvre les alias (vhost ≠ nom supervisé)
            if s.get("kuma"):
                known.add(str(s["kuma"]))
                known.add(norm_domain(str(s["kuma"])))
    for s in rest_sites():
        known.add(str(s.get("domain") or ""))
        known.add(norm_domain(s.get("url") or ""))
    known.discard("")
    return known


def server_for_host(host):
    """Nom du serveur SSH hébergeant cet hôte, si l'IP correspond à un serveur connu."""
    ips, err = public_ips(host, 443)
    if err:
        return None
    hosts = {str(s.get("host")) for s in servers_list()}
    for ip in ips:
        if ip in hosts:
            return next((s["name"] for s in servers_list() if str(s.get("host")) == ip), None)
    return None


def discover_site(raw_url):
    """Sonde /wp-json/ d'une URL → description du site (jamais d'exception)."""
    url, err = normalize_site_url(raw_url)
    if err:
        return {"ok": False, "error": err}
    host = urllib.parse.urlsplit(url).hostname or ""
    srv_name = server_for_host(host)
    base = {"ok": False, "is_wordpress": False, "name": None, "home": None, "url_effective": url,
            "namespaces": [], "has_agent": False, "has_vizproof": False, "rest_open": False,
            "multisite": None, "already_known": site_key(url) in known_domains() or norm_domain(url) in known_domains(),
            "suggestion": "ssh" if srv_name else "pair", "server": srv_name}
    status, body, final, err = http_get(url + "/wp-json/")
    base["url_effective"] = re.sub(r"/wp-json/?$", "", final) or final
    if err:
        base["error"] = err
        return base
    if status != 200:
        base["error"] = f"API REST inaccessible (HTTP {status})"
        return base
    try:
        data = json.loads((body or b"").decode("utf-8", "replace"))
    except ValueError:
        base["error"] = "réponse illisible (JSON invalide) — API REST filtrée ?"
        return base
    if not isinstance(data, dict):
        base["error"] = "réponse inattendue de l'API REST"
        return base
    ns = [str(n) for n in (data.get("namespaces") or []) if isinstance(n, str)]
    base.update({"rest_open": True, "namespaces": ns, "is_wordpress": "wp/v2" in ns or bool(data.get("name")),
                 "name": data.get("name"), "home": data.get("home") or data.get("url"),
                 "has_agent": AGENT_NS in ns, "has_vizproof": VIZ_NS in ns,
                 "multisite": data.get("multisite") if isinstance(data.get("multisite"), bool) else None})
    if data.get("home"):
        base["url_effective"] = str(data["home"]).rstrip("/")
        base["already_known"] = base["already_known"] or site_key(data["home"]) in known_domains()
    base["ok"] = bool(base["is_wordpress"])
    if not base["ok"]:
        base["error"] = "ce n'est pas un WordPress (namespace wp/v2 absent)"
    return base


# ---------- appairage par code court ----------
PAIR_LOCK = threading.Lock()
PAIR_ATTEMPTS = {}  # ip -> [horodatages] ; compteur volatil, suffisant pour le débit


def new_pair_code():
    """Code lisible XXXX-XXXX, alphabet sans caractères ambigus."""
    draw = "".join(secrets.choice(PAIR_ALPHABET) for _ in range(8))
    return draw[:4] + "-" + draw[4:]


def normalize_pair_code(value):
    code = re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
    return code[:4] + "-" + code[4:] if len(code) == 8 else ""


def create_pair_code(url_hint):
    """Crée un code d'appairage à usage unique, valable 30 minutes."""
    now = time.time()
    with PAIR_LOCK:
        store = load_json(PAIRINGS_PATH, {})
        if not isinstance(store, dict):
            store = {}
        # purge : codes expirés depuis longtemps et codes consommés il y a plus de 24 h
        store = {c: r for c, r in store.items() if isinstance(r, dict)
                 and now - (r.get("used_ts") or r.get("created_ts") or 0) < 24 * 3600}
        code = new_pair_code()
        while code in store:
            code = new_pair_code()
        store[code] = {"url_hint": str(url_hint or "")[:200], "created_ts": now,
                       "used_ts": None, "site_url": None}
        save_json(PAIRINGS_PATH, store)
    return code


def consume_pair_code(code, site_url):
    """Valide et consomme un code → (enregistrement, None) ou (None, erreur)."""
    code = normalize_pair_code(code)
    if not PAIR_CODE_RE.match(code or ""):
        return None, "code invalide"
    now = time.time()
    with PAIR_LOCK:
        store = load_json(PAIRINGS_PATH, {})
        rec = store.get(code) if isinstance(store, dict) else None
        if not isinstance(rec, dict):
            return None, "code inconnu"
        if rec.get("used_ts"):
            return None, "code déjà utilisé"
        if now - (rec.get("created_ts") or 0) > PAIR_TTL:
            return None, "code expiré"
        rec["used_ts"], rec["site_url"] = now, site_url
        store[code] = rec
        save_json(PAIRINGS_PATH, store)
    return rec, None


def pair_rate_ok(ip):
    """Limite de débit d'appairage : 20 tentatives par heure et par IP."""
    now = time.time()
    with PAIR_LOCK:
        hits = [t for t in PAIR_ATTEMPTS.get(ip, []) if now - t < PAIR_RATE_WINDOW] + [now]
        PAIR_ATTEMPTS[ip] = hits
        if len(PAIR_ATTEMPTS) > 2000:  # bornage mémoire
            for k in [k for k, v in PAIR_ATTEMPTS.items() if not v or now - v[-1] > PAIR_RATE_WINDOW]:
                PAIR_ATTEMPTS.pop(k, None)
        return len(hits) <= PAIR_RATE_MAX


def pair_site(code, site_url, agent_version=None, multisite=False):
    """Appairage d'un site : contrôle du code, génération du secret, inscription en mode REST.

    Le secret n'est renvoyé qu'ici, une seule fois ; il n'est jamais journalisé.
    """
    url, err = normalize_site_url(site_url)
    if err:
        return None, f"url du site : {err}"
    _, err = validate_public_url(url)  # même garde anti-SSRF que le sondage
    if err:
        return None, f"url du site : {err}"
    rec, err = consume_pair_code(code, url)
    if err:
        return None, err
    key = site_key(url)
    secret = set_site_secret(key, secrets.token_urlsafe(32))
    entry = add_rest_site(url, name=(rec.get("url_hint") or None), multisite=bool(multisite),
                          agent_version=agent_version)
    # Première collecte immédiate : le site apparaît dans le dashboard sans attendre le cron.
    def _first_collect(domain):
        try:
            subprocess.run(["/usr/bin/python3", os.path.join(BASE, "collect.py"),
                            "--only", "rest", "--match", domain],
                           capture_output=True, text=True, timeout=180)
        except Exception:
            pass
    threading.Thread(target=_first_collect, args=(entry["domain"],), daemon=True).start()
    return {"secret": secret, "endpoint": DASH_ENDPOINT, "domain": entry["domain"]}, None


# ---------- sites gérés via l'agent REST (aucun accès SSH) ----------
REST_LOCK = threading.Lock()


def rest_sites():
    lst = load_json(REST_SITES_PATH, [])
    return [s for s in lst if isinstance(s, dict)] if isinstance(lst, list) else []


def add_rest_site(url, name=None, multisite=False, blog_id=None, agent_version=None):
    """Ajoute (ou actualise) un site collecté par l'agent REST."""
    url = re.sub(r"/+$", "", str(url or ""))
    key = site_key(url)
    with REST_LOCK:
        lst = rest_sites()
        prev = next((s for s in lst if s.get("domain") == key), None)
        entry = {"domain": key, "url": url, "name": name or (prev or {}).get("name") or key,
                 "added_ts": (prev or {}).get("added_ts") or time.time(),
                 "multisite": bool(multisite), "blog_id": blog_id}
        if agent_version:
            entry["agent_version"] = str(agent_version)[:40]
        save_json(REST_SITES_PATH, [s for s in lst if s.get("domain") != key] + [entry])
    return entry


def rest_target(server_name, domain):
    """Site de fleet.json géré sans SSH (via="rest") → le site, sinon None."""
    for srv in load_json(FLEET_PATH, {"servers": []}).get("servers", []):
        if server_name and srv.get("name") != server_name:
            continue
        for s in srv.get("sites", []):
            if s.get("domain") == domain and s.get("via") == "rest":
                return s
    return None


def secret_for(site):
    """Secret HMAC d'un site REST, quelle que soit la forme de sa clé."""
    store, url = site_secrets(), site.get("url") or site.get("siteurl") or ""
    for k in (site.get("domain"), site_key(url), norm_domain(site.get("domain") or url)):
        if k and store.get(k):
            return store[k]
    return None


def agent_post(url, path, body, secret, timeout=AGENT_TIMEOUT):
    """POST signé vers l'agent → (status, données).

    Symétrique d'agent_get côté collecteur, mais ici la signature porte sur le
    CORPS brut : HMAC sha256 de « <ts>.<corps> ».
    """
    raw = json.dumps(body, ensure_ascii=False).encode()
    ts = str(int(time.time()))
    sig = hmac.new(str(secret).encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
    full = str(url).rstrip("/") + "/wp-json/" + AGENT_NS + path
    req = urllib.request.Request(full, data=raw, method="POST", headers={
        "User-Agent": USER_AGENT,  # indispensable : Cloudflare rejette les requêtes sans UA
        "Accept": "application/json", "Content-Type": "application/json",
        "X-Viz-Site": str(url), "X-Viz-Timestamp": ts, "X-Viz-Signature": sig})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", resp.getcode())
        return status, json.loads(resp.read(512 * 1024).decode("utf-8", "replace") or "{}")


def rest_install_plugin(site, slug=VIZ_SLUG):
    """Installe et active un plugin de wordpress.org via l'agent (aucun SSH requis).

    Ne lève jamais : toute panne devient un couple (code, message lisible).
    """
    url = re.sub(r"/+$", "", str(site.get("url") or site.get("siteurl") or ""))
    if not url:
        return 92, "site sans url connue : relancez une collecte"
    _, err = validate_public_url(url)
    if err:
        return 92, f"url du site : {err}"
    secret = secret_for(site)
    if not secret:
        return 98, "aucun secret enregistré pour ce site : ré-appairez-le depuis Gestion"
    try:
        status, data = agent_post(url, "/install-plugin", {"slug": slug, "activate": True}, secret)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return AGENT_OLD_RC, AGENT_OLD_MSG
        if e.code in (401, 403):
            return AGENT_OLD_RC, f"agent : HTTP {e.code} (signature refusée ou site non appairé ?)"
        return AGENT_OLD_RC, f"agent : HTTP {e.code}"
    except Exception as e:
        return AGENT_OLD_RC, f"agent injoignable : {type(e).__name__}: {e}"[:300]
    if not isinstance(data, dict):
        return 1, "réponse inattendue de l'agent"
    if not data.get("ok"):
        return 1, "installation refusée : " + str(data.get("message") or data.get("error")
                                                  or "raison non précisée")[:300]
    parts = [f"{slug} déjà présent" if data.get("already") else f"{slug} installé"]
    if data.get("version"):
        parts.append(f"version {data['version']}")
    if data.get("activated"):
        parts.append("activé")
    return 0, ", ".join(parts)


def remove_rest_site(domain):
    """Retire un site REST et oublie son secret."""
    key = site_key(domain)
    with REST_LOCK:
        lst = rest_sites()
        kept = [s for s in lst if s.get("domain") != key]
        save_json(REST_SITES_PATH, kept)
    forget_site_secret(key)
    return len(kept) != len(lst)


# ---------- candidats à ajouter (moniteurs Kuma non gérés) ----------
def kuma_monitor_urls():
    """[(nom, url)] des moniteurs Kuma hors groupes."""
    rc, out = kuma_sql("SELECT name||char(9)||COALESCE(url,'') FROM monitor WHERE type!='group';")
    rows = []
    if rc != 0:
        return rows
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, url = line.split("\t", 1)
        rows.append((name.strip(), url.strip()))
    return rows


def kuma_candidates():
    """Sites supervisés par Kuma mais absents du parc (ni SSH ni REST)."""
    known, seen, out = known_domains(), set(), []
    for name, url in kuma_monitor_urls():
        url = re.sub(r"/wp-login\.php/?$", "", url or "").rstrip("/")
        if not url.startswith("http"):
            continue  # moniteurs ping/port : pas d'url exploitable
        dom, key = norm_domain(url), site_key(url)
        if not dom or dom in known or key in known or key in seen:
            continue
        seen.add(key)
        out.append({"name": name or dom, "url": url, "source": "kuma",
                    "reason": "supervisé par Kuma, absent du parc"})
    out.sort(key=lambda c: c["url"])
    return out


def agent_zip_bytes():
    """Archive ZIP en mémoire contenant le mu-plugin → (octets, erreur)."""
    content, err = agent_source()
    if err:
        return None, err
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Paquet complet quand il existe (readme, licence, traductions), sinon le seul PHP.
        added = set()
        if os.path.basename(AGENT_DIR) == AGENT_SLUG and os.path.isdir(AGENT_DIR):
            for root, _dirs, files in os.walk(AGENT_DIR):
                for name in sorted(files):
                    if name.startswith("."):
                        continue
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, AGENT_DIR).replace(os.sep, "/")
                    try:
                        with open(full, "rb") as fh:
                            data = fh.read()
                    except OSError:
                        continue
                    info = zipfile.ZipInfo(f"{AGENT_SLUG}/{rel}", time.localtime()[:6])
                    info.external_attr = 0o644 << 16
                    z.writestr(info, data)
                    added.add(rel)
        if AGENT_NAME not in added:
            info = zipfile.ZipInfo(f"{AGENT_SLUG}/{AGENT_NAME}", time.localtime()[:6])
            info.external_attr = 0o644 << 16
            z.writestr(info, content)
    return buf.getvalue(), None


# ---------- timeline par site (C3) ----------
def site_timeline(server, domain, limit=200):
    """Fusionne actions, évènements poussés et changements de collecte pour un site."""
    items = []
    for e in read_log(4000):
        if e.get("domain") != domain or (server and e.get("server") != server):
            continue
        action, rc = e.get("action") or "", e.get("rc")
        label = ACTIONS.get(action, (action,))[0]
        if "{arg}" in label:
            label = label.replace("{arg}", str(e.get("arg") or ""))
        if rc == 0:
            status = "ok"
        elif rc == VIZ_ANOMALY_RC and action in VIZ_ACTIONS:
            status = "anomalies"
        else:
            status = "échec"
        items.append({"ts": e.get("ts"), "kind": "action", "label": label, "status": status,
                      "detail": (e.get("output_tail") or "").strip()[-300:]})
    for e in read_events(4000, domain=domain):
        crit = event_is_critical(e.get("event"), e.get("detail"))
        items.append({"ts": e.get("ts"), "kind": "event", "label": e.get("event") or "évènement",
                      "status": "alerte" if crit else "info",
                      "detail": str(e.get("detail") or "")[:300]})
    # Historique persistant des changements de collecte (data/changes.jsonl) :
    # tout l'historique du site, pas seulement la dernière collecte. Un même
    # domaine pouvant exister sur deux serveurs, on ne filtre que sur le domaine.
    for ch in read_changes(2000, domain=domain):
        items.append({"ts": ch.get("ts"), "kind": "collect",
                      "label": CHANGE_LABELS.get(ch.get("kind"), "changement"),
                      "status": "alerte" if ch.get("severity") == "warn" else "info",
                      "detail": str(ch.get("detail") or "")[:300]})
    items.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)
    return items[:limit]


# ---------- HTTP ----------

# ---------- autorisation WordPress (mot de passe d'application) ----------
# Flux natif de WordPress : on redirige l'administrateur vers
# wp-admin/authorize-application.php de SON site ; il approuve ; WordPress crée
# un mot de passe d'application dédié et nous le renvoie sur /api/wp_callback.
# Protection CSRF : un jeton « state » aléatoire à usage unique (le retour vient
# d'une redirection externe, il ne peut donc pas porter de nonce applicatif).
# ⚠ Un mot de passe d'application n'est PAS limitable : il confère toutes les
# capacités du compte. Il est révocable depuis le profil de l'utilisateur.
WPAUTH_PATH = os.path.join(DATA, "app_passwords.json")
WPSTATE_PATH = os.path.join(DATA, "wp_states.json")
WPAUTH_TTL = 900          # 15 min pour terminer l'autorisation
WPAUTH_APP_NAME = "Dashboard parc WordPress"
WPAUTH_LOCK = threading.Lock()


def wp_creds():
    return load_json(WPAUTH_PATH, {})


def wp_cred_for(domain, url=""):
    """Identifiants d'un site, quelle que soit la forme de sa clé."""
    store = wp_creds()
    for k in (domain, site_key(url or domain), norm_domain(domain or url)):
        if k and store.get(k):
            return k, store[k]
    return None, None


def wp_cred_save(key, entry):
    with WPAUTH_LOCK:
        store = wp_creds()
        store[key] = entry
        save_json(WPAUTH_PATH, store)
    try:
        os.chmod(WPAUTH_PATH, 0o600)   # identifiants : lecture root uniquement
    except OSError:
        pass


def wp_cred_forget(domain, url=""):
    key, _ = wp_cred_for(domain, url)
    if not key:
        return False
    with WPAUTH_LOCK:
        store = wp_creds()
        store.pop(key, None)
        save_json(WPAUTH_PATH, store)
    return True


def wp_state_new(server, domain, url):
    state = secrets.token_urlsafe(24)
    with WPAUTH_LOCK:
        store = load_json(WPSTATE_PATH, {})
        now = time.time()
        store = {k: v for k, v in store.items() if now - v.get("created", 0) < WPAUTH_TTL}
        store[state] = {"server": server or "", "domain": domain, "url": url, "created": now}
        save_json(WPSTATE_PATH, store)
    return state


def wp_state_consume(state):
    """Jeton à usage unique : consommé qu'il soit valide ou expiré."""
    with WPAUTH_LOCK:
        store = load_json(WPSTATE_PATH, {})
        rec = store.pop(state, None)
        save_json(WPSTATE_PATH, store)
    if not rec:
        return None, "invalid"
    if time.time() - rec.get("created", 0) > WPAUTH_TTL:
        return None, "expired"
    return rec, None


def wp_apppass_available(url, timeout=12):
    """WordPress annonce « application-passwords » dans /wp-json/ quand ils sont
    disponibles. Un champ vide = désactivés (souvent par une extension de
    sécurité : Wordfence Login Security, Solid Security…) ou site non-HTTPS."""
    st, body, _final, err = http_get(url.rstrip("/") + "/wp-json/", timeout=timeout)
    if err or st != 200 or not body:
        return None, "API REST inaccessible"
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return None, "réponse REST illisible"
    if not isinstance(data, dict):
        return None, "réponse REST inattendue"
    auth = data.get("authentication")
    if isinstance(auth, dict) and "application-passwords" in auth:
        return True, "disponibles"
    return False, ("les mots de passe d'application sont désactivés sur ce site "
                   "(extension de sécurité, ou site non servi en HTTPS)")


def wp_authorize_url(server, domain):
    """URL d'autorisation à ouvrir dans l'onglet de l'administrateur."""
    site = rest_target(server, domain) or rest_target("", domain)
    url = (site or {}).get("siteurl") or (site or {}).get("url") or ""
    if not url:
        for s in rest_sites():
            if s.get("domain") == domain:
                url = s.get("url") or ""
                break
    if not url:
        return None, "site inconnu"
    url, err = normalize_site_url(url)
    if err:
        return None, err
    _, err = validate_public_url(url)   # même garde anti-SSRF que le sondage
    if err:
        return None, err
    dispo, note = wp_apppass_available(url)
    if dispo is False:   # inutile d'envoyer l'utilisateur sur une page d'erreur
        return None, note
    state = wp_state_new(server, domain, url)
    success = f"{DASH_BASE}/api/wp_callback?state={urllib.parse.quote(state)}"
    reject = f"{DASH_BASE}/?wpauth=refuse&domain={urllib.parse.quote(domain)}"
    qs = urllib.parse.urlencode({
        "app_name": f"{WPAUTH_APP_NAME} · {norm_domain(domain)}",
        "success_url": success,
        "reject_url": reject,
    })
    return f"{url.rstrip('/')}/wp-admin/authorize-application.php?{qs}", None


def wp_verify(url, user, password, timeout=20):
    """Teste les identifiants → (ok, message). Vérifie aussi le droit d'installer."""
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        url.rstrip("/") + "/wp-json/wp/v2/users/me?context=edit",
        headers={"Authorization": "Basic " + token, "User-Agent": USER_AGENT,
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        caps = (data.get("capabilities") or {}) if isinstance(data, dict) else {}
        if caps and not caps.get("install_plugins"):
            return False, "compte sans droit d'installer des extensions"
        return True, "ok"
    except urllib.error.HTTPError as e:
        return False, f"refusé par le site (HTTP {e.code})"
    except Exception as e:
        return False, f"site injoignable : {e}"


def wp_trace(domain, etape, detail=""):
    """Trace le déroulé de l'autorisation (jamais le mot de passe)."""
    append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": "wp_authorize", "server": "rest", "domain": domain or "?",
                "action": "autorisation", "arg": etape, "rc": 0, "duration_s": 0,
                "output_tail": str(detail)[:500]})


def wp_callback(params):
    """Retour du flux d'autorisation → (domaine, statut)."""
    rec, err = wp_state_consume(str(params.get("state", "")))
    if err:
        wp_trace("", "jeton refusé", err)
        return "", err
    domain = rec["domain"]
    # WordPress renvoie les valeurs encodées dans l'URL ; le mot de passe
    # d'application contient des espaces (encodés en « + » ou « %20 »).
    user = urllib.parse.unquote_plus(str(params.get("user_login", ""))).strip()
    password = urllib.parse.unquote_plus(str(params.get("password", ""))).strip()
    if not user or not password:
        wp_trace(domain, "paramètres manquants",
                 f"user={'oui' if user else 'NON'} password={'oui' if password else 'NON'}")
        return domain, "invalid"
    ok, msg = wp_verify(rec["url"], user, password)
    wp_trace(domain, "vérification des identifiants",
             f"utilisateur={user} longueur_mdp={len(password)} résultat={'OK' if ok else msg}")
    # Un identifiant explicitement refusé par le site n'est pas conservé ; en
    # revanche une simple indisponibilité réseau ne doit pas le faire perdre.
    if not ok and "refusé par le site" in msg:
        wp_trace(domain, "identifiants rejetés — rien enregistré", msg)
        return domain, "error"
    store_user, store_pass, note = user, password, msg
    if ok:
        # Bascule sur l'identité propre au dashboard, puis révocation de l'accès
        # obtenu avec le compte personnel de l'administrateur.
        bot_user, bot_pass, bot_msg = wp_provision_bot(rec["url"], user, password, domain)
        if bot_user and bot_pass:
            ok2, msg2 = wp_verify(rec["url"], bot_user, bot_pass)
            if ok2:
                store_user, store_pass, note = bot_user, bot_pass, bot_msg
                wp_baseline_allow(domain, bot_user)
                wp_revoke_bootstrap(rec["url"], user, password,
                                    f"{WPAUTH_APP_NAME} · {norm_domain(domain)}")
            else:
                note = f"compte dédié inutilisable ({msg2}) — compte d'origine conservé"
        else:
            note = f"{bot_msg} — compte d'origine conservé"
    wp_cred_save(site_key(rec["url"]) or domain, {
        "user": store_user, "password": store_pass, "url": rec["url"], "domain": domain,
        "dedicated": store_user == WP_BOT_LOGIN,
        "verified": bool(ok), "message": note,
        "checked_ts": int(time.time()), "created_ts": int(time.time()),
    })
    wp_trace(domain, "identifiants enregistrés", f"compte={store_user} · {note}")
    return domain, ("ok" if ok else "error")


def wp_install_plugin(site, slug=VIZ_SLUG):
    """Installe une extension publique via l'API REST native de WordPress."""
    domain = site.get("domain") or ""
    url = site.get("siteurl") or site.get("url") or ""
    _, cred = wp_cred_for(domain, url)
    if not cred:
        return 98, ("aucun identifiant WordPress pour ce site : autorisez-le "
                    "depuis Gestion (bouton « Autoriser en un clic »)")
    body = json.dumps({"slug": slug, "status": "active"}).encode()
    token = base64.b64encode(f"{cred['user']}:{cred['password']}".encode()).decode()
    req = urllib.request.Request(
        (cred.get("url") or url).rstrip("/") + "/wp-json/wp/v2/plugins",
        data=body, method="POST",
        headers={"Authorization": "Basic " + token, "Content-Type": "application/json",
                 "User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return 0, f"{slug} installé et activé (version {data.get('version', '?')})"
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")[:400]
        try:
            info = json.loads(raw)
            code, message = info.get("code", ""), info.get("message", raw)
        except ValueError:
            code, message = "", raw
        if code == "folder_exists":
            return 0, f"{slug} déjà présent sur le site"
        if e.code in (401, 403):
            return 1, f"identifiants refusés ou droits insuffisants : {message}"
        return 1, f"échec de l'installation (HTTP {e.code}) : {message}"
    except Exception as e:
        return 1, f"site injoignable : {e}"


# ---------- compte WordPress dédié au dashboard ----------
# Après l'autorisation initiale (faite avec le compte de l'administrateur), on
# bascule sur une identité propre au dashboard : les actions sont attribuées à
# ce compte dans les journaux du site, et la révocation consiste à supprimer un
# seul utilisateur. Le rôle reste « administrator » (nécessaire pour installer
# des extensions) : c'est un gain d'attribution et de révocabilité, PAS une
# réduction de privilège. Toute création est journalisée ET alertée.
WP_BOT_LOGIN = CONFIG["bot_admin_login"]
WP_BOT_NAME = "Dashboard parc WordPress"
WP_BOT_EMAIL_BASE = CONFIG["bot_admin_email"]


def _wp_req(url, path, user, password, method="GET", payload=None, timeout=30):
    """Requête authentifiée par mot de passe d'application → (statut, données)."""
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": "Basic " + token, "User-Agent": USER_AGENT,
               "Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url.rstrip("/") + path, data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(body) if body.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")[:400]
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"message": raw}
    except Exception as e:
        return 0, {"message": str(e)}


def wp_bot_email(domain):
    """Adresse unique par site (plus-addressing) : WordPress refuse les doublons."""
    local, _, host = WP_BOT_EMAIL_BASE.partition("@")
    tag = re.sub(r"[^a-z0-9]+", "", (norm_domain(domain) or "site").lower())[:24]
    return f"{local}+{tag}@{host}"


def wp_find_bot(url, user, password):
    """Identifiant interne du compte dédié sur le site, ou None."""
    st, data = _wp_req(url, f"/wp-json/wp/v2/users?context=edit&search={WP_BOT_LOGIN}",
                       user, password)
    if st == 200 and isinstance(data, list):
        for u in data:
            if u.get("slug") == WP_BOT_LOGIN or u.get("username") == WP_BOT_LOGIN:
                return u.get("id")
    return None


def wp_provision_bot(url, user, password, domain):
    """Crée (ou retrouve) le compte dédié et lui génère un mot de passe
    d'application → (login, mot_de_passe, message) ou (None, None, erreur)."""
    uid, created = wp_find_bot(url, user, password), False
    if not uid:
        st, data = _wp_req(url, "/wp-json/wp/v2/users", user, password, "POST", {
            "username": WP_BOT_LOGIN,
            "email": wp_bot_email(domain),
            "password": secrets.token_urlsafe(32),
            "name": WP_BOT_NAME,
            "roles": ["administrator"],
        })
        if st not in (200, 201) or not isinstance(data, dict) or not data.get("id"):
            return None, None, f"création impossible : {data.get('message', st)}"
        uid, created = data["id"], True
    st, data = _wp_req(url, f"/wp-json/wp/v2/users/{uid}/application-passwords",
                       user, password, "POST", {"name": WP_BOT_NAME})
    if st not in (200, 201) or not isinstance(data, dict) or not data.get("password"):
        return None, None, f"mot de passe d'application refusé : {data.get('message', st)}"
    if created:   # création d'un administrateur : jamais silencieuse
        append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "wp_authorize", "server": "rest", "domain": domain,
                    "action": "creation_admin_dedie", "arg": WP_BOT_LOGIN, "rc": 0,
                    "duration_s": 0,
                    "output_tail": f"compte administrateur {WP_BOT_LOGIN} (id {uid}) créé sur {domain}"})
        try:
            alert(f"admin_dedie:{domain}",
                  f"👤 Compte <b>{WP_BOT_LOGIN}</b> (administrateur) créé sur <b>{domain}</b> "
                  f"par le dashboard, pour la gestion à distance.")
        except Exception:
            pass
    return WP_BOT_LOGIN, data["password"], ("compte dédié créé" if created
                                            else "compte dédié existant réutilisé")


def wp_revoke_bootstrap(url, user, password, app_name):
    """Révoque le mot de passe d'application obtenu avec le compte personnel :
    une fois le compte dédié en place, il ne doit plus servir."""
    st, data = _wp_req(url, "/wp-json/wp/v2/users/me/application-passwords", user, password)
    if st != 200 or not isinstance(data, list):
        return False
    for item in data:
        if item.get("name") == app_name and item.get("uuid"):
            st2, _ = _wp_req(url,
                             f"/wp-json/wp/v2/users/me/application-passwords/{item['uuid']}",
                             user, password, "DELETE")
            return st2 in (200, 204)
    return False


def wp_unprovision_bot(domain, url=""):
    """Désenrôlement : supprime le compte dédié du site distant (ses contenus
    éventuels sont réattribués au premier administrateur restant), puis oublie
    l'identifiant local. Appelé quand on retire un site du dashboard."""
    _, cred = wp_cred_for(domain, url)
    if not cred:
        return True, "aucun identifiant enregistré"
    site_url = cred.get("url") or url
    user, password = cred.get("user"), cred.get("password")
    if user != WP_BOT_LOGIN:   # autorisation faite avec un compte personnel
        wp_cred_forget(domain, url)
        return True, "identifiant local effacé (aucun compte dédié à supprimer)"
    uid = wp_find_bot(site_url, user, password)
    if not uid:
        wp_cred_forget(domain, url)
        return True, "compte dédié introuvable sur le site ; identifiant local effacé"
    # WordPress exige de dire quoi faire des contenus : on réattribue à un autre admin.
    st, admins = _wp_req(site_url, "/wp-json/wp/v2/users?context=edit&roles=administrator",
                         user, password)
    heir = None
    if st == 200 and isinstance(admins, list):
        for a in admins:
            if a.get("id") and a.get("id") != uid:
                heir = a["id"]
                break
    path = f"/wp-json/wp/v2/users/{uid}?force=true" + (f"&reassign={heir}" if heir else "")
    st, data = _wp_req(site_url, path, user, password, "DELETE")
    ok = st in (200, 204) or (isinstance(data, dict) and data.get("deleted"))
    append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": "wp_unenroll", "server": "rest", "domain": domain,
                "action": "suppression_admin_dedie", "arg": WP_BOT_LOGIN,
                "rc": 0 if ok else 1, "duration_s": 0,
                "output_tail": (f"compte {WP_BOT_LOGIN} (id {uid}) supprimé de {domain}"
                                if ok else f"suppression refusée : {data}")})
    wp_cred_forget(domain, url)
    return ok, ("compte dédié supprimé du site" if ok
                else f"suppression refusée par le site : {data.get('message', st)}")


def wp_baseline_allow(domain, login):
    """Le compte du dashboard ne doit pas déclencher l'alerte « nouvel admin ».

    Si le site n'a pas encore de référence, on l'amorce avec les administrateurs
    déjà connus : sinon les comptes légitimes existants passeraient en rouge.
    """
    try:
        path = os.path.join(DATA, "admins_baseline.json")
        base = load_json(path, {})
        entry = base.get(domain)
        if not entry:
            connus = []
            for srv in load_json(FLEET_PATH, {"servers": []}).get("servers", []):
                for st in srv.get("sites", []):
                    if st.get("domain") == domain or st.get("kuma") == domain:
                        connus = [a.get("login") for a in (st.get("admins") or []) if a.get("login")]
            entry = {"logins": connus,
                     "set_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
        if login not in entry.get("logins", []):
            entry["logins"] = sorted(set(entry.get("logins", [])) | {login})
        base[domain] = entry
        save_json(path, base)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path.split("?")[0]
        q = dict(x.split("=", 1) for x in self.path.split("?", 1)[1].split("&") if "=" in x) if "?" in self.path else {}
        if p == "/api/auth/check":
            # appelé par nginx auth_request : 200 si session valide, 401 sinon
            code = 200 if cookie_user(self.headers) else 401
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if p == "/api/auth/me":
            self._send(200, {"user": cookie_user(self.headers)})
            return
        if p == "/api/actions/log":
            self._send(200, {"log": read_log()})
        elif p == "/api/actions/list":
            self._send(200, {"actions": {k: v[0] for k, v in ACTIONS.items()}})
        elif p == "/api/actions/collect_status":
            self._send(200, {"running": COLLECT["running"], "rc": COLLECT["rc"],
                             "done": COLLECT["done_servers"], "total": COLLECT["total_servers"],
                             "started": COLLECT["started"], "lines": COLLECT["lines"][-14:]})
        elif p == "/api/actions/collect_history":
            try:
                with open(os.path.join(DATA, "collect_history.jsonl")) as fh:
                    hist = [json.loads(l) for l in fh.readlines()[-60:]]
            except FileNotFoundError:
                hist = []
            self._send(200, {"history": hist})
        elif p == "/api/actions/bulk_status":
            job = JOBS.get(int(q.get("job", 0)) if q.get("job", "0").isdigit() else 0)
            self._send(200, job or {"error": "job inconnu"})
        elif p == "/api/mgmt/state":
            groups, monitors = kuma_state()
            self._send(200, {"servers": servers_list(),
                             "overrides": load_json(os.path.join(DATA, "overrides.json"), {}),
                             "extra_docroots": load_json(os.path.join(DATA, "extra_docroots.json"), []),
                             "kuma_groups": groups, "kuma_monitors": monitors})
        elif p == "/api/mgmt/sshkeys":
            self._send(200, {"keys": ssh_keys_list(), "assignments": ssh_key_assignments()})
        elif p == "/api/mgmt/rest_sites":
            if not cookie_user(self.headers):
                return self._send(401, {"error": "non authentifié"})
            self._send(200, {"rest_sites": rest_sites()})
        elif p == "/api/mgmt/candidates":
            if not cookie_user(self.headers):
                return self._send(401, {"error": "non authentifié"})
            self._send(200, {"candidates": kuma_candidates()})
        elif p == "/api/mgmt/agent.zip":
            # téléchargement direct (lien) : contrôle du cookie de session, pas d'en-tête X-Dash
            if not cookie_user(self.headers):
                return self._send(401, {"error": "non authentifié"})
            blob, err = agent_zip_bytes()
            if err:
                return self._send(404, {"error": err})
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="sumotori-dash-agent.zip"')
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(blob)
        elif p == "/api/mgmt/wp_credentials":
            _, cred = wp_cred_for(urllib.parse.unquote(q.get("domain", "")))
            self._send(200, {"has_password": bool(cred), "user": (cred or {}).get("user", ""),
                             "verified": (cred or {}).get("verified"),
                             "checked_ts": (cred or {}).get("checked_ts")})
        elif p == "/api/wp_callback":
            # Retour de wp-admin/authorize-application.php : jeton state à usage
            # unique, puis redirection vers l'interface. Aucun secret en réponse.
            domain, status = wp_callback(q)
            dest = (DASH_BASE + "/?wpauth=" + urllib.parse.quote(status)
                    + "&domain=" + urllib.parse.quote(domain or ""))
            self.send_response(302)
            self.send_header("Location", dest)
            self.send_header("Content-Length", "0")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
        elif p == "/api/mgmt/schedule":
            self._send(200, read_schedule())
        elif p == "/api/mgmt/alerts":
            # le token n'est jamais renvoyé en clair : booléen + 4 derniers caractères
            cfg = alerts_cfg()
            token = str(cfg.get("bot_token") or "")
            self._send(200, {"enabled": bool(cfg.get("enabled")), "chat_id": cfg.get("chat_id") or "",
                             "rules": cfg.get("rules"), "token_set": bool(token),
                             "token_tail": token[-4:] if token else ""})
        elif p == "/api/sec/diff":
            self._send(200, compute_diff())
        elif p == "/api/sec/certs":
            self._send(200, ssl_certs())
        elif p == "/api/sec/checksums":
            self._send(200, {"checksums": load_json(CHECKSUMS_PATH, {})})
        elif p == "/api/actions/plugin_versions":
            self._send(200, wporg_versions(urllib.parse.unquote(q.get("slug", ""))) or
                            {"current": None, "versions": []})
        elif p == "/api/actions/rollback_points":
            server = urllib.parse.unquote(q.get("server", ""))
            dom = urllib.parse.unquote(q.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(dom):
                return self._send(400, {"error": "cible invalide"})
            self._send(200, {"points": rollback_points(server, dom)})
        elif p == "/api/actions/policy":
            dom = urllib.parse.unquote(q.get("domain", ""))
            self._send(200, {"frozen": frozen_plugins(dom) if SLUG_RE.match(dom) else []})
        elif p == "/api/actions/safe_update_status":
            self._send(200, dict(SAFE))
        elif p == "/api/sec/vulns":
            # Résultat du dernier croisement local (vulns.py --scan) + état d'avancement.
            res = load_json(VULNS_FOUND_PATH, {"sites": [], "totals": {},
                                               "sites_affected": 0, "sites_scanned": 0})
            res["running"] = VULNS["running"]
            res["run_message"] = VULNS["message"]
            self._send(200, res)
        elif p == "/api/sec/baseline":
            self._send(200, {"baseline": load_json(os.path.join(DATA, "admins_baseline.json"), {})})
        elif p == "/api/mgmt/changes":
            if not cookie_user(self.headers):
                return self._send(401, {"error": "non authentifié"})
            try:
                limit = min(int(q.get("limit", "400")), 2000)
            except ValueError:
                limit = 400
            rows = read_changes(2000)[:limit]
            for r in rows:
                r["label"] = CHANGE_LABELS.get(r.get("kind"), "changement")
            # résumé sur 24 h : nb de changements, sites touchés, dont à surveiller
            cutoff = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")
            recent = [r for r in read_changes(2000) if str(r.get("ts") or "") >= cutoff]
            self._send(200, {"changes": rows,
                             "summary": {"day_total": len(recent),
                                         "day_sites": len({r.get("domain") for r in recent}),
                                         "day_warn": sum(1 for r in recent if r.get("severity") == "warn")}})
        elif p == "/api/site/timeline":
            server = urllib.parse.unquote(q.get("server", ""))
            domain = urllib.parse.unquote(q.get("domain", ""))
            if (server and not SERVER_RE.match(server)) or not SLUG_RE.match(domain):
                self._send(400, {"error": "cible invalide"})
            else:
                self._send(200, {"events": site_timeline(server, domain)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        # login/logout : hors garde X-Dash (le login page les appelle avant toute session)
        if p == "/api/auth/login":
            try:
                body = self._body()
            except (ValueError, TypeError):
                return self._send(400, {"error": "payload invalide"})
            user, pw = str(body.get("user", "")), str(body.get("password", ""))
            ip = self.headers.get("X-Real-IP", "?")
            if verify_password(user, pw):
                tok = make_token(user)
                data = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Set-Cookie", f"dash_session={tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={SESSION_TTL}")
                self.end_headers()
                self.wfile.write(data)
            else:
                log_auth_fail(user, ip)
                self._send(401, {"ok": False, "error": "identifiants invalides"})
            return
        if p == "/api/auth/logout":
            data = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Set-Cookie", "dash_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
            self.end_headers()
            self.wfile.write(data)
            return

        # ingestion d'évènements : route PUBLIQUE (appelée par les sites WordPress),
        # authentifiée par HMAC — donc hors garde X-Dash / cookie de session
        if p == "/api/ingest":
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                return self._send(400, {"error": "longueur invalide"})
            if length <= 0 or length > INGEST_MAX_BYTES:
                return self._send(413, {"error": "corps absent ou trop volumineux"})
            raw = self.rfile.read(length)
            domain, err = verify_ingest(self.headers, raw)
            if err:
                return self._send(401, {"error": err})
            try:
                payload = json.loads(raw.decode("utf-8", "replace") or "{}")
            except ValueError:
                return self._send(400, {"error": "payload invalide"})
            if not isinstance(payload, dict):
                return self._send(400, {"error": "payload invalide"})
            ingest_event(domain, payload)
            return self._send(200, {"ok": True})

        # appairage d'un site : route PUBLIQUE (appelée par le plugin après saisie du code),
        # protégée par le code à usage unique + limite de débit — hors garde X-Dash / cookie
        if p == "/api/pair":
            ip = self.headers.get("X-Real-IP", "?")
            try:
                body = self._body()
            except (ValueError, TypeError):
                body = {}
            code = normalize_pair_code(body.get("code"))
            if not pair_rate_ok(ip):
                alerts_log(f"appairage refusé (débit) ip={ip}")
                log_auth_fail("pair", ip)
                return self._send(429, {"ok": False, "error": "trop de tentatives, réessayez plus tard"})
            res, err = pair_site(code, body.get("site_url"), body.get("agent_version"),
                                 body.get("multisite"))
            if err:
                alerts_log(f"appairage refusé ({err}) code={code or '?'} ip={ip}")
                log_auth_fail("pair", ip)
                return self._send(403, {"ok": False, "error": err})
            alerts_log(f"appairage accepté site={res['domain']} ip={ip}")
            return self._send(200, {"ok": True, "secret": res["secret"], "endpoint": res["endpoint"]})

        if self.headers.get("X-Dash") != "1":
            return self._send(403, {"error": "en-tête manquant"})
        if not cookie_user(self.headers):
            return self._send(401, {"error": "non authentifié"})
        try:
            body = self._body()
        except (ValueError, TypeError):
            return self._send(400, {"error": "payload invalide"})

        if p == "/api/actions/collect":
            ok = start_collect()
            return self._send(200 if ok else 409, {"ok": ok, "error": None if ok else "collecte déjà en cours"})

        if p == "/api/actions/run":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            action, arg = str(body.get("action", "")), body.get("arg")
            if action != "rescan" and action not in ACTIONS:
                return self._send(400, {"error": "action inconnue"})
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            rc, out = logged_action(server, domain, action, arg)
            # rc 2 sur une action vizproof = anomalies visuelles, pas une erreur technique ;
            # rc 97 = action impossible sans SSH, c'est une réponse, pas une panne serveur
            anomaly = rc == VIZ_ANOMALY_RC and action in VIZ_ACTIONS
            soft = anomaly or rc == REST_UNSUPPORTED_RC
            return self._send(200 if (rc == 0 or soft) else 500,
                              {"ok": rc == 0, "rc": rc, "viz_anomaly": anomaly, "output": out,
                               "error": None if rc == 0 else out})

        if p == "/api/actions/bulk":
            tasks = body.get("tasks") or []
            mode = "stop" if body.get("mode") == "stop" else "continue"
            backup_first = bool(body.get("backup_first"))
            viz_verify = bool(body.get("viz_verify"))  # baseline avant / scan après la MAJ
            if not tasks or len(tasks) > 200:
                return self._send(400, {"error": "liste de tâches invalide"})
            for t in tasks:
                if not SERVER_RE.match(str(t.get("server", ""))) or not SLUG_RE.match(str(t.get("domain", ""))):
                    return self._send(400, {"error": "cible invalide dans la liste"})
                if t.get("action") not in ("rescan", "dash_connect") and t.get("action") not in ACTIONS:
                    return self._send(400, {"error": f"action inconnue: {t.get('action')}"})
            jid = start_bulk(tasks, mode, backup_first, viz_verify)
            return self._send(200, {"ok": True, "job": jid})

        if p == "/api/actions/bulk_cancel":
            job = JOBS.get(int(body.get("job", 0)))
            if job:
                job["cancel"] = True
            return self._send(200, {"ok": bool(job)})

        if p == "/api/mgmt/override":
            domain = str(body.get("domain", ""))
            if not SLUG_RE.match(domain):
                return self._send(400, {"error": "domaine invalide"})
            ov = load_json(os.path.join(DATA, "overrides.json"), {})
            cur = ov.get(domain, {})
            if "visible" in body:
                cur["visible"] = body["visible"] if body["visible"] in (True, False) else None
            if "alias" in body:
                al = str(body["alias"]).strip()
                cur["alias"] = al or None
            ov[domain] = {k: v for k, v in cur.items() if v is not None}
            if not ov[domain]:
                ov.pop(domain, None)
            save_json(os.path.join(DATA, "overrides.json"), ov)
            return self._send(200, {"ok": True, "overrides": ov})

        if p == "/api/mgmt/servers":
            servers = body.get("servers")
            if not isinstance(servers, list):
                return self._send(400, {"error": "format invalide"})
            for s in servers:
                if not re.match(r"^[a-z0-9-]{1,40}$", str(s.get("name", ""))) or not s.get("host") or not s.get("patterns"):
                    return self._send(400, {"error": "serveur invalide"})
            save_json(os.path.join(BASE, "servers.json"), servers)
            return self._send(200, {"ok": True})

        if p == "/api/mgmt/docroots":
            docs = body.get("docroots")
            if not isinstance(docs, list):
                return self._send(400, {"error": "format invalide"})
            save_json(os.path.join(DATA, "extra_docroots.json"), docs)
            return self._send(200, {"ok": True})

        if p == "/api/mgmt/discover":
            return self._send(200, discover_site(body.get("url")))

        if p == "/api/mgmt/pair_code":
            url, err = normalize_site_url(body.get("url")) if body.get("url") else (None, None)
            if err:
                return self._send(400, {"error": err})
            return self._send(200, {"code": create_pair_code(url or ""), "expires_in": PAIR_TTL})

        if p == "/api/mgmt/rest_sites":
            url, err = normalize_site_url(body.get("url"))
            if err:
                return self._send(400, {"error": err})
            _, err = validate_public_url(url)  # même garde anti-SSRF que le sondage
            if err:
                return self._send(400, {"error": err})
            return self._send(200, {"ok": True, "site": add_rest_site(url, name=body.get("name"),
                                                                      multisite=bool(body.get("multisite")))})

        if p == "/api/mgmt/rest_sites/delete":
            domain = site_key(body.get("domain", ""))
            if not SLUG_RE.match(domain):
                return self._send(400, {"error": "domaine invalide"})
            # Désenrôlement complet : on retire d'abord le compte dédié du site
            # distant (sinon il y resterait un administrateur orphelin), puis le
            # site du dashboard. `keep_account` permet de sauter cette étape.
            cleanup = "non demandé"
            if not body.get("keep_account"):
                try:
                    _, cleanup = wp_unprovision_bot(domain)
                except Exception as e:
                    cleanup = f"nettoyage impossible : {e}"
            return self._send(200, {"ok": remove_rest_site(domain), "cleanup": cleanup})

        if p == "/api/mgmt/kuma/create":
            domain = str(body.get("domain", ""))
            name = str(body.get("monitor_name") or domain)
            gid = body.get("group_id")
            mtype = "http" if body.get("type") == "http" else "keyword"
            url = str(body.get("url") or (f"https://{domain}/" if mtype == "http" else f"https://{domain}/wp-login.php"))
            keyword = str(body.get("keyword") or "loginform")
            if not SLUG_RE.match(domain) or not str(gid).isdigit():
                return self._send(400, {"error": "paramètres invalides"})
            if not re.match(r"^https?://", url):
                return self._send(400, {"error": "url invalide"})
            rc, out = kuma_create(domain, name, gid, url, mtype, keyword)
            return self._send(200 if rc == 0 else 500, {"ok": rc == 0, "output": out})

        if p == "/api/mgmt/kuma/pause":
            mid = body.get("monitor_id")
            active = 1 if body.get("active") else 0
            if not str(mid).isdigit():
                return self._send(400, {"error": "id invalide"})
            rc, out = kuma_sql(f"UPDATE monitor SET active={active} WHERE id={int(mid)} AND type!='group';")
            kuma_restart()
            return self._send(200 if rc == 0 else 500, {"ok": rc == 0, "output": out})

        if p == "/api/mgmt/kuma/delete":
            mid = body.get("monitor_id")
            if not str(mid).isdigit():
                return self._send(400, {"error": "id invalide"})
            kuma_sql(f"DELETE FROM monitor_group WHERE monitor_id={int(mid)};")
            kuma_sql(f"DELETE FROM heartbeat WHERE monitor_id={int(mid)};")
            rc, out = kuma_sql(f"DELETE FROM monitor WHERE id={int(mid)} AND type!='group';")
            kuma_restart()
            return self._send(200 if rc == 0 else 500, {"ok": rc == 0, "output": out})

        if p == "/api/mgmt/sshkeys/generate":
            name = str(body.get("name", ""))
            if not SSH_KEYNAME_RE.match(name):
                return self._send(400, {"error": "nom invalide (a-z, 0-9, _ et -, 30 max)"})
            path = os.path.join(SSH_DIR, "dash_" + name)
            if os.path.exists(path) or os.path.exists(path + ".pub"):
                return self._send(409, {"error": "une clé porte déjà ce nom"})
            try:
                r = subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "wp-dashboard", "-f", path],
                                   capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as e:
                return self._send(500, {"error": f"ssh-keygen: {e}"})
            if r.returncode != 0:
                return self._send(500, {"error": ((r.stdout + r.stderr).strip() or "échec ssh-keygen")[-400:]})
            return self._send(200, {"ok": True, "path": path, "pub": ssh_pub_text(path)})

        if p == "/api/mgmt/sshkeys/test":
            server, key = str(body.get("server", "")), str(body.get("key", ""))
            srv = next((s for s in servers_list() if s.get("name") == server), None)
            if not srv:
                return self._send(400, {"error": "serveur inconnu"})
            if not valid_key_path(key):
                return self._send(400, {"error": "clé invalide"})
            cmd = ["ssh", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
                   "-p", str(srv["port"]), ssh_target(srv), "echo OK depuis $(hostname)"]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                rc, out = r.returncode, (r.stdout + r.stderr).strip()
            except subprocess.TimeoutExpired:
                rc, out = 93, "timeout"
            except (OSError, subprocess.SubprocessError) as e:
                rc, out = 94, f"erreur interne: {e}"
            return self._send(200, {"ok": rc == 0, "output": out[:400]})

        if p == "/api/mgmt/sshkeys/assign":
            server, key = str(body.get("server", "")), str(body.get("key", ""))
            if not valid_key_path(key):
                return self._send(400, {"error": "clé invalide"})
            servers = servers_list()
            targets = servers if server == "*" else [s for s in servers if s.get("name") == server]
            if not targets:
                return self._send(400, {"error": "serveur inconnu"})
            for s in targets:
                s["key"] = key
            save_json(os.path.join(BASE, "servers.json"), servers)
            return self._send(200, {"ok": True})

        if p == "/api/sec/verify":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            rc, out = logged_action(server, domain, "verify_checksums", None, source="securite")
            return self._send(200, {"ok": rc == 0, "rc": rc, "output": out})

        if p == "/api/sec/checksums/run":
            # vérification de tous les sites visibles, en tâche de fond (file d'attente bulk)
            tasks = [{"server": name, "domain": s["domain"], "action": "verify_checksums"}
                     for name, s in visible_sites() if name and s.get("domain")]
            if not tasks:
                return self._send(400, {"error": "aucun site visible"})
            return self._send(200, {"ok": True, "job": start_bulk(tasks, "continue", False),
                                    "total": len(tasks)})

        if p == "/api/actions/plugin_rollback":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            slug = str(body.get("slug", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            t0 = time.time()
            rc, out = plugin_rollback(server, domain, slug,
                                      body.get("dir") or None, body.get("version") or None)
            append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "retablissement", "server": server, "domain": domain,
                        "action": "plugin_rollback", "arg": slug, "rc": rc,
                        "duration_s": round(time.time() - t0, 1), "output_tail": str(out)[-2000:]})
            return self._send(200, {"ok": rc == 0, "rc": rc, "output": out})

        if p == "/api/actions/policy":
            domain, slug = str(body.get("domain", "")), str(body.get("slug", ""))
            if not SLUG_RE.match(domain) or not SLUG_RE.match(slug):
                return self._send(400, {"error": "cible invalide"})
            frozen = set_frozen_plugin(domain, slug, bool(body.get("frozen")))
            append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "politique", "server": str(body.get("server", "")),
                        "domain": domain, "action": "plugin_freeze", "arg": slug, "rc": 0,
                        "duration_s": 0,
                        "output_tail": ("gelée" if body.get("frozen") else "dégelée") + f" : {slug}"})
            return self._send(200, {"ok": True, "frozen": frozen})

        if p == "/api/actions/safe_update":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            with SAFE_LOCK:
                if SAFE["running"]:
                    return self._send(409, {"error": f"mise à jour sûre déjà en cours sur {SAFE['domain']}"})
                SAFE["running"] = True   # réservation immédiate : évite deux lancements simultanés
            slugs = body.get("slugs") or None
            if slugs is not None:
                slugs = [s for s in slugs if isinstance(s, str) and SLUG_RE.match(s)]
            threading.Thread(target=safe_update_run,
                             args=(server, domain, slugs, bool(body.get("backup", True)),
                                   bool(body.get("viz", True)), bool(body.get("core", False))),
                             daemon=True).start()
            return self._send(200, {"ok": True, "running": True})

        if p == "/api/sec/vulns/run":
            # Rafraîchit la base publique puis recroise, en tâche de fond :
            # ~320 slugs à interroger, bien plus long que le délai d'une requête HTTP.
            if VULNS["running"]:
                return self._send(409, {"error": "analyse déjà en cours"})
            full = bool(body.get("refresh", True))
            threading.Thread(target=vulns_worker, args=(full,), daemon=True).start()
            return self._send(200, {"ok": True, "running": True})

        if p == "/api/sec/baseline":
            base = set_baseline(body.get("domain") or None)
            return self._send(200, {"ok": True, "baseline": base})

        if p == "/api/mgmt/wp_authorize":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SLUG_RE.match(domain):
                return self._send(400, {"error": "domaine invalide"})
            url, err = wp_authorize_url(server, domain)
            return self._send(200 if url else 400, {"authorize_url": url, "error": err})

        if p == "/api/mgmt/wp_credentials/delete":
            domain = str(body.get("domain", ""))
            if not SLUG_RE.match(domain):
                return self._send(400, {"error": "domaine invalide"})
            return self._send(200, {"ok": wp_cred_forget(domain)})

        if p == "/api/mgmt/schedule":
            ok, err = write_schedule(body.get("interval_minutes"))
            return self._send(200 if ok else 400, {"ok": ok, "error": err, **read_schedule()})

        if p == "/api/mgmt/alerts":
            cfg = alerts_cfg()
            token = str(body.get("bot_token") or body.get("token") or "").strip()
            new = {"enabled": bool(body["enabled"]) if "enabled" in body else bool(cfg.get("enabled")),
                   "chat_id": str(body.get("chat_id") or cfg.get("chat_id") or "").strip(),
                   # token absent ou vide : on conserve celui déjà enregistré
                   "bot_token": token or str(cfg.get("bot_token") or ""),
                   "rules": dict(cfg["rules"])}
            rules = body.get("rules")
            if isinstance(rules, dict):
                for k, v in rules.items():
                    if k in ALERT_DEFAULTS["rules"]:  # les règles inconnues sont ignorées
                        new["rules"][k] = coerce_rule(k, v)
            save_json(ALERTS_PATH, new)
            try:
                os.chmod(ALERTS_PATH, 0o600)  # le fichier contient le token du bot
            except OSError:
                pass
            return self._send(200, {"ok": True, "enabled": new["enabled"], "chat_id": new["chat_id"],
                                    "rules": new["rules"], "token_set": bool(new["bot_token"]),
                                    "token_tail": new["bot_token"][-4:] if new["bot_token"] else ""})

        if p == "/api/mgmt/alerts/test":
            ok, err = telegram_send_sync("✅ <b>Dashboard parc</b> — message de test.")
            alerts_log("test: " + ("ok" if ok else f"échec ({err})"))
            return self._send(200, {"ok": ok, "error": err})

        if p == "/api/mgmt/site_secret":
            domain = site_key(body.get("domain", ""))
            if not SLUG_RE.match(domain):
                return self._send(400, {"error": "domaine invalide"})
            # renvoyé une seule fois : le dashboard le transmet au site, on ne le réaffiche jamais
            return self._send(200, {"ok": True, "domain": domain,
                                    "secret": set_site_secret(domain, secrets.token_urlsafe(32))})

        if p == "/api/mgmt/dash_connect":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            rc, out = dash_connect(server, domain)
            return self._send(200 if rc == 0 else 500, {"ok": rc == 0, "rc": rc, "output": out})

        if p == "/api/mgmt/dash_disconnect":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            rc, out = dash_disconnect(server, domain)
            return self._send(200 if rc == 0 else 500, {"ok": rc == 0, "rc": rc, "output": out})

        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    ThreadingHTTPServer(("127.0.0.1", 8090), Handler).serve_forever()
