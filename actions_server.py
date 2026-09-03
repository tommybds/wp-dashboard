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
import functools, io, ipaddress, socket, urllib.error, urllib.request, urllib.parse, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dashboard_config import CONFIG
from vulns import version_compare
# Briques communes à tous les scripts du dépôt (cf. dashlib.py) : une seule copie
# de la lecture/écriture JSON, du quotage shell, de l'identité d'un site et des
# expressions de validation partagées avec collect.py.
# SRV_PATH_RE, _JSON_LOCKS, _JSON_LOCKS_GUARD et json_lock ne sont plus appelés
# ici mais restent des attributs du module : c'est cette surface que le reste du
# dépôt et les tests connaissent.
from dashlib import (BASE, DATA_DIR as DATA, PUBLIC_DIR as PUB,  # noqa: F401
                     SLUG_RE, SERVER_RE, PATH_PATTERN_RE as SRV_PATH_RE,
                     _JSON_LOCKS, _JSON_LOCKS_GUARD, json_lock,
                     load_json, norm_domain, site_key, site_visible, sq,
                     valid_path_pattern)
from dashlib import (default_mode as _default_mode, save_json as _save_json,
                     update_json as _update_json)

KEY = CONFIG["ssh_key"]              # clé SSH par défaut (surchargée par serveur dans servers.json)
LOG = os.path.join(DATA, "actions.log")
KUMA_DB = CONFIG["kuma_db"]          # chemin de la base Kuma DANS le conteneur
KUMA_CONTAINER = CONFIG["kuma_container"]
SLUG = CONFIG["kuma_slug"]           # slug de la status page Kuma du parc
# SLUG_RE (le « / » reste autorisé : un WordPress peut vivre en sous-répertoire
# comme jupiter.com/zavus-calculator ; « .. » est interdit partout) et SERVER_RE
# viennent de dashlib — collect.py valide les mêmes entrées.
FLEET_PATH = os.path.join(DATA, "fleet.json")
# ---- vizproof (produit public : lecture seule, scan visuel et statut) ----
VIZ_ANOMALY_RC = 2  # code de sortie « anomalies visuelles détectées » : pas une erreur technique
VIZ_ACTIONS = ("viz_baseline", "viz_scan")
# Mises à jour après lesquelles un contrôle visuel a du sens : celles qui
# changent le code servi au visiteur. Le bouton unitaire du tiroir passait
# jusqu'ici par /api/actions/run sans AUCUN contrôle visuel — seules la MAJ sûre
# et l'action groupée « vérifiée visuellement » en faisaient un.
VIZ_AFTER_UPDATE_ACTIONS = ("plugin_update", "plugins_update_all",
                            "plugins_update_except", "core_update", "themes_update_all")
VIZ_AFTER_SOURCE = "auto-after-update"   # source journalisée du scan automatique
# Le plugin vizproof-timeline (≥ 1.3.6) accroche `upgrader_process_complete`
# GLOBALEMENT, donc aussi sous WP-CLI : quand son option de site
# `enable_update_scan_by_default` est vraie (son défaut), IL LANCE LUI-MÊME un
# scan à chaque `wp plugin update`. Le dashboard attend donc ce scan-là et ne
# lance le sien qu'en repli — sans quoi chaque mise à jour en déclenchait deux.
VIZ_OPTION_NAME = "vizproof_timeline_options"
VIZ_AUTOSCAN_KEY = "enable_update_scan_by_default"
VIZ_POLL_S = 10       # cadence d'interrogation de `wp vizproof status`
VIZ_WAIT_NEW_S = 90   # au plus 90 s pour voir APPARAÎTRE le run lancé par le plugin
VIZ_WAIT_DONE_S = 300 # et 5 min au total pour le voir se TERMINER
# Tolérance d'horloge entre le dashboard et le serveur du site : un run daté
# jusqu'à une minute AVANT la mise à jour compte encore comme postérieur.
VIZ_CLOCK_SKEW_S = 60
VIZ_RUN_PENDING = ("queued", "running", "pending", "in_progress", "processing")
VIZ_RUN_FAILED = ("failed", "error", "cancelled", "canceled", "aborted")
VIZ_RUN_FAIL_RC = 1   # run du plugin terminé en échec : ni « ok » ni « anomalies »
VIZ_SRC_PLUGIN = "plugin"       # le scan a été lancé par vizproof-timeline
VIZ_SRC_DASHBOARD = "dashboard"  # …ou, en repli, par nous
VIZ_PHASE_WAIT = "attente du scan du plugin"
VIZ_PHASE_RUNNING = "scan en cours"
VIZ_PHASE_DASHBOARD = "scan dashboard"
# Connexion d'un site à VizProof (`wp vizproof connect`, plugin ≥ 1.3.6).
VIZ_SITE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
# Jeton de compte : jeu de caractères des jetons porteurs usuels, sur UNE ligne.
# Le refus du saut de ligne n'est pas cosmétique : le jeton voyage dans un
# document ici (heredoc) sur l'entrée standard de la commande distante.
VIZ_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~:/+=-]{8,512}$")
VIZ_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")   # code de connexion à usage unique
VIZ_SCOPES = ("site", "selected_pages")
# Jeton de COMPTE enregistré dans les Réglages (« Authorization: Bearer vrt_… »).
# Plus étroit que VIZ_TOKEN_RE : celui-là accepte tout jeton porteur transmis au
# coup par coup à `wp vizproof connect`, celui-ci est le format que l'API
# publique de vizproof.com délivre — on refuse d'enregistrer autre chose.
VIZ_ACCOUNT_TOKEN_RE = re.compile(r"^vrt_[A-Za-z0-9_-]{8,200}$")
VIZ_API_BASE_DEFAULT = "https://vizproof.com"
VIZ_API_TIMEOUT = 20
VIZ_API_MAX_BYTES = 512 * 1024
VIZ_PAGE_LIMIT = 100     # `limit` maximal documenté par l'API publique
VIZ_SITES_MAX = 500      # plafond de parcours : au-delà on renonce plutôt que de boucler
VIZ_NO_TOKEN_MSG = "aucun token VizProof dans les Réglages"
# Hôte plausible : au moins un point, étiquettes DNS classiques (déjà en minuscule).
VIZ_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                         r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
VIZ_RESOLVE_RC = 95      # « site VizProof non résolu » : ni SSH ni wp-cli en cause
VIZ_OLD_RC = 99   # même convention que AGENT_OLD_RC : « le site a une version trop ancienne »
VIZ_OLD_MSG = "plugin VizProof trop ancien sur ce site : mettre à jour vers 1.3.6"
VIZ_OLD_RE = re.compile(r"is not a registered (?:sub)?command|"
                        r"n'est pas une (?:sous-)?commande", re.I)
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
# Réglages généraux du dashboard (distincts des alertes, qui ont leur fichier).
SETTINGS_PATH = os.path.join(DATA, "settings.json")
CHECKSUMS_PATH = os.path.join(DATA, "checksums.json")
VULNS_FOUND_PATH = os.path.join(DATA, "vulns_found.json")
PHPERR_PATH = os.path.join(DATA, "php_errors.json")
# Index local des archives de restauration : interroger le serveur en SSH à
# chaque ouverture de tiroir coûtait 2 secondes. On tient donc la liste ici,
# alimentée au moment où la MAJ sûre crée l'archive.
ROLLBACK_INDEX_PATH = os.path.join(DATA, "rollback_index.json")
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
    # La connexion, elle, n'est PAS ici : elle transporte un jeton, qui ne doit
    # jamais passer par une ligne de commande (cf. viz_connect_run).
    "viz_disconnect":     ("Dissocier VizProof", False, "vizproof disconnect --format=json"),
}
# actions bulk qui doivent d'abord backuper si UpdraftPlus est présent
BACKUP_FIRST = {"core_update", "plugins_update_all", "plugins_update_except", "themes_update_all"}
# actions groupées qui ne sont pas des commandes wp-cli de ACTIONS : la collecte
# ciblée, et la liaison/déliaison de l'agent (dépôt ou retrait d'un fichier).
BULK_EXTRA_ACTIONS = ("rescan", "dash_connect", "dash_disconnect")
MAX_BODY_BYTES = 1024 * 1024   # plafond du corps d'une requête JSON

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


# ---------- cadence de la collecte automatique (cron) ----------
CRON_PATH = "/etc/cron.d/wp-dashboard"
CRON_MINUTE = 17          # décalé de l'heure pile : évite les pics de charge
SCHEDULE_CHOICES = [0, 15, 30, 60, 120, 180, 360, 720, 1440]
# Le fichier cron ne contient PAS que la collecte : phperrors, vulns, digest et
# rotate y vivent aussi. Seule la ligne collect.py (ou la ligne de désactivation)
# est réécrite ; tout le reste est recopié à l'identique.
CRON_HEADER = "# Collecte du parc WordPress — géré depuis le dashboard (Réglages)"
CRON_DISABLED = "# collecte automatique désactivée"


def cron_expr(minutes):
    """Expression cron pour un intervalle en minutes (0 = désactivé)."""
    if minutes < 60:
        return f"*/{minutes} * * * *"
    if minutes == 60:
        return f"{CRON_MINUTE} * * * *"
    if minutes < 1440:
        return f"{CRON_MINUTE} */{minutes // 60} * * *"
    return f"{CRON_MINUTE} 3 * * *"   # quotidien : 3h17 du matin


def is_collect_line(line):
    """Vrai si la ligne du cron porte la collecte (active ou désactivée)."""
    s = str(line).strip()
    if s == CRON_DISABLED:
        return True
    return bool(s) and not s.startswith("#") and "collect.py" in s


def read_schedule():
    """Intervalle courant lu depuis le fichier cron.

    Un fichier cron édité à la main ne doit jamais faire tomber la route : une
    expression illisible se traduit par un intervalle inconnu (0), pas par un 500.
    """
    interval, expr = 0, None
    try:
        with open(CRON_PATH) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "collect.py" not in line:
                    continue
                champs = line.split()
                if len(champs) < 5:
                    continue
                expr = " ".join(champs[:5])
                m, h = champs[0], champs[1]
                try:
                    if m.startswith("*/"):
                        interval = int(m[2:])
                    elif h.startswith("*/"):
                        interval = int(h[2:]) * 60
                    elif h == "*":
                        interval = 60
                    else:
                        interval = 1440
                except ValueError:
                    interval = 0   # cadence non reconnue : on ne devine pas
                break
    except OSError:
        pass
    return {"interval_minutes": interval, "cron": expr, "choices": SCHEDULE_CHOICES}


def collect_cron_line(minutes):
    """Ligne cron de la collecte pour cet intervalle (0 = ligne de désactivation)."""
    if minutes == 0:
        return CRON_DISABLED
    return (f"{cron_expr(minutes)} root cd {BASE} && /usr/bin/python3 collect.py "
            f">> /var/log/wp-dashboard.log 2>&1")


def write_schedule(minutes):
    """Change la cadence de collecte dans /etc/cron.d/wp-dashboard.

    SEULE la ligne collect.py est remplacée : phperrors, vulns, digest et rotate
    vivent dans le même fichier et doivent être recopiés à l'identique.
    0 désactive la collecte automatique (ligne de commentaire).
    """
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return False, "intervalle invalide"
    if minutes not in SCHEDULE_CHOICES:
        return False, "intervalle non autorisé"
    nouvelle = collect_cron_line(minutes)
    try:
        with open(CRON_PATH) as fh:
            lignes = fh.read().splitlines()
    except FileNotFoundError:
        lignes = []
    except OSError as e:
        return False, f"lecture impossible : {e}"

    sortie, remplacee = [], False
    for ligne in lignes:
        if not is_collect_line(ligne):
            sortie.append(ligne)
            continue
        if not remplacee:          # une seule ligne de collecte au final
            sortie.append(nouvelle)
            remplacee = True
    if not remplacee:
        # Aucune ligne de collecte : on l'ajoute en tête, après l'en-tête de
        # commentaires du fichier (et on pose cet en-tête s'il manque).
        i = 0
        while i < len(sortie) and sortie[i].lstrip().startswith("#"):
            i += 1
        bloc = [nouvelle] if any(l.strip() == CRON_HEADER for l in sortie) else [CRON_HEADER, nouvelle]
        sortie[i:i] = bloc
    contenu = "\n".join(sortie).rstrip("\n") + "\n"
    try:
        rep = os.path.dirname(os.path.abspath(CRON_PATH)) or "."
        fd, tmp = tempfile.mkstemp(dir=rep, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w") as fh:
                os.fchmod(fh.fileno(), 0o644)
                fh.write(contenu)
            os.replace(tmp, CRON_PATH)
            tmp = None
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    except OSError as e:
        return False, f"écriture impossible : {e}"
    return True, None


# ---------- authentification (session par cookie signé) ----------
SESSION_SECRET_PATH = os.path.join(DATA, ".session_secret")
AUTH_PATH = os.path.join(DATA, "auth.json")
AUTH_FAIL_LOG = os.path.join(DATA, "auth_fail.log")
SESSION_TTL = 7 * 24 * 3600  # 7 jours


_SESSION_SECRET = None
_SESSION_SECRET_LOCK = threading.Lock()


def session_secret():
    """Secret de signature des cookies : chargé une fois, créé atomiquement.

    Sans O_EXCL, deux requêtes simultanées sur une installation neuve créaient
    deux secrets différents et invalidaient les sessions l'une de l'autre.
    """
    global _SESSION_SECRET
    if _SESSION_SECRET:
        return _SESSION_SECRET
    with _SESSION_SECRET_LOCK:
        if _SESSION_SECRET:
            return _SESSION_SECRET
        try:
            with open(SESSION_SECRET_PATH, "rb") as fh:
                sec = fh.read()
        except OSError:
            sec = b""
        if not sec:
            try:
                fd = os.open(SESSION_SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                sec = os.urandom(32)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(sec)
            except FileExistsError:
                # un autre processus a gagné la course : on relit le sien
                with open(SESSION_SECRET_PATH, "rb") as fh:
                    sec = fh.read()
        _SESSION_SECRET = sec
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


# ---------- écriture atomique + verrou par fichier ----------
# Le mécanisme vit dans dashlib (tmp unique, droits posés AVANT le renommage,
# un verrou par chemin). Les deux enveloppes ci-dessous n'ajoutent qu'une chose,
# mais elle est essentielle : le répertoire de données de CE module. `DATA` est
# redirigé par les tests, et c'est lui — pas celui du dépôt — qui décide du 0600.


def default_mode(path):
    """0600 pour tout ce qui vit dans data/ (secrets, identifiants), 0644 ailleurs
    — public/fleet.json et servers.json sont lus hors du service."""
    return _default_mode(path, DATA)


def save_json(path, obj, mode=None):
    """Écriture atomique d'un JSON. `mode` None = 0600 sous data/, 0644 sinon."""
    return _save_json(path, obj, mode=mode, data_dir=DATA)


def update_json(path, fn, default=None, mode=None):
    """Lecture → modification → écriture sous verrou. `fn(courant)` rend l'objet
    à écrire (ou None pour conserver le courant). → objet écrit."""
    return _update_json(path, fn, default=default, mode=mode, data_dir=DATA)


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


def ssh_target(srv):
    """Cible ssh du serveur : root@host par défaut, <user>@host sur un mutualisé.

    Garde-fou de dernier recours (la validation d'entrée est validate_server) :
    un user ou un host commençant par « - » serait lu par ssh comme une OPTION
    (« -oProxyCommand=… » = exécution de commande sous root sur le dashboard).
    """
    user = str(srv.get("user") or "root")
    host = str(srv.get("host") or "")
    if not SRV_USER_RE.match(user):
        raise ValueError(f"utilisateur ssh invalide : « {user[:40]} »")
    if not SRV_HOST_RE.match(host) or host.startswith("-"):
        raise ValueError(f"hôte ssh invalide : « {host[:60]} »")
    return f"{user}@{host}"


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


# ---------- validation d'un serveur déclaré (servers.json) ----------
# Ces valeurs finissent en arguments de `ssh` (utilisateur, hôte, port) et, pour
# les patterns, dans un shell distant : un `user` valant « -oProxyCommand=… » est
# une option ssh, donc une exécution de commande sous root sur ce serveur, et un
# pattern contenant une apostrophe casse le quoting du collecteur. On refuse
# donc à l'entrée, en plus des échappements posés à l'usage.
SRV_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")   # même alphabet que SERVER_RE
SRV_HOST_RE = re.compile(r"^[A-Za-z0-9.:-]+$")     # nom d'hôte, IPv4 ou IPv6
SRV_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
# SRV_PATH_RE (glob de docroot, absolu) et valid_path_pattern viennent de
# dashlib : collect.py applique EXACTEMENT la même règle avant d'envoyer un
# motif au shell distant.


def _int_between(value, mini, maxi):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if mini <= n <= maxi else None


def validate_server(obj):
    """Contrôle un serveur de servers.json → (ok, message d'erreur)."""
    if not isinstance(obj, dict):
        return False, "serveur invalide (objet attendu)"
    nom = str(obj.get("name") or "")
    if not SRV_NAME_RE.match(nom):
        return False, f"nom de serveur invalide : « {nom[:40]} »"
    hote = str(obj.get("host") or "")
    if not SRV_HOST_RE.match(hote) or hote.startswith("-") or ".." in hote:
        return False, f"hôte invalide pour « {nom} »"
    user = obj.get("user")
    if user not in (None, "") and not SRV_USER_RE.match(str(user)):
        return False, f"utilisateur ssh invalide pour « {nom} »"
    if _int_between(obj.get("port"), 1, 65535) is None:
        return False, f"port invalide pour « {nom} » (1-65535 attendu)"
    key = obj.get("key")
    if key not in (None, "") and not valid_key_path(key):
        return False, f"clé ssh invalide pour « {nom} » (attendue sous {SSH_DIR}, existante)"
    patterns = obj.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        return False, f"patterns manquants pour « {nom} »"
    for p in patterns:
        if not isinstance(p, str) or not valid_path_pattern(p):
            return False, f"chemin invalide pour « {nom} » : « {str(p)[:60]} »"
    if obj.get("parallel") is not None and _int_between(obj.get("parallel"), 1, 16) is None:
        return False, f"parallel invalide pour « {nom} » (1-16 attendu)"
    if obj.get("priority") is not None and _int_between(obj.get("priority"), -10 ** 6, 10 ** 6) is None:
        return False, f"priority invalide pour « {nom} »"
    return True, None


# ---------- wp-cli action ----------
def run_remote_script(srv, script, timeout=300, max_out=6000):
    """Exécute un script bash sur le serveur : transmis à `bash -s` sur l'entrée standard.

    `max_out` borne la sortie renvoyée (fin du flux) ; None = sortie complète
    (utilisé par phperrors.py, qui a besoin de tout le journal).
    """
    cmd = ["ssh", "-i", srv.get("key") or KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=12",
           "-p", str(srv["port"]), "--", ssh_target(srv), "bash -s"]
    r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout + 40)
    out = (r.stdout + r.stderr).strip()
    return r.returncode, (out if max_out is None else out[-max_out:])


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
    resultat = []

    def _muter(pol):
        if not isinstance(pol, dict):
            pol = {}
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
        resultat[:] = sorted(cur)
        return pol

    update_json(UPDATE_POLICY_PATH, _muter, {})
    return list(resultat)


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


TAIL_BLOCK = 64 * 1024


def tail_lines(path, n):
    """n dernières lignes d'un fichier texte, lues PAR LA FIN.

    actions.log et events.jsonl atteignent plusieurs mégaoctets : les charger
    entiers pour n'en garder que la queue coûtait la taille du fichier à chaque
    ouverture de tiroir. → liste de lignes, ou None si le fichier est illisible.
    """
    if n <= 0:
        return []
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos, morceaux, sauts = fh.tell(), [], 0
            while pos > 0 and sauts <= n:
                pas = min(TAIL_BLOCK, pos)
                pos -= pas
                fh.seek(pos)
                bloc = fh.read(pas)
                morceaux.append(bloc)
                sauts += bloc.count(b"\n")
            brut = b"".join(reversed(morceaux))
    except OSError:
        return None
    return brut.decode("utf-8", "replace").splitlines()[-n:]


def read_jsonl_tail(path, n):
    """n dernières lignes JSON d'un .jsonl, du plus ancien au plus récent."""
    lignes = tail_lines(path, n)
    if lignes is None:
        return []
    out = []
    for l in lignes:
        try:
            out.append(json.loads(l))
        except ValueError:
            continue  # ligne tronquée par une écriture concurrente : ignorée
    return out


def read_log(n=120):
    return read_jsonl_tail(LOG, n)[::-1]


# ---------- checksums mémorisés (C2) ----------
CHECKSUMS_LOCK = threading.Lock()


def record_checksum(domain, rc, out):
    """Mémorise le dernier résultat de `core verify-checksums` pour un domaine."""
    with CHECKSUMS_LOCK:
        store = load_json(CHECKSUMS_PATH, {})
        store[domain] = {"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         "ok": rc == 0, "output_tail": (out or "")[-1200:]}
        save_json(CHECKSUMS_PATH, store)


# ---------- seuils de la file « à traiter » ----------
# Déclarés ici parce qu'ils entrent dans SETTINGS_DEFAULTS juste en dessous ;
# la logique qui les consomme vit plus bas, avec les incidents.
INCIDENT_RULES_DEFAULTS = {
    # Sauvegarde UpdraftPlus jugée en retard au-delà de ce nombre d'heures.
    "backup_max_age_h": 48,
    # Certificat TLS signalé en dessous de ce nombre de jours restants…
    "cert_warn_days": 21,
    # …et compté comme critique en dessous de celui-ci.
    "cert_critical_days": 7,
    # Une vulnérabilité « high » corrigeable devient-elle un incident critique ?
    # Non par défaut : sinon la file d'attente est illisible, et l'écran
    # Sécurité montre déjà l'ensemble des vulnérabilités.
    "vuln_high_is_incident": False,
    # Versions PHP majeure.mineure hors support (une entrée par serveur).
    "php_eol_versions": ["7.0", "7.1", "7.2", "7.3", "7.4", "8.0"],
}

# ---------- réglages persistants (data/settings.json) ----------
# Un seul fichier pour les réglages qui ne sont ni des alertes, ni une cadence
# de cron. Le type de la valeur par défaut fait foi à l'écriture : une clé
# inconnue est ignorée, une valeur d'un autre type est ramenée au type attendu.
SETTINGS_DEFAULTS = {
    # Anomalie visuelle pendant une MAJ sûre : par défaut on AVERTIT sans
    # annuler. Un rendu qui change n'est pas forcément un rendu cassé (bandeau
    # de cookies, carrousel, publicité) et le retour arrière automatique coûtait
    # plus de mises à jour perdues qu'il n'évitait de régressions.
    "viz_anomaly_rollback": False,
    # Contrôle visuel après une mise à jour lancée depuis le tiroir (bouton
    # unitaire). Actif par défaut : une mise à jour sans filet est justement
    # celle après laquelle personne ne regarde le site. On informe seulement —
    # le bouton unitaire n'a pas d'archive, il n'y a rien à annuler.
    "viz_scan_after_update": True,
    # Baseline VizProof AVANT une mise à jour unitaire, comme en prend la MAJ
    # sûre. Sans elle, le contrôle d'après compare au dernier état connu de
    # VizProof — qui peut dater de la veille et mêler d'autres changements.
    "viz_baseline_before_update": True,
    # …mais une baseline qui échoue ne doit pas retenir la mise à jour : VizProof
    # est un filet, pas une condition. Coché, il le devient (site vitrine dont
    # aucune régression visuelle ne doit passer sans témoin d'avant).
    "viz_baseline_required": False,
    # Jeton de compte VizProof : sert à retrouver (ou créer) le site VizProof
    # d'après l'URL WordPress, puis à relier le plugin. Le fichier est en 0600
    # et la valeur n'est JAMAIS renvoyée par l'API : cf. settings_public().
    "vizproof_token": "",
    "vizproof_api_base": VIZ_API_BASE_DEFAULT,
    # Seuils de la file d'incidents (GET /api/incidents). Sous-dictionnaire :
    # les clés inconnues y sont ignorées comme au premier niveau, et chaque
    # valeur est ramenée au type de sa valeur par défaut.
    "incident_rules": dict(INCIDENT_RULES_DEFAULTS),
}
# Réglages qui sont des secrets : exclus de toute réponse HTTP et de tout journal.
SETTINGS_SECRETS = ("vizproof_token",)


def settings_public(cfg=None):
    """Réglages tels qu'ils sortent de l'API : aucun secret, juste un témoin.

    Même modèle que le jeton Telegram de `/api/mgmt/alerts` : un booléen
    « enregistré » et les 4 derniers caractères, jamais la valeur.
    """
    cfg = dict(cfg if cfg is not None else settings_cfg())
    for k in SETTINGS_SECRETS:
        val = str(cfg.pop(k, "") or "")
        cfg[k + "_set"] = bool(val)
        cfg[k + "_tail"] = val[-4:] if val else ""
    return cfg


def settings_cfg():
    """Réglages persistants, complétés par les valeurs par défaut."""
    raw = load_json(SETTINGS_PATH, {})
    # dict() seul serait une copie de SURFACE : le sous-dictionnaire
    # `incident_rules` et sa liste seraient partagés avec les valeurs par défaut.
    cfg = {k: (coerce_value(v, v) if isinstance(v, (dict, list)) else v)
           for k, v in SETTINGS_DEFAULTS.items()}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k in SETTINGS_DEFAULTS:
                cfg[k] = coerce_setting(k, v)
    return cfg


def coerce_value(ref, value):
    """Normalise une valeur selon le TYPE de la valeur de référence.

    Récursive : un réglage peut être un sous-dictionnaire de seuils
    (`incident_rules`) ou une liste homogène (`php_eol_versions`). La référence
    fait foi de bout en bout — une clé absente de la référence est ignorée, une
    valeur d'un autre type est ramenée au type attendu, une liste est bornée.
    `bool` est testé avant `int` : en Python, True EST un int.
    """
    if isinstance(ref, bool):
        return bool(value)
    if isinstance(ref, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return ref
    if isinstance(ref, float):
        try:
            return float(value)
        except (TypeError, ValueError):
            return ref
    if isinstance(ref, str):
        return str("" if value is None else value).strip()
    if isinstance(ref, dict):
        # Copie PROFONDE de la référence : rendre le sous-dictionnaire de
        # SETTINGS_DEFAULTS tel quel exposerait les valeurs par défaut à la
        # mutation d'un appelant, pour tout le processus.
        out = {k: (coerce_value(v, v) if isinstance(v, (dict, list)) else v)
               for k, v in ref.items()}
        if isinstance(value, dict):
            for k, v in value.items():
                if k in ref:
                    out[k] = coerce_value(ref[k], v)
        return out
    if isinstance(ref, list):
        if not isinstance(value, (list, tuple)):
            return list(ref)
        modele = ref[0] if ref else ""
        # borne dure : un réglage de liste est une poignée de valeurs, pas un
        # dépôt de données que l'API réécrirait à chaque enregistrement.
        return [coerce_value(modele, v) for v in list(value)[:100]]
    return value


def coerce_setting(key, value):
    """Normalise un réglage selon le type de sa valeur par défaut."""
    return coerce_value(SETTINGS_DEFAULTS.get(key), value)


def settings_write(patch):
    """Applique un lot de réglages (clés inconnues ignorées) → configuration écrite."""
    def _muter(cur):
        base = cur if isinstance(cur, dict) else {}
        out = {k: v for k, v in base.items() if k in SETTINGS_DEFAULTS}
        for k, v in (patch or {}).items():
            if k in SETTINGS_DEFAULTS:
                out[k] = coerce_setting(k, v)
        return out

    update_json(SETTINGS_PATH, _muter, {})
    return settings_cfg()


def viz_token_stored():
    """Jeton de compte VizProof enregistré dans les Réglages (« » s'il n'y en a pas)."""
    return str(settings_cfg().get("vizproof_token") or "")


def viz_api_base(override=None):
    """Base de l'API VizProof : surcharge ponctuelle, réglage, puis défaut."""
    base = str(override or "").strip() or str(settings_cfg().get("vizproof_api_base") or "").strip()
    return (base or VIZ_API_BASE_DEFAULT).rstrip("/")


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


def safe_step(label, ok, detail="", warn=False):
    """Étape du journal de la MAJ sûre. `warn` = ni vert ni rouge : constat sans
    conséquence (anomalie visuelle qu'on a choisi de ne pas annuler)."""
    SAFE["steps"].append({"label": label, "ok": ok, "warn": bool(warn),
                          "detail": str(detail or "")[:600],
                          "ts": datetime.datetime.now().strftime("%H:%M:%S")})


def viz_json_tail(out):
    """Dernier objet JSON d'une sortie wp-cli (None si aucun ne se lit).

    Lu par la FIN : wp-cli fait précéder son JSON d'éventuels avertissements
    PHP, jamais l'inverse.
    """
    for ligne in reversed(str(out or "").splitlines()):
        if ligne.lstrip()[:1] != "{":
            continue
        try:
            d = json.loads(ligne.strip())
        except ValueError:
            continue
        return d if isinstance(d, dict) else None
    return None


def viz_http_url(u):
    """URL http(s) ou None — tout le reste (javascript:, chemin relatif) est rejeté."""
    s = str(u or "")
    return s if s.startswith("http://") or s.startswith("https://") else None


def viz_report_url(out):
    """URL de rapport (`report_url`) contenue dans le JSON d'un scan, si elle est http(s)."""
    return viz_http_url((viz_json_tail(out) or {}).get("report_url"))


def viz_anomalies_count(src):
    """Nombre d'anomalies d'un run ou d'un JSON de scan (0 si absent/illisible)."""
    try:
        n = int((src or {}).get("anomalies") or 0)
    except (TypeError, ValueError):
        return 0
    return max(n, 0)


def viz_decide(rc, rollback):
    """Suite à donner à un scan visuel de MAJ sûre → (bloquant, libellé, anomalie).

    `bloquant` True = le scan compte comme un échec de santé, donc retour
    arrière. Une anomalie visuelle (rc 2) n'est bloquante que si le réglage
    `viz_anomaly_rollback` le demande ; toute AUTRE sortie non nulle est un
    échec technique du scan, et reste bloquante quel que soit le réglage.
    """
    if rc == 0:
        return False, "aucune anomalie visuelle", False
    if rc == VIZ_ANOMALY_RC:
        if rollback:
            return True, "anomalies détectées — retour arrière déclenché (réglage)", True
        return False, "anomalies détectées — avertissement, mise à jour conservée (réglage)", True
    return True, "", False


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


# --------------------------------------------------------------------------- #
#  Contrôle visuel automatique après une mise à jour unitaire                  #
#                                                                             #
#  Le scan est le plus souvent celui du PLUGIN, qui s'accroche lui-même à la   #
#  fin d'une mise à jour (cf. viz_wait_plugin_run) ; le nôtre n'est qu'un       #
#  repli. Dans les deux cas la même règle vaut :                               #
#                                                                             #
#  Pourquoi en tâche de fond : attendre le run du plugin coûte jusqu'à 5 min,  #
#  et `wp vizproof scan --wait` photographie toutes les pages suivies — plus   #
#  d'une minute couramment, parfois plusieurs.                                 #
#  La route /api/actions/run tient la connexion HTTP pendant toute l'action,   #
#  et nginx la coupe à 340 s (proxy_read_timeout, deploy/nginx-dashboard.conf).#
#  Enchaîner MAJ *puis* scan dans la réponse ferait donc perdre, sur les gros  #
#  sites, non seulement le scan mais le RÉSULTAT DE LA MISE À JOUR déjà        #
#  appliquée — le pire des deux mondes. On répond donc dès la MAJ terminée, le #
#  contrôle part dans un thread, et son verdict se récupère sur                #
#  GET /api/actions/viz_last (journalisé par ailleurs sous `viz_verdict`, donc #
#  visible dans l'historique du site — y compris quand c'est le plugin qui a   #
#  scanné, auquel cas rien d'autre n'en garderait la trace).                   #
# --------------------------------------------------------------------------- #
VIZ_LAST = {}                 # domaine → dernier contrôle visuel automatique
VIZ_LAST_LOCK = threading.Lock()
VIZ_LAST_MAX = 60             # mémoire de processus, bornée : ce n'est pas un journal
#: squelette d'un bloc `viz` — TOUTES les clés du contrat y figurent, y compris
#: celles qui restent vides : l'UI lit `source`, `run_id`, `anomalies_count` et
#: `phase` sans avoir à tester leur présence.
VIZ_BASE = {"ran": False, "pending": False, "rc": None, "anomalies": False,
            "anomalies_count": 0, "report_url": None, "message": "", "reason": "",
            "source": None, "run_id": "", "phase": None,
            "server": "", "domain": "", "action": "", "ts": ""}
VIZ_AFTER_MSG = {
    "ok": "aucune anomalie visuelle",
    "anomalies": "anomalies visuelles détectées",
    "non configuré": "site non relié à VizProof",
    "échec": "le scan visuel a échoué",
}


def _spawn(fn, *args):
    """Lance `fn` en tâche de fond. Point d'injection unique pour les tests."""
    threading.Thread(target=fn, args=args, daemon=True).start()


def _now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def viz_last_set(domain, info):
    with VIZ_LAST_LOCK:
        VIZ_LAST[str(domain)] = dict(info)
        if len(VIZ_LAST) > VIZ_LAST_MAX:
            vieux = sorted(VIZ_LAST.items(), key=lambda kv: str(kv[1].get("ts") or ""))
            for k, _v in vieux[:len(VIZ_LAST) - VIZ_LAST_MAX]:
                VIZ_LAST.pop(k, None)


def viz_last_get(domain):
    with VIZ_LAST_LOCK:
        return dict(VIZ_LAST.get(str(domain)) or {})


def viz_site_linked(site):
    """Le site est-il relié à VizProof d'après l'inventaire ? None = on ne sait pas.

    `configured` n'existe qu'à partir du plugin 1.3.6 ; sur un inventaire plus
    ancien la connexion établie est la seule preuve disponible. Aucune fiche
    `vizproof` du tout = inventaire trop vieux, il faudra demander au site.
    """
    v = (site or {}).get("vizproof")
    if not isinstance(v, dict):
        return None
    if v.get("configured") is None and v.get("connected") is None:
        return None
    return bool(v.get("configured")) or bool(v.get("connected"))


def viz_linked_probe(srv, site):
    """Repli quand l'inventaire ne sait pas : `wp vizproof status --format=json`.

    Le plugin sort en rc 1 quand il répond mais n'est pas configuré : c'est la
    clé `configured` du JSON qui fait foi, pas le code de sortie (même lecture
    que le collecteur).
    """
    rc, out = remote_bash(srv, site, 'run vizproof status --format=json', timeout=90)
    for ligne in reversed(str(out or "").splitlines()):
        s = ligne.strip()
        if s[:1] != "{":
            continue
        try:
            d = json.loads(s)
        except ValueError:
            continue
        if isinstance(d, dict) and ("configured" in d or "connected" in d):
            return bool(d.get("configured")) or bool(d.get("connected"))
    return rc == 0


# --------------------------------------------------------------------------- #
#  Le scan que le PLUGIN lance tout seul après une mise à jour                 #
#                                                                             #
#  vizproof-timeline enregistre `upgrader_pre_install`/`upgrader_process_      #
#  complete` sans condition : ces hooks partent aussi sous WP-CLI. Quand       #
#  l'option de site `enable_update_scan_by_default` est vraie — son défaut —   #
#  un `wp plugin update` met donc DÉJÀ un scan en file côté vizproof.com.      #
#  Lancer le nôtre par-dessus, c'était payer deux fois la même photo de toutes #
#  les pages suivies. On attend désormais le run du plugin, et on ne scanne    #
#  nous-mêmes que si l'option est éteinte (ou illisible).                      #
# --------------------------------------------------------------------------- #
def viz_status_json(srv, site):
    """`wp vizproof status --format=json` côté site → dict (None si illisible).

    Plugins CHARGÉS (helper `run`, pas de `--skip-plugins`) : la commande vient
    justement du plugin.
    """
    _rc, out = remote_bash(srv, site, 'run vizproof status --format=json', timeout=90)
    return viz_json_tail(out)


def viz_run_of(status):
    """Bloc `last_run` d'un statut vizproof (dict vide s'il n'y en a pas)."""
    r = (status or {}).get("last_run")
    return r if isinstance(r, dict) else {}


def viz_prev_run_id(site):
    """`vizproof.last_run.id` de l'inventaire — « » quand il est inconnu.

    C'est le repère qui distingue le run déclenché par NOTRE mise à jour du
    dernier run déjà connu ; fleet.json n'étant réécrit qu'au re-scan, il porte
    encore l'état d'AVANT la mise à jour au moment où on le lit.
    """
    v = (site or {}).get("vizproof")
    r = v.get("last_run") if isinstance(v, dict) else None
    return str(r.get("id") or "") if isinstance(r, dict) else ""


def viz_run_epoch(at):
    """Date ISO d'un run (`2026-09-02T14:48:09+00:00`) → epoch UTC, None si illisible."""
    s = str(at or "").strip()
    if not s:
        return None
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:                      # date sans fuseau : lue en UTC
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.timestamp()


def viz_run_is_new(run, prev_id, t0):
    """Ce `last_run` est-il celui que notre mise à jour vient de déclencher ?

    Deux conditions, l'une sans l'autre ne prouvant rien : un identifiant
    DIFFÉRENT du dernier connu (un run rejoué garde le sien) ET une date au
    moins aussi récente que la mise à jour, à `VIZ_CLOCK_SKEW_S` près. Une date
    illisible ne suffit pas : sans repère d'identifiant fiable (sites jamais
    scannés, inventaire muet), on prendrait un vieux run pour un verdict.
    """
    rid = str((run or {}).get("id") or "").strip()
    if not rid or (prev_id and rid == str(prev_id)):
        return False
    at = viz_run_epoch((run or {}).get("at"))
    return at is not None and at >= (float(t0) - VIZ_CLOCK_SKEW_S)


def viz_run_done(run):
    """Le run est-il sorti de la file ? Un statut inconnu — ou absent sur une
    vieille version — compte pour terminé : rien ne sert d'attendre 5 minutes
    un état qu'on ne saura de toute façon pas lire."""
    return str((run or {}).get("status") or "").strip().lower() not in VIZ_RUN_PENDING


def viz_run_failed(run):
    return str((run or {}).get("status") or "").strip().lower() in VIZ_RUN_FAILED


def _viz_sleep(seconds):
    """Attente entre deux interrogations — point d'injection unique pour les tests."""
    time.sleep(seconds)


def _tours(total_s, poll_s):
    """Nombre d'interrogations tenant dans `total_s` à la cadence `poll_s`."""
    return max(1, (int(total_s) + poll_s - 1) // poll_s)


def viz_wait_plugin_run(srv, site, prev_id, t0, on_phase=None):
    """Attend le run lancé par le plugin → dict `last_run`, ou None.

    None = rien de neuf après `VIZ_WAIT_NEW_S` : le plugin n'a pas déclenché de
    scan (option éteinte, site sans page suivie…). Un run repéré est ensuite
    suivi jusqu'à son état final, `VIZ_WAIT_DONE_S` au total ; s'il est encore
    en file au bout de ce délai, il est rendu tel quel — le verdict sera
    « scan non terminé », pas un faux « aucune anomalie ».
    """
    poll = max(1, int(VIZ_POLL_S))
    n_attente, n_total = _tours(VIZ_WAIT_NEW_S, poll), _tours(VIZ_WAIT_DONE_S, poll)
    n_total = max(n_total, n_attente)
    vu = None
    if on_phase:
        on_phase(VIZ_PHASE_WAIT)
    for tour in range(n_total):
        if tour:
            _viz_sleep(poll)
        run = viz_run_of(viz_status_json(srv, site))
        if vu is None:
            if viz_run_is_new(run, prev_id, t0):
                vu = run
                if on_phase:
                    on_phase(VIZ_PHASE_RUNNING)
        elif str(run.get("id") or "") == str(vu.get("id") or ""):
            vu = run                       # même run : on rafraîchit son état
        if vu is not None:
            if viz_run_done(vu):
                return vu
        elif tour + 1 >= n_attente:
            return None
    return vu


def viz_truthy(v):
    """Vrai/faux tolérant : une option WordPress ressort en true, 1, "1" ou ""."""
    if isinstance(v, str):
        return v.strip().lower() not in ("", "0", "false", "no", "off", "null")
    return bool(v)


def viz_plugin_autoscan(srv, site):
    """L'option de site `enable_update_scan_by_default` est-elle active ?
    None = illisible (option absente, wp-cli en erreur, JSON inattendu) — et
    dans le doute on scanne nous-mêmes plutôt que de ne rien contrôler."""
    rc, out = remote_bash(srv, site,
                          'run option get ' + VIZ_OPTION_NAME + ' --format=json', timeout=90)
    d = viz_json_tail(out)
    if rc != 0 or not isinstance(d, dict) or VIZ_AUTOSCAN_KEY not in d:
        return None
    return viz_truthy(d.get(VIZ_AUTOSCAN_KEY))


def viz_verdict_from_run(run):
    """Verdict d'un run du plugin (déjà terminé, ou rendu tel quel à l'expiration)."""
    n = viz_anomalies_count(run)
    base = {"source": VIZ_SRC_PLUGIN, "run_id": str(run.get("id") or ""),
            "anomalies_count": n, "report_url": viz_http_url(run.get("url")),
            "phase": None, "ran": True}
    if not viz_run_done(run):
        # Encore en file au bout de 5 min : pas de verdict, et surtout pas un
        # « aucune anomalie » qui serait faux. rc None = rien à journaliser.
        return dict(base, rc=None, anomalies=False, status="en cours",
                    message="scan du plugin toujours en cours (verdict non parvenu)")
    if viz_run_failed(run):
        return dict(base, rc=VIZ_RUN_FAIL_RC, anomalies=False, status="échec",
                    message="le scan lancé par le plugin a échoué")
    return dict(base, rc=VIZ_ANOMALY_RC if n else 0, anomalies=n > 0,
                status="anomalies" if n else "ok",
                message=(VIZ_AFTER_MSG["anomalies"] + " (%d)" % n) if n
                        else VIZ_AFTER_MSG["ok"])


def viz_verdict_dashboard(server, domain):
    """Repli : c'est le dashboard qui lance le scan (`wp vizproof scan --wait`)."""
    rcv, out = logged_action(server, domain, "viz_scan", None, source=VIZ_AFTER_SOURCE)
    statut = viz_status(rcv, out)
    j = viz_json_tail(out) or {}
    res = {"source": VIZ_SRC_DASHBOARD, "rc": rcv, "status": statut, "phase": None,
           "anomalies": rcv == VIZ_ANOMALY_RC, "anomalies_count": viz_anomalies_count(j),
           "report_url": viz_report_url(out), "run_id": str(j.get("run_id") or j.get("id") or ""),
           "message": VIZ_AFTER_MSG.get(statut, statut)}
    # « non configuré » : la commande a bien tourné, mais le site n'est pas
    # relié — ce n'est pas un scan, on ne le présente pas comme tel.
    res["ran"] = statut != "non configuré"
    if not res["ran"]:
        res["reason"] = "non relié"
    return res


def viz_verdict_after_update(server, domain, srv, site, t0, prev_id, on_phase=None):
    """Verdict du contrôle visuel : celui du plugin s'il a scanné, sinon le nôtre."""
    run = viz_wait_plugin_run(srv, site, prev_id, t0, on_phase=on_phase)
    if run:
        return viz_verdict_from_run(run)
    if viz_plugin_autoscan(srv, site):
        # Le plugin DEVAIT scanner et n'a rien lancé : le site n'était pas
        # éligible (aucune page suivie, scan désactivé pour ce site…). Lancer
        # le nôtre maintenant ferait le doublon tardif qu'on cherche à éviter.
        return {"ran": False, "source": None, "rc": None, "anomalies": False,
                "anomalies_count": 0, "report_url": None, "run_id": "", "phase": None,
                "reason": "le plugin n'a lancé aucun scan",
                "message": "le plugin VizProof n'a lancé aucun scan après cette mise à jour"}
    if on_phase:
        on_phase(VIZ_PHASE_DASHBOARD)
    return viz_verdict_dashboard(server, domain)


def viz_log_verdict(server, domain, res, duree=None):
    """Trace le VERDICT dans actions.log. Sans elle, un scan lancé par le plugin
    ne laisserait AUCUNE trace dans l'historique du site : il ne passe pas par
    `logged_action`, puisqu'il ne passe pas par nous."""
    resume = "%s · %s" % (res.get("source") or "?", res.get("message") or "")
    if res.get("report_url"):
        resume += " · " + str(res["report_url"])
    append_log({"ts": _now_s(), "source": VIZ_AFTER_SOURCE, "server": server,
                "domain": domain, "action": "viz_verdict", "arg": res.get("run_id") or None,
                "rc": int(res.get("rc") or 0), "duration_s": round(float(duree or 0), 1),
                "output_tail": resume[-2000:]})


def viz_after_update(server, domain, action, rc, t0=None):
    """Bloc `viz` de la réponse de /api/actions/run — None si l'action n'est pas
    une mise à jour. Les refus « bon marché » (réglage, échec, site non relié
    d'après l'inventaire) répondent tout de suite ; le reste part en tâche de
    fond, y compris la détection de la CLI qui coûte un aller-retour ssh."""
    if action not in VIZ_AFTER_UPDATE_ACTIONS:
        return None
    base = dict(VIZ_BASE, server=server, domain=domain, action=action, ts=_now_s())
    if not settings_cfg().get("viz_scan_after_update"):
        return dict(base, reason="désactivé",
                    message="contrôle visuel désactivé dans les Réglages")
    if rc != 0:
        return dict(base, reason="mise à jour en échec",
                    message="mise à jour en échec : aucun contrôle visuel")
    srv, site = find_site(server, domain)
    if not srv or not site:
        return dict(base, reason="site introuvable", message="site absent de l'inventaire")
    if viz_site_linked(site) is False:
        return dict(base, reason="non relié", message="site non relié à VizProof")
    info = dict(base, ran=True, pending=True, phase=VIZ_PHASE_WAIT,
                message="contrôle visuel VizProof en cours…")
    viz_last_set(domain, info)
    # `t0` vient de l'APPELANT, pris avant la mise à jour : le run du plugin est
    # mis en file PENDANT celle-ci, donc avant que ce thread ne démarre.
    _spawn(viz_after_update_worker, server, domain, action,
           float(t0) if t0 is not None else time.time(), viz_prev_run_id(site))
    return dict(info)


def viz_verdict_publish(server, domain, action, res, duree=0):
    """Suites d'un verdict : journal `viz_verdict` et alerte sur anomalies.

    Commune au thread simple et au job `viz_update`, pour qu'un verdict soit
    tracé et alerté de la même façon quel que soit le chemin qui l'a produit.
    """
    if res.get("rc") is not None:
        viz_log_verdict(server, domain, res, duree)
    if res.get("anomalies"):
        libelle = ACTIONS.get(action, (action,))[0]
        if "{arg}" in libelle:
            libelle = action
        alert(f"viz_anomaly:{domain}", "viz_anomaly",
              f"👁 <b>Anomalies visuelles</b> après « {esc_html(libelle)} »"
              f"\nSite : <b>{esc_html(domain)}</b> ({esc_html(server)})"
              + (f"\n{esc_html(res['report_url'])}" if res.get("report_url") else ""))


def viz_after_update_worker(server, domain, action, t0=None, prev_id=""):
    """Contrôle visuel de fin de mise à jour : attendu, journalisé, alerté, mémorisé."""
    debut = time.time()
    t0 = float(t0) if t0 is not None else debut
    res = dict(VIZ_BASE, server=server, domain=domain, action=action, ts=_now_s())

    def phase(p):
        """Publie l'étape en cours pour /api/actions/viz_last (progression de l'UI)."""
        viz_last_set(domain, dict(res, ran=True, pending=True, phase=p,
                                  message="contrôle visuel VizProof : " + p,
                                  ts=_now_s()))

    try:
        srv, site = find_site(server, domain)
        if not srv or not site:
            res.update(reason="site introuvable", message="site absent de l'inventaire")
        elif not viz_available(srv, site):
            res.update(reason="CLI absente",
                       message="la commande wp vizproof n'existe pas sur ce site")
        elif viz_site_linked(site) is None and not viz_linked_probe(srv, site):
            res.update(reason="non relié", message="site non relié à VizProof")
        else:
            res.update(viz_verdict_after_update(server, domain, srv, site, t0,
                                                prev_id or viz_prev_run_id(site),
                                                on_phase=phase))
            res["phase"] = None
            viz_verdict_publish(server, domain, action, res, time.time() - debut)
            # L'inventaire porte `vizproof.last_run` : sans re-scan, le tiroir
            # continuerait d'afficher le scan précédent.
            logged_action(server, domain, "rescan", None, source=VIZ_AFTER_SOURCE)
    except Exception as e:                        # un thread muet ne doit rien avaler
        res.update(reason="erreur", message=f"erreur interne : {type(e).__name__}: {e}")
    res["ts"] = _now_s()
    viz_last_set(domain, res)
    return res


# --------------------------------------------------------------------------- #
#  Job « mise à jour sous contrôle visuel » : baseline → MAJ → verdict         #
#                                                                             #
#  Le contrôle d'APRÈS compare le rendu à la dernière baseline connue de       #
#  VizProof — qui peut dater de la veille et mêler d'autres changements. Pour  #
#  que le verdict porte sur LA mise à jour, il faut une baseline prise juste   #
#  avant, comme le fait la MAJ sûre. Or baseline + MAJ + attente du verdict    #
#  dépassent largement les 340 s que nginx laisse à /api/actions/run : quand   #
#  le site est relié, la route ne fait donc plus la mise à jour elle-même, elle #
#  DÉMARRE UN JOB et répond aussitôt. L'UI suit sur                            #
#  GET /api/actions/viz_update_status?domain=.                                 #
#                                                                             #
#  Un seul job par site, et jamais en même temps qu'une MAJ sûre sur ce site : #
#  les deux archivent, mettent à jour et scannent le même WordPress.           #
# --------------------------------------------------------------------------- #
VIZUP_LABELS = {"baseline": "Baseline VizProof", "update": "Mise à jour",
                "viz": "Contrôle visuel", "rescan": "Inventaire à jour"}
VIZUP_ORDER = ("baseline", "update", "viz", "rescan")
VIZUP_WAIT, VIZUP_RUN = "attente", "en cours"
VIZUP_OK, VIZUP_WARN, VIZUP_ERR = "ok", "warn", "erreur"
VIZUP = {}                    # domaine → job (mémoire de processus, bornée)
VIZUP_LOCK = threading.Lock()
VIZUP_MAX = 20
VIZ_PRE_SOURCE = "pre-update"  # source journalisée de la baseline d'avant MAJ


def vizup_empty(domain=""):
    """Job « aucun » — même forme que les autres, pour que l'UI n'ait rien à tester."""
    return {"running": False, "domain": str(domain), "server": "", "action": "",
            "arg": None, "steps": [], "result": None, "started": None, "finished": None}


def vizup_copy(job):
    """Copie profonde suffisante : le job continue d'évoluer pendant la réponse."""
    if not job:
        return None
    r = job.get("result")
    return dict(job, steps=[dict(s) for s in job.get("steps") or []],
                result=(dict(r, viz=dict(r["viz"]) if isinstance(r.get("viz"), dict) else r.get("viz"))
                        if isinstance(r, dict) else None))


def vizup_get(domain):
    with VIZUP_LOCK:
        return vizup_copy(VIZUP.get(str(domain)))


def vizup_running(domain):
    with VIZUP_LOCK:
        j = VIZUP.get(str(domain))
        return bool(j and j.get("running"))


def vizup_any_running():
    """Domaine d'un job en cours, « » s'il n'y en a aucun (garde de la MAJ sûre)."""
    with VIZUP_LOCK:
        for dom, j in VIZUP.items():
            if j.get("running"):
                return dom
    return ""


def vizup_step(domain, key, statut, detail=""):
    """Fait avancer une étape du job. Sans effet si le job a disparu."""
    with VIZUP_LOCK:
        j = VIZUP.get(str(domain))
        for s in (j or {}).get("steps") or []:
            if s["key"] == key:
                s.update(status=statut, detail=str(detail or "")[:600],
                         ts=datetime.datetime.now().strftime("%H:%M:%S"))
                return


def vizup_has(domain, key):
    with VIZUP_LOCK:
        j = VIZUP.get(str(domain))
        return any(s["key"] == key for s in (j or {}).get("steps") or [])


def vizup_finish(domain, result):
    with VIZUP_LOCK:
        j = VIZUP.get(str(domain))
        if j:
            j.update(running=False, finished=_now_s(), result=result)


def viz_update_eligible(site):
    """Site à passer par le job : l'inventaire dit la CLI présente ET le site
    configuré côté VizProof. Volontairement plus strict que `viz_site_linked` —
    on ne démarre pas un job de plusieurs minutes sur un « peut-être »."""
    v = (site or {}).get("vizproof")
    return bool(isinstance(v, dict) and v.get("has_cli") and v.get("configured"))


def viz_update_wanted(action):
    """Cette action mérite-t-elle le job ? (action de MAJ + au moins un contrôle)"""
    if action not in VIZ_AFTER_UPDATE_ACTIONS:
        return False
    cfg = settings_cfg()
    return bool(cfg.get("viz_baseline_before_update") or cfg.get("viz_scan_after_update"))


def vizup_start(server, domain, action, arg):
    """Réserve et lance le job → (job, erreur).

    La réservation se fait sous SAFE_LOCK, le même verrou que la MAJ sûre :
    c'est ce qui garantit qu'un site n'est jamais mis à jour deux fois de front.
    """
    cfg = settings_cfg()
    etapes = [k for k in VIZUP_ORDER
              if (k != "baseline" or cfg.get("viz_baseline_before_update"))
              and (k != "viz" or cfg.get("viz_scan_after_update"))]
    with SAFE_LOCK:
        if SAFE.get("running") and SAFE.get("domain") == domain:
            return None, f"une mise à jour sûre est déjà en cours sur {domain}"
        if vizup_running(domain):
            return None, f"une mise à jour sous contrôle visuel est déjà en cours sur {domain}"
        job = {"running": True, "domain": domain, "server": server, "action": action,
               "arg": arg, "started": _now_s(), "finished": None, "result": None,
               "steps": [{"key": k, "label": VIZUP_LABELS[k], "status": VIZUP_WAIT,
                          "detail": "", "ts": ""} for k in etapes]}
        with VIZUP_LOCK:
            VIZUP[str(domain)] = job
            if len(VIZUP) > VIZUP_MAX:      # bornée : ce n'est pas un journal
                vieux = sorted(((d, j) for d, j in VIZUP.items() if not j.get("running")),
                               key=lambda kv: str(kv[1].get("started") or ""))
                for d, _j in vieux[:len(VIZUP) - VIZUP_MAX]:
                    VIZUP.pop(d, None)
        instantane = vizup_copy(job)
    _spawn(vizup_run, server, domain, action, arg)
    return instantane, None


def vizup_run(server, domain, action, arg):
    """Le job lui-même : baseline → mise à jour → verdict visuel → re-scan."""
    debut = time.time()
    resultat = {"rc": None, "output": "", "viz": None}
    try:
        srv, site = find_site(server, domain)
        if not srv or not site:
            vizup_step(domain, "update", VIZUP_ERR, "site absent de l'inventaire")
            resultat.update(rc=92, output="site inconnu")
            return resultat

        # (a) baseline — le témoin d'AVANT, sans lequel le verdict d'après ne
        #     porterait pas sur cette mise à jour.
        if vizup_has(domain, "baseline"):
            vizup_step(domain, "baseline", VIZUP_RUN)
            rcb, outb = logged_action(server, domain, "viz_baseline", None,
                                      source=VIZ_PRE_SOURCE)
            if rcb == 0:
                vizup_step(domain, "baseline", VIZUP_OK, "baseline capturée")
            elif settings_cfg().get("viz_baseline_required"):
                vizup_step(domain, "baseline", VIZUP_ERR,
                           "baseline exigée par les Réglages : " + str(outb or "")[-300:])
                vizup_step(domain, "update", VIZUP_ERR,
                           "non lancée : la baseline VizProof a échoué")
                resultat.update(rc=rcb, output=outb)
                return resultat
            else:
                # VizProof est un filet, pas une condition : une baseline ratée
                # avertit, elle ne prend pas la mise à jour en otage.
                vizup_step(domain, "baseline", VIZUP_WARN,
                           "sans baseline, le contrôle d'après compare au dernier "
                           "état connu : " + str(outb or "")[-300:])

        # (b) la mise à jour, exactement celle qu'aurait faite la route
        vizup_step(domain, "update", VIZUP_RUN)
        t0 = time.time()
        rc, out = logged_action(server, domain, action, arg, source="manuel")
        resultat.update(rc=rc, output=out)
        vizup_step(domain, "update", VIZUP_OK if rc == 0 else VIZUP_ERR,
                   str(out or "")[-300:])

        # (c) le verdict visuel : celui du plugin s'il scanne, le nôtre sinon
        if rc == 0 and vizup_has(domain, "viz"):
            res = dict(VIZ_BASE, server=server, domain=domain, action=action,
                       ran=True, pending=True, phase=VIZ_PHASE_WAIT, ts=_now_s())
            viz_last_set(domain, res)

            def phase(p):
                vizup_step(domain, "viz", VIZUP_RUN, p)
                viz_last_set(domain, dict(res, phase=p, ts=_now_s(),
                                          message="contrôle visuel VizProof : " + p))

            vizup_step(domain, "viz", VIZUP_RUN, VIZ_PHASE_WAIT)
            t1 = time.time()
            res.update(viz_verdict_after_update(server, domain, srv, site, t0,
                                                viz_prev_run_id(site), on_phase=phase),
                       pending=False, phase=None, ts=_now_s())
            viz_last_set(domain, res)
            viz_verdict_publish(server, domain, action, res, time.time() - t1)
            resultat["viz"] = dict(res)
            vizup_step(domain, "viz", vizup_viz_status(res), res.get("message") or "")
        elif vizup_has(domain, "viz"):
            vizup_step(domain, "viz", VIZUP_WARN, "mise à jour en échec : aucun contrôle")

        # (d) inventaire : sans re-scan, le tiroir montrerait le scan précédent
        vizup_step(domain, "rescan", VIZUP_RUN)
        rcr, outr = logged_action(server, domain, "rescan", None, source=VIZ_AFTER_SOURCE)
        vizup_step(domain, "rescan", VIZUP_OK if rcr == 0 else VIZUP_WARN,
                   "" if rcr == 0 else str(outr or "")[-300:])
        return resultat
    except Exception as e:                    # un thread muet ne doit rien avaler
        vizup_step(domain, "update", VIZUP_ERR, f"erreur interne : {type(e).__name__}: {e}")
        if resultat.get("rc") is None:
            resultat["rc"] = 94
        resultat["output"] = f"erreur interne : {type(e).__name__}: {e}"
        return resultat
    finally:
        resultat["duration_s"] = round(time.time() - debut, 1)
        vizup_finish(domain, resultat)


def vizup_viz_status(res):
    """Verdict visuel → statut d'étape. Une anomalie n'est pas une erreur du
    job : la mise à jour est passée, c'est le rendu qui a changé."""
    if not res.get("ran"):
        return VIZUP_WARN
    if res.get("anomalies") or res.get("rc") is None:
        return VIZUP_WARN
    return VIZUP_OK if res.get("rc") == 0 else VIZUP_ERR


# --------------------------------------------------------------------------- #
#  Connexion d'un site à VizProof                                             #
#                                                                             #
#  Le jeton de compte part sur l'ENTRÉE STANDARD de la commande distante       #
#  (`--token-stdin`). Jamais en argument : sur un serveur mutualisé, la ligne   #
#  de commande d'un processus est lisible par tous les comptes (`ps aux`), et   #
#  elle finirait en clair dans actions.log et dans la réponse HTTP. Il n'est    #
#  pas non plus enregistré côté dashboard : il ne sert qu'à cet appel.          #
# --------------------------------------------------------------------------- #
def viz_connect_script(site_id, api_base=None, scope=None, token=None, code=None):
    """Corps bash de la connexion → (body, marqueur du document ici ou None).

    `run` du template ne convient pas : il faut rediriger l'entrée standard de
    la commande, ce que `run` ne permet pas. On appelle donc `asuser` en direct.
    """
    args = ["vizproof", "connect", "--site-id=" + sq(site_id), "--format=json"]
    if api_base:
        args.append("--api-base=" + sq(api_base))
    if scope:
        args.append("--scope=" + sq(scope))
    if code:
        args.append("--code=" + sq(code))
    marker = None
    if token:
        args.append("--token-stdin")
        marker = "VIZTOK_" + secrets.token_hex(8)
    cmd = " ".join(args)
    body = f'out=$(asuser "$base wp {cmd} $extra --no-color"'
    if marker:
        # Document ici : le contenu est lu dans le script lui-même (que ssh
        # transmet à `bash -s`), pas dans un fichier — rien n'est écrit sur le
        # disque du serveur du site.
        body += f" <<'{marker}'\n{token}\n{marker}\n)"
    else:
        body += ")"
    body += '\nrc=$?\nprintf "%s\\n" "$out"\nexit $rc\n'
    return body, marker


def viz_connect_run(server_name, domain, site_id, api_base=None, scope=None,
                    token=None, code=None, source="ui", site_created=False):
    """Exécute `wp vizproof connect` sur un site → (rc, sortie MASQUÉE).

    Journalise l'action `viz_connect` avec la même sortie masquée : ni le
    jeton ni le code de connexion ne doivent apparaître dans actions.log.
    `arg` porte l'identifiant du site VizProof (jamais le jeton) et
    `site_created` dit si ce site vient d'être créé par la résolution d'URL.
    """
    t0 = time.time()
    secret = str(token or code or "")

    def fin(rc, out):
        out = mask_secret(str(out or ""), secret)
        append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": source, "server": server_name, "domain": domain,
                    "action": "viz_connect", "arg": site_id, "rc": rc,
                    "site_created": bool(site_created),
                    "duration_s": round(time.time() - t0, 1),
                    "output_tail": out[-2000:]})
        return rc, out

    srv, site = find_site(server_name, domain)
    if not srv or not site:
        if rest_target(server_name, domain):
            return fin(REST_UNSUPPORTED_RC, REST_UNSUPPORTED_MSG)
        return fin(92, "site inconnu")
    body, marker = viz_connect_script(site_id, api_base, scope, token, code)
    if marker and re.search(rf"^{marker}$", str(token), re.M):
        return fin(96, "marqueur de transfert en collision avec le jeton")
    try:
        rc, out = remote_bash(srv, site, body, timeout=180)
    except subprocess.TimeoutExpired:
        return fin(93, "timeout")
    except Exception as e:
        return fin(94, f"erreur interne: {e}")
    # « 'connect' is not a registered subcommand » : le site tourne sur un
    # plugin d'avant 1.3.6. C'est un diagnostic, pas une panne — même
    # convention que AGENT_OLD_RC pour l'agent.
    if rc != 0 and VIZ_OLD_RE.search(out or ""):
        return fin(VIZ_OLD_RC, VIZ_OLD_MSG)
    return fin(rc, out)


# --------------------------------------------------------------------------- #
#  Pages surveillées par VizProof                                             #
#                                                                             #
#  Lecture et écriture de la liste des pages qu'un site relié fait scanner.    #
#  Deux chemins, selon la version du plugin installée :                        #
#                                                                             #
#  1.3.8+ : `wp vizproof pages [set]` fait tout, et VALIDE (page publiée,      #
#           limite, portée). Le contrat de sortie est le même en lecture et    #
#           en écriture :                                                      #
#             {scope, selected:[ids], critical:[ids],                          #
#              pages:[{id,title,url,type,selected,critical}], message}         #
#           `type` ∈ page | front | home. L'entrée `{id:0, type:"home"}` est   #
#           INFORMATIVE : l'accueil « flux d'articles » n'a pas d'identifiant  #
#           de page, `set --ids=0` est refusé, et la seule façon de le          #
#           surveiller est la portée « site ». Quand l'accueil est une page    #
#           statique, il apparaît avec `type:"front"` et son vrai identifiant. #
#                                                                             #
#  1.3.7  : la sous-commande n'existe pas (« 'pages' is not a registered       #
#           subcommand »). Repli sur `wp post list` + `wp option`. LIMITES,    #
#           assumées et dites à l'utilisateur : aucune validation par le       #
#           plugin (une page dépubliée depuis la lecture passera quand même),  #
#           pas de notion de page critique, et l'accueil « flux d'articles »   #
#           n'est pas distingué autrement que par `page_on_front = 0`.         #
#                                                                             #
#           Le repli écrit `selected_wordpress_page_ids` — des identifiants    #
#           de POSTS WordPress (entiers) — et surtout PAS                      #
#           `selected_page_ids`, qui contient des identifiants de pages        #
#           VizProof (chaînes) et ne sert qu'à l'écran réseau multisite : y    #
#           mettre des identifiants WordPress casse les captures (404 sur      #
#           /api/pages/{id}/capture). Sous WP-CLI le sanitizer de l'option ne  #
#           tourne pas : on écrit donc un tableau JSON d'entiers propres, et   #
#           rien d'autre dans l'option (`option patch update` ne touche que    #
#           la clé nommée).                                                    #
# --------------------------------------------------------------------------- #
VIZ_PAGES_MAX = 20          # le plugin tronque à 20 (`array_slice($ids, 0, 20)`)
VIZ_PAGES_TIMEOUT = 120
VIZ_PAGES_OPTION = "vizproof_timeline_options"
VIZ_PAGES_KEY = "selected_wordpress_page_ids"
VIZ_PAGES_SEP_OPT = "---VIZ-OPTIONS---"
VIZ_PAGES_SEP_FRONT = "---VIZ-FRONT---"
VIZ_PAGES_137_MSG = ("plugin VizProof 1.3.7 : liste et enregistrement en mode compatible "
                     "(sans validation par l'extension)")


def viz_json_array(out):
    """Dernier tableau JSON d'une sortie wp-cli, ou None.

    Lu par la FIN, comme `viz_json_tail` : wp-cli fait précéder son JSON
    d'éventuels avertissements PHP, jamais l'inverse.
    """
    for ligne in reversed(str(out or "").splitlines()):
        if ligne.lstrip()[:1] != "[":
            continue
        try:
            d = json.loads(ligne.strip())
        except ValueError:
            continue
        if isinstance(d, list):
            return d
    return None


def viz_pages_ids(valeurs):
    """Liste d'entiers positifs, dédoublonnée, dans l'ordre reçu."""
    out = []
    for v in valeurs or []:
        try:
            n = int(v)
        except (TypeError, ValueError):
            continue
        if n >= 0 and n not in out:
            out.append(n)
    return out


def viz_pages_payload(j, source):
    """Normalise la réponse du plugin — toutes les clés du contrat, toujours."""
    pages = []
    for p in (j.get("pages") or []):
        if not isinstance(p, dict):
            continue
        try:
            pid = int(p.get("id") or 0)
        except (TypeError, ValueError):
            continue
        typ = str(p.get("type") or "page")
        pages.append({"id": pid, "title": str(p.get("title") or ""),
                      "url": viz_http_url(p.get("url")) or "",
                      "type": typ if typ in ("page", "front", "home") else "page",
                      "selected": bool(p.get("selected")), "critical": bool(p.get("critical"))})
    scope = str(j.get("scope") or "site")
    return {"ok": True, "source": source, "limit": VIZ_PAGES_MAX,
            "scope": scope if scope in VIZ_SCOPES else "site",
            "selected": viz_pages_ids(j.get("selected")),
            "critical": viz_pages_ids(j.get("critical")),
            "pages": pages, "message": str(j.get("message") or "")}


def viz_pages_cible(server_name, domain):
    """(srv, site) ou (None, réponse d'erreur) — REST compris."""
    srv, site = find_site(server_name, domain)
    if srv and site:
        return srv, site
    if rest_target(server_name, domain):
        return None, (REST_UNSUPPORTED_RC, {"ok": False, "error": REST_UNSUPPORTED_MSG})
    return None, (92, {"ok": False, "error": "site inconnu"})


def viz_pages_read(server_name, domain):
    """→ (rc, payload). rc 0 = lu ; 97 = site sans SSH ; autre = échec."""
    srv, site = viz_pages_cible(server_name, domain)
    if not srv:
        return site
    rc, out = remote_bash(srv, site, "run vizproof pages --format=json",
                          timeout=VIZ_PAGES_TIMEOUT)
    if rc == 0:
        j = viz_json_tail(out)
        if isinstance(j, dict) and isinstance(j.get("pages"), list):
            return 0, viz_pages_payload(j, "plugin")
        return 95, {"ok": False, "error": "réponse illisible de « wp vizproof pages »",
                    "output": str(out or "")[-800:]}
    if VIZ_OLD_RE.search(out or ""):
        return viz_pages_read_137(srv, site)
    return rc, {"ok": False, "error": str(out or "")[-800:]}


def viz_pages_read_137(srv, site):
    """Repli de lecture pour la 1.3.7 : `post list` + les deux options utiles."""
    body = (
        "run post list --post_type=page --post_status=publish"
        " --fields=ID,post_title,url --format=json || true\n"
        f"echo '{VIZ_PAGES_SEP_OPT}'\n"
        f"run option get {VIZ_PAGES_OPTION} --format=json || true\n"
        f"echo '{VIZ_PAGES_SEP_FRONT}'\n"
        "run option get page_on_front || true\n"
        "exit 0\n"
    )
    rc, out = remote_bash(srv, site, body, timeout=VIZ_PAGES_TIMEOUT)
    if rc != 0:
        return rc, {"ok": False, "error": str(out or "")[-800:]}
    txt = str(out or "")
    bloc_pages, _, reste = txt.partition(VIZ_PAGES_SEP_OPT)
    bloc_opt, _, bloc_front = reste.partition(VIZ_PAGES_SEP_FRONT)
    liste = viz_json_array(bloc_pages)
    if liste is None:
        return 95, {"ok": False, "error": "liste des pages illisible (repli 1.3.7)",
                    "output": txt[-800:]}
    opt = viz_json_tail(bloc_opt) or {}
    front = 0
    for ligne in reversed(bloc_front.splitlines()):
        ligne = ligne.strip()
        if ligne.isdigit():
            front = int(ligne)
            break
    choisies = set(viz_pages_ids(opt.get(VIZ_PAGES_KEY)))
    critiques = set(viz_pages_ids(opt.get("critical_wordpress_page_ids")))
    scope = str(opt.get("scan_scope") or "site")
    pages = []
    for p in liste:
        if not isinstance(p, dict):
            continue
        try:
            pid = int(p.get("ID") or 0)
        except (TypeError, ValueError):
            continue
        pages.append({"id": pid, "title": str(p.get("post_title") or ""),
                      "url": p.get("url") or "", "type": "front" if pid == front else "page",
                      "selected": pid in choisies, "critical": pid in critiques})
    if not front:
        # Accueil « flux d'articles » : aucun identifiant de page ne le désigne.
        pages.insert(0, {"id": 0, "title": "Accueil (flux d’articles)",
                         "url": site_home_url(site), "type": "home",
                         "selected": scope == "site", "critical": False})
    pages.sort(key=lambda p: 0 if p["type"] in ("home", "front") else 1)
    return 0, viz_pages_payload(
        {"scope": scope, "selected": sorted(choisies), "critical": sorted(critiques),
         "pages": pages, "message": VIZ_PAGES_137_MSG}, "repli-1.3.7")


def viz_pages_write(server_name, domain, ids, scope, source="ui"):
    """Enregistre la sélection → (rc, payload). Journalise l'action `viz_pages`."""
    t0 = time.time()

    def fin(rc, payload):
        append_log({"ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": source, "server": server_name, "domain": domain,
                    "action": "viz_pages", "arg": f"{scope}:{','.join(str(i) for i in ids)}"[:200],
                    "rc": rc, "duration_s": round(time.time() - t0, 1),
                    "output_tail": json.dumps(payload, ensure_ascii=False)[-2000:]})
        return rc, payload

    srv, site = viz_pages_cible(server_name, domain)
    if not srv:
        return fin(site[0], site[1])
    args = ["vizproof", "pages", "set", "--scope=" + sq(scope), "--format=json"]
    if ids:
        args.insert(3, "--ids=" + sq(",".join(str(i) for i in ids)))
    rc, out = remote_bash(srv, site, "run " + " ".join(args), timeout=VIZ_PAGES_TIMEOUT)
    if rc == 0:
        j = viz_json_tail(out)
        if isinstance(j, dict) and isinstance(j.get("pages"), list):
            return fin(0, viz_pages_payload(j, "plugin"))
        return fin(0, {"ok": True, "source": "plugin", "limit": VIZ_PAGES_MAX,
                       "scope": scope, "selected": list(ids), "critical": [], "pages": [],
                       "message": str(out or "")[-300:]})
    if VIZ_OLD_RE.search(out or ""):
        return fin(*viz_pages_write_137(srv, site, ids, scope))
    return fin(rc, {"ok": False, "error": str(out or "")[-800:]})


def viz_pages_write_137(srv, site, ids, scope):
    """Repli d'écriture pour la 1.3.7 : deux `option patch update`, rien d'autre."""
    liste = json.dumps([int(i) for i in ids])
    body = (
        f"run option patch update {VIZ_PAGES_OPTION} {VIZ_PAGES_KEY} {sq(liste)}"
        " --format=json || exit $?\n"
        f"run option patch update {VIZ_PAGES_OPTION} scan_scope {sq(scope)} || exit $?\n"
    )
    rc, out = remote_bash(srv, site, body, timeout=VIZ_PAGES_TIMEOUT)
    if rc != 0:
        return rc, {"ok": False, "error": str(out or "")[-800:]}
    rc2, lu = viz_pages_read_137(srv, site)
    if rc2 == 0:
        lu["message"] = VIZ_PAGES_137_MSG
        return 0, lu
    return 0, {"ok": True, "source": "repli-1.3.7", "limit": VIZ_PAGES_MAX, "scope": scope,
               "selected": list(ids), "critical": [], "pages": [],
               "message": VIZ_PAGES_137_MSG}


def safe_update_run(server_name, domain, slugs=None, do_backup=True, use_viz=True,
                    with_core=False, dry_run=False, viz_rollback=None):
    """Orchestration complète.

    `slugs` None = toutes les extensions ayant une mise à jour en attente.
    `with_core` inclut le cœur WordPress : ses fichiers sont archivés et
    restaurables, MAIS les migrations de base de données déclenchées par
    `core update-db` ne sont PAS annulées par le retour arrière — c'est la
    sauvegarde UpdraftPlus qui sert de recours pour la base.
    `viz_rollback` None = on suit le réglage `viz_anomaly_rollback` ;
    True/False le surchargent pour cette exécution seulement.
    """
    if viz_rollback is None:
        viz_rollback = bool(settings_cfg().get("viz_anomaly_rollback"))
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
        # `core_before` = version installée AVANT l'opération, écrite au manifeste
        # pour que l'archive dise vers quoi on reviendrait. On la lit sur le site
        # (source de vérité) avec l'inventaire pour repli.
        core_before = str(site.get("core_version") or "") or None
        core_target = ""
        if with_core:
            rcv0, outv0 = remote_bash(srv, site,
                                      'asuser "$base wp core version '
                                      '--skip-plugins --skip-themes $extra --no-color"', timeout=90)
            vues = [l.strip() for l in (outv0 or "").splitlines()
                    if re.match(r"^\d+\.\d+(\.\d+)?$", l.strip())]
            if rcv0 == 0 and vues:
                core_before = vues[-1]
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
        if dry_run:
            # Garde-fou : une simulation s'arrête AVANT toute écriture. Sert aux
            # tests et à la prévisualisation depuis l'interface.
            safe_step("Simulation", True,
                      "aucune modification effectuée (sauvegarde, archivage et mise à jour non exécutés)")
            SAFE["verdict"] = "simulation"
            return
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
        manifest = json.dumps({"domain": domain, "ts": stamp,
                               "core_before": core_before if with_core else None,
                               "core_target": core_target if with_core else None,
                               "plugins": versions_avant}, ensure_ascii=False)
        body = f'''
set -o pipefail
PLUGDIR=$(asuser "$base wp plugin path $extra --no-color" 2>/dev/null | tail -1)
[ -d "$PLUGDIR" ] || PLUGDIR="$D/wp-content/plugins"
echo "PLUGDIR=$PLUGDIR"
# Liste passée en tableau : une mise à jour du seul cœur laisse `pending` vide,
# et « for s in ; do » serait une erreur de syntaxe bash (script entier perdu).
SLUGS=({lst})

# Purge des archives d'anciennes exécutions (retour arrière conservé 7 jours).
find {sq(SAFE_ROLLBACK_DIR)} -maxdepth 1 -type d -mtime +{SAFE_KEEP_DAYS} -exec rm -rf {{}} + 2>/dev/null

# Volume à archiver, puis contrôle d'espace : on refuse de commencer si /tmp
# ne peut pas absorber les archives avec une marge confortable.
besoin=0
for s in "${{SLUGS[@]}}"; do
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
for s in "${{SLUGS[@]}}"; do
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
        rollback_index_add(domain, arc, pending, versions_avant)
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

        viz_ok, viz_used, viz_anomaly = True, False, False
        if use_viz and viz_available(srv, site):
            viz_used = True
            rcv, outv = remote_bash(srv, site,
                                    'run vizproof scan --wait --format=json', timeout=600)
            bloquant, libelle, viz_anomaly = viz_decide(rcv, viz_rollback)
            viz_ok = not bloquant
            detail = libelle or (outv or "")[-300:]
            rapport = viz_report_url(outv)
            if rapport:
                detail += " · rapport : " + rapport
            # Une anomalie qu'on a choisi de ne pas annuler n'est ni « ok » ni
            # « échec » : elle réclame un œil, pas une alarme.
            safe_step("Contrôle visuel VizProof", viz_ok and not viz_anomaly, detail,
                      warn=viz_anomaly and viz_ok)
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
            # Verdict distinct : « réussi » doit rester le mot qui veut dire
            # « rien à regarder ». Une MAJ conservée malgré des anomalies
            # visuelles demande une vérification humaine.
            SAFE["verdict"] = ("réussie avec anomalies visuelles" if viz_anomaly
                               else "réussi")
            if viz_anomaly:
                alert(f"viz_anomaly:{domain}", "viz_anomaly",
                      f"⚠️ <b>{esc_html(domain)}</b> — mise à jour conservée, mais VizProof "
                      "signale des anomalies visuelles : à vérifier à l'œil.")
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


def rollback_index_add(domain, arc_dir, plugins, versions):
    """Enregistre un point de restauration dans l'index local."""
    def _muter(idx):
        if not isinstance(idx, dict):
            idx = {}
        entries = [e for e in (idx.get(domain) or []) if e.get("dir") != arc_dir]
        entries.insert(0, {"dir": arc_dir, "plugins": sorted(plugins),
                           "versions": versions or {},
                           "ts": datetime.datetime.now().strftime("%Y%m%d-%H%M%S")})
        idx[domain] = entries[:SAFE_KEEP_SETS]
        return idx

    update_json(ROLLBACK_INDEX_PATH, _muter, {})


def rollback_points(server_name, domain, verify=False):
    """Points de restauration d'un site → liste décroissante.

    Par défaut on lit l'index local (instantané). `verify=True` interroge le
    serveur en SSH pour refléter l'état réel du disque — utile si /tmp a été
    vidé entre-temps, mais trop lent pour l'ouverture d'un tiroir.
    """
    if not verify:
        idx = load_json(ROLLBACK_INDEX_PATH, {})
        entrees = idx.get(domain) or [] if isinstance(idx, dict) else []
        limite = (datetime.datetime.now()
                  - datetime.timedelta(days=SAFE_KEEP_DAYS)).strftime("%Y%m%d-%H%M%S")
        return [e for e in entrees if str(e.get("ts", "")) >= limite and e.get("plugins")]

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

    Renvoie TOUJOURS un dict {"current", "versions", "error"} : une extension
    premium (absente du dépôt public) donne une liste vide et un motif.
    """
    vide = {"current": None, "versions": [], "error": None}
    if not SLUG_RE.match(str(slug or "")):
        return dict(vide, error="extension invalide")
    url = f"https://api.wordpress.org/plugins/info/1.0/{urllib.parse.quote(str(slug))}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read(2 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception as e:
        return dict(vide, error=f"wordpress.org injoignable : {type(e).__name__}")
    if not isinstance(data, dict):
        return dict(vide, error="réponse inattendue de wordpress.org")
    if data.get("error"):
        return dict(vide, error=str(data.get("error"))[:200])
    brutes = [v for v in (data.get("versions") or {}) if v and v != "trunk"]
    # Tri décroissant à la sémantique PHP : on réutilise le comparateur déjà
    # validé contre version_compare() (1.10 > 1.9, et beta2 > beta1).
    brutes.sort(key=functools.cmp_to_key(version_compare), reverse=True)
    return {"current": data.get("version"), "versions": brutes[:limit], "error": None}


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
        # « .. » interdit : [A-Za-z0-9._-]+ l'accepterait et permettrait de
        # remonter hors du répertoire d'archives.
        if (".." in str(arc_dir)
                or not re.match(r"^/tmp/\.wpdash-rollback/[A-Za-z0-9._-]+$", str(arc_dir))):
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
# ---------- erreurs PHP (lecture des journaux serveur, aucun site modifié) ----------
PHPERR = {"running": False, "message": "", "finished": None}


def phperr_worker(hours=24):
    PHPERR.update({"running": True, "message": "analyse en cours…", "finished": None})
    try:
        r = subprocess.run([sys.executable, os.path.join(BASE, "phperrors.py"),
                            "--hours", str(int(hours))],
                           capture_output=True, text=True, timeout=900, cwd=BASE)
        out = (r.stdout or "").strip().splitlines()
        PHPERR["message"] = out[-1] if out else ((r.stderr or "").strip()[-200:] or "terminé")
    except subprocess.TimeoutExpired:
        PHPERR["message"] = "délai dépassé"
    except Exception as e:
        PHPERR["message"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        PHPERR["running"] = False
        PHPERR["finished"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


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
        # Liaison/déliaison de l'agent : dépôt (ou retrait) du fichier + appairage,
        # pas une commande wp-cli de la liste ACTIONS.
        if task["action"] in ("dash_connect", "dash_disconnect"):
            fn = dash_connect if task["action"] == "dash_connect" else dash_disconnect
            try:
                rc, out = fn(task["server"], task["domain"])  # secret déjà masqué en interne
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
    with JOB_LOCK:
        JOBS[jid] = job
        # purge des vieux jobs terminés
        for k in [k for k, v in JOBS.items() if not v["running"] and k < jid - 8]:
            JOBS.pop(k, None)
    threading.Thread(target=bulk_worker, args=(job,), daemon=True).start()
    return jid


def get_job(jid):
    """Job de la file d'attente, ou None."""
    try:
        jid = int(jid)
    except (TypeError, ValueError):
        return None
    with JOB_LOCK:
        return JOBS.get(jid)


# ---------- Kuma (manipulation directe SQLite + redémarrage) ----------
KUMA_UNAVAILABLE_RC = 95


def kuma_sql(sql):
    """Requête SQLite dans le conteneur Kuma → (rc, sortie).

    Docker absent, conteneur arrêté ou requête bloquée : erreur lisible plutôt
    qu'une exception qui remonterait en 500 dans toutes les routes Gestion.
    """
    try:
        r = subprocess.run(["docker", "exec", KUMA_CONTAINER, "sqlite3", "-cmd", ".timeout 8000",
                            KUMA_DB, sql],
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return KUMA_UNAVAILABLE_RC, "docker indisponible : délai dépassé"
    except (OSError, subprocess.SubprocessError) as e:
        return KUMA_UNAVAILABLE_RC, f"docker indisponible : {type(e).__name__}: {e}"[:300]
    return r.returncode, (r.stdout + r.stderr).strip()


def kuma_restart():
    try:
        subprocess.run(["docker", "restart", KUMA_CONTAINER], capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        pass  # sans docker il n'y a rien à redémarrer ; l'appelant a déjà l'erreur SQL


def kuma_text_ok(value, maxlen=200):
    """Libellé acceptable dans Kuma : borné et sans caractère de contrôle."""
    s = str(value or "")
    return len(s) <= maxlen and not re.search(r"[\x00-\x1f\x7f]", s)


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


# ---------- Kuma : dernier battement de chaque moniteur ----------
# Le statut « live » de l'interface vient de la status page publique (HTTP).
# La file d'incidents, elle, ne doit faire AUCUN appel réseau : elle lit le
# dernier battement directement dans la base, comme les autres lectures Kuma.
KUMA_HEARTBEAT_SQL = (
    "SELECT m.name||char(9)||h.status||char(9)||COALESCE(h.time,'')||char(9)||"
    "REPLACE(REPLACE(COALESCE(h.msg,''),char(9),' '),char(10),' ')||char(9)||COALESCE(m.active,1) "
    "FROM heartbeat h JOIN monitor m ON m.id=h.monitor_id "
    "WHERE h.id IN (SELECT MAX(id) FROM heartbeat GROUP BY monitor_id) "
    "AND m.type!='group';")   # les moniteurs en pause sont gardés : leur dernier état reste une information


def kuma_heartbeat_epoch(value):
    """Horodatage d'un battement Kuma → epoch.

    Kuma écrit la colonne `time` en UTC (« 2026-09-03 07:12:44.123 »). On la
    convertit explicitement : la lire comme une heure locale décalait l'âge des
    incidents de la valeur du fuseau.
    """
    s = str(value or "").strip().replace("T", " ")
    if not s:
        return None
    s = s.split("+")[0].split("Z")[0].split(".")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            d = datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
        return d.replace(tzinfo=datetime.timezone.utc).timestamp()
    return None


def kuma_heartbeats():
    """{nom du moniteur: {status, time, msg, ts}} — dernier battement connu.

    LÈVE si la base est hors d'atteinte (docker absent, conteneur arrêté) :
    l'appelant en fait une ligne `errors`, au lieu de conclure « rien n'est
    down » sur une lecture qui n'a pas eu lieu.
    """
    rc, out = kuma_sql(KUMA_HEARTBEAT_SQL)
    if rc != 0:
        raise RuntimeError((out or f"rc={rc}")[-200:])
    battements = {}
    for line in (out or "").splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        try:
            statut = int(p[1])
        except (TypeError, ValueError):
            continue
        actif = True
        if len(p) >= 5:
            actif = p[4].strip() not in ("0", "false", "")
        battements[p[0]] = {"status": statut, "time": p[2], "msg": p[3].strip(),
                            "ts": kuma_heartbeat_epoch(p[2]), "active": actif}
    return battements


def kuma_create(domain, monitor_name, group_id, url, mtype, keyword):
    name = monitor_name or domain
    esc = lambda s: str(s).replace('"', '""')
    gid = int(group_id)
    if not kuma_text_ok(name) or not kuma_text_ok(keyword) or not kuma_text_ok(url, 500):
        return 91, "libellé, mot-clé ou url invalide (trop long ou caractère de contrôle)"
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
    # SLUG vient de config.json : échappé comme toute autre valeur du SQL.
    kuma_sql('INSERT INTO monitor_group (monitor_id, group_id, weight) '
             'SELECT (SELECT MAX(id) FROM monitor), '
             '(SELECT id FROM `group` WHERE status_page_id='
             f'(SELECT id FROM status_page WHERE slug="{esc(SLUG)}")), '
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
        # api.telegram.org : la garde anti-SSRF n'a pas de sens ici, mais le
        # non-suivi des redirections et le bornage de lecture, si.
        _st, raw = _open_no_redirect(req, timeout=10, ssrf_guard=False)
        body = json.loads(raw.decode("utf-8", "replace") or "{}")
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
        derniers = read_jsonl_tail(os.path.join(DATA, "collect_history.jsonl"), 1)
        last = parse_ts(derniers[-1].get("ts")) if derniers else None
        age_h = (now - last) / 3600 if last else None
        if age_h is None or age_h > dead_h:
            detail = f"il y a {age_h:.0f} h" if age_h is not None else "aucun historique"
            sent += alert("collect_dead", "collect_dead_h",
                          "🕳 <b>Collecteur muet</b>"
                          f"\nDernière collecte : {esc_html(detail)} — seuil {dead_h:g} h")
    return {"enabled": True, "sent": sent}


# ---------------------------------------------------------------------------
#  Incidents : la file « à traiter » (§4 du plan de refonte)
# ---------------------------------------------------------------------------
# Un SEUL agrégat sert l'écran Incidents et les pastilles de la barre latérale :
# deux calculs séparés finiraient par ne plus dire la même chose, et c'est
# précisément ce que le plan demande d'éviter (« les pastilles de compteur
# correspondent aux règles de la file à traiter »).
#
# Contrat de la route : aucune sortie RÉSEAU ni SSH. On ne lit que des fichiers
# de data/ et la base SQLite de Kuma (docker exec local, comme /api/sec/certs).
# Chaque source est isolée : celle qui échoue laisse une ligne dans `errors`,
# les autres remontent quand même leurs incidents.
INCIDENT_FATAL_SEVERITIES = ("Fatal error", "Parse error")
INCIDENT_CACHE_TTL = 30          # secondes, pour /api/mgmt/counts


def incident_rules(cfg=None):
    """Seuils de la file d'incidents, complétés par les valeurs par défaut."""
    raw = (cfg if cfg is not None else settings_cfg()).get("incident_rules")
    rules = dict(INCIDENT_RULES_DEFAULTS)
    if isinstance(raw, dict):
        for k in rules:
            if k in raw:
                rules[k] = raw[k]
    return rules


def incident_json(path, default):
    """Lit un JSON de data/ pour la file d'incidents.

    Différence volontaire avec `load_json` : un fichier ILLISIBLE lève, au lieu
    de se confondre avec « rien à signaler ». Un fichier simplement absent
    (source jamais lancée) rend la valeur par défaut, ce n'est pas une erreur.
    """
    if not os.path.exists(path):
        return default
    with open(path) as fh:
        return json.load(fh)


def incident_iso(epoch):
    """Epoch → ISO 8601 local (secondes), ou None."""
    if epoch is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(float(epoch)).replace(microsecond=0).isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def make_incident(kind, severity, key, title, detail, site="", server="", arg="",
                  since=None, action=None, link=None, now=None):
    """Une entrée de la file. `id` = kind:cible:arg — stable d'un appel à l'autre.

    La « cible » est la clé du site (clé Kuma ou domaine) ou, pour les incidents
    qui portent sur un serveur (`server_stale`, `php_eol`), son nom : c'est ce
    qui rend l'identifiant unique, et c'est lui qui sert au dédoublonnage.
    """
    age = 0.0
    if since is not None:
        # Un `since` dans le futur (horloge distante en avance) donnerait un âge
        # négatif, donc un tri à l'envers : on plafonne à 0.
        age = max(0.0, ((time.time() if now is None else now) - float(since)) / 3600.0)
    return {"id": f"{kind}:{key}:{arg}", "severity": severity, "kind": kind,
            "site": site, "server": server or "", "title": title, "detail": detail,
            "since": incident_iso(since), "age_h": round(age, 2),
            "action": action, "link": link}


def incident_fleet():
    """fleet.json → (sites visibles, index par clé, serveurs).

    `sites` : [(nom du serveur, site)] · `index` : clé Kuma ou domaine →
    (nom du serveur, site). Un même domaine peut exister sur deux serveurs
    (copie legacy) : l'install rattaché à Kuma l'emporte, comme partout ailleurs.
    """
    fleet = incident_json(FLEET_PATH, {"servers": []})
    sites, index, servers = [], {}, []
    for srv in (fleet.get("servers") or []):
        if not isinstance(srv, dict):
            continue
        nom = srv.get("name") or ""
        servers.append(srv)
        for s in (srv.get("sites") or []):
            if not isinstance(s, dict) or not site_visible(s):
                continue
            sites.append((nom, s))
            for cle in (s.get("kuma"), s.get("domain")):
                if cle and (cle not in index or s.get("kuma")):
                    index[cle] = (nom, s)
    return sites, index, servers


def inc_down(sites, now):
    """Moniteur Kuma dont le dernier battement est en échec (status 0)."""
    battements = kuma_heartbeats()
    out = []
    for server, s in sites:
        nom = s.get("kuma")
        if not nom:
            continue                      # site non supervisé : rien à conclure
        hb = battements.get(nom)
        if not hb or hb.get("status") != 0:
            continue
        # Un moniteur mis en pause alors qu'il était down reste à voir (le
        # tableau de bord le compte « down ») mais n'est plus une urgence.
        actif = hb.get("active", True)
        out.append(make_incident(
            "down", "critical" if actif else "warning", nom,
            f"{nom} injoignable" if actif else f"{nom} : moniteur en pause, dernier état injoignable",
            (hb.get("msg") or "moniteur Kuma en échec, sans détail")
            + ("" if actif else " — réactiver le moniteur dans Gestion une fois le site réparé"),
            site=nom, server=server, since=hb.get("ts"), now=now,
            action={"label": "Re-scan", "act": "rescan", "arg": ""},
            link={"tab": "incidents", "sub": ""}))
    return out


def inc_php_fatal(index, now):
    """Erreurs PHP fatales de la fenêtre courante de php_errors.json."""
    res = incident_json(PHPERR_PATH, {})
    out = []
    for s in (res.get("sites") or []):
        dom = s.get("domain") or ""
        if dom not in index:
            continue                      # site masqué ou disparu du parc
        server, _site = index[dom]
        for g in (s.get("groups") or []):
            if g.get("severity") not in INCIDENT_FATAL_SEVERITIES:
                continue
            ou = str(g.get("short") or g.get("file") or "?")
            if g.get("line"):
                ou = f"{ou}:{g['line']}"
            try:
                n = int(g.get("count") or 1)
            except (TypeError, ValueError):
                n = 1
            out.append(make_incident(
                "php_fatal", "critical", dom,
                f"{g.get('severity') or 'Fatal error'} sur {dom}",
                f"{g.get('message') or 'erreur sans message'} — {ou} (×{n})",
                site=dom, server=server, arg=ou,
                since=parse_ts(g.get("first")), now=now,
                link={"tab": "securite", "sub": "phperrors"}))
    return out


def inc_vulns(index, rules, now):
    """Vulnérabilité grave AVEC correctif disponible : une entrée par (site, composant)."""
    res = incident_json(VULNS_FOUND_PATH, {})
    graves = {"critical"}
    if rules.get("vuln_high_is_incident"):
        graves.add("high")
    out, vus = [], set()
    for s in (res.get("sites") or []):
        cle = s.get("domain") or ""
        if cle not in index:
            continue
        server, site = index[cle]
        rest = site.get("via") == "rest"   # aucune action wp-cli possible
        for v in (s.get("findings") or []):
            if str(v.get("severity") or "").lower() not in graves:
                continue
            vers = str(v.get("update_to") or "").strip()
            if not vers:
                continue                  # pas de correctif : rien à proposer
            comp = str(v.get("component") or "?")
            if (cle, comp) in vus:
                continue
            vus.add((cle, comp))
            if v.get("kind") == "core":
                action = {"label": f"Mettre à jour WordPress → {vers}",
                          "act": "core_update", "arg": ""}
            else:
                action = {"label": f"MAJ {comp} → {vers}",
                          "act": "plugin_update", "arg": comp}
            titre = f"{comp} {v.get('version') or ''} · {v.get('severity')} corrigeable"
            detail = str(v.get("title") or "vulnérabilité")
            if v.get("cve"):
                detail += f" ({v['cve']})"
            out.append(make_incident(
                "vuln_critical_fixable", "critical", cle, " ".join(titre.split()),
                detail + f" — correctif en {vers}",
                site=cle, server=server, arg=comp, now=now,
                action=None if rest else action,
                link={"tab": "securite", "sub": "vulns"}))
    return out


def inc_checksums(index, now):
    """Dernier `verify_checksums` en échec : des fichiers du cœur ont été modifiés."""
    store = incident_json(CHECKSUMS_PATH, {})
    out = []
    for dom, rec in (store if isinstance(store, dict) else {}).items():
        if not isinstance(rec, dict) or rec.get("ok") is not False:
            continue
        if dom not in index:
            continue
        server, _site = index[dom]
        queue = str(rec.get("output_tail") or "")
        touches = len(re.findall(r"doesn't verify against checksum", queue, re.I))
        detail = (f"{touches} fichier(s) ne correspondent pas au cœur officiel"
                  if touches else "vérification en échec")
        out.append(make_incident(
            "checksums_modified", "critical", dom,
            f"Intégrité du cœur en échec sur {dom}",
            detail + " — " + (queue[-200:].strip() or "aucune sortie conservée"),
            site=dom, server=server, since=parse_ts(rec.get("ts")), now=now,
            link={"tab": "securite", "sub": "checksums"}))
    return out


def inc_admins(sites, now):
    """Administrateur absent de la référence admins_baseline.json.

    Un site SANS référence enregistrée est ignoré : sans point de comparaison,
    tous ses comptes seraient « inconnus » et la file d'attente deviendrait
    illisible au premier site ajouté.
    """
    base = incident_json(os.path.join(DATA, "admins_baseline.json"), {})
    out = []
    for server, s in sites:
        admins = s.get("admins")
        if not isinstance(admins, list):
            continue
        cle = s.get("kuma") or s.get("domain") or ""
        ref = base.get(cle) if isinstance(base, dict) else None
        if not isinstance(ref, dict):
            continue
        connus = set(ref.get("logins") or [])
        for a in admins:
            login = (a or {}).get("login") if isinstance(a, dict) else None
            if not login or login in connus:
                continue
            detail = f"compte « {login} » absent de la référence"
            if a.get("registered"):
                detail += f" (inscrit le {a['registered']})"
            out.append(make_incident(
                "admin_unknown", "critical", cle,
                f"Administrateur inconnu sur {cle}", detail,
                site=cle, server=server, arg=str(login),
                since=parse_ts(a.get("registered")), now=now,
                link={"tab": "securite", "sub": "admins"}))
    return out


def inc_server_stale(servers, now):
    """Serveur injoignable à la dernière collecte (fleet.json, `stale`)."""
    out = []
    for srv in servers:
        if not srv.get("stale"):
            continue
        nom = srv.get("name") or "?"
        essai = str(srv.get("last_attempt") or "")
        detail = str(srv.get("error") or "serveur injoignable")
        if essai:
            detail += f" — dernière tentative {essai}"
        detail += (f" — {len(srv.get('sites') or [])} site(s) affichés d'après "
                   "la collecte précédente")
        out.append(make_incident(
            "server_stale", "warning", nom, f"Serveur {nom} injoignable", detail,
            server=nom, since=parse_ts(essai), now=now,
            link={"tab": "gestion", "sub": "serveurs"}))
    return out


def inc_backup(sites, rules, now):
    """Sauvegarde UpdraftPlus plus vieille que le seuil, ou jamais faite.

    Un site SANS UpdraftPlus (`updraft` absent) est ignoré : il n'y a rien à
    comparer et rien à déclencher — même règle que l'alerte Telegram.
    """
    seuil = to_number(rules.get("backup_max_age_h")) or INCIDENT_RULES_DEFAULTS["backup_max_age_h"]
    out = []
    for server, s in sites:
        up = s.get("updraft")
        if not isinstance(up, dict):
            continue
        cle = s.get("kuma") or s.get("domain") or ""
        ts = to_number(up.get("last_backup_ts"))
        age_h = (now - ts) / 3600.0 if ts else None
        if age_h is not None and age_h <= seuil:
            continue
        # Site géré sans SSH : l'incident reste, mais aucune action à proposer —
        # `updraft_backup` y répondrait « action indisponible ».
        rest = s.get("via") == "rest"
        out.append(make_incident(
            "backup_late", "warning", cle, f"Sauvegarde en retard sur {cle}",
            (f"dernière sauvegarde il y a {age_h:.0f} h" if age_h is not None
             else "aucune sauvegarde connue") + f" — seuil {seuil:g} h",
            site=cle, server=server, since=ts if ts else None, now=now,
            action=None if rest else {"label": "Sauvegarder",
                                      "act": "updraft_backup", "arg": ""},
            link={"tab": "parc", "sub": ""}))
    return out


def inc_certs(index, rules, now):
    """Certificat TLS proche de l'expiration (info relevée par Kuma)."""
    res = ssl_certs()
    if res.get("error"):
        raise RuntimeError(str(res["error"])[-200:])
    warn = to_number(rules.get("cert_warn_days")) or INCIDENT_RULES_DEFAULTS["cert_warn_days"]
    crit = to_number(rules.get("cert_critical_days")) or INCIDENT_RULES_DEFAULTS["cert_critical_days"]
    out = []
    for c in (res.get("certs") or []):
        jours = c.get("days_left", c.get("days"))
        try:
            jours = int(jours)
        except (TypeError, ValueError):
            continue                       # jours inconnus : rien à comparer
        if jours >= warn:
            continue
        nom = c.get("monitor") or "?"
        server = (index.get(nom) or ("", None))[0]
        detail = (f"expire dans {jours} jour(s)" if jours >= 0
                  else f"expiré depuis {-jours} jour(s)")
        if c.get("valid_to"):
            detail += f" (le {c['valid_to']})"
        out.append(make_incident(
            "cert_expiring", "critical" if jours < crit else "warning", nom,
            f"Certificat de {nom} à renouveler", detail + f" — seuil {warn:g} j",
            site=nom, server=server, now=now,
            link={"tab": "securite", "sub": "certs"}))
    return out


def inc_php_eol(sites, rules, now):
    """PHP hors support : UNE entrée par serveur et par version, sites regroupés."""
    eol = {str(v).strip() for v in (rules.get("php_eol_versions") or []) if str(v).strip()}
    if not eol:
        return []
    groupes = {}
    for server, s in sites:
        m = re.match(r"^(\d+)\.(\d+)", str(s.get("php_version") or ""))
        if not m:
            continue
        court = f"{m.group(1)}.{m.group(2)}"
        if court not in eol:
            continue
        groupes.setdefault((server, court), []).append(s.get("kuma") or s.get("domain") or "?")
    out = []
    for (server, court), doms in sorted(groupes.items()):
        doms = sorted(set(doms))
        out.append(make_incident(
            "php_eol", "warning", server or "?",
            f"PHP {court} en fin de support sur {server or '?'}",
            f"{len(doms)} site(s) : " + ", ".join(doms[:12]) + ("…" if len(doms) > 12 else ""),
            server=server, arg=court, now=now,
            link={"tab": "securite", "sub": "php"}))
    return out


def inc_counters(sites, index):
    """Compteurs de la barre latérale qui ne sont PAS des incidents.

    `vulns_fixable` compte toutes les vulnérabilités corrigeables (pas seulement
    les critiques) : c'est le nombre affiché sur la destination Sécurité.
    """
    res = incident_json(VULNS_FOUND_PATH, {})
    fixables = 0
    for s in (res.get("sites") or []):
        if (s.get("domain") or "") not in index:
            continue
        for v in (s.get("findings") or []):
            if str(v.get("update_to") or "").strip():
                fixables += 1
    maj = sum(1 for _srv, s in sites
              if s.get("core_update") or (s.get("plugins_updates") or 0)
              or (s.get("themes_updates") or 0))
    return {"vulns_fixable": fixables, "updates_sites": maj}


def incidents_snapshot(now=None):
    """Agrégat complet → (réponse de /api/incidents, compteurs annexes)."""
    now = time.time() if now is None else float(now)
    rules = incident_rules()
    incidents, errors = [], []

    def source(nom, fn):
        """Une source qui échoue laisse une trace et n'emporte pas les autres.

        `list(fn())` est construit DANS le try : une source qui casse à mi-course
        n'injecte donc aucun incident partiel.
        """
        try:
            incidents.extend(list(fn()))
        except Exception as e:
            errors.append({"source": nom, "error": f"{type(e).__name__}: {e}"[:300]})

    try:
        sites, index, servers = incident_fleet()
    except Exception as e:
        sites, index, servers = [], {}, []
        errors.append({"source": "fleet", "error": f"{type(e).__name__}: {e}"[:300]})

    source("kuma", lambda: inc_down(sites, now))
    source("php_errors", lambda: inc_php_fatal(index, now))
    source("vulns", lambda: inc_vulns(index, rules, now))
    source("checksums", lambda: inc_checksums(index, now))
    source("admins", lambda: inc_admins(sites, now))
    source("fleet_servers", lambda: inc_server_stale(servers, now))
    source("updraft", lambda: inc_backup(sites, rules, now))
    source("certs", lambda: inc_certs(index, rules, now))
    source("php_eol", lambda: inc_php_eol(sites, rules, now))

    # Dédoublonnage par identifiant stable : la PREMIÈRE occurrence gagne.
    vus, uniques = set(), []
    for i in incidents:
        if i["id"] in vus:
            continue
        vus.add(i["id"])
        uniques.append(i)
    # Critique avant avertissement, puis le plus ancien d'abord ; `id` en
    # dernier ressort pour que deux appels rendent exactement le même ordre.
    uniques.sort(key=lambda i: (0 if i["severity"] == "critical" else 1, -i["age_h"], i["id"]))

    extra = {"vulns_fixable": 0, "updates_sites": 0,
             "admins_unknown": sum(1 for i in uniques if i["kind"] == "admin_unknown")}
    try:
        extra.update(inc_counters(sites, index))
    except Exception as e:
        errors.append({"source": "counters", "error": f"{type(e).__name__}: {e}"[:300]})

    payload = {"generated_at": incident_iso(now),
               "counts": {"critical": sum(1 for i in uniques if i["severity"] == "critical"),
                          "warning": sum(1 for i in uniques if i["severity"] == "warning")},
               "incidents": uniques, "errors": errors}
    return payload, extra


# Cache mémoire de 30 s : la barre latérale demande ses compteurs à chaque
# changement d'écran, et l'agrégat relit une demi-douzaine de fichiers.
_INCIDENTS_CACHE = {"ts": 0.0, "payload": None, "extra": None}
_INCIDENTS_CACHE_LOCK = threading.Lock()


def incidents_cached(max_age=INCIDENT_CACHE_TTL, refresh=False):
    """Agrégat, recalculé au plus une fois par `max_age` secondes.

    Le calcul se fait HORS verrou : deux requêtes simultanées peuvent le faire
    deux fois (sans effet de bord, tout est en lecture), mais aucune n'attend.
    """
    with _INCIDENTS_CACHE_LOCK:
        if (not refresh and _INCIDENTS_CACHE["payload"] is not None
                and time.time() - _INCIDENTS_CACHE["ts"] < max_age):
            return _INCIDENTS_CACHE["payload"], _INCIDENTS_CACHE["extra"]
    payload, extra = incidents_snapshot()
    with _INCIDENTS_CACHE_LOCK:
        _INCIDENTS_CACHE.update({"ts": time.time(), "payload": payload, "extra": extra})
    return payload, extra


def sidebar_counts():
    """Pastilles de la barre latérale, dérivées du MÊME agrégat que les incidents."""
    payload, extra = incidents_cached()
    return {"incidents": dict(payload["counts"]),
            "securite": {"vulns_fixable": extra.get("vulns_fixable", 0),
                         "admins_unknown": extra.get("admins_unknown", 0)},
            "parc": {"updates_sites": extra.get("updates_sites", 0)}}


# ---------- évènements poussés par les sites (B1) ----------
EVENTS_LOCK = threading.Lock()
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
    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        store[site_key(domain)] = secret
        return store

    update_json(SECRETS_PATH, _muter, {}, mode=0o600)
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
    return [e for e in read_jsonl_tail(EVENTS_PATH, n)
            if not domain or e.get("domain") == domain]


def read_changes(n=1500, domain=None):
    """Historique persistant des changements de collecte (data/changes.jsonl).

    Produit par collect.py : chaque ligne est un changement d'état réel (version
    installée qui bouge, admin/extension ajouté), déjà dédoublonné par domaine
    Kuma. C'est l'historique complet — au-delà de la seule dernière collecte que
    donne compute_diff(). Renvoyé du plus récent au plus ancien.
    """
    out = [c for c in read_jsonl_tail(CHANGES_PATH, n)
           if not domain or c.get("domain") == domain]
    out.reverse()
    return out


def event_is_critical(event, detail):
    """Évènement justifiant une alerte immédiate (création d'admin, plugin activé)."""
    if event in CRITICAL_EVENTS:
        return True
    return event == "set_user_role" and "administrator" in str(detail or "").lower()


INGEST_SEEN = {}          # signature → horodatage de première acceptation
INGEST_SEEN_LOCK = threading.Lock()


def ingest_replay(sig, now=None):
    """Signature déjà acceptée ? (et l'enregistre sinon).

    Le HMAC seul n'empêche pas le rejeu : un intermédiaire pouvait capturer une
    requête signée et la renvoyer autant de fois qu'il voulait dans la fenêtre
    de tolérance. Le cache est purgé au-delà de cette fenêtre : rien à borner.
    """
    now = time.time() if now is None else now
    with INGEST_SEEN_LOCK:
        for k, t in list(INGEST_SEEN.items()):
            if now - t > INGEST_SKEW * 2:
                INGEST_SEEN.pop(k, None)
        if sig in INGEST_SEEN:
            return True
        INGEST_SEEN[sig] = now
        return False


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
    # Anti-rejeu : seules les signatures VALIDES entrent au cache (sinon
    # n'importe qui pourrait le remplir avec des signatures inventées).
    if ingest_replay(sig):
        return None, "rejeu"
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
    etat = {"removed": False}

    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        etat["removed"] = store.pop(site_key(domain), None) is not None
        return store

    update_json(SECRETS_PATH, _muter, {}, mode=0o600)
    return etat["removed"]


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


HTTP_MAX_BYTES = 2 * 1024 * 1024


def _open_no_redirect(req, timeout=20, max_bytes=HTTP_MAX_BYTES, ssrf_guard=True):
    """Ouvre une requête SANS suivre les redirections, lecture bornée → (statut, corps).

    urllib.request.urlopen() suit les 30x en CONSERVANT l'en-tête Authorization :
    un site compromis répondant « 302 → attaquant » recevait le mot de passe
    d'application administrateur. Ici toute redirection remonte telle quelle en
    HTTPError (code 30x), jamais suivie ; l'appelant la traite comme un échec.
    `ssrf_guard` : contrôle de résolution DNS publique (inutile pour Telegram).
    """
    if ssrf_guard:
        _, err = validate_public_url(req.full_url)
        if err:
            raise urllib.error.URLError(err)
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(req, timeout=timeout) as resp:
        status = getattr(resp, "status", resp.getcode())
        return status, resp.read(max_bytes)


# --------------------------------------------------------------------------- #
#  API publique de VizProof (vizproof.com) — jeton de COMPTE en Bearer.         #
#                                                                              #
#  Sert au « flux en un clic » : le site VizProof est retrouvé par l'HÔTE de    #
#  l'URL WordPress, ou créé s'il n'existe pas. Le jeton n'apparaît ni en        #
#  réponse, ni dans actions.log : il ne sort d'ici que dans l'en-tête           #
#  Authorization, et `_open_no_redirect` garantit qu'aucune redirection ne le   #
#  transporte ailleurs que sur l'hôte visé.                                    #
# --------------------------------------------------------------------------- #
def viz_api_error(code, detail=""):
    """Message court et lisible pour un statut HTTP de l'API VizProof."""
    detail = re.sub(r"\s+", " ", str(detail or "")).strip()[:160]
    if code in (301, 302, 303, 307, 308):
        return f"redirection refusée ({code}) : vérifiez la base API"
    if code in (401, 403):
        return f"jeton refusé par VizProof ({code})"
    if code == 404:
        return "route introuvable (404) : base API incorrecte ?"
    if code == 429:
        return "trop d'appels (429) : réessayez dans un instant"
    return f"HTTP {code}" + (f" : {detail}" if detail else "")


def viz_api_call(path, token, base=None, data=None, timeout=VIZ_API_TIMEOUT):
    """Appel de l'API VizProof → (statut, objet JSON ou None, erreur).

    `data` non nul = POST JSON. Toujours via `_open_no_redirect` : un 30x
    remonte en erreur au lieu de rejouer l'en-tête Authorization ailleurs.
    """
    url = viz_api_base(base) + str(path)
    u, err = validate_public_url(url)
    if err:
        return None, None, f"base API refusée : {err}"
    if u.scheme != "https":
        return None, None, "base API : https exigé"
    entetes = {"Authorization": "Bearer " + str(token or ""),
               "Accept": "application/json", "User-Agent": USER_AGENT}
    corps = None
    if data is not None:
        corps = json.dumps(data).encode()
        entetes["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=corps, headers=entetes,
                                 method="POST" if data is not None else "GET")
    try:
        st, raw = _open_no_redirect(req, timeout=timeout, max_bytes=VIZ_API_MAX_BYTES)
    except urllib.error.HTTPError as e:
        try:
            detail = (e.read(4096) or b"").decode("utf-8", "replace")
        except Exception:
            detail = ""
        finally:
            try:
                e.close()
            except Exception:
                pass
        # le corps d'erreur pourrait recopier le jeton : il ne ressortira pas d'ici
        return e.code, None, mask_secret(viz_api_error(e.code, detail), str(token or ""))
    except Exception as e:
        return None, None, mask_secret(f"{type(e).__name__}: {e}"[:200], str(token or ""))
    try:
        return st, json.loads(raw.decode("utf-8", "replace")), None
    except ValueError:
        return st, None, "réponse illisible (JSON attendu)"


def viz_hostname(value):
    """Hôte d'une URL ou d'un domaine : minuscule, sans schéma, sans port, « www. » CONSERVÉ."""
    h = str(value or "").strip().lower()
    if "//" in h:
        h = h.split("//", 1)[1]
    return h.split("/")[0].split("@")[-1].split(":")[0].strip()


def viz_site_hosts(site):
    """Hôtes déclarés sur une fiche VizProof → [(hôte, valeur brute)].

    `domains` est une CHAÎNE JSON contenant une liste (« ["a.fr","www.a.fr"] »),
    nulle tant qu'aucune page n'a été ajoutée au site. Tout ce qui n'est pas
    exploitable rend une liste vide plutôt qu'une exception.
    """
    raw = (site or {}).get("domains")
    if isinstance(raw, str):
        try:
            vals = json.loads(raw)
        except ValueError:
            vals = [raw]              # tolérance : un hôte nu, pas du JSON
    else:
        vals = raw
    if isinstance(vals, (str, bytes)):
        vals = [vals]
    if not isinstance(vals, list):
        return []
    out = []
    for v in vals:
        if isinstance(v, dict):       # forme {"domain": "a.fr"} tolérée
            v = v.get("domain") or v.get("host") or ""
        h = viz_hostname(v)
        if h:
            out.append((h, str(v)))
    return out


def viz_resolve_site(domain, siteurl, token, base=None, create=True):
    """Retrouve — ou crée — le site VizProof correspondant à une URL WordPress.

    → {"ok", "site_id", "name", "created", "matched_domain", "ambiguous",
       "host", "error"}. Ne touche à RIEN côté WordPress : c'est de la lecture
    (plus, au besoin, une création côté VizProof), pas une connexion.
    """
    # Le siteurl fait foi (un vhost peut différer de l'URL réelle), mais un
    # siteurl aberrant — « javascript:… » vu en base sur un site compromis — ne
    # doit pas devenir le nom d'un site créé chez VizProof : repli sur le domaine.
    host = next((h for h in (norm_domain(siteurl), norm_domain(domain))
                 if VIZ_HOST_RE.match(h or "")), "")
    res = {"ok": False, "site_id": "", "name": "", "created": False,
           "matched_domain": "", "ambiguous": False, "host": host, "error": None}
    if not host:
        res["error"] = "hôte introuvable pour ce site"
        return res
    if not token:
        res["error"] = VIZ_NO_TOKEN_MSG
        return res
    variantes = {host, "www." + host}
    trouves, vus, page = [], 0, 1
    while vus < VIZ_SITES_MAX:
        st, j, err = viz_api_call(f"/api/sites?limit={VIZ_PAGE_LIMIT}&page={page}", token, base)
        if err:
            res["error"] = err
            return res
        lot = (j or {}).get("data") if isinstance(j, dict) else j
        if not isinstance(lot, list):
            res["error"] = "réponse inattendue de /api/sites (liste attendue)"
            return res
        if not lot:
            break
        for s in lot:
            vus += 1
            if not isinstance(s, dict):
                continue
            for h, brut in viz_site_hosts(s):
                if h in variantes:
                    trouves.append((s, brut))
                    break
            if vus >= VIZ_SITES_MAX:
                break
        total = (j or {}).get("total") if isinstance(j, dict) else None
        if len(lot) < VIZ_PAGE_LIMIT:
            break
        if isinstance(total, int) and vus >= total:
            break
        page += 1
    if trouves:
        s, brut = trouves[0]
        sid = str(s.get("id") or "")
        if not VIZ_SITE_ID_RE.match(sid):
            res["error"] = "identifiant de site VizProof inexploitable"
            return res
        # Plusieurs SITES distincts revendiquant l'hôte : on prend le premier et
        # on le signale — c'est à l'utilisateur de trancher, pas au dashboard.
        distincts = {str(x.get("id") or "") for x, _ in trouves}
        res.update(ok=True, site_id=sid, name=str(s.get("name") or "") or host,
                   matched_domain=brut, ambiguous=len(distincts) > 1)
        return res
    if not create:
        # Aperçu : on dit ce qui SERAIT créé, sans le créer. Seule la connexion crée.
        res.update(ok=True, would_create=True)
        return res
    st, j, err = viz_api_call("/api/sites", token, base, data={"name": host})
    if err:
        res["error"] = err
        return res
    site = j.get("site") if isinstance(j, dict) and isinstance(j.get("site"), dict) else j
    sid = str((site or {}).get("id") or "") if isinstance(site, dict) else ""
    if not VIZ_SITE_ID_RE.match(sid):
        res["error"] = "site créé mais identifiant absent de la réponse"
        return res
    res.update(ok=True, site_id=sid, created=True,
               name=str(site.get("name") or "") or host)
    return res


def viz_site_url(server_name, domain):
    """URL publique connue d'un site du parc (fleet.json), repli sur son domaine."""
    for srv in load_json(FLEET_PATH, {"servers": []}).get("servers", []):
        if server_name and srv.get("name") != server_name:
            continue
        for s in srv.get("sites", []):
            if s.get("domain") == domain:
                return str(s.get("siteurl") or s.get("url") or "") or str(domain)
    return str(domain)


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
    genere = {}

    def _muter(store):
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
        genere["code"] = code
        return store

    update_json(PAIRINGS_PATH, _muter, {})
    return genere["code"]


def consume_pair_code(code, site_url):
    """Valide et consomme un code → (enregistrement, None) ou (None, erreur)."""
    code = normalize_pair_code(code)
    if not PAIR_CODE_RE.match(code or ""):
        return None, "code invalide"
    now = time.time()
    issue = {"rec": None, "err": None}

    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        rec = store.get(code)
        if not isinstance(rec, dict):
            issue["err"] = "code inconnu"
            return store
        if rec.get("used_ts"):
            issue["err"] = "code déjà utilisé"
            return store
        if now - (rec.get("created_ts") or 0) > PAIR_TTL:
            issue["err"] = "code expiré"
            return store
        rec["used_ts"], rec["site_url"] = now, site_url
        store[code] = rec
        issue["rec"] = rec
        return store

    update_json(PAIRINGS_PATH, _muter, {})
    return issue["rec"], issue["err"]


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
def rest_sites():
    lst = load_json(REST_SITES_PATH, [])
    return [s for s in lst if isinstance(s, dict)] if isinstance(lst, list) else []


def add_rest_site(url, name=None, multisite=False, blog_id=None, agent_version=None):
    """Ajoute (ou actualise) un site collecté par l'agent REST."""
    url = re.sub(r"/+$", "", str(url or ""))
    key = site_key(url)
    cree = {}

    def _muter(lst):
        lst = [s for s in lst if isinstance(s, dict)] if isinstance(lst, list) else []
        prev = next((s for s in lst if s.get("domain") == key), None)
        entry = {"domain": key, "url": url, "name": name or (prev or {}).get("name") or key,
                 "added_ts": (prev or {}).get("added_ts") or time.time(),
                 "multisite": bool(multisite), "blog_id": blog_id}
        if agent_version:
            entry["agent_version"] = str(agent_version)[:40]
        cree["entry"] = entry
        return [s for s in lst if s.get("domain") != key] + [entry]

    update_json(REST_SITES_PATH, _muter, [])
    return cree["entry"]


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
    status, raw = _open_no_redirect(req, timeout=timeout, max_bytes=512 * 1024)
    return status, json.loads(raw.decode("utf-8", "replace") or "{}")


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
    compte = {"avant": 0, "apres": 0}

    def _muter(lst):
        lst = [s for s in lst if isinstance(s, dict)] if isinstance(lst, list) else []
        kept = [s for s in lst if s.get("domain") != key]
        compte["avant"], compte["apres"] = len(lst), len(kept)
        return kept

    update_json(REST_SITES_PATH, _muter, [])
    forget_site_secret(key)
    return compte["avant"] != compte["apres"]


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
    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        store[key] = entry
        return store

    # identifiants : lecture root uniquement, y compris pendant l'écriture
    update_json(WPAUTH_PATH, _muter, {}, mode=0o600)


def wp_cred_forget(domain, url=""):
    key, _ = wp_cred_for(domain, url)
    if not key:
        return False

    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        store.pop(key, None)
        return store

    update_json(WPAUTH_PATH, _muter, {}, mode=0o600)
    return True


def wp_state_new(server, domain, url):
    state = secrets.token_urlsafe(24)

    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        now = time.time()
        store = {k: v for k, v in store.items()
                 if isinstance(v, dict) and now - v.get("created", 0) < WPAUTH_TTL}
        store[state] = {"server": server or "", "domain": domain, "url": url, "created": now}
        return store

    update_json(WPSTATE_PATH, _muter, {}, mode=0o600)
    return state


def wp_state_consume(state):
    """Jeton à usage unique : consommé qu'il soit valide ou expiré."""
    pris = {}

    def _muter(store):
        if not isinstance(store, dict):
            store = {}
        pris["rec"] = store.pop(state, None)
        return store

    update_json(WPSTATE_PATH, _muter, {}, mode=0o600)
    rec = pris.get("rec")
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
        _st, raw = _open_no_redirect(req, timeout=timeout)
        data = json.loads(raw.decode("utf-8", "replace"))
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
        _st, blob = _open_no_redirect(req, timeout=AGENT_TIMEOUT)
        data = json.loads(blob.decode("utf-8", "replace"))
        return 0, f"{slug} installé et activé (version {data.get('version', '?')})"
    except urllib.error.HTTPError as e:
        raw = e.read(HTTP_MAX_BYTES).decode("utf-8", "replace")[:400]
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
        status, blob = _open_no_redirect(req, timeout=timeout)
        body = blob.decode("utf-8", "replace")
        return status, (json.loads(body) if body.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read(HTTP_MAX_BYTES).decode("utf-8", "replace")[:400]
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
            # alert(clé, règle, texte) : la règle manquait, l'alerte ne partait
            # jamais (TypeError avalé par le except ci-dessous).
            alert(f"admin_dedie:{domain}", "new_admin",
                  f"👤 Compte <b>{esc_html(WP_BOT_LOGIN)}</b> (administrateur) créé sur "
                  f"<b>{esc_html(domain)}</b> par le dashboard, pour la gestion à distance.")
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
    def _muter(base):
        if not isinstance(base, dict):
            base = {}
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
        return base

    try:
        update_json(os.path.join(DATA, "admins_baseline.json"), _muter, {})
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
        """Corps JSON de la requête, plafonné à 1 Mo. ValueError → 400 chez l'appelant."""
        brut = self.headers.get("Content-Length", 0)
        try:
            length = int(brut)
        except (TypeError, ValueError):
            raise ValueError("longueur invalide")
        if length < 0:
            raise ValueError("longueur invalide")
        if length > MAX_BODY_BYTES:
            raise ValueError("corps trop volumineux")
        return json.loads(self.rfile.read(length)) if length else {}

    @staticmethod
    def _viz_api_base(body):
        """Surcharge ponctuelle de la base API VizProof → (base ou None, erreur).

        Même garde SSRF que le sondage d'URL : le champ est saisi dans
        l'interface, il ne doit pas pouvoir viser un réseau interne.
        """
        base = str((body or {}).get("api_base") or "").strip()
        if not base:
            return None, None
        u, err = validate_public_url(base)
        if err:
            return None, f"base API refusée : {err}"
        if u.scheme != "https":
            return None, "base API : https exigé"
        return base, None

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path.split("?")[0]
        q = dict(x.split("=", 1) for x in self.path.split("?", 1)[1].split("&") if "=" in x) if "?" in self.path else {}
        # Contrôle de session GLOBAL. Seules deux routes s'en passent :
        #   /api/auth/check   — c'est elle qui REND le verdict à nginx auth_request ;
        #   /api/wp_callback  — retour d'une redirection externe, protégé par son
        #                       propre jeton « state » à usage unique.
        # Les agents WordPress n'appellent que POST /api/ingest et POST /api/pair.
        if p not in ("/api/auth/check", "/api/wp_callback") and not cookie_user(self.headers):
            return self._send(401, {"error": "non authentifié"})
        if p == "/api/auth/check":
            # appelé par nginx auth_request : 200 si session valide, 401 sinon
            code = 200 if cookie_user(self.headers) else 401
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if p == "/api/actions/log":
            self._send(200, {"log": read_log()})
        elif p == "/api/actions/collect_status":
            self._send(200, {"running": COLLECT["running"], "rc": COLLECT["rc"],
                             "done": COLLECT["done_servers"], "total": COLLECT["total_servers"],
                             "started": COLLECT["started"], "lines": COLLECT["lines"][-14:]})
        elif p == "/api/actions/collect_history":
            self._send(200, {"history": read_jsonl_tail(os.path.join(DATA, "collect_history.jsonl"), 60)})
        elif p == "/api/actions/bulk_status":
            self._send(200, get_job(q.get("job", 0)) or {"error": "job inconnu"})
        elif p == "/api/mgmt/state":
            groups, monitors = kuma_state()
            self._send(200, {"servers": servers_list(),
                             "overrides": load_json(os.path.join(DATA, "overrides.json"), {}),
                             "extra_docroots": load_json(os.path.join(DATA, "extra_docroots.json"), []),
                             "kuma_groups": groups, "kuma_monitors": monitors})
        elif p == "/api/mgmt/sshkeys":
            self._send(200, {"keys": ssh_keys_list(), "assignments": ssh_key_assignments()})
        elif p == "/api/mgmt/rest_sites":
            self._send(200, {"rest_sites": rest_sites()})
        elif p == "/api/mgmt/candidates":
            self._send(200, {"candidates": kuma_candidates()})
        elif p == "/api/mgmt/agent.zip":
            # téléchargement direct (lien) : session vérifiée en tête de do_GET
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
        elif p == "/api/mgmt/settings":
            # settings_public() retire le jeton VizProof : il ne sort jamais d'ici
            self._send(200, {"settings": settings_public(),
                             "defaults": {k: v for k, v in SETTINGS_DEFAULTS.items()
                                          if k not in SETTINGS_SECRETS}})
        elif p == "/api/mgmt/alerts":
            # le token n'est jamais renvoyé en clair : booléen + 4 derniers caractères
            cfg = alerts_cfg()
            token = str(cfg.get("bot_token") or "")
            self._send(200, {"enabled": bool(cfg.get("enabled")), "chat_id": cfg.get("chat_id") or "",
                             "rules": cfg.get("rules"), "token_set": bool(token),
                             "token_tail": token[-4:] if token else ""})
        elif p == "/api/incidents":
            # File « à traiter » : agrégat des sources déjà collectées, sans
            # aucun appel réseau ni ssh. Toujours recalculée (c'est l'écran qui
            # fait autorité), ce qui rafraîchit au passage le cache des compteurs.
            payload, _extra = incidents_cached(refresh=True)
            self._send(200, payload)
        elif p == "/api/mgmt/counts":
            # Pastilles de la barre latérale : même agrégat, mis en cache 30 s.
            self._send(200, sidebar_counts())
        elif p == "/api/sec/certs":
            self._send(200, ssl_certs())
        elif p == "/api/sec/checksums":
            self._send(200, {"checksums": load_json(CHECKSUMS_PATH, {})})
        elif p == "/api/actions/plugin_versions":
            # réponse inchangée pour l'interface : {"current": …, "versions": […]}
            res = wporg_versions(urllib.parse.unquote(q.get("slug", "")))
            self._send(200, {"current": res.get("current"), "versions": res.get("versions") or []})
        elif p == "/api/actions/rollback_points":
            server = urllib.parse.unquote(q.get("server", ""))
            dom = urllib.parse.unquote(q.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(dom):
                return self._send(400, {"error": "cible invalide"})
            self._send(200, {"points": rollback_points(server, dom,
                                                       verify=q.get("verify") == "1")})
        elif p == "/api/actions/policy":
            dom = urllib.parse.unquote(q.get("domain", ""))
            self._send(200, {"frozen": frozen_plugins(dom) if SLUG_RE.match(dom) else []})
        elif p == "/api/actions/safe_update_status":
            self._send(200, dict(SAFE))
        elif p == "/api/actions/viz_update_status":
            # Job « baseline → mise à jour → verdict » d'un site : mémoire de
            # processus, comme viz_last. Un domaine sans job répond un job vide
            # plutôt qu'une erreur — l'UI interroge avant de savoir.
            dom = urllib.parse.unquote(q.get("domain", ""))
            if not SLUG_RE.match(dom):
                return self._send(400, {"error": "cible invalide"})
            self._send(200, vizup_get(dom) or vizup_empty(dom))
        elif p == "/api/actions/viz_last":
            # Verdict du contrôle visuel de fin de mise à jour unitaire, avec
            # `source` (plugin|dashboard), `run_id`, `anomalies_count` et, tant
            # qu'il n'est pas rendu, la `phase` en cours. Vide tant qu'aucun
            # contrôle n'a eu lieu depuis le démarrage du service : c'est une
            # mémoire de processus, l'historique reste dans actions.log.
            dom = urllib.parse.unquote(q.get("domain", ""))
            if not SLUG_RE.match(dom):
                return self._send(400, {"error": "cible invalide"})
            self._send(200, {"viz": viz_last_get(dom) or None})
        elif p == "/api/actions/viz_pages":
            # Pages surveillées d'un site relié. rc 97 (site sans SSH) et rc 99
            # (plugin trop ancien) sont des RÉPONSES, pas des pannes : 200 avec
            # `ok:false`, l'interface sait quoi en dire.
            server = urllib.parse.unquote(q.get("server", ""))
            dom = urllib.parse.unquote(q.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(dom):
                return self._send(400, {"error": "cible invalide"})
            rc, payload = viz_pages_read(server, dom)
            payload.setdefault("ok", rc == 0)
            doux = rc in (0, VIZ_OLD_RC, REST_UNSUPPORTED_RC)
            self._send(200 if doux else 500, dict(payload, rc=rc))
        elif p == "/api/sec/phperrors":
            res = load_json(PHPERR_PATH, {"sites": [], "total": 0, "fatals": 0,
                                          "sites_with_errors": 0})
            res["running"] = PHPERR["running"]
            res["run_message"] = PHPERR["message"]
            self._send(200, res)
        elif p == "/api/sec/vulns":
            # Résultat du dernier croisement local (vulns.py --scan) + état d'avancement.
            res = load_json(VULNS_FOUND_PATH, {"sites": [], "totals": {},
                                               "sites_affected": 0, "sites_scanned": 0})
            dom = urllib.parse.unquote(q.get("domain", ""))
            if dom:
                # Le tiroir n'a besoin que de son site : renvoyer les 190 Ko du
                # parc entier à chaque ouverture serait du gaspillage.
                res = dict(res, sites=[x for x in (res.get("sites") or [])
                                       if x.get("domain") == dom])
            res["running"] = VULNS["running"]
            res["run_message"] = VULNS["message"]
            self._send(200, res)
        elif p == "/api/sec/baseline":
            self._send(200, {"baseline": load_json(os.path.join(DATA, "admins_baseline.json"), {})})
        elif p == "/api/mgmt/events":
            # Événements poussés par les agents, à l'échelle du parc (la page
            # Changements les fusionne avec les changements détectés et les
            # actions). `domain` optionnel pour filtrer un site.
            try:
                lim = max(1, min(int(q.get("limit", "400")), 2000))
            except ValueError:
                lim = 400
            dom = q.get("domain") or None
            self._send(200, {"events": read_events(lim, dom)})
        elif p == "/api/mgmt/changes":
            try:
                limit = min(int(q.get("limit", "400")), 2000)
            except ValueError:
                limit = 400
            tous = read_changes(2000)          # un seul parcours du fichier
            rows = tous[:limit]
            for r in rows:
                r["label"] = CHANGE_LABELS.get(r.get("kind"), "changement")
            # résumé sur 24 h : nb de changements, sites touchés, dont à surveiller
            cutoff = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")
            recent = [r for r in tous if str(r.get("ts") or "") >= cutoff]
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
            # Site relié à VizProof : la mise à jour est encadrée (baseline
            # avant, verdict après), ce qui ne tient pas dans une réponse HTTP —
            # la route démarre un job et rend la main. Tous les autres cas
            # gardent la réponse synchrone d'avant.
            if viz_update_wanted(action):
                _srvj, sitej = find_site(server, domain)
                if sitej and viz_update_eligible(sitej):
                    job, err = vizup_start(server, domain, action, arg)
                    if err:
                        return self._send(409, {"error": err})
                    return self._send(200, {"ok": True, "job": "viz_update",
                                            "domain": domain, "server": server,
                                            "action": action, "arg": arg,
                                            "steps": job["steps"]})
            # `t0` AVANT la mise à jour : le plugin vizproof met son propre scan
            # en file PENDANT celle-ci, et c'est à cet instant-là qu'on compare
            # la date du run pour savoir s'il est bien le nôtre.
            t0 = time.time()
            rc, out = logged_action(server, domain, action, arg)
            # rc 2 sur une action vizproof = anomalies visuelles, pas une erreur technique ;
            # rc 97 = action impossible sans SSH, c'est une réponse, pas une panne serveur
            anomaly = rc == VIZ_ANOMALY_RC and action in VIZ_ACTIONS
            soft = anomaly or rc == REST_UNSUPPORTED_RC
            corps = {"ok": rc == 0, "rc": rc, "viz_anomaly": anomaly, "output": out,
                     "error": None if rc == 0 else out}
            # Contrôle visuel de fin de mise à jour : jamais au prix du résultat
            # de la mise à jour elle-même, qui est déjà appliquée à ce stade.
            try:
                viz = viz_after_update(server, domain, action, rc, t0)
            except Exception as e:
                viz = {"ran": False, "pending": False, "reason": "erreur",
                       "message": f"contrôle visuel impossible : {e}"}
            if viz is not None:
                corps["viz"] = viz
            return self._send(200 if (rc == 0 or soft) else 500, corps)

        if p == "/api/actions/viz_resolve":
            # Aperçu : quel site VizProof recevra ce WordPress. Rien n'est écrit
            # côté WordPress ; côté VizProof, un site peut être CRÉÉ (c'est le
            # propre du flux « en un clic » : la résolution est la création).
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            jeton = viz_token_stored()
            if not jeton:
                return self._send(200, {"ok": False, "error": VIZ_NO_TOKEN_MSG})
            api_base, err = self._viz_api_base(body)
            if err:
                return self._send(400, {"error": err})
            r = viz_resolve_site(domain, viz_site_url(server, domain), jeton, api_base, create=False)
            return self._send(200, r)

        if p == "/api/actions/viz_connect":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            site_id = str(body.get("site_id", "")).strip()
            token = str(body.get("token") or "").strip()
            code = str(body.get("code") or "").strip()
            if token and code:
                return self._send(400, {"error": "jeton et code de connexion sont exclusifs"})
            if token and not VIZ_TOKEN_RE.match(token):
                return self._send(400, {"error": "jeton invalide (une ligne, 8 à 512 caractères)"})
            if code and not VIZ_CODE_RE.match(code):
                return self._send(400, {"error": "code de connexion invalide"})
            enregistre = viz_token_stored()
            if not token and not code:
                # Repli sur le jeton des Réglages : c'est le cas courant depuis
                # que le jeton est enregistré une fois pour tout le parc.
                token = enregistre
                if not token:
                    return self._send(400, {"error": "jeton ou code de connexion requis ("
                                                     + VIZ_NO_TOKEN_MSG + ")"})
            scope = str(body.get("scope") or "").strip() or None
            if scope and scope not in VIZ_SCOPES:
                return self._send(400, {"error": "portée invalide (site ou selected_pages)"})
            api_base, err = self._viz_api_base(body)
            if err:
                return self._send(400, {"error": err})
            site_created, site_name = False, ""
            if not site_id:
                # Résolution par URL. Le jeton de COMPTE est celui des Réglages ;
                # un jeton ponctuel du corps ne sert qu'à l'appel wp-cli, sauf
                # s'il a lui-même le format d'un jeton de compte.
                jeton_api = enregistre or (token if VIZ_ACCOUNT_TOKEN_RE.match(token) else "")
                r = viz_resolve_site(domain, viz_site_url(server, domain), jeton_api, api_base)
                if not r["ok"]:
                    return self._send(200, {"ok": False, "rc": VIZ_RESOLVE_RC,
                                            "output": r["error"], "error": r["error"],
                                            "site_id": "", "site_created": False, "site_name": ""})
                site_id, site_created, site_name = r["site_id"], r["created"], r["name"]
            if not VIZ_SITE_ID_RE.match(site_id):
                return self._send(400, {"error": "identifiant de site invalide "
                                                 "(lettres, chiffres, « _ » et « - », 80 max)"})
            rc, out = viz_connect_run(server, domain, site_id, api_base, scope, token, code,
                                      site_created=site_created)
            if rc == 0:
                try:   # la colonne VizProof doit refléter l'état tout de suite
                    logged_action(server, domain, "rescan", None, source="viz_connect")
                except Exception as e:
                    out += f"\n(re-scan à refaire : {e})"
            # rc 99 (plugin trop ancien) et 97 (site sans SSH) sont des réponses,
            # pas des pannes du dashboard : 200 avec ok=false.
            soft = rc in (VIZ_OLD_RC, REST_UNSUPPORTED_RC)
            return self._send(200 if (rc == 0 or soft) else 500,
                              {"ok": rc == 0, "rc": rc, "output": out,
                               "error": None if rc == 0 else out,
                               "site_id": site_id, "site_created": site_created,
                               "site_name": site_name})

        if p == "/api/actions/viz_pages":
            # Enregistrement de la sélection. La validation double celle du
            # plugin (qui reste l'autorité) pour dire l'erreur AVANT le ssh.
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            brut = body.get("ids")
            if not isinstance(brut, list):
                return self._send(400, {"error": "ids : une liste d'entiers est attendue"})
            for x in brut:
                entier = isinstance(x, int) and not isinstance(x, bool)
                if not (entier or (isinstance(x, str) and x.isdigit())):
                    return self._send(400, {"error": "ids : entiers positifs attendus"})
                if entier and x < 0:
                    return self._send(400, {"error": "ids : entiers positifs attendus"})
            scope = str(body.get("scope") or "").strip()
            if scope not in VIZ_SCOPES:
                return self._send(400, {"error": "portée invalide (site ou selected_pages)"})
            ids = viz_pages_ids(brut)
            # L'accueil « flux d'articles » porte l'identifiant 0 : il n'a pas de
            # page à capturer, le plugin refuse `--ids=0`, et la seule façon de
            # le surveiller est la portée « tout le site ».
            if 0 in ids and scope != "site":
                return self._send(400, {"error": "l'accueil « flux d'articles » ne se surveille "
                                                 "qu'avec la portée « tout le site »"})
            ids = [i for i in ids if i > 0]
            if len(ids) > VIZ_PAGES_MAX:
                return self._send(400, {"error": f"{VIZ_PAGES_MAX} pages au maximum "
                                                 "(le plugin ne scanne pas au-delà)"})
            if scope == "selected_pages" and not ids:
                return self._send(400, {"error": "choisissez au moins une page à surveiller"})
            rc, payload = viz_pages_write(server, domain, ids, scope)
            payload.setdefault("ok", rc == 0)
            doux = rc in (0, VIZ_OLD_RC, REST_UNSUPPORTED_RC)
            return self._send(200 if doux else 500, dict(payload, rc=rc))

        if p == "/api/actions/viz_disconnect":
            server, domain = str(body.get("server", "")), str(body.get("domain", ""))
            if not SERVER_RE.match(server) or not SLUG_RE.match(domain):
                return self._send(400, {"error": "cible invalide"})
            rc, out = logged_action(server, domain, "viz_disconnect", None)
            if rc != 0 and VIZ_OLD_RE.search(out or ""):
                rc, out = VIZ_OLD_RC, VIZ_OLD_MSG
            if rc == 0:
                try:
                    logged_action(server, domain, "rescan", None, source="viz_connect")
                except Exception as e:
                    out += f"\n(re-scan à refaire : {e})"
            soft = rc in (VIZ_OLD_RC, REST_UNSUPPORTED_RC)
            return self._send(200 if (rc == 0 or soft) else 500,
                              {"ok": rc == 0, "rc": rc, "output": out,
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
                if t.get("action") not in BULK_EXTRA_ACTIONS and t.get("action") not in ACTIONS:
                    return self._send(400, {"error": f"action inconnue: {t.get('action')}"})
            jid = start_bulk(tasks, mode, backup_first, viz_verify)
            return self._send(200, {"ok": True, "job": jid})

        if p == "/api/actions/bulk_cancel":
            try:
                jid = int(body.get("job", 0))
            except (TypeError, ValueError):
                return self._send(400, {"error": "identifiant de job invalide"})
            job = get_job(jid)
            if job:
                job["cancel"] = True
            return self._send(200, {"ok": bool(job)})

        if p == "/api/mgmt/override":
            domain = str(body.get("domain", ""))
            if not SLUG_RE.match(domain):
                return self._send(400, {"error": "domaine invalide"})

            def _muter_overrides(ov):
                if not isinstance(ov, dict):
                    ov = {}
                cur = ov.get(domain, {})
                if "visible" in body:
                    cur["visible"] = body["visible"] if body["visible"] in (True, False) else None
                if "alias" in body:
                    al = str(body["alias"]).strip()
                    cur["alias"] = al or None
                ov[domain] = {k: v for k, v in cur.items() if v is not None}
                if not ov[domain]:
                    ov.pop(domain, None)
                return ov

            ov = update_json(os.path.join(DATA, "overrides.json"), _muter_overrides, {})
            return self._send(200, {"ok": True, "overrides": ov})

        if p == "/api/mgmt/servers":
            servers = body.get("servers")
            if not isinstance(servers, list):
                return self._send(400, {"error": "format invalide"})
            for s in servers:
                ok, err = validate_server(s)
                if not ok:
                    return self._send(400, {"error": err})
            save_json(os.path.join(BASE, "servers.json"), servers, mode=0o600)
            return self._send(200, {"ok": True})

        if p == "/api/mgmt/docroots":
            docs = body.get("docroots")
            if not isinstance(docs, list):
                return self._send(400, {"error": "format invalide"})
            # Ces chemins partent dans un shell distant (collect.py) : mêmes
            # règles que les patterns d'un serveur, contrôlées ici aussi.
            for d in docs:
                if not isinstance(d, dict):
                    return self._send(400, {"error": "docroot invalide"})
                if not SRV_NAME_RE.match(str(d.get("server") or "")):
                    return self._send(400, {"error": "serveur invalide pour un docroot"})
                if not valid_path_pattern(d.get("path")):
                    return self._send(400, {"error": f"chemin invalide : « {str(d.get('path'))[:60]} »"})
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
            try:
                cmd = ["ssh", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                       "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
                       "-p", str(srv["port"]), "--", ssh_target(srv), "echo OK depuis $(hostname)"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                rc, out = r.returncode, (r.stdout + r.stderr).strip()
            except subprocess.TimeoutExpired:
                rc, out = 93, "timeout"
            except ValueError as e:      # cible ssh refusée par ssh_target()
                rc, out = 91, str(e)
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
            save_json(os.path.join(BASE, "servers.json"), servers, mode=0o600)
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
                # Même verrou que le job `viz_update` : deux mises à jour de
                # front sur le même WordPress, c'est un site cassé sans coupable.
                if vizup_running(domain):
                    return self._send(409, {"error": "une mise à jour sous contrôle "
                                                     f"visuel est en cours sur {domain}"})
                SAFE["running"] = True   # réservation immédiate : évite deux lancements simultanés
            slugs = body.get("slugs") or None
            if slugs is not None:
                slugs = [s for s in slugs if isinstance(s, str) and SLUG_RE.match(s)]
            # viz_rollback absent = on suit le réglage persistant ; présent, il
            # ne vaut que pour cette exécution (case de la modale de confirmation).
            vrb = body.get("viz_rollback")
            threading.Thread(target=safe_update_run,
                             args=(server, domain, slugs, bool(body.get("backup", True)),
                                   bool(body.get("viz", True)), bool(body.get("core", False)),
                                   bool(body.get("dry_run", False)),
                                   None if vrb is None else bool(vrb)),
                             daemon=True).start()
            return self._send(200, {"ok": True, "running": True})

        if p == "/api/sec/phperrors/run":
            if PHPERR["running"]:
                return self._send(409, {"error": "analyse déjà en cours"})
            try:
                heures = max(1, min(720, int(body.get("hours", 24))))
            except (TypeError, ValueError):
                heures = 24
            threading.Thread(target=phperr_worker, args=(heures,), daemon=True).start()
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

        if p == "/api/mgmt/settings":
            patch = body.get("settings")
            if not isinstance(patch, dict):
                # tolérance : les réglages peuvent aussi arriver à plat
                patch = {k: v for k, v in body.items() if k in SETTINGS_DEFAULTS}
            patch = dict(patch)
            # Jeton VizProof : absent ou vide = INCHANGÉ (le champ du formulaire
            # reste vide quand on ne veut pas le retoucher). L'effacement est un
            # geste explicite : "" accompagné de vizproof_token_clear.
            efface = bool(patch.pop("vizproof_token_clear", body.get("vizproof_token_clear")))
            jeton = patch.pop("vizproof_token", None)
            if efface:
                patch["vizproof_token"] = ""
            elif jeton is not None and str(jeton).strip():
                jeton = str(jeton).strip()
                if not VIZ_ACCOUNT_TOKEN_RE.match(jeton):
                    return self._send(400, {"error": "jeton VizProof invalide "
                                                     "(vrt_… , 8 à 200 caractères après le préfixe)"})
                patch["vizproof_token"] = jeton
            if "vizproof_api_base" in patch:
                base = str(patch.get("vizproof_api_base") or "").strip() or VIZ_API_BASE_DEFAULT
                u, err = validate_public_url(base)   # même garde anti-SSRF que le sondage d'URL
                if err:
                    return self._send(400, {"error": f"base API refusée : {err}"})
                if u.scheme != "https":
                    return self._send(400, {"error": "base API : https exigé"})
                patch["vizproof_api_base"] = base.rstrip("/")
            return self._send(200, {"ok": True, "settings": settings_public(settings_write(patch))})

        if p == "/api/mgmt/vizproof/test":
            # Vérifie le jeton ENREGISTRÉ : rien n'est accepté depuis le corps,
            # pour qu'un jeton ne transite pas ici sans être stocké.
            jeton = viz_token_stored()
            if not jeton:
                return self._send(200, {"ok": False, "total": None, "error": VIZ_NO_TOKEN_MSG})
            _st, j, err = viz_api_call("/api/sites?limit=1", jeton)
            if err:
                return self._send(200, {"ok": False, "total": None, "error": err})
            total = (j or {}).get("total") if isinstance(j, dict) else None
            if not isinstance(total, int):
                lot = (j or {}).get("data") if isinstance(j, dict) else j
                total = len(lot) if isinstance(lot, list) else None
            return self._send(200, {"ok": True, "total": total, "error": None,
                                    "api_base": viz_api_base()})

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
            # le fichier contient le token du bot : 0600 posé par save_json (data/)
            save_json(ALERTS_PATH, new, mode=0o600)
            return self._send(200, {"ok": True, "enabled": new["enabled"], "chat_id": new["chat_id"],
                                    "rules": new["rules"], "token_set": bool(new["bot_token"]),
                                    "token_tail": new["bot_token"][-4:] if new["bot_token"] else ""})

        if p == "/api/mgmt/alerts/test":
            ok, err = telegram_send_sync("✅ <b>Dashboard parc</b> — message de test.")
            alerts_log("test: " + ("ok" if ok else f"échec ({err})"))
            return self._send(200, {"ok": ok, "error": err})

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
