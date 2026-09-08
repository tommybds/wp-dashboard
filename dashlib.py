#!/usr/bin/env python3
"""Fonctions utilitaires communes au dashboard (aucune dépendance interne).

Ce module existe pour qu'une seule copie de ces briques circule dans le dépôt :
elles étaient recopiées à l'identique dans actions_server.py, collect.py,
vulns.py et phperrors.py, et les copies commençaient à diverger (une correction
de sécurité appliquée à l'une passait à côté des autres).

Il ne doit RIEN importer du dépôt (ni actions_server, ni dashboard_config) :
actions_server.py, collect.py, vulns.py, phperrors.py, rotate.py et digest.py
l'importent tous, y compris en chaîne.

Les chemins (`BASE`, `DATA_DIR`, `PUBLIC_DIR`) sont dérivés de `__file__` comme
ils l'étaient dans chaque module. Attention : les fonctions d'écriture ne lisent
JAMAIS `DATA_DIR` directement, elles reçoivent le répertoire de données en
paramètre (`data_dir`). C'est ce qui permet à un module appelant — et aux tests,
qui redirigent `actions_server.DATA` vers un répertoire jetable — de garder la
main sur ses propres chemins.
"""
import ipaddress
import json
import os
import re
import socket
import tempfile
import threading
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
PUBLIC_DIR = os.path.join(BASE, "public")

# ---------------------------------------------------------------------------
#  Validation d'entrées (mêmes règles côté API et côté collecteur)
# ---------------------------------------------------------------------------
# Domaine ou clé de site (« exemple.fr », « exemple.fr/boutique »), sans « .. ».
SLUG_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9_.\-/]{0,80}$")
# Nom de serveur tel qu'il apparaît dans servers.json.
SERVER_RE = re.compile(r"^[a-z0-9-]{1,40}$")
# Docroot ou glob de docroot : chemin absolu, jeu de caractères restreint.
# Cette expression DOIT rester commune à l'API (qui valide ce que l'interface
# enregistre) et au collecteur (qui l'envoie au shell distant) : deux copies qui
# divergent, c'est un motif accepté à l'écriture puis exécuté sans contrôle.
PATH_PATTERN_RE = re.compile(r"^/[A-Za-z0-9_./*@-]+$")


def valid_path_pattern(value):
    """Glob de docroot acceptable : absolu, jeu de caractères restreint, sans « .. »."""
    p = str(value or "")
    return bool(PATH_PATTERN_RE.match(p)) and ".." not in p


# ---------------------------------------------------------------------------
#  Lecture / écriture JSON
# ---------------------------------------------------------------------------
def load_json(path, default):
    """Contenu JSON d'un fichier, ou `default` s'il est absent ou illisible."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


# Un tmp de nom fixe (« <path>.tmp ») faisait s'écraser deux écritures
# concurrentes : le second thread réutilisait le fichier du premier. Le tmp est
# donc unique, les droits sont posés AVANT le renommage (le fichier n'existe
# jamais brièvement en 0644), et chaque chemin a son verrou.
_JSON_LOCKS = {}
_JSON_LOCKS_GUARD = threading.Lock()


def json_lock(path):
    """Verrou dédié à un chemin (créé à la demande)."""
    cle = os.path.abspath(path)
    with _JSON_LOCKS_GUARD:
        verrou = _JSON_LOCKS.get(cle)
        if verrou is None:
            verrou = _JSON_LOCKS[cle] = threading.RLock()
        return verrou


def default_mode(path, data_dir=None):
    """0600 pour tout ce qui vit dans data/ (secrets, identifiants), 0644 ailleurs
    — public/fleet.json et servers.json sont lus hors du service.

    `data_dir` permet à l'appelant d'imposer SON répertoire de données plutôt que
    celui du dépôt : c'est indispensable dès que le module appelant peut le voir
    redirigé (tests, installation déplacée)."""
    try:
        cible = os.path.abspath(path)
        racine = os.path.abspath(data_dir if data_dir is not None else DATA_DIR)
        return 0o600 if cible.startswith(racine + os.sep) else 0o644
    except OSError:
        return 0o600


def save_json(path, obj, mode=None, data_dir=None, indent=1, fsync=False):
    """Écriture atomique d'un JSON (temporaire unique + os.replace).

    Les fichiers sont lus en concurrence par l'API, les tâches cron et le
    navigateur : un `open(…, "w")` les exposerait à un fichier tronqué.

    `mode` None = 0600 sous `data_dir`, 0644 ailleurs. `indent` None produit un
    JSON compact (caches volumineux). `fsync` force l'écriture sur disque avant
    le renommage.
    """
    if mode is None:
        mode = default_mode(path, data_dir)
    dossier = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-" + os.path.basename(path) + ".", dir=dossier)
    try:
        with os.fdopen(fd, "w") as fh:
            os.fchmod(fh.fileno(), mode)
            json.dump(obj, fh, ensure_ascii=False, indent=indent)
            if fsync:
                fh.flush()
                os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:                              # échec en cours de route : pas de résidu
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update_json(path, fn, default=None, mode=None, data_dir=None,
                indent=1, fsync=False):
    """Lecture → modification → écriture sous verrou. `fn(courant)` rend l'objet
    à écrire (ou None pour conserver le courant). → objet écrit."""
    with json_lock(path):
        courant = load_json(path, default)
        nouveau = fn(courant)
        if nouveau is None:
            nouveau = courant
        save_json(path, nouveau, mode=mode, data_dir=data_dir,
                  indent=indent, fsync=fsync)
        return nouveau


# ---------------------------------------------------------------------------
#  Shell
# ---------------------------------------------------------------------------
def sq(s):
    """Quotage shell d'un argument.

    Tout ce qui part dans une commande distante vient de JSON éditable depuis
    l'interface : sans ce quotage, un motif contenant une apostrophe s'exécute
    en root sur les serveurs du parc.
    """
    return "'" + str(s).replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
#  Identité d'un site
# ---------------------------------------------------------------------------
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


def site_visible(site):
    """Règle d'affichage du dashboard.

        override « masquer »  → masqué ;
        override « afficher » → visible ;
        « auto »              → visible SI le site est suivi.

    « Suivi » veut dire : il a un moniteur Uptime Kuma (quand Kuma est installé)
    OU il figure dans data/followed.json. Cette seconde source rend Kuma
    facultatif : une installation sans Kuma décide seule de ce qu'elle affiche.

    Les fichiers data/overrides.json et data/followed.json ne sont PAS relus ici :
    collect.py les a déjà reportés sur la fiche du site (clés `visible` et
    `followed`) au moment de la collecte. `site_visible` reste donc une fonction
    pure, appelée en boucle par tous les agrégats.

    Repli : une fiche produite AVANT la bascule n'a pas de clé `followed` ; on lui
    applique alors l'ancienne règle (`legacy_site_visible`), pour que l'écran ne
    change pas entre la bascule et la collecte suivante.

    C'est la règle officielle de l'interface : la veille de vulnérabilités et le
    relevé d'erreurs PHP s'y conforment, sinon ils signaleraient des problèmes sur
    des installations que personne ne voit.
    """
    if site.get("visible") is False:
        return False
    if site.get("visible") is True:
        return True
    if site.get("followed") is not None:
        # `primary` est faux sur la copie perdante d'un domaine présent sur deux
        # serveurs : la suivre afficherait deux fois le même site. Un affichage
        # forcé (`show`) reste prioritaire, il a été traité au-dessus.
        return bool(site.get("followed")) and site.get("primary", True) is not False
    return legacy_site_visible(site)


def legacy_site_visible(site):
    """Règle d'affichage EN VIGUEUR AVANT que Uptime Kuma devienne facultatif.

    Conservée pour deux usages, et deux seulement :
      * la migration `ensure_followed_migrated()`, qui doit reprendre EXACTEMENT
        la sélection affichée le jour de la bascule ;
      * le repli de `site_visible()` sur une fiche sans clé `followed`.
    """
    if site.get("visible") is False:
        return False
    if site.get("via") == "rest":
        return True
    if site.get("visible") is not True and "kuma" in site and not site.get("kuma"):
        return False
    return True


# ---------------------------------------------------------------------------
#  Sites suivis — data/followed.json
# ---------------------------------------------------------------------------
# Liste JSON de clés de site (« exemple.fr », « exemple.fr/boutique »). C'est la
# source de vérité PROPRE AU DASHBOARD de ce qui est supervisé : un install
# découvert par la collecte reste masqué tant qu'il n'y figure pas — sauf s'il a
# un moniteur Kuma, qui vaut suivi lui aussi.
FOLLOWED_FILE = "followed.json"


def followed_path(data_dir=None):
    return os.path.join(data_dir if data_dir is not None else DATA_DIR, FOLLOWED_FILE)


def load_followed(data_dir=None):
    """Ensemble des clés de site suivies (vide si le fichier est absent)."""
    raw = load_json(followed_path(data_dir), None)
    if isinstance(raw, list):
        return {str(x) for x in raw if isinstance(x, str) and x}
    if isinstance(raw, dict):        # tolérance : {"exemple.fr": true}
        return {str(k) for k, v in raw.items() if v}
    return set()


def set_followed(domain, followed, data_dir=None):
    """Ajoute ou retire un site de la liste → liste triée, écrite sur disque."""
    dom = str(domain or "")

    def _muter(courant):
        vus = set()
        if isinstance(courant, list):
            vus = {str(x) for x in courant if isinstance(x, str) and x}
        elif isinstance(courant, dict):
            vus = {str(k) for k, v in courant.items() if v}
        if followed:
            vus.add(dom)
        else:
            vus.discard(dom)
        return sorted(vus)

    return update_json(followed_path(data_dir), _muter, [], data_dir=data_dir)


def ensure_followed_migrated(data_dir=None, fleet=None):
    """Première bascule : inscrit dans followed.json tout site VISIBLE aujourd'hui.

    Sans elle, activer la nouvelle règle viderait l'écran — plus aucun site ne
    serait « suivi » le premier jour. La sélection est donc calculée sur
    `fleet.json` TEL QU'IL EST SUR LE DISQUE (produit par l'ancienne règle, il
    porte encore la clé `kuma` de chaque site) avec `legacy_site_visible` : le
    nombre de sites affichés est identique avant et après.

    Idempotente : le marqueur est l'EXISTENCE du fichier, testée puis écrite sous
    le verrou du chemin. Un second appel ne recalcule rien — y compris si tout a
    été décoché entre-temps (le fichier existe, fût-il vide) ou si deux processus
    démarrent en même temps. → liste écrite, ou None si la migration a déjà eu lieu.
    """
    chemin = followed_path(data_dir)
    with json_lock(chemin):
        if os.path.exists(chemin):
            return None
        if fleet is None:
            fleet = load_json(os.path.join(data_dir if data_dir is not None else DATA_DIR,
                                           "fleet.json"), None)
        doms = set()
        for srv in ((fleet or {}).get("servers") or []):
            if not isinstance(srv, dict):
                continue
            for s in (srv.get("sites") or []):
                if isinstance(s, dict) and s.get("domain") and legacy_site_visible(s):
                    doms.add(str(s["domain"]))
        suivis = sorted(doms)
        save_json(chemin, suivis, data_dir=data_dir)
        return suivis


# ---------------------------------------------------------------------------
#  Garde anti-SSRF (partagée par l'API et par les sondes du collecteur)
# ---------------------------------------------------------------------------
# Elle vivait dans actions_server.py ; les sondes de collect.py en ont besoin
# aussi, et deux copies d'un contrôle de sécurité, c'est une copie qui finit par
# diverger. Elle est ici pour n'exister qu'une fois.
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


# ---------------------------------------------------------------------------
#  Uptime Kuma : le branchement EFFECTIF, en un seul endroit
# ---------------------------------------------------------------------------
# Trois valeurs relient le dashboard à Uptime Kuma : le slug de la status page,
# le nom du conteneur Docker et le chemin de la base SQLite dans ce conteneur
# (plus l'URL de la status page, rarement touchée). Elles vivaient uniquement
# dans config.json — lu UNE fois au démarrage puis figé dans des constantes de
# module (actions_server.KUMA_DB, collect.KUMA_STATUS…) : les changer voulait
# dire éditer un fichier sur le serveur ET redémarrer le service.
#
# Elles se surchargent maintenant depuis l'interface, dans data/settings.json,
# qui est relu à chaque appel. `kuma_conf()` est la SEULE lecture autorisée :
# tout point du code qui garderait une copie figée rendrait de nouveau un
# changement d'interface sans effet jusqu'au redémarrage — c'est exactement le
# défaut corrigé ici, et un test le vérifie en relisant les sources.
#
# Ordre de fusion, du plus faible au plus fort :
#     valeurs par défaut  →  config.json  →  data/settings.json
# Une surcharge VIDE dans settings.json ne compte pas : effacer le champ dans
# l'interface redonne donc la main à config.json.
KUMA_DEFAULTS = {
    "enabled": "auto",
    "slug": "",
    "container": "uptime-kuma",
    "db": "/app/data/kuma.db",
    "status_url": "http://127.0.0.1:3001/api/status-page/",
}
# Clé rendue par kuma_conf() ↔ clé telle qu'elle s'écrit dans config.json et
# dans data/settings.json. `kuma_enabled` n'en fait pas partie : il reste un
# choix d'installation, il ne s'écrit pas depuis l'interface.
KUMA_KEYS = (("slug", "kuma_slug"), ("container", "kuma_container"),
             ("db", "kuma_db"), ("status_url", "kuma_status_url"))

# Règles de validation des surcharges (mêmes règles côté API et côté tests).
KUMA_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{0,64}$")
KUMA_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Chemin absolu DANS le conteneur : jeu de caractères restreint, « .. » interdit
# (la valeur part en argv d'un `docker exec … sqlite3 <chemin>`).
KUMA_DB_RE = re.compile(r"^/[A-Za-z0-9_./-]{1,200}$")
# Hôtes considérés « locaux » : la status page est jointe sur la machine même,
# elle n'a aucune raison de sortir.
KUMA_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def kuma_status_url_error(url):
    """Message de refus d'une URL de status page, ou « » si elle est acceptable.

    http n'est toléré que vers 127.0.0.1 / localhost : cette URL sert à joindre
    Kuma en local, pas à sortir. Toute autre destination doit être en https ET
    passer la garde anti-SSRF commune (`validate_public_url`).
    """
    s = str(url or "").strip()
    if not s:
        return ""                     # vide = pas de surcharge, rien à valider
    try:
        u = urllib.parse.urlsplit(s)
    except ValueError:
        return "url invalide"
    if u.scheme not in ("http", "https"):
        return "url : http://127.0.0.1 ou https attendu"
    if not u.hostname:
        return "url : hôte manquant"
    if "@" in (u.netloc or ""):
        return "url : identifiants interdits"
    if (u.hostname or "").lower().strip("[]") in KUMA_LOCAL_HOSTS:
        return ""                     # Kuma en local : pas de résolution DNS à faire
    if u.scheme != "https":
        return "url : hors 127.0.0.1 et localhost, https est exigé"
    _, err = validate_public_url(s)
    return f"url refusée : {err}" if err else ""


def kuma_settings_errors(patch):
    """{clé: message} pour chaque surcharge Kuma refusée d'un lot de réglages.

    Une valeur vide est TOUJOURS acceptée : c'est le geste « effacer la
    surcharge », qui redonne la main à config.json.
    """
    errs = {}
    if not isinstance(patch, dict):
        return errs
    if "kuma_slug" in patch:
        v = str(patch.get("kuma_slug") or "").strip()
        if not KUMA_SLUG_RE.match(v):
            errs["kuma_slug"] = ("slug invalide : lettres, chiffres, « _ » et « - » "
                                 "seulement, 64 caractères au plus")
    if "kuma_container" in patch:
        v = str(patch.get("kuma_container") or "").strip()
        if v and not KUMA_CONTAINER_RE.match(v):
            errs["kuma_container"] = ("nom de conteneur invalide : il commence par une "
                                      "lettre ou un chiffre, puis lettres, chiffres, "
                                      "« _ », « . » et « - », 64 caractères au plus")
    if "kuma_db" in patch:
        v = str(patch.get("kuma_db") or "").strip()
        if v and (".." in v or not KUMA_DB_RE.match(v)):
            errs["kuma_db"] = ("chemin invalide : chemin absolu DANS le conteneur, "
                               "sans « .. », 200 caractères au plus")
    if "kuma_status_url" in patch:
        err = kuma_status_url_error(patch.get("kuma_status_url"))
        if err:
            errs["kuma_status_url"] = err
    return errs


def kuma_conf(data_dir=None, config=None, base=None, overrides=None):
    """Branchement Uptime Kuma effectif → {slug, container, db, status_url, enabled}.

    Fusionne, dans cet ordre : `KUMA_DEFAULTS`, puis `config.json` (passé par
    l'appelant via `config`, sinon lu dans `base`), puis les surcharges
    persistantes de `<data_dir>/settings.json`.

    `overrides` ajoute une DERNIÈRE couche, non persistée : c'est ce dont a
    besoin le bouton « Tester la connexion », qui doit essayer les valeurs
    saisies sans les enregistrer — et obtenir exactement l'assemblage (slug
    ajouté à l'URL) que produirait un enregistrement.

    Appelée à CHAQUE usage, jamais mise en cache par l'appelant : c'est ce qui
    fait qu'une valeur changée dans l'interface prend effet tout de suite.

    Le slug est ajouté à l'URL de la status page quand celle-ci se termine par
    « / » — l'assemblage se fait ici et nulle part ailleurs, sans quoi une URL
    déjà complétée avec l'ANCIEN slug survivrait à un changement de slug.
    """
    out = dict(KUMA_DEFAULTS)
    brut = config if isinstance(config, dict) else load_json(
        os.path.join(base if base is not None else BASE, "config.json"), {})
    if isinstance(brut, dict):
        if brut.get("kuma_enabled") is not None:
            out["enabled"] = brut["kuma_enabled"]
        for cle, source in KUMA_KEYS:
            if brut.get(source) is not None:
                out[cle] = str(brut[source]).strip()
    reglages = load_json(os.path.join(
        data_dir if data_dir is not None else DATA_DIR, "settings.json"), {})
    for couche in (reglages, overrides):
        if not isinstance(couche, dict):
            continue
        for cle, source in KUMA_KEYS:
            valeur = str(couche.get(source) or "").strip()
            if valeur:
                out[cle] = valeur
    url = str(out["status_url"] or "").strip()
    if out["slug"] and url.endswith("/"):
        url += out["slug"]
    out["status_url"] = url
    return out
