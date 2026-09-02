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
import json
import os
import re
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
    """Règle d'affichage du dashboard : masqué si override False, ou sans moniteur Kuma
    quand l'affichage n'est pas forcé. Un site ajouté en REST est visible d'office :
    il a été déclaré explicitement, même s'il n'est pas encore supervisé par Kuma.

    Les choix de data/overrides.json ne sont PAS relus ici : collect.py les a déjà
    reportés sur la fiche du site (clé `visible`) au moment de la collecte.

    C'est la règle officielle de l'interface : la veille de vulnérabilités et le
    relevé d'erreurs PHP s'y conforment, sinon ils signaleraient des problèmes sur
    des installations que personne ne voit.
    """
    if site.get("visible") is False:
        return False
    if site.get("via") == "rest":
        return True
    if site.get("visible") is not True and "kuma" in site and not site.get("kuma"):
        return False
    return True
