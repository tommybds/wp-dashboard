#!/usr/bin/env python3
"""Configuration de déploiement du dashboard.

Toutes les valeurs propres à une installation (URL publique, clé SSH, instance
Uptime Kuma, compte administrateur créé sur les sites) sont lues ici depuis
`config.json`. Ce fichier n'est PAS versionné (voir .gitignore) : chacun copie
`config.example.json` en `config.json` et renseigne ses propres valeurs.

Chaque clé possède un défaut raisonnable ; `config.json` ne surcharge que ce
qu'il définit. Les clés inconnues du fichier sont ignorées.
"""
import os, json, subprocess, threading, time

BASE = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
    # Uptime Kuma est OPTIONNEL depuis la bascule de septembre 2026.
    #   "auto" (défaut) : présent si le conteneur répond, absent sinon ;
    #   true / false    : forcent la réponse, sans sonder.
    # Absent ou désactivé, PLUS AUCUN `docker exec` n'est lancé et le dashboard
    # se rabat sur ses propres sondes (cf. collect.probe_fleet).
    "kuma_enabled": "auto",
    # URL publique du dashboard (sans slash final). Sert à construire l'endpoint
    # d'ingestion des agents et les URL de retour du flux d'autorisation WordPress.
    "dashboard_url": "https://dashboard.example.com",
    # Clé SSH par défaut pour joindre les serveurs. Une clé par serveur peut la
    # surcharger via le champ "key" de servers.json.
    "ssh_key": "/root/.ssh/id_dashboard",
    # Uptime Kuma tournant en conteneur Docker : nom du conteneur et chemin de la
    # base SQLite DANS le conteneur (défauts standards de l'image louislam/uptime-kuma).
    "kuma_container": "uptime-kuma",
    "kuma_db": "/app/data/kuma.db",
    # Slug de la status page Kuma qui liste les moniteurs du parc (obligatoire pour
    # relier chaque site à son moniteur). Créez une status page privée dans Kuma
    # et reportez son slug ici.
    "kuma_slug": "",
    # URL JSON de cette status page. Laissez le défaut se terminer par "/" : le
    # slug y est ajouté automatiquement. Surchargez seulement si Kuma n'est pas
    # joignable en local sur le port 3001.
    "kuma_status_url": "http://127.0.0.1:3001/api/status-page/",
    # Compte administrateur que le dashboard crée sur un site lors de la liaison
    # « en un clic » (login + base de l'adresse e-mail).
    "bot_admin_login": "dashboard_agent",
    "bot_admin_email": "admin@example.com",
    # Slugs d'extensions à ne PAS soumettre à la veille de vulnérabilités :
    # mu-plugins maison, extensions internes… (les drop-ins WordPress sont déjà
    # ignorés en dur par vulns.py). Liste de chaînes, vide par défaut.
    "vuln_skip_slugs": [],
}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(os.path.join(BASE, "config.json")) as fh:
            raw = json.load(fh)
        if isinstance(raw, dict):
            cfg.update({k: v for k, v in raw.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass  # pas de config.json → défauts (installation non finalisée)
    # Confort : si seul le slug est fourni, on complète l'URL de la status page.
    if cfg["kuma_slug"] and cfg["kuma_status_url"].rstrip().endswith("/"):
        cfg["kuma_status_url"] = cfg["kuma_status_url"].rstrip() + cfg["kuma_slug"]
    cfg["dashboard_url"] = cfg["dashboard_url"].rstrip("/")
    return cfg


CONFIG = load_config()


# ---------------------------------------------------------------------------
#  Uptime Kuma : présent ou non ?
# ---------------------------------------------------------------------------
# UNE seule fonction fait autorité — `kuma_disponible()`. Tout ce qui voulait
# parler à Kuma (actions_server, collect) l'interroge d'abord ; personne ne
# lance `docker exec` sans être passé par là. Le résultat est mis en cache
# 60 s : sonder à chaque requête HTTP coûterait un `docker exec` par appel,
# et une installation SANS Kuma paierait ce prix pour rien.
KUMA_CACHE_TTL = 60          # secondes
KUMA_PROBE_TIMEOUT = 8       # secondes laissées au conteneur pour répondre
KUMA_ABSENT_MSG = "Uptime Kuma n'est pas configuré"

_KUMA_CACHE = {"ts": 0.0, "enabled": None, "reason": ""}
_KUMA_LOCK = threading.Lock()


def _kuma_probe():
    """Sonde réelle : une requête triviale dans la base du conteneur → (bool, raison).

    La commande est passée en argv (aucune interpolation shell) et la requête
    est constante. Un conteneur arrêté, un docker absent ou un délai dépassé
    donnent tous « absent » — jamais une exception qui remonterait en 500.
    """
    conteneur = str(CONFIG.get("kuma_container") or "")
    base = str(CONFIG.get("kuma_db") or "")
    if not conteneur or not base:
        return False, "kuma_container ou kuma_db vide dans config.json"
    try:
        r = subprocess.run(["docker", "exec", conteneur, "sqlite3", base, "SELECT 1;"],
                           capture_output=True, text=True, timeout=KUMA_PROBE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "conteneur Uptime Kuma : délai dépassé"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"docker indisponible ({type(e).__name__})"
    if r.returncode != 0:
        return False, (f"conteneur « {conteneur} » injoignable : "
                       + ((r.stderr or r.stdout or "").strip() or f"rc={r.returncode}"))[:200]
    return True, f"conteneur « {conteneur} » joignable"


def kuma_statut(force=False):
    """{"enabled": bool, "reason": str} — état de Kuma, mis en cache 60 s.

    `force=True` ignore le cache (utile après une action qui redémarre Kuma).
    """
    reglage = CONFIG.get("kuma_enabled", "auto")
    if reglage is False or str(reglage).strip().lower() in ("false", "0", "off", "no", "non"):
        return {"enabled": False, "reason": "désactivé dans config.json (kuma_enabled=false)"}
    if reglage is True or str(reglage).strip().lower() in ("true", "1", "on", "yes", "oui"):
        return {"enabled": True, "reason": "forcé dans config.json (kuma_enabled=true)"}
    # "auto" (ou n'importe quelle autre valeur) : on sonde, avec cache.
    with _KUMA_LOCK:
        frais = (not force and _KUMA_CACHE["enabled"] is not None
                 and (time.monotonic() - _KUMA_CACHE["ts"]) < KUMA_CACHE_TTL)
        if frais:
            return {"enabled": _KUMA_CACHE["enabled"], "reason": _KUMA_CACHE["reason"]}
        ok, raison = _kuma_probe()
        _KUMA_CACHE.update({"ts": time.monotonic(), "enabled": ok, "reason": raison})
        return {"enabled": ok, "reason": raison}


def kuma_disponible(force=False):
    """True si Kuma est utilisable. À interroger AVANT tout `docker exec`."""
    return bool(kuma_statut(force)["enabled"])


def reset_kuma_cache():
    """Vide le cache de détection (tests, rechargement de configuration)."""
    with _KUMA_LOCK:
        _KUMA_CACHE.update({"ts": 0.0, "enabled": None, "reason": ""})
