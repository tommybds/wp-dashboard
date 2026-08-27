#!/usr/bin/env python3
"""Configuration de déploiement du dashboard.

Toutes les valeurs propres à une installation (URL publique, clé SSH, instance
Uptime Kuma, compte administrateur créé sur les sites) sont lues ici depuis
`config.json`. Ce fichier n'est PAS versionné (voir .gitignore) : chacun copie
`config.example.json` en `config.json` et renseigne ses propres valeurs.

Chaque clé possède un défaut raisonnable ; `config.json` ne surcharge que ce
qu'il définit. Les clés inconnues du fichier sont ignorées.
"""
import os, json

BASE = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
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
