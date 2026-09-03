#!/usr/bin/env python3
"""Page bouchonnée : sert public/ en local avec un backend simulé.

Aucun accès à la production. `window.fetch` est remplacé, dans la page servie,
par un aiguillage vers des fixtures : les vraies réponses déposées dans
scratchpad/fixture/<nom>.json si elles existent, sinon des réponses fabriquées.

    python3 tools/preview.py                 # 20 sites, parc « normal »
    python3 tools/preview.py --scenario vide # aucun site
    python3 tools/preview.py --scenario gros # 200 sites
    python3 tools/preview.py --scenario stale --port 8788

Scénarios : normal · vide · gros · stale (serveur injoignable) ·
            anomalie (anomalie visuelle VizProof) ·
            joblent (collecte, MAJ sûre et MAJ sous contrôle visuel en cours)
"""
import argparse
import http.server
import json
import pathlib
import random
import re
import socketserver
import sys
import time
from datetime import datetime, timedelta

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
FIXTURES = ROOT / "scratchpad" / "fixture"

SCENARIO = "normal"


# ---------------------------------------------------------------- fabrication
def now(offset_h=0):
    return (datetime.now() - timedelta(hours=offset_h)).strftime("%Y-%m-%d %H:%M:%S")


def faux_site(i, srv, rng):
    dom = f"site-{i:02d}.exemple.fr"
    maj = rng.randint(0, 6)
    core = rng.choice(["6.8.8", "7.1", "7.1", "7.0.4"])
    plugins = [{"name": f"plugin-{k}", "version": f"1.{k}.0", "status": "active",
                "update": "available" if k < maj else "none",
                "to": f"1.{k}.1"} for k in range(rng.randint(6, 22))]
    if i % 4 == 0:
        plugins.append({"name": "vizproof-timeline", "version": "1.4.2", "status": "active", "update": "none"})
    s = {
        "domain": dom, "kuma": dom, "kuma_group": rng.choice(["Sumotori", "Client A", "Client B"]),
        "blogname": f"Site {i}", "siteurl": f"https://{dom}",
        "path": f"/var/www/vhosts/{dom}/httpdocs",
        "core_version": core, "core_update": "7.1" if core != "7.1" else "",
        "plugins_total": len(plugins), "plugins_active": len(plugins),
        "plugins_updates": maj, "plugins_auto_update": rng.choice([0, len(plugins)]),
        "themes_updates": rng.choice([0, 0, 1]),
        "php_version": rng.choice(["8.1.2", "8.2.7", "8.3.1", "7.4.33"]),
        "admins": [{"login": "admin", "email": "a@b.fr", "registered": "2024-01-01"}],
        "errors": {},
        "collected_at": now(0),
        "updraft": {"last_backup_ts": time.time() - rng.choice([3600, 7200, 200000]),
                    "interval": "daily", "retain": 42, "interval_db": "daily",
                    "retain_db": 42, "service": "sftp", "extrarules": {}},
    }
    if i % 4 == 0:
        s["vizproof"] = {
            "connected": True, "configured": True, "version": "1.4.2", "has_cli": True,
            "pages": 3, "site_id": f"site-{i:02d}",
            "last_run": {"at": now(2), "anomalies": 2 if SCENARIO == "anomalie" else 0,
                         "status": "ok", "url": "https://vizproof.example/r/1"},
        }
    if i % 7 == 0:
        s["via"] = "rest"
    # Quelques installs SANS moniteur Kuma : c'est le cas qui fait apparaître
    # « créer moniteur » et le filtre « sans moniteur » de l'écran Gestion.
    if i % 9 == 4:
        s["kuma"] = ""
    s["plugins_list"] = plugins
    s["plugins_updates_list"] = [p["name"] for p in plugins if p.get("update") == "available"]
    return s


def fleet():
    rng = random.Random(42)
    n = {"vide": 0, "gros": 200}.get(SCENARIO, 20)
    serveurs = []
    for si, nom in enumerate(["plesk-mutu", "vps-1", "vps-2"]):
        sites = [faux_site(i, nom, rng) for i in range(si, n, 3)]
        srv = {"name": nom, "sites": sites}
        if SCENARIO == "stale" and si == 1:
            srv.update({"stale": True, "error": "ssh: connect timeout",
                        "last_attempt": now(3), "sites": sites})
        serveurs.append(srv)
    return {"generated_at": now(0), "servers": serveurs}


def status_cfg():
    f = fleet()
    mons, i = [], 1
    for s in f["servers"]:
        for x in s["sites"]:
            mons.append({"id": i, "name": x["domain"]})
            i += 1
    return {"publicGroupList": [{"monitorList": mons}]}


def status_hb():
    cfg = status_cfg()
    out = {}
    for k, m in enumerate(cfg["publicGroupList"][0]["monitorList"]):
        out[str(m["id"])] = [{"status": 0 if k % 9 == 0 else 1}]
    return {"heartbeatList": out}


def historique():
    base = datetime.now() - timedelta(days=7)
    return {"history": [{
        "ts": (base + timedelta(minutes=30 * k)).strftime("%Y-%m-%d %H:%M:%S"),
        "sites": 20 + (k % 3), "plugin_updates": 60 - k // 3,
        "core_updates": 5 - (k % 4), "errors": k % 3,
    } for k in range(120)]}


def vulns():
    f = fleet()
    sites = []
    for s in f["servers"]:
        for x in s["sites"][:4]:
            sites.append({
                "domain": x["domain"], "server": s["name"], "via": x.get("via", "ssh"),
                "count": 3, "worst": "high",
                "findings": [
                    {"component": "plugin-1", "version": "1.1.0", "kind": "plugin",
                     "severity": "high", "title": "XSS stockée", "cve": "CVE-2025-0001",
                     "link": "https://example.org/cve", "update_to": "1.1.1", "unfixed": False},
                    {"component": "plugin-2", "version": "1.2.0", "kind": "plugin",
                     "severity": "critical", "title": "RCE", "cve": "CVE-2025-0002",
                     "link": "https://example.org/cve", "update_to": "", "unfixed": True},
                    {"component": "wordpress", "version": x["core_version"], "kind": "core",
                     "severity": "medium", "title": "SSRF", "cve": "CVE-2025-0003",
                     "link": "", "update_to": "7.1", "unfixed": False},
                ],
            })
    return {"sites": sites, "sites_scanned": 20, "sites_affected": len(sites),
            "totals": {"critical": len(sites), "high": len(sites), "medium": len(sites)},
            "php": [{"version": "7.4.33", "worst": "high", "count": 12,
                     "sites": ["site-03.exemple.fr", "site-07.exemple.fr"]}],
            "generated_at": now(0), "running": False}


def phperrors():
    return {"sites": [{"domain": "site-01.exemple.fr", "total": 42, "groups": [
        {"severity": "Fatal error", "count": 12, "message": "Uncaught Error: Call to undefined function",
         "short": "wp-content/plugins/x/x.php", "line": 42, "last": now(1)},
        {"severity": "Warning", "count": 30, "message": "Undefined array key \"id\"",
         "short": "wp-content/themes/y/functions.php", "line": 7, "last": now(3)},
    ]}], "sites_with_errors": 1, "total": 42, "fatals": 12,
        "generated_at": now(0), "running": False,
        "truncated": {}, "servers_failed": {}}


def incidents():
    """File « à traiter » : les deux gravités du backend (plus une inconnue),
    neuf types, trois formes d'action et une source en échec.

    Volontairement bâtie « à la main » plutôt que dérivée de fleet() : c'est le
    rendu de la file qu'on veut éprouver (gravités, ancienneté, action en ligne,
    lien seul, incident sans site, type inattendu), pas la logique du backend.
    """
    def iso(h):
        return (datetime.now() - timedelta(hours=h)).replace(microsecond=0).isoformat()

    inc = [
        {"id": "down:site-00.exemple.fr:", "severity": "critical", "kind": "down",
         "site": "site-00.exemple.fr", "server": "plesk-mutu",
         "title": "site-00.exemple.fr injoignable",
         "detail": "moniteur Kuma en échec — 503 Service Unavailable",
         "since": iso(216), "age_h": 216.0,
         "action": {"label": "Re-scan", "act": "rescan", "arg": ""},
         "link": {"tab": "incidents", "sub": ""}},
        {"id": "vuln_critical_fixable:site-01.exemple.fr:plugin-2", "severity": "critical",
         "kind": "vuln_critical_fixable", "site": "site-01.exemple.fr", "server": "vps-1",
         "title": "plugin-2 1.2.0 · critical corrigeable",
         "detail": "RCE (CVE-2025-0002) — correctif en 1.2.1",
         "since": iso(30), "age_h": 30.0,
         "action": {"label": "MAJ plugin-2 → 1.2.1", "act": "plugin_update", "arg": "plugin-2"},
         "link": {"tab": "securite", "sub": "vulns"}},
        {"id": "admin_unknown:site-02.exemple.fr:wpsvc", "severity": "critical",
         "kind": "admin_unknown", "site": "site-02.exemple.fr", "server": "vps-2",
         "title": "Administrateur inconnu sur site-02.exemple.fr",
         "detail": "compte « wpsvc_fkmdmu » absent de la référence (inscrit le 2026-08-11)",
         "since": iso(72), "age_h": 72.0, "action": None,
         "link": {"tab": "securite", "sub": "admins"}},
        {"id": "backup_late:site-03.exemple.fr:", "severity": "warning", "kind": "backup_late",
         "site": "site-03.exemple.fr", "server": "plesk-mutu",
         "title": "Sauvegarde en retard sur site-03.exemple.fr",
         "detail": "dernière sauvegarde il y a 56 h — seuil 48 h",
         "since": iso(56), "age_h": 56.0,
         "action": {"label": "Sauvegarder", "act": "updraft_backup", "arg": ""},
         "link": {"tab": "parc", "sub": ""}},
        {"id": "php_eol:vps-1:7.4", "severity": "warning", "kind": "php_eol",
         "site": "", "server": "vps-1",
         "title": "PHP 7.4 en fin de support sur vps-1",
         "detail": "3 site(s) : site-04.exemple.fr, site-07.exemple.fr, site-10.exemple.fr",
         "since": None, "age_h": 0.0, "action": None,
         "link": {"tab": "securite", "sub": "php"}},
        {"id": "php_fatal:site-01.exemple.fr:x.php:42", "severity": "critical", "kind": "php_fatal",
         "site": "site-01.exemple.fr", "server": "vps-1",
         "title": "Fatal error sur site-01.exemple.fr",
         "detail": "Uncaught Error: Call to undefined function — "
                   "wp-content/plugins/x/x.php:42 (×12)",
         "since": iso(11), "age_h": 11.0, "action": None,
         "link": {"tab": "securite", "sub": "phperrors"}},
        {"id": "checksums_modified:site-05.exemple.fr:", "severity": "critical",
         "kind": "checksums_modified", "site": "site-05.exemple.fr", "server": "vps-2",
         "title": "Intégrité du cœur en échec sur site-05.exemple.fr",
         "detail": "3 fichier(s) ne correspondent pas au cœur officiel — "
                   "wp-includes/load.php doesn't verify against checksum",
         "since": iso(5), "age_h": 5.0,
         "action": {"label": "Vérifier", "act": "verify_checksums", "arg": ""},
         "link": {"tab": "securite", "sub": "checksums"}},
        {"id": "cert_expiring:site-01.exemple.fr:", "severity": "warning", "kind": "cert_expiring",
         "site": "site-01.exemple.fr", "server": "vps-1",
         "title": "Certificat de site-01.exemple.fr à renouveler",
         "detail": "expire dans 6 jour(s) (le 2026-09-09) — seuil 21 j",
         "since": None, "age_h": 0.0, "action": None,
         "link": {"tab": "securite", "sub": "certs"}},
        # Gravité inconnue du front : elle doit rester visible, pas disparaître.
        {"id": "inattendu:site-06.exemple.fr:", "severity": "info", "kind": "type_inconnu",
         "site": "site-06.exemple.fr", "server": "vps-2",
         "title": "Type d'incident inconnu du front",
         "detail": "backend plus récent que l'interface : la ligne reste lisible",
         "since": iso(1), "age_h": 1.0, "action": None, "link": None},
    ]
    if SCENARIO == "stale":
        inc.append({"id": "server_stale:vps-1:", "severity": "warning", "kind": "server_stale",
                    "site": "", "server": "vps-1", "title": "Serveur vps-1 injoignable",
                    "detail": "ssh: connect timeout — dernière tentative il y a 3 h",
                    "since": iso(3), "age_h": 3.0, "action": None,
                    "link": {"tab": "gestion", "sub": "serveurs"}})
    if SCENARIO == "vide":
        inc = []
    # Une source en échec : la file doit le DIRE, sinon « rien à traiter » se
    # confond avec « on n'a pas pu regarder ».
    errs = [] if SCENARIO == "vide" else [
        {"source": "certs", "error": "RuntimeError: docker exec: conteneur uptime-kuma absent"}]
    return {"generated_at": now(0),
            "counts": {"critical": sum(1 for i in inc if i["severity"] == "critical"),
                       "warning": sum(1 for i in inc if i["severity"] == "warning")},
            "incidents": inc, "errors": errs}


def sidebar_counts():
    """Pastilles de la barre latérale, comme le backend : `counts` ne compte que
    `critical` et `warning`. La file bouchonnée porte EN PLUS un incident de
    gravité inconnue (pour éprouver le groupe « Autres »), d'où un écart de 1
    entre la pastille et la longueur de la liste — écart impossible en
    production, où le backend n'émet que ces deux gravités.
    """
    p = incidents()
    return {"incidents": dict(p["counts"]),
            "securite": {"vulns_fixable": 6, "admins_unknown": 1},
            "parc": {"updates_sites": 12}}


def safe_update_status():
    """Scénario « joblent » : une MAJ sûre en cours sur le premier site SSH."""
    if SCENARIO != "joblent":
        return {"running": False, "domain": "", "steps": [], "verdict": ""}
    return {"running": True, "domain": "site-00.exemple.fr", "verdict": "",
            "steps": [
                {"label": "Contrôle avant", "ok": True, "ts": now(0), "detail": ""},
                {"label": "Liste des mises à jour", "ok": True, "ts": now(0), "detail": "4 extensions"},
                {"label": "Sauvegarde UpdraftPlus", "ok": True, "ts": now(0), "detail": ""},
                {"label": "Archivage des fichiers", "ok": True, "ts": now(0),
                 "detail": "wp-content/plugins/plugin-1, plugin-2"},
                {"label": "Mise à jour", "ok": True, "ts": now(0), "detail": "en cours…"},
            ]}


def viz_update_status():
    if SCENARIO != "joblent":
        return {"running": False, "steps": []}
    return {"running": True, "result": None, "steps": [
        {"key": "baseline", "label": "Baseline VizProof", "status": "ok", "ts": now(0), "detail": ""},
        {"key": "update", "label": "Mise à jour des extensions", "status": "en cours",
         "ts": now(0), "detail": ""},
        {"key": "viz", "label": "Contrôle visuel", "status": "attente", "ts": "", "detail": ""},
        {"key": "rescan", "label": "Inventaire", "status": "attente", "ts": "", "detail": ""},
    ]}


# État mutable de la page bouchonnée : sans lui, un POST répondait toujours
# `{"ok":true}` et l'interface ne pouvait pas montrer l'effet d'une action
# (geler/dégeler une extension, sortie d'une commande, tâche groupée, ajout
# d'un serveur, réglage enregistré).
POLICY = {"frozen": ["plugin-4"]}
BULK = {"tasks": [], "done": 0, "total": 0, "running": False}

SETTINGS = {
    "viz_anomaly_rollback": False, "viz_scan_after_update": True,
    "viz_baseline_before_update": True, "viz_baseline_required": False,
    "vizproof_token_set": True, "vizproof_token_tail": "9f2c",
    "vizproof_api_base": "https://vizproof.com",
    "incident_rules": {"backup_max_age_h": 48, "cert_warn_days": 21,
                       "cert_critical_days": 7, "vuln_high_is_incident": False,
                       "php_eol_versions": ["7.0", "7.1", "7.2", "7.3", "7.4", "8.0"]},
}
ALERTES = {"enabled": True, "token_set": True, "token_tail": "aa42", "chat_id": "-100123",
           "rules": {"new_admin": True, "checksum_fail": True, "viz_anomaly": False,
                     "site_down": True, "backup_stale_h": 48, "cert_days": 21,
                     "collect_dead_h": 6}}
SCHEDULE = {"interval_minutes": 30, "choices": [0, 15, 30, 60, 120, 180, 360, 720, 1440],
            "cron": "*/30 * * * *", "ok": True}
SSHKEYS = {"keys": [
    {"name": "dashboard", "path": "/root/.ssh/id_dashboard", "type": "ed25519",
     "fingerprint": "SHA256:8p1c…", "pub": "ssh-ed25519 AAAAC3Nza… wp-dashboard"},
    {"name": "sumotori", "path": "/root/.ssh/dash_sumotori", "type": "ed25519",
     "fingerprint": "SHA256:q3Ze…", "pub": "ssh-ed25519 AAAAC3Nza… sumotori"}],
    "assignments": [{"server": "plesk-mutu", "key": "/root/.ssh/id_dashboard"},
                    {"server": "vps-1", "key": "/root/.ssh/id_dashboard"},
                    {"server": "vps-2", "key": "/root/.ssh/dash_sumotori"}]}
REST_SITES = [
    {"domain": "site-07.exemple.fr", "url": "https://site-07.exemple.fr", "name": "Site 7",
     "added_at": now(48), "multisite": False, "server": ""},
    {"domain": "boutique.exemple.fr", "url": "https://boutique.exemple.fr", "name": "Boutique",
     "added_at": now(300), "multisite": True, "server": ""},
]
# Identifiants WordPress : un site sur deux est autorisé, pour que les deux
# états (« autorisé + Révoquer » et « non autorisé + Autoriser ») se voient.
WPCRED = {"site-07.exemple.fr": {"has_password": True, "user": "dash_bot",
                                 "verified": True, "checked_ts": now(5)}}

# Pages surveillées par VizProof : huit pages, l'accueil en tête et UNE SEULE
# pré-cochée — c'est le cas qu'il faut voir, l'étape « Pages surveillées » doit
# refléter la sélection enregistrée et non tout cocher.
VIZPAGES = {"scope": "selected_pages", "selected": [12], "critical": [12], "pages": [
    {"id": 12, "title": "Accueil", "url": "https://site-00.exemple.fr/",
     "type": "front", "selected": True, "critical": True},
    {"id": 18, "title": "Nos services", "url": "https://site-00.exemple.fr/services/",
     "type": "page", "selected": False, "critical": False},
    {"id": 24, "title": "Tarifs", "url": "https://site-00.exemple.fr/tarifs/",
     "type": "page", "selected": False, "critical": False},
    {"id": 31, "title": "À propos", "url": "https://site-00.exemple.fr/a-propos/",
     "type": "page", "selected": False, "critical": False},
    {"id": 37, "title": "Références clients", "url": "https://site-00.exemple.fr/references/",
     "type": "page", "selected": False, "critical": False},
    {"id": 42, "title": "Blog", "url": "https://site-00.exemple.fr/blog/",
     "type": "page", "selected": False, "critical": False},
    {"id": 55, "title": "Contact", "url": "https://site-00.exemple.fr/contact/",
     "type": "page", "selected": False, "critical": False},
    {"id": 61, "title": "Mentions légales", "url": "https://site-00.exemple.fr/mentions/",
     "type": "page", "selected": False, "critical": False},
]}


def viz_pages_etat(domain=""):
    """GET /api/actions/viz_pages — un site sans SSH répond rc 97, comme en vrai."""
    if any(x["domain"] == domain for x in REST_SITES):
        return {"ok": False, "rc": 97, "pages": [], "selected": [], "critical": [],
                "scope": "site", "limit": 20,
                "error": "action indisponible : site géré sans SSH (l'agent est en lecture seule)"}
    d = json.loads(json.dumps(VIZPAGES))
    d.update({"ok": True, "rc": 0, "source": "plugin", "limit": 20, "message": ""})
    return d


def evenements():
    """Évènements poussés par les agents, au format de data/events.jsonl."""
    return {"events": [
        {"ts": now(2), "domain": "site-01.exemple.fr", "event": "wp_login",
         "detail": '{"login":"admin","ip":"10.0.0.9"}'},
        {"ts": now(3), "domain": "site-02.exemple.fr", "event": "user_register",
         "detail": '{"login":"wpsvc_fkmdmu","email":"x@y.tld","roles":["administrator"]}'},
        {"ts": now(8), "domain": "site-02.exemple.fr", "event": "activated_plugin",
         "detail": '{"plugin":"wp-file-manager/file_folder_manager.php"}'},
        {"ts": now(19), "domain": "site-05.exemple.fr", "event": "upgrader_process_complete",
         "detail": '{"type":"plugin","action":"update","items":["akismet/akismet.php"]}'},
        {"ts": now(31), "domain": "site-04.exemple.fr", "event": "switch_theme",
         "detail": '{"name":"Divi","stylesheet":"Divi"}'},
        {"ts": now(60), "domain": "site-00.exemple.fr", "event": "evenement_inconnu_du_front",
         "detail": '{"quoi":"un agent plus recent","reste":"lisible"}'},
    ]}


def rollback_points():
    return {"points": [
        {"ts": "20260901-1042", "dir": "/var/backups/dash/20260901-1042",
         "plugins": ["plugin-1", "plugin-2"],
         "versions": {"plugin-1": "1.1.0", "plugin-2": "1.2.0"}},
    ]}


def collect_status():
    if SCENARIO == "joblent":
        return {"running": True, "rc": None, "done": 1, "total": 3,
                "started": now(0), "lines": ["plesk-mutu : 12 sites", "vps-1 : en cours…"]}
    return {"running": False, "rc": None, "done": 0, "total": 0, "lines": []}


# Serveurs de la page bouchonnée : ils vivent en variable de MODULE pour qu'un
# POST /api/mgmt/servers ait un effet visible (ajout, modification, retrait).
SERVEURS = [
    {"name": "plesk-mutu", "host": "148.251.123.48", "port": 10022, "priority": 3,
     "patterns": ["/var/www/vhosts/*/httpdocs"], "parallel": 4},
    {"name": "vps-1", "host": "159.69.95.228", "port": 22,
     "patterns": ["/var/www/*/htdocs", "/var/www/html"],
     "key": "/root/.ssh/id_dashboard"},
    {"name": "vps-2", "host": "mutu.hebergeur.example", "port": 22, "user": "u94559715",
     "no_su": True, "patterns": ["/home/clients/*/sites/*"], "priority": 1},
]
DOCROOTS = [{"server": "vps-1", "path": "/var/www/dev"}]
OVERRIDES = {"site-03.exemple.fr": {"visible": False},
             "site-05.exemple.fr": {"alias": "client-cinq.fr"}}
MONITEURS = [
    {"id": 9, "name": "Sumotori", "active": True, "parent": None},
    {"id": 11, "name": "Client A", "active": True, "parent": None},
    {"id": 1, "name": "site-00.exemple.fr", "active": True, "parent": 9},
    {"id": 2, "name": "site-01.exemple.fr", "active": True, "parent": 9},
    {"id": 3, "name": "site-02.exemple.fr", "active": False, "parent": 11},
]
# Clés réellement présentes sous /root/.ssh : c'est le SEUL contrôle que le
# formulaire ne peut pas faire lui-même (il ne voit pas le disque du serveur),
# donc le seul chemin normal vers un refus 400 champ par champ.
CLES = ["/root/.ssh/id_dashboard", "/root/.ssh/dash_sumotori"]


def mgmt_state():
    return {
        "kuma_monitors": list(MONITEURS),
        "kuma_groups": [{"id": 9, "name": "Sumotori"}, {"id": 11, "name": "Client A"}],
        "overrides": dict(OVERRIDES),
        "servers": [dict(s) for s in SERVEURS],
        "extra_docroots": [dict(d) for d in DOCROOTS],
    }


# ---- validation d'un serveur : MÊMES règles que validate_server() ------------
SRV_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
SRV_HOST_RE = re.compile(r"^[A-Za-z0-9.:-]+$")
SRV_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SRV_PATH_RE = re.compile(r"^/[A-Za-z0-9_./*@-]+$")


def _entier(v, mini, maxi):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if mini <= n <= maxi else None


def valider_serveur(o):
    """Copie fidèle de validate_server(), messages compris : la page bouchonnée
    doit refuser exactement ce que refuse la production, sinon la mise au point
    de l'affichage « erreur champ par champ » ne prouve rien."""
    if not isinstance(o, dict):
        return "serveur invalide (objet attendu)"
    nom = str(o.get("name") or "")
    if not SRV_NAME_RE.match(nom):
        return f"nom de serveur invalide : « {nom[:40]} »"
    hote = str(o.get("host") or "")
    if not SRV_HOST_RE.match(hote) or hote.startswith("-") or ".." in hote:
        return f"hôte invalide pour « {nom} »"
    user = o.get("user")
    if user not in (None, "") and not SRV_USER_RE.match(str(user)):
        return f"utilisateur ssh invalide pour « {nom} »"
    if _entier(o.get("port"), 1, 65535) is None:
        return f"port invalide pour « {nom} » (1-65535 attendu)"
    key = o.get("key")
    if key not in (None, "") and key not in CLES:
        return f"clé ssh invalide pour « {nom} » (attendue sous /root/.ssh, existante)"
    pats = o.get("patterns")
    if not isinstance(pats, list) or not pats:
        return f"patterns manquants pour « {nom} »"
    for p in pats:
        if not isinstance(p, str) or not SRV_PATH_RE.match(p) or ".." in p:
            return f"chemin invalide pour « {nom} » : « {str(p)[:60]} »"
    if o.get("parallel") is not None and _entier(o.get("parallel"), 1, 16) is None:
        return f"parallel invalide pour « {nom} » (1-16 attendu)"
    if o.get("priority") is not None and _entier(o.get("priority"), -10 ** 6, 10 ** 6) is None:
        return f"priority invalide pour « {nom} »"
    return None


ROUTES = {
    "fleet.json": fleet,
    "/api/status-page/parc-x7k2m9": status_cfg,
    "/api/status-page/heartbeat/parc-x7k2m9": status_hb,
    "/api/mgmt/schedule": lambda: dict(SCHEDULE),
    "/api/actions/collect_status": collect_status,
    "/api/actions/collect_history": historique,
    "/api/actions/log": lambda: {"log": [
        {"domain": "site-01.exemple.fr", "action": "plugin_update", "arg": "akismet", "rc": 0,
         "source": "dashboard", "ts": now(1), "duration_s": 12.4,
         "output_tail": "Success: Updated 1 of 1 plugins."},
        {"domain": "site-03.exemple.fr", "action": "updraft_backup", "arg": None, "rc": 0,
         "source": "dashboard", "ts": now(7), "duration_s": 96.2,
         "output_tail": "Backup finished (files + db)."},
        {"domain": "site-00.exemple.fr", "action": "viz_scan", "arg": None, "rc": 2,
         "source": "dashboard", "ts": now(26), "duration_s": 31.0,
         "output_tail": "2 anomalies détectées sur 3 pages."},
        {"domain": "site-05.exemple.fr", "action": "core_update", "arg": None, "rc": 1,
         "source": "bulk", "ts": now(50), "duration_s": 8.1,
         "output_tail": "Error: Could not create directory."}]},
    "/api/actions/bulk_status": lambda: dict(BULK),
    "/api/actions/safe_update_status": safe_update_status,
    "/api/actions/viz_update_status": viz_update_status,
    "/api/actions/policy": lambda: dict(POLICY),
    "/api/actions/rollback_points": rollback_points,
    "/api/actions/plugin_versions": lambda: {"versions": ["1.1.0", "1.0.9"], "current": "1.1.0"},
    "/api/actions/viz_last": lambda: {"viz": None},
    "/api/site/timeline": lambda: {"events": [
        {"kind": "action", "label": "plugin_update akismet", "status": "ok", "ts": now(1),
         "detail": "Success: Updated 1 of 1 plugins."},
        {"kind": "event", "label": "wp_login", "status": "", "ts": now(5),
         "detail": '{"login":"admin","ip":"10.0.0.9"}'},
        {"kind": "collect", "label": "collecte", "status": "", "ts": now(6), "detail": ""}]},
    "/api/mgmt/state": mgmt_state,
    "/api/mgmt/events": evenements,
    "/api/mgmt/candidates": lambda: {"candidates": [
        {"name": "nouveau.exemple.fr", "url": "https://nouveau.exemple.fr",
         "source": "Kuma", "reason": "non géré"},
        {"name": "vitrine.exemple.fr", "url": "https://vitrine.exemple.fr",
         "source": "Kuma", "reason": "aucun install correspondant"}]},
    "/api/mgmt/rest_sites": lambda: {"rest_sites": [dict(x) for x in REST_SITES]},
    "/api/mgmt/changes": lambda: {"changes": [
        {"domain": "site-02.exemple.fr", "label": "extension ajoutée", "detail": "wp-file-manager",
         "severity": "warn", "kind": "plugin_add", "ts": now(4)},
        {"domain": "site-02.exemple.fr", "label": "admin ajouté", "detail": "wpsvc_fkmdmu",
         "severity": "warn", "kind": "admin_add", "ts": now(9)},
        {"domain": "site-05.exemple.fr", "label": "cœur WordPress", "detail": "6.8.8 → 7.1",
         "severity": "info", "kind": "core", "ts": now(20)},
        {"domain": "site-01.exemple.fr", "label": "extension mise à jour", "detail": "akismet 5.3 → 5.4",
         "severity": "info", "kind": "plugin_update", "ts": now(28)},
        {"domain": "site-07.exemple.fr", "label": "PHP", "detail": "8.1.2 → 8.2.7",
         "severity": "info", "kind": "php", "ts": now(52)},
        {"domain": "site-04.exemple.fr", "label": "extension retirée", "detail": "duplicator",
         "severity": "info", "kind": "plugin_remove", "ts": now(78)}],
        "summary": {"day_total": 3, "day_sites": 2, "day_warn": 2}},
    "/api/mgmt/sshkeys": lambda: json.loads(json.dumps(SSHKEYS)),
    "/api/mgmt/settings": lambda: {"settings": json.loads(json.dumps(SETTINGS))},
    "/api/mgmt/alerts": lambda: json.loads(json.dumps(ALERTES)),
    "/api/incidents": incidents,
    "/api/mgmt/counts": sidebar_counts,
    "/api/sec/vulns": vulns,
    "/api/sec/phperrors": phperrors,
    "/api/sec/baseline": lambda: {"baseline": {"site-00.exemple.fr": {"logins": ["admin"]}}},
    "/api/sec/certs": lambda: {"certs": [{"monitor": "site-00.exemple.fr", "days": 40, "valid_to": "2027-01-01"},
                                         {"monitor": "site-01.exemple.fr", "days": 6, "valid_to": "2026-09-09"}]},
    "/api/sec/checksums": lambda: {"checksums": {"site-00.exemple.fr": {"ok": True, "ts": now(9), "output_tail": ""}}},
    "/api/auth/check": lambda: {"ok": True},
}


def fixture_ou_fabrique(nom):
    """Fixture réelle si elle a été déposée, sinon réponse fabriquée."""
    f = FIXTURES / (nom.strip("/").replace("/", "_") + ".json")
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    fn = ROUTES.get(nom)
    return fn() if fn else {"ok": True}


def paquet():
    """Toutes les réponses, prêtes à être injectées dans la page."""
    return {k: fixture_ou_fabrique(k) for k in ROUTES}


STUB = """
<script>
/* --- page bouchonnée : aucun appel réseau ne sort d'ici --- */
(function(){
  const DATA = __DATA__;
  // Routes dont la réponse DÉPEND de la requête ou de l'état déjà modifié par
  // un POST : elles vont au serveur local, qui tient cet état, au lieu du
  // paquet figé injecté au chargement. Sans cela, un serveur ajouté ou un
  // réglage enregistré n'apparaîtrait jamais au rechargement de la section.
  const DIRECT = ['/api/mgmt/wp_credentials', '/api/mgmt/state', '/api/mgmt/rest_sites',
    '/api/mgmt/sshkeys', '/api/mgmt/settings', '/api/mgmt/alerts', '/api/mgmt/schedule',
    '/api/mgmt/candidates', '/api/mgmt/events', '/api/actions/viz_pages'];
  const vrai = window.fetch.bind(window);
  window.__PREVIEW__ = true;
  window.fetch = function(url, opts){
    const u = String(url);
    const chemin = u.replace(location.origin,'').split('?')[0];
    if(DIRECT.includes(chemin)) return vrai(url, opts);
    // Ressources statiques (sprite, polices, CSS) : vrai chargement.
    if(!/^\\/api\\/|fleet\\.json/.test(u.replace(location.origin,''))) return vrai(url, opts);
    // Les ÉCRITURES passent au serveur local, qui tient un peu d'état (gel
    // d'une extension, sortie d'une commande, tâches d'un job groupé) : une
    // réponse figée ne permettrait pas de voir l'effet d'un bouton.
    if(opts && String(opts.method||'GET').toUpperCase() !== 'GET') return vrai(url, opts);
    const cle = Object.keys(DATA).find(k => u.split('?')[0].endsWith(k) || u.startsWith(k));
    const corps = cle ? DATA[cle] : {ok:true, preview:'route non bouchonnée : '+u};
    return Promise.resolve(new Response(JSON.stringify(corps),
      {status:200, headers:{'Content-Type':'application/json'}}));
  };
})();
</script>
"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(PUBLIC), **kw)

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        # Aucun cache pendant la mise au point : les modules portent tous le même
        # `?v=dev`, un cache navigateur servirait la version d'avant l'édition.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _json(self, code, obj):
        corps = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def do_GET(self):
        chemin = self.path.split("?")[0]
        if chemin == "/api/actions/viz_pages":
            import urllib.parse as up
            dom = up.parse_qs(self.path.split("?", 1)[-1]).get("domain", [""])[0]
            return self._json(200, viz_pages_etat(dom))
        if chemin == "/api/mgmt/wp_credentials":
            import urllib.parse as up
            dom = up.parse_qs(self.path.split("?", 1)[-1]).get("domain", [""])[0]
            return self._json(200, WPCRED.get(dom, {"has_password": False, "user": "",
                                                    "verified": None, "checked_ts": None}))
        if chemin.startswith("/api/") and chemin in ROUTES:
            return self._json(200, fixture_ou_fabrique(chemin))
        if chemin in ("/", "/index.html"):
            html = (PUBLIC / "index.html").read_text(encoding="utf-8")
            stub = STUB.replace("__DATA__", json.dumps(paquet(), ensure_ascii=False))
            html = html.replace('<script type="module" src="app.js', stub + '<script type="module" src="app.js')
            corps = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(corps)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(corps)
            return
        super().do_GET()

    def do_POST(self):
        """Réponses d'écriture : quelques routes ont un EFFET, les autres disent OK.

        Une page bouchonnée qui répond invariablement `{"ok":true}` ne permet pas
        de voir ce que fait un bouton : le gel d'une extension ne bascule pas, la
        console reste vide, la barre de progression n'a rien à montrer.
        """
        chemin = self.path.split("?")[0]
        taille = int(self.headers.get("Content-Length") or 0)
        try:
            corps = json.loads(self.rfile.read(taille) or b"{}") if taille else {}
        except ValueError:
            corps = {}
        rep, code = {"ok": True}, 200
        gere = self._mgmt_post(chemin, corps)
        if gere is not None:
            return self._json(gere[0], gere[1])
        if chemin.endswith("/api/actions/policy"):
            gel = set(POLICY["frozen"])
            slug = str(corps.get("slug") or "")
            if corps.get("frozen"):
                gel.add(slug)
            else:
                gel.discard(slug)
            POLICY["frozen"] = sorted(x for x in gel if x)
            rep = {"ok": True, "frozen": POLICY["frozen"]}
        elif chemin.endswith("/api/actions/run"):
            rep = {"ok": True, "rc": 0,
                   "output": f"Success: {corps.get('action', '?')} sur "
                             f"{corps.get('domain', '?')} (page bouchonnée)"}
        elif chemin.endswith("/api/actions/bulk"):
            taches = corps.get("tasks") or []
            BULK.update({
                "running": False, "done": len(taches), "total": len(taches),
                "tasks": [{"domain": t.get("domain"), "status": "ok", "rc": 0,
                           "output_tail": "Success: (page bouchonnée)",
                           "viz": "ok" if corps.get("viz_verify") else None,
                           "backup": "ok" if corps.get("backup_first") else None}
                          for t in taches],
            })
            rep = {"job": "apercu", "ok": True}
        elif chemin.endswith("/api/actions/viz_pages"):
            # Écriture des pages surveillées : elle a un EFFET (la sélection est
            # relue à la réouverture) et rejoue les refus du backend.
            ids = corps.get("ids")
            scope = str(corps.get("scope") or "")
            if not isinstance(ids, list) or any(not isinstance(x, int) for x in ids):
                return self._json(400, {"error": "ids : une liste d'entiers est attendue"})
            if scope not in ("site", "selected_pages"):
                return self._json(400, {"error": "portée invalide (site ou selected_pages)"})
            if 0 in ids and scope != "site":
                return self._json(400, {"error": "l'accueil « flux d'articles » ne se surveille "
                                                 "qu'avec la portée « tout le site »"})
            ids = [i for i in ids if i > 0]
            if len(ids) > 20:
                return self._json(400, {"error": "20 pages au maximum (le plugin ne scanne pas au-delà)"})
            if scope == "selected_pages" and not ids:
                return self._json(400, {"error": "choisissez au moins une page à surveiller"})
            VIZPAGES["scope"] = scope
            VIZPAGES["selected"] = list(ids)
            for pg in VIZPAGES["pages"]:
                pg["selected"] = pg["id"] in ids
            return self._json(200, viz_pages_etat(str(corps.get("domain") or "")))
        elif chemin.endswith("/api/actions/safe_update"):
            rep = {"ok": True, "running": True}
        elif chemin.endswith("/api/sec/verify"):
            rep = {"ok": True, "output": "Success: WordPress installation verifies against checksums."}
        elif chemin.endswith("/api/sec/checksums/run"):
            # Un job, pour que « Vérifier tout le parc » ouvre bien la modale de suivi.
            BULK.update({"running": False, "done": 1, "total": 1,
                         "tasks": [{"domain": "site-00.exemple.fr", "status": "ok", "rc": 0,
                                    "output_tail": "Success: verifies against checksums."}]})
            rep = {"job": "apercu", "ok": True}
        elif chemin.endswith("/api/sec/vulns/run") or chemin.endswith("/api/sec/phperrors/run"):
            # `running: True` : le front enchaîne sur son sondage, puis le GET
            # correspondant répond `running: False` — le cycle complet est joué.
            rep = {"ok": True, "running": True}
        self._json(code, rep)

    def _mgmt_post(self, chemin, corps):
        """Écritures de l'écran Gestion et de l'écran Réglages.

        Elles ont un EFFET sur l'état du module : sans cela, on ne peut vérifier
        ni qu'un serveur ajouté apparaît, ni qu'un refus de validation se pose
        sur le bon champ, ni qu'un réglage enregistré est bien relu.
        Renvoie (code, réponse) ou None si la route n'est pas de son ressort.
        """
        if chemin == "/api/mgmt/servers":
            liste = corps.get("servers")
            if not isinstance(liste, list):
                return 400, {"error": "format invalide"}
            for x in liste:
                err = valider_serveur(x)
                if err:
                    return 400, {"error": err}
            SERVEURS[:] = [dict(x) for x in liste]
            return 200, {"ok": True}

        if chemin == "/api/mgmt/docroots":
            docs = corps.get("docroots")
            if not isinstance(docs, list):
                return 400, {"error": "format invalide"}
            for d in docs:
                if not isinstance(d, dict) or not SRV_NAME_RE.match(str(d.get("server") or "")):
                    return 400, {"error": "serveur invalide pour un docroot"}
                p2 = str(d.get("path") or "")
                if not SRV_PATH_RE.match(p2) or ".." in p2:
                    return 400, {"error": f"chemin invalide : « {p2[:60]} »"}
            DOCROOTS[:] = [dict(d) for d in docs]
            return 200, {"ok": True}

        if chemin == "/api/mgmt/override":
            dom = str(corps.get("domain") or "")
            cur = dict(OVERRIDES.get(dom, {}))
            if "visible" in corps:
                if corps["visible"] in (True, False):
                    cur["visible"] = corps["visible"]
                else:
                    cur.pop("visible", None)
            if "alias" in corps:
                al = str(corps["alias"] or "").strip()
                if al:
                    cur["alias"] = al
                else:
                    cur.pop("alias", None)
            if cur:
                OVERRIDES[dom] = cur
            else:
                OVERRIDES.pop(dom, None)
            return 200, {"ok": True, "overrides": dict(OVERRIDES)}

        if chemin == "/api/mgmt/kuma/create":
            mid = max([m["id"] for m in MONITEURS] or [0]) + 1
            MONITEURS.append({"id": mid, "name": str(corps.get("domain") or "?"),
                              "active": True, "parent": int(corps.get("group_id") or 9)})
            return 200, {"ok": True, "output": "monitor created (page bouchonnée)"}
        if chemin == "/api/mgmt/kuma/pause":
            for m in MONITEURS:
                if m["id"] == corps.get("monitor_id"):
                    m["active"] = bool(corps.get("active"))
            return 200, {"ok": True, "output": ""}
        if chemin == "/api/mgmt/kuma/delete":
            MONITEURS[:] = [m for m in MONITEURS if m["id"] != corps.get("monitor_id")]
            return 200, {"ok": True, "output": ""}

        if chemin == "/api/mgmt/discover":
            url = str(corps.get("url") or "")
            if "inconnu" in url:
                return 200, {"ok": False, "error": "aucune réponse HTTP à cette adresse"}
            hote = url.replace("https://", "").replace("http://", "").split("/")[0] or "exemple.fr"
            return 200, {"ok": True, "name": "Site " + hote, "url_effective": "https://" + hote,
                         "home": "https://" + hote, "is_wordpress": True, "rest_open": True,
                         "namespaces": ["wp/v2", "sumotori-dash/v1"],
                         "has_agent": False, "has_vizproof": False, "multisite": False,
                         "already_known": False,
                         "suggestion": "ssh" if hote.endswith("exemple.fr") else "pair"}
        if chemin == "/api/mgmt/pair_code":
            return 200, {"code": "K7F2-9QMD", "expires_in": 600}

        if chemin == "/api/mgmt/rest_sites":
            url = str(corps.get("url") or "")
            if not url.startswith("http"):
                return 400, {"error": "url invalide (http/https attendu)"}
            dom = url.replace("https://", "").replace("http://", "").split("/")[0]
            REST_SITES.append({"domain": dom, "url": url, "name": corps.get("name") or "",
                               "added_at": now(0), "multisite": False, "server": ""})
            return 200, {"ok": True, "site": REST_SITES[-1]}
        if chemin == "/api/mgmt/rest_sites/delete":
            dom = str(corps.get("domain") or "")
            REST_SITES[:] = [x for x in REST_SITES if x["domain"] != dom]
            WPCRED.pop(dom, None)
            return 200, {"ok": True,
                         "cleanup": "non demandé" if corps.get("keep_account") else "compte supprimé"}

        if chemin == "/api/mgmt/wp_authorize":
            return 200, {"authorize_url": "https://" + str(corps.get("domain") or "exemple.fr")
                         + "/wp-admin/authorize-application.php?app_name=Dashboard"}
        if chemin == "/api/mgmt/wp_credentials/delete":
            WPCRED.pop(str(corps.get("domain") or ""), None)
            return 200, {"ok": True}

        if chemin == "/api/mgmt/sshkeys/test":
            cle = str(corps.get("key") or "")
            if cle and cle not in CLES:
                return 400, {"error": "clé invalide"}
            ok = str(corps.get("server")) != "vps-2"
            return 200, {"ok": ok, "output": "OK depuis srv01" if ok
                         else "Permission denied (publickey)."}
        if chemin == "/api/mgmt/sshkeys/generate":
            nom = str(corps.get("name") or "")
            chemin_cle = "/root/.ssh/dash_" + nom
            if chemin_cle in CLES:
                return 409, {"error": "une clé porte déjà ce nom"}
            CLES.append(chemin_cle)
            SSHKEYS["keys"].append({"name": nom, "path": chemin_cle, "type": "ed25519",
                                    "fingerprint": "SHA256:nouv…",
                                    "pub": "ssh-ed25519 AAAAC3Nza… wp-dashboard"})
            return 200, {"ok": True, "path": chemin_cle,
                         "pub": "ssh-ed25519 AAAAC3Nza… wp-dashboard"}
        if chemin == "/api/mgmt/sshkeys/assign":
            cle = str(corps.get("key") or "")
            if cle not in CLES:
                return 400, {"error": "clé invalide"}
            cible = str(corps.get("server") or "")
            for a in SSHKEYS["assignments"]:
                if cible in ("*", a["server"]):
                    a["key"] = cle
            return 200, {"ok": True}

        if chemin == "/api/mgmt/schedule":
            v = corps.get("interval_minutes")
            if v not in SCHEDULE["choices"]:
                return 400, {"ok": False, "error": "cadence non proposée", **SCHEDULE}
            SCHEDULE["interval_minutes"] = v
            SCHEDULE["cron"] = "" if v == 0 else (f"*/{v} * * * *" if v < 60 else f"0 */{v // 60} * * *")
            return 200, {"ok": True, **SCHEDULE}

        if chemin == "/api/mgmt/settings":
            patch = corps.get("settings")
            if not isinstance(patch, dict):
                patch = {}
            if corps.get("vizproof_token_clear"):
                SETTINGS["vizproof_token_set"] = False
                SETTINGS["vizproof_token_tail"] = ""
                patch.pop("vizproof_token", None)
            jeton = str(patch.pop("vizproof_token", "") or "")
            if jeton:
                if not jeton.startswith("vrt_") or len(jeton) < 12:
                    return 400, {"error": "jeton VizProof invalide (vrt_… , 8 à 200 caractères "
                                          "après le préfixe)"}
                SETTINGS["vizproof_token_set"] = True
                SETTINGS["vizproof_token_tail"] = jeton[-4:]
            if "vizproof_api_base" in patch:
                base = str(patch["vizproof_api_base"] or "").strip() or "https://vizproof.com"
                if not base.startswith("https://"):
                    return 400, {"error": "base API : https exigé"}
                patch["vizproof_api_base"] = base.rstrip("/")
            for k, v in patch.items():
                if k == "incident_rules" and isinstance(v, dict):
                    # Comme le backend : le sous-dictionnaire est RECOMPOSÉ à
                    # partir des valeurs par défaut, jamais fusionné.
                    base = {"backup_max_age_h": 48, "cert_warn_days": 21, "cert_critical_days": 7,
                            "vuln_high_is_incident": False,
                            "php_eol_versions": ["7.0", "7.1", "7.2", "7.3", "7.4", "8.0"]}
                    base.update({kk: vv for kk, vv in v.items() if kk in base})
                    SETTINGS["incident_rules"] = base
                elif k in SETTINGS:
                    SETTINGS[k] = v
            return 200, {"ok": True, "settings": json.loads(json.dumps(SETTINGS))}

        if chemin == "/api/mgmt/vizproof/test":
            if not SETTINGS["vizproof_token_set"]:
                return 200, {"ok": False, "total": None, "error": "aucun jeton enregistré"}
            return 200, {"ok": True, "total": 12, "error": None,
                         "api_base": SETTINGS["vizproof_api_base"]}

        if chemin == "/api/mgmt/alerts":
            ALERTES["enabled"] = bool(corps.get("enabled"))
            ALERTES["chat_id"] = str(corps.get("chat_id") or "")
            jeton = str(corps.get("token") or "").strip()
            if jeton:
                ALERTES["token_set"] = True
                ALERTES["token_tail"] = jeton[-4:]
            regles = corps.get("rules")
            if isinstance(regles, dict):
                for k, v in regles.items():
                    if k in ALERTES["rules"]:
                        ALERTES["rules"][k] = v
            return 200, {"ok": True, **json.loads(json.dumps(ALERTES))}
        if chemin == "/api/mgmt/alerts/test":
            return 200, {"ok": bool(ALERTES["token_set"] and ALERTES["chat_id"]),
                         "error": "" if ALERTES["token_set"] else "aucun jeton enregistré"}

        if chemin in ("/api/mgmt/dash_connect", "/api/mgmt/dash_disconnect"):
            return 200, {"ok": True, "rc": 0, "output": "agent : opération simulée"}
        return None


def main():
    global SCENARIO
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--scenario", default="normal",
                    choices=["normal", "vide", "gros", "stale", "anomalie", "joblent"])
    a = ap.parse_args()
    SCENARIO = a.scenario
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", a.port), Handler) as srv:
        print(f"Page bouchonnée ({a.scenario}) : http://127.0.0.1:{a.port}/", flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
