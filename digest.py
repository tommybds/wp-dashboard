#!/usr/bin/env python3
"""Bilan journalier du parc → une notification Telegram s'il y a eu du changement.

Lit data/changes.jsonl (produit par collect.py à chaque collecte) sur les
dernières 24 h, regroupe par site, et envoie UN message Telegram. Aucun message
si rien n'a changé. Réutilise la configuration et l'envoi de actions_server.py
(token dans data/alerts.json, respect du drapeau « enabled »).

Lancé par cron une fois par jour. En test manuel : `python3 digest.py --dry-run`
affiche le message sans l'envoyer ; `--since H` change la fenêtre (défaut 24 h).
"""
import os, sys, json, datetime, collections

# BASE reste calculé ici : il doit exister AVANT le sys.path.insert qui rend le
# dépôt importable (dashlib et actions_server en dépendent).
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA  # noqa: E402  — chemins communs à tout le dépôt
import actions_server as A  # noqa: E402  — import sûr : le serveur ne tourne que sous __main__

CHANGES_PATH = os.path.join(DATA, "changes.jsonl")

# Ordre d'affichage et libellés courts par type de changement.
KIND_ORDER = {"admin_add": 0, "admin_remove": 1, "plugin_add": 2, "core": 3,
              "php": 4, "plugin_update": 5, "plugin_status": 6,
              "plugin_remove": 7, "updraft": 8}


def load_recent(hours):
    """Changements des `hours` dernières heures, ts au format 'YYYY-mm-dd HH:MM'."""
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
    out = []
    try:
        fh = open(CHANGES_PATH)
    except OSError:
        return out
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
                # TypeError : une ligne avec « ts »: null (ou un autre type)
                # faisait planter le bilan au lieu de sauter la ligne.
                t = datetime.datetime.strptime(c["ts"], "%Y-%m-%d %H:%M")
            except (ValueError, KeyError, TypeError):
                continue
            if t >= cutoff:
                out.append(c)
    return out


def build_message(changes, hours=24):
    """(texte HTML Telegram, nb_sites, nb_warn) ou (None, 0, 0) si rien."""
    if not changes:
        return None, 0, 0
    by_site = collections.OrderedDict()
    for c in changes:
        by_site.setdefault(c["domain"], []).append(c)
    # sites avec un changement « à surveiller » d'abord, puis par volume
    def site_key(item):
        dom, lst = item
        warn = any(x["severity"] == "warn" for x in lst)
        return (0 if warn else 1, -len(lst), dom)
    sites = sorted(by_site.items(), key=site_key)
    n_warn = sum(1 for _, lst in sites if any(x["severity"] == "warn" for x in lst))

    day = datetime.datetime.now().strftime("%d/%m")
    total = len(changes)
    head = f"📊 <b>Bilan parc WordPress — {day}</b>"
    win = "24 h" if hours == 24 else f"{hours} h"
    sub = f"{total} changement{'s' if total > 1 else ''} sur {len(sites)} site{'s' if len(sites) > 1 else ''} ({win})"
    if n_warn:
        sub += f" — {n_warn} à surveiller ⚠️"
    lines = [head, sub, ""]

    MAX_SITES, MAX_PER_SITE = 25, 12
    for dom, lst in sites[:MAX_SITES]:
        warn = any(x["severity"] == "warn" for x in lst)
        lst.sort(key=lambda x: (KIND_ORDER.get(x["kind"], 9), x["detail"]))
        flag = "⚠️ " if warn else ""
        lines.append(f"{flag}<b>{A.esc_html(dom)}</b>")
        for x in lst[:MAX_PER_SITE]:
            mark = "⚠️ " if x["severity"] == "warn" else "• "
            lines.append(f"  {mark}{A.esc_html(x['detail'])}")
        if len(lst) > MAX_PER_SITE:
            lines.append(f"  … +{len(lst) - MAX_PER_SITE} autre(s)")
        lines.append("")
    if len(sites) > MAX_SITES:
        lines.append(f"… +{len(sites) - MAX_SITES} autre(s) site(s)")
    return "\n".join(lines).rstrip(), len(sites), n_warn


def main():
    hours, dry = 24, False
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--dry-run":
            dry = True
        elif a == "--since" and args:
            hours = int(args.pop(0))
    changes = load_recent(hours)
    text, n_sites, n_warn = build_message(changes, hours)
    if not text:
        print("Aucun changement sur la fenêtre — pas de bilan.")
        return
    if dry:
        print(text)
        return
    cfg = A.alerts_cfg()
    if not cfg.get("enabled"):
        print("Alertes désactivées (data/alerts.json) — bilan non envoyé.")
        print(f"({len(changes)} changement(s) sur {n_sites} site(s) auraient été notifiés.)")
        return
    ok, err = A.telegram_send_sync(text)
    A.alerts_log(("bilan envoyé: " if ok else f"bilan échec ({err}): ")
                 + f"{len(changes)} changement(s)/{n_sites} site(s)")
    print("Bilan envoyé." if ok else f"Échec envoi : {err}")


if __name__ == "__main__":
    main()
