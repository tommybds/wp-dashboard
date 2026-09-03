#!/usr/bin/env python3
"""Rotation des journaux du dashboard, à rétention différenciée.

Une rotation qui coupe bêtement aux N dernières lignes fait disparaître les
évènements rares et importants — une création d'administrateur pirate, une
mise à jour qui a échoué — noyés sous le bruit courant. Ici chaque journal a
donc DEUX durées : une courte pour le tout-venant, une longue pour ce qui a
valeur de preuve.

Une ligne est conservée si elle vérifie l'une des conditions :
  * elle est plus récente que la rétention courante ;
  * elle est « importante » et plus récente que la rétention longue ;
  * elle fait partie des N dernières (filet, même si les dates sont illisibles).

Usage :
    python3 rotate.py            # applique
    python3 rotate.py --dry-run  # montre ce qui serait supprimé
"""
import os, sys, json, re, datetime

from dashlib import BASE, DATA_DIR as DATA  # chemins communs à tout le dépôt

# Évènements poussés par l'agent qui documentent une compromission possible :
# ce sont eux qu'on veut pouvoir consulter un an plus tard.
EVENEMENTS_SENSIBLES = {
    "user_register", "set_user_role", "deleted_user", "grant_super_admin",
    "activated_plugin", "deactivated_plugin", "switch_theme", "wp_initialize_site",
}
# Actions qui modifient un site : on garde la trace de qui a fait quoi.
ACTIONS_SENSIBLES = {
    "core_update", "plugins_update_all", "plugins_update_except", "plugin_update",
    "themes_update_all", "autoupdate_on", "autoupdate_off", "vizproof_install",
    "plugin_rollback", "safe_update", "plugin_freeze", "creation_admin_dedie",
    "suppression_admin_dedie", "dash_connect", "dash_disconnect",
}

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})")


def horodatage(ligne, obj=None):
    """Date d'une ligne, quel que soit son format → datetime ou None."""
    brut = (obj or {}).get("ts") if isinstance(obj, dict) else None
    m = TS_RE.search(str(brut) if brut else ligne)
    if not m:
        return None
    try:
        return datetime.datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M")
    except ValueError:
        return None


# --- Règles d'importance, une par journal --------------------------------- #
def evt_important(o):
    return isinstance(o, dict) and o.get("event") in EVENEMENTS_SENSIBLES


def chg_important(o):
    # « warn » = admin ou extension apparu/disparu : le signal n°1 d'intrusion.
    return isinstance(o, dict) and o.get("severity") == "warn"


def action_importante(o):
    if not isinstance(o, dict):
        return False
    # Un échec est toujours instructif, même sur une action anodine.
    return o.get("rc") not in (0, None) or o.get("action") in ACTIONS_SENSIBLES


def alerte_importante(o, ligne):
    return "appairage" in ligne.lower() or "admin" in ligne.lower()


# (fichier, jours courants, jours longs, filet de lignes, test d'importance)
#
# Le « filet » protege les N dernieres lignes quoi qu'il arrive : il garantit
# que l'interface a toujours de quoi afficher, meme si l'horloge deraille ou si
# les dates sont illisibles. Il doit rester PROCHE de ce que l'interface lit
# reellement (800 changements, 200 evenements de fiche) : trop large, il
# protege tout le fichier et les regles d'age ne s'appliquent jamais.
#
# changes.jsonl : collect.py se contente désormais d'ajouter des lignes (il
# tronquait à 5000, 48 fois par jour, ce qui contredisait la rétention longue
# ci-dessous). C'est donc bien cette règle, et elle seule, qui borne le fichier.
REGLES = [
    ("events.jsonl",          60,  400,  400, lambda o, l: evt_important(o)),
    ("changes.jsonl",         90,  400,  900, lambda o, l: chg_important(o)),
    ("actions.log",           60,  400,  400, lambda o, l: action_importante(o)),
    ("collect_history.jsonl", 400, 400, 2000, lambda o, l: False),   # 1 point/30 min, leger
    ("alerts.log",            90,  400,  300, alerte_importante),
    ("auth_fail.log",         30,  180,  300, lambda o, l: True),    # securite : tout compte
]


def traiter(nom, jours, jours_longs, filet, important, dry=False):
    chemin = os.path.join(DATA, nom)
    try:
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            lignes = fh.read().splitlines()
    except OSError:
        return None
    if not lignes:
        return None

    now = datetime.datetime.now()
    court = now - datetime.timedelta(days=jours)
    long_ = now - datetime.timedelta(days=jours_longs)
    garde_index = len(lignes) - filet

    gardees, retirees, sauvees = [], 0, 0
    for i, ligne in enumerate(lignes):
        if not ligne.strip():
            continue
        obj = None
        if ligne.lstrip().startswith("{"):
            try:
                obj = json.loads(ligne)
            except ValueError:
                obj = None
        ts = horodatage(ligne, obj)
        if i >= garde_index or ts is None:
            gardees.append(ligne)          # filet : récent, ou date illisible
            continue
        if ts >= court:
            gardees.append(ligne)
            continue
        try:
            gros = important(obj, ligne)
        except Exception:
            gros = True                    # dans le doute, on garde
        if gros and ts >= long_:
            gardees.append(ligne)
            sauvees += 1
            continue
        retirees += 1

    if retirees and not dry:
        tmp = chemin + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(gardees) + ("\n" if gardees else ""))
        try:
            os.chmod(tmp, 0o600)   # avant le remplacement : jamais de fenêtre en 0644
        except OSError:
            pass
        os.replace(tmp, chemin)
        try:
            # 0600 pour TOUS les journaux : events, changes, actions et alerts
            # citent des logins et des adresses e-mail d'administrateurs. Rien
            # dans data/ n'a vocation à être lisible par un autre compte.
            os.chmod(chemin, 0o600)
        except OSError:
            pass
    return {"fichier": nom, "avant": len(lignes), "apres": len(gardees),
            "retirees": retirees, "conservees_car_importantes": sauvees}


# --- acquittements d'incidents -------------------------------------------- #
# data/incident_acks.json n'est pas un journal : c'est un état. Mais il vieillit
# de la même façon — une alerte écartée dont l'incident a disparu depuis des
# mois n'a plus d'objet, et l'entrée oubliée masquerait un incident de MÊME
# identifiant qui reviendrait bien plus tard. La règle (90 jours sans revoir
# l'incident) vit dans actions_server, qui connaît la forme du fichier ; la
# rotation ne fait que l'appeler, au même rythme que le reste.
def purger_acquittements(dry=False):
    """→ nombre d'entrées retirées, ou None si le module n'est pas importable."""
    try:
        import actions_server
    except Exception:
        return None                      # rotation lancée hors installation complète
    if not dry:
        return actions_server.incident_acks_purge()
    limite = datetime.datetime.now().timestamp() - actions_server.ACK_PURGE_DAYS * 86400

    def perimee(e):
        if not isinstance(e, dict):
            return True
        try:
            return float(e.get("last_seen") or e.get("ts") or 0) < limite
        except (TypeError, ValueError):
            return True

    return sum(1 for e in actions_server.incident_acks().values() if perimee(e))


def main():
    dry = "--dry-run" in sys.argv
    total = 0
    for nom, j, jl, filet, imp in REGLES:
        r = traiter(nom, j, jl, filet, imp, dry)
        if not r:
            continue
        total += r["retirees"]
        if r["retirees"] or "--verbose" in sys.argv:
            print(f"  {r['fichier']:24} {r['avant']:6} → {r['apres']:6} lignes"
                  f"  (-{r['retirees']}"
                  + (f", {r['conservees_car_importantes']} gardées car importantes" if r["conservees_car_importantes"] else "")
                  + ")")
    acks = purger_acquittements(dry)
    if acks:
        print(f"  {'incident_acks.json':24} -{acks} acquittement(s) sans objet")
    print(("[simulation] " if dry else "") + f"{total} ligne(s) retirée(s).")


if __name__ == "__main__":
    main()
