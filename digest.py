#!/usr/bin/env python3
"""Bilan journalier du parc → UNE notification Telegram, lisible en 20 secondes.

Le bilan répond à trois questions, dans cet ordre :
  1. qu'est-ce qui a CASSÉ depuis hier ? — incidents « à traiter » apparus depuis
     le bilan précédent (même agrégat que la file du dashboard, acquittements
     compris) ;
  2. qu'est-ce qui s'est RÉGLÉ ? — incidents du bilan précédent disparus ;
  3. qu'est-ce qui a CHANGÉ ? — data/changes.jsonl sur 24 h, RÉSUMÉ : une
     extension passée par trois versions ne compte qu'une fois, un aller-retour
     (banc d'essai, retour arrière) ne compte pas, les mises à jour sont
     regroupées par extension, et seuls les changements qui touchent la
     sécurité (admins, extensions ajoutées) sont détaillés site par site.

Les préprods (drapeau `preprod` de fleet.json) sont repliées en une ligne : un
banc d'essai qui bouge dix fois par jour ne doit pas noyer la production.

L'état « incidents vus au dernier bilan » est gardé dans data/digest_state.json,
écrit seulement quand le bilan part vraiment. Aucun message si rien de neuf.

Lancé par cron une fois par jour. En test manuel : `python3 digest.py --dry-run`
affiche le message sans l'envoyer ni toucher à l'état ; `--since H` change la
fenêtre des changements (défaut 24 h).
"""
import os, re, sys, html, json, datetime, collections

# BASE reste calculé ici : il doit exister AVANT le sys.path.insert qui rend le
# dépôt importable (dashlib et actions_server en dépendent).
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA, load_json, save_json  # noqa: E402
import actions_server as A  # noqa: E402  — import sûr : le serveur ne tourne que sous __main__

CHANGES_PATH = os.path.join(DATA, "changes.jsonl")
STATE_PATH = os.path.join(DATA, "digest_state.json")

JOURS = ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."]
MAX_NOUVEAUX, MAX_REGLES, MAX_SECU = 8, 5, 8
SEUIL_MASSIF = 10   # extensions ajoutées + retirées d'un coup sur un site

RE_MAJ = re.compile(r"^(\S+) (\S+) → (\S+)$")
RE_COEUR = re.compile(r"^cœur WordPress (\S+) → (\S+)$")
RE_PHP = re.compile(r"^PHP (\S+) → (\S+)$")


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


def pluriel(n, mot, mots=None):
    return f"{n} {mot if n == 1 else (mots or mot + 's')}"


# ---------------------------------------------------------------------------
#  Changements : versions nettes, regroupements
# ---------------------------------------------------------------------------
def versions_nettes(changes, kind, motif):
    """{(domaine, nom): (de, vers)} — la chaîne A→B→C devient A→C, et un
    aller-retour A→B→A disparaît. `changes` est dans l'ordre du fichier."""
    net = collections.OrderedDict()
    for c in changes:
        if c.get("kind") != kind:
            continue
        m = motif.match(str(c.get("detail") or ""))
        if not m:
            continue
        g = m.groups()
        nom, de, vers = g if len(g) == 3 else ("",) + g
        cle = (c.get("domain"), nom)
        net[cle] = (net[cle][0], vers) if cle in net else (de, vers)
    return {k: v for k, v in net.items() if v[0] != v[1]}


def resume_changements(changes):
    """Changements de PRODUCTION → lignes du bloc « Changements »."""
    lignes = []

    # 1. sécurité, détaillée : c'est là qu'un piratage se voit. Les admins
    #    passent AVANT les extensions ; un site dont la moitié des extensions
    #    change d'un coup (restauration, bascule vers une autre copie) est
    #    résumé en une ligne au lieu d'une liste illisible.
    par_site = collections.OrderedDict()
    for c in changes:
        kind = c.get("kind")
        if c.get("severity") == "warn" or kind == "plugin_remove":
            par_site.setdefault(c.get("domain"), []).append(c)
    blocs = []
    for dom, lst in par_site.items():
        # « + admin login <e-mail> » → « + admin login » : l'e-mail est dans le dashboard
        admins = [re.sub(r" <[^>]*>$", "", str(c.get("detail") or ""))
                  for c in lst if str(c.get("kind")).startswith("admin")]
        ajouts = [str(c.get("detail") or "").replace("+ extension ", "+ ")
                  for c in lst if c.get("kind") == "plugin_add"]
        retraits = sum(1 for c in lst if c.get("kind") == "plugin_remove")
        autres = [str(c.get("detail") or "") for c in lst
                  if c.get("severity") == "warn"
                  and c.get("kind") not in ("plugin_add",) and not str(c.get("kind")).startswith("admin")]
        if not (admins or ajouts or autres):
            continue                      # un simple retrait n'est pas à vérifier
        if len(ajouts) + retraits >= SEUIL_MASSIF:
            det = [f"changement massif, +{len(ajouts)} / −{retraits} extensions "
                   "(restauration ou autre installation ?)"] + admins + autres
        else:
            det = admins + autres + ajouts
        txt = ", ".join(det[:4]) + (f" … +{len(det) - 4}" if len(det) > 4 else "")
        blocs.append(f"  {A.esc_html(dom)} : {A.esc_html(txt)}")
    if blocs:
        lignes.append("⚠️ <b>À vérifier</b>")
        lignes += blocs[:MAX_SECU]
        if len(blocs) > MAX_SECU:
            lignes.append(f"  … +{len(blocs) - MAX_SECU} site(s)")

    # 2. cœur
    coeurs = versions_nettes(changes, "core", RE_COEUR)
    if coeurs:
        det = " · ".join(f"{A.esc_html(d)} {A.esc_html(v)}"
                         for (d, _), (_, v) in sorted(coeurs.items()))
        lignes.append(f"• WordPress : {det}")

    # 3. extensions : total + les plus fréquentes
    maj = versions_nettes(changes, "plugin_update", RE_MAJ)
    if maj:
        sites = {d for d, _ in maj}
        freq = collections.Counter(nom for _, nom in maj)
        top = [f"{A.esc_html(n)} ×{k}" for n, k in freq.most_common(4) if k > 1]
        txt = f"• {pluriel(len(maj), 'extension')} à jour sur {pluriel(len(sites), 'site')}"
        lignes.append(txt + (f" ({', '.join(top)})" if top else ""))

    # 4. PHP
    php = versions_nettes(changes, "php", RE_PHP)
    if php:
        det = " · ".join(f"{A.esc_html(d)} {A.esc_html(de)} → {A.esc_html(v)}"
                         for (d, _), (de, v) in sorted(php.items()))
        lignes.append(f"• PHP : {det}")

    # 5. le reste, compté
    compte = collections.Counter(c.get("kind") for c in changes
                                 if c.get("severity") != "warn")
    autres = []
    if compte.get("plugin_remove"):
        autres.append(pluriel(compte["plugin_remove"], "extension retirée", "extensions retirées"))
    if compte.get("plugin_status"):
        autres.append(pluriel(compte["plugin_status"], "activation"))
    if compte.get("updraft"):
        autres.append(pluriel(compte["updraft"], "réglage Updraft", "réglages Updraft"))
    suivis = compte.get("install_moved", 0) + compte.get("install_new", 0)
    if suivis:
        autres.append(pluriel(suivis, "installation suivie changée",
                              "installations suivies changées"))
    if autres:
        lignes.append("• " + " · ".join(autres))
    return lignes


# ---------------------------------------------------------------------------
#  Incidents : nouveaux / réglés depuis le bilan précédent
# ---------------------------------------------------------------------------
def libelle(i):
    """« site : quoi » en une ligne courte, sans répéter le nom du site."""
    site = i.get("site") or i.get("server") or ""
    kind, detail = i.get("kind"), str(i.get("detail") or "")
    if kind == "php_fatal":
        quoi = "erreur fatale : " + detail.split(" — ")[0][:60]
    elif kind in ("down", "down_probe"):
        quoi = "injoignable (" + detail[:50] + ")"
    elif kind == "cert_expiring":
        m = re.search(r"expire dans (\d+) jour", detail)
        quoi = f"certificat, expire dans {m.group(1)} j" if m else "certificat"
    else:
        quoi = str(i.get("title") or "")
        if site:
            for motif in (f" sur {site}", f" — {site}", f"{site} : ", f"{site} "):
                quoi = quoi.replace(motif, " ")
        quoi = quoi.strip()
        quoi = quoi[:1].lower() + quoi[1:]
    return f"<b>{A.esc_html(site)}</b> : {A.esc_html(quoi)}"


FAMILLES = [  # (kinds, singulier, pluriel) — pour la ligne « toujours ouvert »
    (("vuln_critical_fixable",), "faille critique corrigeable", "failles critiques corrigeables"),
    (("vuln_critical_unfixed",), "faille critique sans correctif", "failles critiques sans correctif"),
    (("down", "down_probe"), "site injoignable", "sites injoignables"),
    (("php_fatal",), "erreur fatale", "erreurs fatales"),
    (("backup_late",), "sauvegarde en retard", "sauvegardes en retard"),
    (("cert_expiring",), "certificat", "certificats"),
    (("admin_unknown",), "admin inconnu", "admins inconnus"),
]


def resume_familles(incidents):
    compte = collections.Counter(i.get("kind") for i in incidents)
    out, vus = [], set()
    for kinds, un, plusieurs in FAMILLES:
        n = sum(compte.get(k, 0) for k in kinds)
        vus.update(kinds)
        if n:
            out.append(pluriel(n, un, plusieurs))
    reste = sum(n for k, n in compte.items() if k not in vus)
    if reste:
        out.append(pluriel(reste, "autre"))
    return " · ".join(out)


def contexte_parc():
    """(clés des préprods, nb de sites de production suivis)."""
    sites, _index, _ = A.incident_fleet()
    preprod, prod = set(), set()
    for _srv, s in sites:
        cles = {k for k in (s.get("kuma"), s.get("domain")) if k}
        if s.get("preprod"):
            preprod |= cles
        else:
            prod.add(s.get("kuma") or s.get("domain"))
    return preprod, len(prod)


# ---------------------------------------------------------------------------
#  Message
# ---------------------------------------------------------------------------
def build_message(changes, hours=24, incidents=None, previous=None,
                  preprod=frozenset(), n_sites=None, url="", now=None):
    """(texte HTML Telegram, état à mémoriser) ou (None, état) si rien de neuf.

    `incidents` : file « à traiter » (bucket now) du dashboard ;
    `previous` : {id: libellé} des incidents vus au bilan précédent, None si
    aucun bilan n'a encore été mémorisé (premier passage : rien n'est
    « nouveau », tout est « ouvert »).
    """
    now = now or datetime.datetime.now()
    incidents = list(incidents or [])
    inc_prod = [i for i in incidents if i.get("site") not in preprod]
    inc_pp = [i for i in incidents if i.get("site") in preprod]
    ch_prod = [c for c in changes if c.get("domain") not in preprod]
    ch_pp = [c for c in changes if c.get("domain") in preprod]

    etat = {"ts": now.strftime("%Y-%m-%d %H:%M"),
            "incidents": {i["id"]: libelle(i) for i in inc_prod}}
    if previous is None:
        nouveaux, regles = [], []
    else:
        nouveaux = [i for i in inc_prod if i["id"] not in previous]
        regles = [lib for iid, lib in previous.items() if iid not in etat["incidents"]]
    ids_nouveaux = {i["id"] for i in nouveaux}
    ouverts = [i for i in inc_prod if i["id"] not in ids_nouveaux]

    resume = resume_changements(ch_prod)
    if not (nouveaux or regles or resume or (previous is None and inc_prod)):
        return None, etat

    lignes = [f"📊 <b>Parc WordPress · {JOURS[now.weekday()]} {now.strftime('%d/%m')}</b>"]
    if nouveaux:
        verdict = "🔴 " + pluriel(len(nouveaux), "nouveau problème", "nouveaux problèmes")
    elif regles and not inc_prod:
        verdict = "✅ Tout est réglé"
    else:
        verdict = "🟢 Rien de nouveau de grave"
    bilan = [pluriel(n_sites, "site")] if n_sites is not None else []
    bilan.append(f"{len(inc_prod)} à traiter" if inc_prod else "rien à traiter")
    lignes += [f"{verdict} · {' · '.join(bilan)}", ""]

    if nouveaux:
        lignes.append("🆕 <b>Depuis hier</b>")
        lignes += [f"  {libelle(i)}" for i in nouveaux[:MAX_NOUVEAUX]]
        if len(nouveaux) > MAX_NOUVEAUX:
            lignes.append(f"  … +{len(nouveaux) - MAX_NOUVEAUX}")
        lignes.append("")
    if regles:
        lignes.append(f"✅ <b>Réglé</b> ({len(regles)})")
        lignes += [f"  {lib}" for lib in regles[:MAX_REGLES]]
        if len(regles) > MAX_REGLES:
            lignes.append(f"  … +{len(regles) - MAX_REGLES}")
        lignes.append("")
    if ouverts:
        lignes += [f"📌 <b>Toujours ouvert</b> : {resume_familles(ouverts)}", ""]

    if resume:
        win = "24 h" if hours == 24 else f"{hours} h"
        lignes.append(f"🔄 <b>Changements</b> ({win})")
        lignes += resume
        lignes.append("")

    if ch_pp or inc_pp:
        noms = sorted({str(c.get("domain")) for c in ch_pp} | {str(i.get("site")) for i in inc_pp})
        bouts = []
        if ch_pp:
            bouts.append(pluriel(len(ch_pp), "changement"))
        if inc_pp:
            bouts.append(pluriel(len(inc_pp), "incident"))
        cites = ", ".join(noms[:4]) + (" …" if len(noms) > 4 else "")
        lignes += [f"🧪 Préprod : {' · '.join(bouts)} ({A.esc_html(cites)})", ""]

    if url:
        lignes.append(f'<a href="{html.escape(url, quote=True)}">Ouvrir le dashboard</a>')
    return "\n".join(lignes).rstrip(), etat


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
    try:
        payload, _extra = A.incidents_snapshot()
        incidents = [i for i in payload.get("incidents") or [] if i.get("bucket") == "now"]
    except Exception as e:           # le bilan des changements part quand même
        print(f"incidents indisponibles : {type(e).__name__}: {e}")
        incidents = []
    preprod, n_sites = contexte_parc()
    etat_prec = load_json(STATE_PATH, None)
    previous = etat_prec.get("incidents") if isinstance(etat_prec, dict) else None
    url = str(load_json(A.SETTINGS_PATH, {}).get("public_url") or "").strip()

    text, etat = build_message(changes, hours, incidents, previous, preprod, n_sites, url)
    if not text:
        print("Rien de neuf — pas de bilan.")
        if not dry:
            save_json(STATE_PATH, etat, mode=0o600)
        return
    if dry:
        print(text)
        return
    cfg = A.alerts_cfg()
    if not cfg.get("enabled"):
        print("Alertes désactivées (data/alerts.json) — bilan non envoyé.")
        return
    ok, err = A.telegram_send_sync(text)
    A.alerts_log(("bilan envoyé: " if ok else f"bilan échec ({err}): ")
                 + f"{len(changes)} changement(s), {len(incidents)} incident(s)")
    if ok:
        save_json(STATE_PATH, etat, mode=0o600)
    print("Bilan envoyé." if ok else f"Échec envoi : {err}")


if __name__ == "__main__":
    main()
