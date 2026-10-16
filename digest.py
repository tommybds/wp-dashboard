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
écrit seulement quand le bilan part vraiment.

Le bilan part TOUS les jours, même sans rien de neuf : un silence ne doit
jamais pouvoir passer pour « tout va bien » quand c'est le cron, Telegram ou le
serveur qui est en panne. Il rend compte aussi de la passe de nuit du dashboard
(data/maj_nuit.json : sites mis à jour, en attente, mises à jour impossibles),
dont les incidents « à planifier » n'entrent pas dans la file « à traiter ».

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
MAJ_NUIT_PATH = os.path.join(DATA, "maj_nuit.json")
NUIT_FRAICHE_H = 20      # une passe plus vieille n'est pas « cette nuit »
MAX_NUIT = 8

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


def court(site):
    """« terrainnova.fr » → « terrainnova » : le nom se lit aussi bien, et
    Telegram ne le transforme plus en lien bleu vers le site public (tous les
    noms de site du bilan l'étaient, et rien n'y était utile)."""
    site = str(site or "").removeprefix("www.")
    hote, sep, chemin = site.partition("/")
    if "." in hote:
        hote = hote.rsplit(".", 1)[0]
    return hote + sep + chemin


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


def reinstallations(changes):
    """Une extension « retirée » puis « ajoutée » sous le même nom sur le même
    site, c'est une mise à jour vue EN COURS : WordPress supprime l'ancien
    dossier avant de poser le nouveau, et une collecte qui passe entre les deux
    voit l'extension disparaître. Annoncer « + extension » en « À vérifier »
    (signal d'intrusion) et « 1 extension retirée » était doublement faux.

    → changements où chaque paire retrait → ajout devient une mise à jour."""
    retraits = {}
    for k, c in enumerate(changes):
        if c.get("kind") == "plugin_remove":
            nom = str(c.get("detail") or "").replace("− extension ", "", 1).strip()
            retraits.setdefault((c.get("domain"), nom), []).append(k)
    sautes, ajouts = set(), {}
    for k, c in enumerate(changes):
        if c.get("kind") != "plugin_add":
            continue
        reste = str(c.get("detail") or "").replace("+ extension ", "", 1).strip().split(" ")
        nom, vers = reste[0], (reste[1] if len(reste) > 1 else "?")
        avant = [r for r in retraits.get((c.get("domain"), nom), []) if r < k and r not in sautes]
        if avant:
            sautes.update((avant[-1], k))
            ajouts[k] = dict(c, kind="plugin_update", severity="info", detail=f"{nom} ? → {vers}")
    return [ajouts.get(k, c) for k, c in enumerate(changes) if k not in sautes or k in ajouts]


def maintenance_wpt(changes):
    """`maintenance.php` qui apparaît pendant une mise à jour du cœur : c'est la
    page de maintenance que Plesk WP Toolkit génère (« DO NOT MODIFY THIS FILE
    BECAUSE IT WAS GENERATED AUTOMATICALLY »), pas une extension inconnue.
    Rangée en information ; le scan structurel reste là pour un faux de ce nom."""
    return [dict(c, kind="maintenance_wpt", severity="info") if c.get("kind") == "plugin_add"
            and str(c.get("detail") or "").replace("+ extension ", "", 1).strip().split(" ")[0] == "maintenance.php"
            else c for c in changes]


def resume_changements(changes):
    """Changements de PRODUCTION → lignes du bloc « Changements »."""
    changes = maintenance_wpt(reinstallations(changes))
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
        blocs.append(f"  {A.esc_html(court(dom))} : {A.esc_html(txt)}")
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

    # 3 bis. thèmes (journalisés depuis le 30/09)
    themes = versions_nettes(changes, "theme_update", RE_MAJ)
    if themes:
        lignes.append(f"• {pluriel(len(themes), 'thème')} à jour sur "
                      f"{pluriel(len({d for d, _ in themes}), 'site')}")

    # 4. PHP. Un correctif de l'hébergeur (8.3.33 → 8.3.35) touche vingt sites
    #    d'un coup et n'appelle aucun geste : il est regroupé par transition. Un
    #    changement de BRANCHE (8.2 → 8.3), lui, peut casser un site : il reste
    #    détaillé site par site.
    php = versions_nettes(changes, "php", RE_PHP)
    if php:
        branche = lambda v: ".".join(str(v).split(".")[:2])
        correctifs = collections.OrderedDict()
        bascules = []
        for (d, _), (de, v) in sorted(php.items()):
            if branche(de) == branche(v):
                correctifs.setdefault((de, v), []).append(d)
            else:
                bascules.append(f"{A.esc_html(d)} {A.esc_html(de)} → {A.esc_html(v)}")
        if bascules:
            lignes.append("• PHP : " + " · ".join(bascules))
        if correctifs:
            det = []
            for (de, v), doms in sorted(correctifs.items(), key=lambda x: -len(x[1])):
                qui = (", ".join(A.esc_html(x) for x in doms) if len(doms) <= 2
                       else pluriel(len(doms), "site"))
                det.append(f"{A.esc_html(de)} → {A.esc_html(v)} ({qui})")
            lignes.append("• PHP, correctifs de l’hébergeur : " + " · ".join(det))

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
# Causes de fatale qu'on sait dire en une expression. Le message PHP brut,
# coupé à 60 caractères (« Uncaught Error: Failed opening required
# '/var/www/vhosts/les »), ne disait ni QUI est en cause ni si c'est grave.
CAUSES_FATALE = [
    (re.compile(r"Maximum execution time", re.I), "délai d’exécution dépassé"),
    (re.compile(r"Allowed memory size", re.I), "mémoire insuffisante"),
    (re.compile(r"Failed opening required|failed to open stream", re.I), "fichier introuvable"),
    (re.compile(r"Call to undefined (function|method)", re.I), "fonction introuvable"),
    (re.compile(r"Class .* not found", re.I), "classe introuvable"),
    (re.compile(r"syntax error|Parse error", re.I), "erreur de syntaxe PHP"),
    (re.compile(r"Undefined constant", re.I), "constante non définie"),
]


def libelle_fatale(i, detail):
    """« erreur fatale dans l'extension wp-seopress (fichier introuvable), 12 fois »."""
    x = i.get("extra") if isinstance(i.get("extra"), dict) else {}
    fichier = str(x.get("file") or "")
    message = str(x.get("message") or detail)
    m = re.search(r"wp-content/(plugins|themes)/([^/]+)", fichier)
    if m:
        ou = ("l’extension " if m.group(1) == "plugins" else "le thème ") + m.group(2)
    elif re.search(r"(^|/)(wp-includes|wp-admin)/", fichier):
        ou = "le cœur WordPress"
    else:
        ou = ""
    cause = next((txt for motif, txt in CAUSES_FATALE if motif.search(message)), "")
    if not ou and not cause:                  # rien de reconnu : le message, faute de mieux
        return "erreur fatale : " + detail.split(" — ")[0][:60]
    quoi = "erreur fatale" + (f" dans {ou}" if ou else "") + (f" ({cause})" if cause else "")
    try:
        n = int(x.get("count") or 1)
    except (TypeError, ValueError):
        n = 1
    return quoi + (f", {n} fois" if n > 1 else "")


def libelle(i):
    """« site : quoi » en une ligne courte, sans répéter le nom du site."""
    site = i.get("site") or i.get("server") or ""
    return f"<b>{A.esc_html(court(site))}</b> — {A.esc_html(quoi_incident(i))}"


def quoi_incident(i):
    """Ce qui arrive, sans le nom du site (texte brut)."""
    site = i.get("site") or i.get("server") or ""
    kind, detail = i.get("kind"), str(i.get("detail") or "")
    if kind == "php_fatal":
        quoi = libelle_fatale(i, detail)
    elif kind == "licence_attendue":
        x = i.get("extra") if isinstance(i.get("extra"), dict) else {}
        quoi = f"licence à renouveler : {x.get('item') or '?'}"
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
        quoi = " ".join(quoi.split())
        quoi = quoi[:1].lower() + quoi[1:]
    return quoi


# Le geste attendu, pour les incidents qui en ont un évident. Une nouveauté
# sans « que faire » obligeait à ouvrir le dashboard pour le savoir.
A_FAIRE = {
    "auto_update_blocked": "régler l'écart dans VizProof (accepter ou corriger)",
    "auto_update_failed": "voir la cause dans Mises à jour",
    "auto_rollback": "intervenir sur le site",
    "viz_auto_update": "regarder l'écart, revenir en arrière si c'est cassé",
    "vuln_critical_fixable": "lancer la mise à jour",
    "vuln_critical_licence": "renouveler la licence, la mise à jour suivra",
    "vuln_critical_unfixed": "désactiver ou remplacer l'extension",
    "backup_late": "relancer UpdraftPlus",
    "cert_expiring": "relancer le certificat (SSL It!)",
    "admin_unknown": "vérifier ce compte, compromission possible",
    "checksums_modified": "vérifier les fichiers du cœur, compromission possible",
    "down": "vérifier le site",
    "down_probe": "vérifier le site",
    "licence_attendue": "renouveler la licence — la mise à jour reprendra seule la nuit suivante",
}


def lien_ecart(url):
    """« voir l'écart » vers le passage VizProof, ou '' (seul https est lié)."""
    url = str(url or "")
    return (f'<a href="{html.escape(url, quote=True)}">voir l’écart</a>'
            if url.startswith("https://") else "")


MAX_SITES_GROUPE = 8


def grouper(incidents):
    """[[incident, …]] : les incidents de même nature et de même cause, sur
    plusieurs sites, forment UN problème. Le 16/10, une panne de VizProof (une
    seule cause) s'est lue « 🔴 7 nouveaux problèmes », un par site."""
    groupes, index = [], {}
    for i in incidents:
        cle = (i.get("kind"), quoi_incident(i), " ".join(str(i.get("detail") or "").split()))
        if cle in index:
            groupes[index[cle]].append(i)
        else:
            index[cle] = len(groupes)
            groupes.append([i])
    return groupes


def ligne_groupe(g):
    """Une ligne pour un problème : un site, ou plusieurs touchés de la même façon."""
    if len(g) == 1:
        return ligne_nouveau(g[0])
    i = g[0]
    noms = [court(x.get("site") or x.get("server") or "") for x in g]
    sites = ", ".join(noms[:MAX_SITES_GROUPE]) + (f" … +{len(noms) - MAX_SITES_GROUPE}"
                                                  if len(noms) > MAX_SITES_GROUPE else "")
    cause = " ".join(str(i.get("detail") or "").split())[:160]
    faire = A_FAIRE.get(i.get("kind"))
    return (f"• <b>{len(g)} sites</b> — {A.esc_html(quoi_incident(i))}"
            + (f" : {A.esc_html(cause)}" if cause else "")
            + f"\n   {A.esc_html(sites)}"
            + (f"\n   👉 {A.esc_html(faire)}" if faire else ""))


RE_LIGNE_NUIT = re.compile(r"^• (\S+) <b>([^<]+)</b> — (.*)$", re.S)


def grouper_nuit(lignes):
    """Lignes « Cette nuit » identiques à part le site → une seule ligne."""
    groupes, index = [], {}
    for l in lignes:
        m = RE_LIGNE_NUIT.match(l)
        cle = (m.group(1), m.group(3)) if m else (None, l)
        if m and cle in index:
            groupes[index[cle]][1].append(m.group(2))
            continue
        index[cle] = len(groupes)
        groupes.append((l, [m.group(2)] if m else []))
    out = []
    for l, noms in groupes:
        if len(noms) < 2:
            out.append(l)
            continue
        m = RE_LIGNE_NUIT.match(l)
        liste = ", ".join(noms[:MAX_SITES_GROUPE]) + (f" … +{len(noms) - MAX_SITES_GROUPE}"
                                                      if len(noms) > MAX_SITES_GROUPE else "")
        out.append(f"• {m.group(1)} <b>{len(noms)} sites</b> — {m.group(3)}\n   {liste}")
    return out


def ligne_nouveau(i):
    faire = A_FAIRE.get(i.get("kind"))
    x = i.get("extra") if isinstance(i.get("extra"), dict) else {}
    lien = lien_ecart(x.get("report_url"))
    if faire:
        return f"• {libelle(i)}\n   👉 {A.esc_html(faire)}" + (f" · {lien}" if lien else "")
    return f"• {libelle(i)}" + (f" · {lien}" if lien else "")


FAMILLES = [  # (kinds, singulier, pluriel) — pour la ligne « toujours ouvert »
    (("vuln_critical_fixable",), "faille critique corrigeable", "failles critiques corrigeables"),
    (("vuln_critical_unfixed",), "faille critique sans correctif", "failles critiques sans correctif"),
    (("vuln_critical_licence",), "faille critique bloquée par une licence",
     "failles critiques bloquées par une licence"),
    (("down", "down_probe"), "site injoignable", "sites injoignables"),
    (("php_fatal",), "erreur fatale", "erreurs fatales"),
    (("backup_late",), "sauvegarde en retard", "sauvegardes en retard"),
    (("cert_expiring",), "certificat", "certificats"),
    (("admin_unknown",), "admin inconnu", "admins inconnus"),
    (("viz_auto_update",), "écart après mise à jour auto", "écarts après mise à jour auto"),
    (("auto_rollback",), "mise à jour auto annulée", "mises à jour auto annulées"),
    (("auto_update_blocked",), "site en automatique bloqué par un écart", "sites en automatique bloqués par un écart"),
    (("auto_update_failed",), "mise à jour de nuit non faite", "mises à jour de nuit non faites"),
    (("licence_attendue",), "licence à renouveler", "licences à renouveler"),
]


def suffixe(iid):
    """« kind:site:composant » → « site:composant » (ce qui désigne la faille)."""
    parts = str(iid).split(":", 1)
    return parts[1] if len(parts) == 2 else ""


def correctifs_publies(nouveaux, previous):
    """Une faille critique « sans correctif » au bilan précédent qui revient
    « corrigeable » n'est ni un nouveau problème ni un problème réglé : c'est la
    MÊME faille, pour laquelle l'éditeur vient de publier la version corrigée.
    L'annoncer comme « 🔴 nouveau problème » + « ✅ réglé » disait deux fois
    faux ; elle a sa propre section, qui dit le geste à faire.

    → (incidents « correctif publié », ids anciens à retirer des réglés)."""
    anciens = {suffixe(iid): iid for iid in (previous or {})
               if str(iid).startswith("vuln_critical_unfixed:")}
    paires, retires = [], set()
    for i in nouveaux:
        if i.get("kind") != "vuln_critical_fixable":
            continue
        vieux = anciens.get(suffixe(i.get("id")))
        if vieux:
            paires.append(i)
            retires.add(vieux)
    return paires, retires


# Genres d'un même problème : une faille passe de l'un à l'autre quand sa
# situation change (correctif publié, licence expirée ou renouvelée). Le genre
# fait partie de l'identifiant ; sans ce regroupement, le changement de genre se
# lisait « 🆕 nouveau problème » + « ✅ réglé » pour la même faille (lesgeiq,
# 14/10, corrigeable → bloquée par la licence).
MEMES_FAILLES = {"vuln_critical_fixable", "vuln_critical_unfixed", "vuln_critical_licence"}


def requalifies(nouveaux, previous, deja=frozenset()):
    """(incidents nouveaux qui ne sont qu'un changement de genre, ids anciens
    correspondants) — ni nouveaux, ni réglés : ils restent « ouverts »."""
    anciens = {suffixe(iid): iid for iid in (previous or {})
               if str(iid).split(":", 1)[0] in MEMES_FAILLES and iid not in deja}
    out, retires = [], set()
    for i in nouveaux:
        if i.get("kind") not in MEMES_FAILLES:
            continue
        vieux = anciens.get(suffixe(i.get("id")))
        if vieux and vieux != i.get("id"):
            out.append(i)
            retires.add(vieux)
    return out, retires


def libelle_correctif(i):
    x = i.get("extra") if isinstance(i.get("extra"), dict) else {}
    site = i.get("site") or ""
    slug, de, vers = str(x.get("slug") or ""), str(x.get("from") or ""), str(x.get("to") or "")
    if slug and vers:
        quoi = f"{slug} {de} → {vers}".replace("  ", " ")
    else:
        quoi = re.sub(r" · .*$", "", str(i.get("title") or ""))
    return f"<b>{A.esc_html(court(site))}</b> — {A.esc_html(quoi)}"


# Telegram transforme en lien tout ce qui ressemble à une adresse IPv4 : une
# version à quatre nombres (gravityforms 3.1.0.2) s'affichait en bleu,
# cliquable vers http://3.1.0.2. En <code>, elle reste du texte.
RE_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")


def sans_lien_ip(ligne):
    return RE_IPV4.sub(r"<code>\1</code>", ligne)


def resume_familles(incidents, max_sites=6):
    """« Toujours ouvert » : une ligne par famille, avec les sites concernés.
    Un compteur seul (« 6 failles critiques corrigeables ») ne disait pas où."""
    par_kind = collections.defaultdict(list)
    for i in incidents:
        par_kind[i.get("kind")].append(i)
    out, vus = [], set()

    def sites_de(xs):
        noms = sorted({court(i.get("site") or i.get("server") or "") for i in xs} - {""})
        txt = ", ".join(noms[:max_sites]) + (f" … +{len(noms) - max_sites}" if len(noms) > max_sites else "")
        return f" : {A.esc_html(txt)}" if txt else ""
    for kinds, un, plusieurs in FAMILLES:
        xs = [i for k in kinds for i in par_kind.get(k, [])]
        vus.update(kinds)
        if xs:
            out.append(f"• {pluriel(len(xs), un, plusieurs)}{sites_de(xs)}")
    reste = [i for k, xs in par_kind.items() if k not in vus for i in xs]
    if reste:
        out.append(f"• {pluriel(len(reste), 'autre')}{sites_de(reste)}")
    return out


def resume_nuit(nuit, now=None):
    """Lignes « Cette nuit » depuis data/maj_nuit.json (liste vide : pas de passe
    à raconter — mode automatique jamais activé)."""
    if not isinstance(nuit, dict) or not nuit.get("ts"):
        return []
    now = now or datetime.datetime.now()
    try:
        quand = datetime.datetime.fromtimestamp(float(nuit["ts"]))
    except (TypeError, ValueError, OverflowError, OSError):
        return []
    if (now - quand).total_seconds() > NUIT_FRAICHE_H * 3600:
        return [f"⚠️ <b>Passe de nuit absente</b> — dernière le {quand.strftime('%d/%m à %H:%M')}"]
    lignes = []
    for dom, r in sorted((nuit.get("sites") or {}).items()):
        if not isinstance(r, dict):
            continue
        d = f"<b>{A.esc_html(court(dom))}</b>"
        v = str(r.get("verdict") or "")
        echecs = r.get("echecs") if isinstance(r.get("echecs"), dict) else {}
        items = [str(x) for x in r.get("items") or [] if str(x) not in echecs]
        cause = str(r.get("cause") or "")
        lien = lien_ecart(r.get("report_url")) if (v in ("bloqué", "page instable") or "anomalies" in v
                                                    or v.startswith(("annulé (retour", "ÉCHEC"))) else ""
        lien = f" · {lien}" if lien else ""
        if v == "annulé":
            # Interrompue AVANT toute modification (« annulé (retour arrière) »
            # est l'autre cas) : la flèche ↩️ faisait croire à un retour arrière.
            lignes.append(f"• ⏹ {d} — mise à jour non lancée, rien n'a changé"
                          + (f" : {A.esc_html(cause[:140])}" if cause else ""))
        elif v.startswith(("annulé", "ÉCHEC", "impossible", "erreur")):
            lignes.append(f"• {'⛔' if v.startswith('ÉCHEC') else '↩️'} {d} — {A.esc_html(v)}"
                          + (f" : {A.esc_html(cause[:140])}" if cause else "") + lien)
        elif v.startswith("réussi") and items:
            lignes.append(f"• ✅ {d} — {A.esc_html(', '.join(items))}"
                          + (" (écart visuel à regarder)" if "anomalies" in v else "") + lien)
        elif v in ("bloqué", "page instable"):
            m = re.search(r"\(([^)]*)\)", cause)
            motif = ("écart VizProof non réglé" + (f" ({m.group(1)})" if m else "")
                     if cause.startswith("écart VizProof") else (cause or v))
            nuits = int(r.get("nuits_attente") or 1)
            lignes.append(f"• ⏸ {d} — bloqué" + (f" depuis {nuits} nuits" if nuits > 1 else "")
                          + f" : {A.esc_html(motif[:90])}" + lien)
        for slug, vers in echecs.items():
            lignes.append(f"• ⚠️ {d} — {A.esc_html(f'{slug} {vers}'.strip())} impossible "
                          "(paquet indisponible, licence ?)")
        n = r.get("neutralisation") if isinstance(r.get("neutralisation"), dict) else {}
        for x in n.get("neutralisees") or []:
            lignes.append(f"• 🧯 {d} — {A.esc_html(x.get('slug'))} désactivée ({A.esc_html(x.get('raison'))})")
        for x in n.get("refusees") or []:
            lignes.append(f"• ⚠️ {d} — {A.esc_html(x.get('slug'))} : {A.esc_html(x.get('action'))} annulée, "
                          "le site cassait sans elle")
        for x in n.get("reactivees") or []:
            lignes.append(f"• ✅ {d} — {A.esc_html(x.get('slug'))} réactivée (corrigée)")
    if not lignes:
        return ["🌙 <b>Cette nuit</b> : rien à mettre à jour"]
    lignes = grouper_nuit(lignes)
    reste = len(lignes) - MAX_NUIT
    return (["🌙 <b>Cette nuit</b>"] + lignes[:MAX_NUIT]
            + ([f"• … +{reste}"] if reste > 0 else []))


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
                  preprod=frozenset(), n_sites=None, url="", now=None, nuit=None,
                  ailleurs=frozenset()):
    """(texte HTML Telegram, état à mémoriser) — toujours un texte.

    `incidents` : file « à traiter » (bucket now) du dashboard ;
    `previous` : {id: libellé} des incidents vus au bilan précédent, None si
    aucun bilan n'a encore été mémorisé (premier passage : rien n'est
    « nouveau », tout est « ouvert ») ; `ailleurs` : ids encore présents mais
    hors de « à traiter » (déclassés en « à planifier ») — sortis de la file,
    ils ne sont pas pour autant « réglés ».
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
        nouveaux, regles, publies = [], [], []
    else:
        nouveaux = [i for i in inc_prod if i["id"] not in previous]
        publies, retires = correctifs_publies(nouveaux, previous)
        ids_publies = {i["id"] for i in publies}
        nouveaux = [i for i in nouveaux if i["id"] not in ids_publies]
        requal, retires_rq = requalifies(nouveaux, previous, retires)
        ids_requal = {i["id"] for i in requal}
        nouveaux = [i for i in nouveaux if i["id"] not in ids_requal]
        retires = retires | retires_rq
        regles = [lib for iid, lib in previous.items()
                  if iid not in etat["incidents"] and iid not in retires and iid not in ailleurs]
    ids_nouveaux = {i["id"] for i in nouveaux} | {i["id"] for i in publies}
    ouverts = [i for i in inc_prod if i["id"] not in ids_nouveaux]

    resume = resume_changements(ch_prod)
    lignes_nuit = resume_nuit(nuit, now)

    lignes = [f"📊 <b>Parc WordPress · {JOURS[now.weekday()]} {now.strftime('%d/%m')}</b>"]
    groupes = grouper(nouveaux)
    if nouveaux:
        verdict = "🔴 " + pluriel(len(groupes), "nouveau problème", "nouveaux problèmes")
        if len(groupes) < len(nouveaux):
            verdict += f" ({pluriel(len({i.get('site') for i in nouveaux}), 'site')})"
    elif publies:
        verdict = "🟠 " + pluriel(len(publies), "correctif à appliquer", "correctifs à appliquer")
    elif regles and not inc_prod:
        verdict = "✅ Tout est réglé"
    else:
        verdict = "🟢 Rien de nouveau de grave"
    bilan = [pluriel(n_sites, "site")] if n_sites is not None else []
    bilan.append(f"{len(inc_prod)} à traiter" if inc_prod else "rien à traiter")
    lignes += [f"{verdict} · {' · '.join(bilan)}", ""]

    if nouveaux:
        lignes.append("🆕 <b>Depuis hier</b>")
        lignes += [ligne_groupe(g) for g in groupes[:MAX_NOUVEAUX]]
        if len(groupes) > MAX_NOUVEAUX:
            lignes.append(f"• … +{len(groupes) - MAX_NOUVEAUX}")
        lignes.append("")
    if publies:
        lignes.append("🔧 <b>Correctif publié</b> — faille critique, mise à jour à lancer")
        lignes += [f"• {libelle_correctif(i)}" for i in publies[:MAX_NOUVEAUX]]
        if len(publies) > MAX_NOUVEAUX:
            lignes.append(f"• … +{len(publies) - MAX_NOUVEAUX}")
        lignes.append("")
    if regles:
        lignes.append(f"✅ <b>Réglé</b> ({len(regles)})")
        lignes += [f"• {lib}" for lib in regles[:MAX_REGLES]]
        if len(regles) > MAX_REGLES:
            lignes.append(f"• … +{len(regles) - MAX_REGLES}")
        lignes.append("")
    if lignes_nuit:
        lignes += lignes_nuit + [""]
    if ouverts:
        lignes += [f"📌 <b>Toujours ouvert</b> ({len(ouverts)})"] + resume_familles(ouverts) + [""]

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
        cites = ", ".join(court(n) for n in noms[:4]) + (" …" if len(noms) > 4 else "")
        lignes += [f"🧪 Préprod : {' · '.join(bouts)} ({A.esc_html(cites)})", ""]

    lignes = [sans_lien_ip(x) for x in lignes]
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
        tous = payload.get("incidents") or []
        incidents = [i for i in tous if i.get("bucket") == "now"]
        ailleurs = {i.get("id") for i in tous if i.get("bucket") != "now"}
    except Exception as e:           # le bilan des changements part quand même
        print(f"incidents indisponibles : {type(e).__name__}: {e}")
        incidents, ailleurs = [], set()
    preprod, n_sites = contexte_parc()
    etat_prec = load_json(STATE_PATH, None)
    previous = etat_prec.get("incidents") if isinstance(etat_prec, dict) else None
    url = str(load_json(A.SETTINGS_PATH, {}).get("public_url") or "").strip()

    nuit = load_json(MAJ_NUIT_PATH, None)
    text, etat = build_message(changes, hours, incidents, previous, preprod, n_sites, url,
                               nuit=nuit, ailleurs=ailleurs)
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
