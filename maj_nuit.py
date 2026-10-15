#!/usr/bin/env python3
"""Mises à jour de la nuit des sites en mode automatique — faites par le dashboard.

Jusqu'au 01/10, le « mode automatique » laissait l'hébergeur (Plesk WP Toolkit,
vers 5 h) appliquer les nouvelles versions, et viz_nuit.py passait derrière à
6 h 45. Deux défauts sans remède de ce côté-là :

  * pas de référence VizProof d'AVANT : WP Toolkit met à jour extension par
    extension avec 5 minutes de délai chacune, trop court pour une baseline. Le
    scan d'après se comparait à la dernière référence promue, parfois vieille
    de semaines et sans les pages ajoutées depuis (tiphainedesign, 3 pages
    « sans baseline » le 01/10) ;
  * le retour arrière ne pouvait que REDESCENDRE une version publiée sur
    wordpress.org — ni les extensions premium, ni un rétablissement à
    l'identique.

Désormais, pour chaque site de data/auto_mode.json, le dashboard fait lui-même
une mise à jour « Contrôlée » (`safe_update_run`, la même chaîne que le bouton
de la page site) : contrôle avant, référence VizProof, sauvegarde UpdraftPlus,
archive des fichiers, mise à jour, contrôles, scan VizProof, retour arrière
depuis l'archive si une page casse (`rollback` du site) ou si le site tombe.
Les MAJ automatiques natives de ces sites sont coupées à l'activation du mode :
WordPress et WP Toolkit (qui les lit) n'y touchent plus.

Deux garde-fous propres à la nuit :

  * ÉCART NON RÉGLÉ. Si le dernier rapport VizProof du site montre des pages en
    échec, on ne met pas à jour : la référence d'avant serait prise sur un site
    déjà cassé, et l'écart deviendrait la norme. Le site est « bloqué » (incident
    à planifier) jusqu'à ce que l'écart soit réglé ou accepté.
  * VERSION REFUSÉE. Une mise à jour annulée n'est pas retentée la nuit suivante
    à la même version (elle casserait de nouveau) : on retient
    {composant: version visée} et on ne réessaie qu'à la version suivante.

Le cœur WordPress : depuis le 07/10 ses versions MINEURES passent aussi par ici
(`--minor`, référence d'avant comprise) ; WordPress et WP Toolkit ne mettent
plus le cœur à jour sur ces sites. Une version majeure reste un geste manuel.

Résultat dans data/maj_nuit.json (file d'incidents `inc_maj_nuit`, écran Mises
à jour, bilan de 8 h) ; viz_nuit.py ne repasse pas sur ces sites. Cron 4 h.
`--dry-run` : dit ce qui serait fait, sans rien lancer ni écrire.
"""
import os, re, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA, load_json, save_json  # noqa: E402
import actions_server as A  # noqa: E402
import viz_nuit  # noqa: E402

PATH = os.path.join(DATA, "maj_nuit.json")
ATTENTE = ("bloqué", "page instable")     # rien n'est fait tant que ce n'est pas réglé


def a_mettre_a_jour(s, refus):
    """→ (extensions, thèmes, écartées) d'après la dernière collecte.

    `refus` = {composant: version visée} des mises à jour annulées : écartées
    tant que la version proposée est la même."""
    gel_p, gel_t = A._frozen_lists(s.get("domain"))
    plugs, themes, ecartees = [], [], []
    for p in s.get("plugins_updates_list") or []:
        if not isinstance(p, dict) or not A.SLUG_RE.match(str(p.get("name") or "")):
            continue
        nom, vers = str(p["name"]), str(p.get("to") or "")
        if nom in gel_p:
            continue
        if refus.get(nom) and refus[nom] == vers:
            ecartees.append(f"{nom} {vers}")
            continue
        plugs.append(nom)
    for t in s.get("themes_list") or []:
        if not isinstance(t, dict) or t.get("update") not in ("available", True, "true", 1):
            continue
        nom, vers = str(t.get("name") or ""), str(t.get("update_version") or "")
        if not A.SLUG_RE.match(nom) or nom in gel_t:
            continue
        if refus.get("theme:" + nom) and refus["theme:" + nom] == vers:
            ecartees.append(f"{nom} {vers}")
            continue
        themes.append(nom)
    return plugs, themes, ecartees


def coeur_mineur(s, refus):
    """Version MINEURE du cœur à appliquer (« 7.1.3 » depuis « 7.1.2 »), ou "".

    Depuis le 07/10 le cœur mineur passe lui aussi par le dashboard : WP
    Toolkit l'appliquait à 4 h 58 sans référence d'avant, et le scan de
    contrôle prenait des retouches de contenu de l'après-midi pour un effet
    de la mise à jour (tiphainedesign). Une version majeure n'est jamais prise
    ici : elle reste un geste à la main."""
    cur, cible = str(s.get("core_version") or ""), str(s.get("core_update") or "")
    a, b = cur.split("."), cible.split(".")
    if len(a) < 2 or len(b) < 2 or a[:2] != b[:2] or cible == cur:
        return ""
    if refus.get("core") == cible:
        return ""
    return cible


def versions_visees(s, plugs, themes, core=""):
    """{composant: version visée} — clé `theme:<slug>` pour un thème, `core`
    pour le cœur."""
    v = {str(p.get("name")): str(p.get("to") or "") for p in s.get("plugins_updates_list") or []
         if isinstance(p, dict) and p.get("name") in plugs}
    for t in s.get("themes_list") or []:
        if isinstance(t, dict) and t.get("name") in themes:
            v["theme:" + str(t["name"])] = str(t.get("update_version") or "")
    if core:
        v["core"] = core
    return v


def ecart_ouvert(srv_name, s, run_garde=""):
    """(pages en échec dans le dernier rapport VizProof du site, id du passage).

    `run_garde` : passage de fin d'une mise à jour que la chaîne a jugée saine
    (« réussi ») malgré des pages en échec — page instable au scan témoin. Ce
    jugement vaut pour les nuits suivantes : le 10/10, terrainnova a gardé sa
    mise à jour (accueil desktop 1,88 %, la page bougeait seule), puis ce même
    rapport a bloqué le site les 11 et 12/10."""
    v = s.get("vizproof") or {}
    if not (v.get("connected") and v.get("has_cli")):
        return [], ""
    rapport = viz_nuit.lire_rapport(srv_name, s.get("domain"))
    if not isinstance(rapport, dict) or rapport.get("is_baseline"):
        return [], ""
    rid = str(rapport.get("run_id") or "")
    if rid and rid == run_garde:
        return [], rid
    return viz_nuit.pages_en_ecart(rapport), rid


def recouper_natives(srv_name, s, dry):
    """Recoupe les MAJ automatiques natives d'un site en automatique → nombre
    d'éléments trouvés actifs (0 = rien à faire).

    Le 03/10, celles de tiphainedesign s'étaient réactivées (restauration de
    l'option, cause non établie) : WP Toolkit a refait à 4 h 56 la mise à jour
    que le dashboard venait d'annuler. On les coupe donc chaque nuit, et on le
    dit — une réactivation répétée a une cause qu'il faut trouver."""
    n = int(s.get("plugins_auto_update") or 0) + int(s.get("themes_auto_update") or 0)
    if not n:
        return 0
    if not dry:
        for act in ("autoupdate_off", "themes_autoupdate_off"):
            A.run_action(srv_name, s.get("domain"), act, None)
        A.alert(f"natives:{s.get('domain')}:{time.strftime('%Y-%m-%d')}", "viz_anomaly", A.carte(
            "⚠️", s.get("domain"), "mises à jour automatiques de WordPress réactivées",
            [f"{n} élément(s) en mise à jour native alors que le dashboard s'en charge : recoupé(s)"],
            faire="Si ça revient, chercher qui les rallume (WP Toolkit, une extension, "
                  "une restauration).", onglet="reglages"))
    return n


def recouper_coeur(srv_name, s, dry):
    """Mise à jour automatique du CŒUR par WordPress / WP Toolkit sur un site en
    automatique → True si elle était active (et vient d'être coupée).

    Depuis le 07/10 le cœur mineur passe par le dashboard. WP Toolkit (réglage
    « core: disabled ») écrit `WP_AUTO_UPDATE_CORE = false` dans wp-config ; une
    constante absente laisse WordPress appliquer seul les mineures, une valeur
    « minor » / true aussi. Lecture : false → chaîne vide, code 0."""
    srv, site = A.find_site(srv_name, s.get("domain"))
    if not site:
        return False
    rc, out = A.remote_bash(srv, site, "run config get WP_AUTO_UPDATE_CORE --skip-plugins --skip-themes", timeout=60)
    val = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
    if rc == 0 and val.lower() in ("", "false", "0"):
        return False
    if not dry:
        A.remote_bash(srv, site, "run config set WP_AUTO_UPDATE_CORE false --raw --skip-plugins --skip-themes", timeout=60)
        A.alert(f"natives-coeur:{s.get('domain')}:{time.strftime('%Y-%m-%d')}", "viz_anomaly", A.carte(
            "⚠️", s.get("domain"), "mise à jour automatique du cœur réactivée",
            [f"WP_AUTO_UPDATE_CORE = {val or 'absent'} alors que le dashboard s'en charge : coupée"],
            faire="Si WP Toolkit la remet, régler son « Cœur » sur « désactivé ».",
            onglet="reglages"))
    return True


RE_SLUG = re.compile(r"[A-Za-z0-9._-]{1,100}")


def paquet_disponible(srv_name, s, slug):
    """Le paquet de mise à jour de `slug` se télécharge-t-il de nouveau ?

    Sonde générique d'une licence renouvelée : on demande à WordPress l'adresse
    du paquet (extensions chargées, c'est leur code qui la fournit) et on en lit
    les premiers octets — « PK », c'est un zip ; une page d'erreur ou un refus,
    non. Sans elle, une version refusée faute de licence ne serait plus jamais
    retentée, même licence renouvelée (Astra Pro sur sumotori, 13/10)."""
    if not RE_SLUG.fullmatch(str(slug or "")):
        return False
    srv, site = A.find_site(srv_name, s.get("domain"))
    if not site:
        return False
    rc, out = A.remote_bash(
        srv, site,
        f'U=$(run plugin list --name={slug} --field=update_package --skip-themes 2>/dev/null | tail -n 1)\n'
        'case "$U" in https://*) curl -s -L --max-time 60 -r 0-3 "$U" | head -c 2 ;; esac\n',
        timeout=120)
    return rc == 0 and (out or "").strip().endswith("PK")


def _controle(srv, site, viz):
    """(sain, pages en écart) après un changement : accueil servi, puis scan
    VizProof s'il est relié (référence prise juste avant par l'appelant)."""
    ok, _st, _taille, msg = A.health_probe(site)
    if not ok:
        return False, [f"accueil : {msg}"]
    if not viz:
        return True, []
    rc, out = A.remote_bash(srv, site, "run vizproof scan --wait --format=json", timeout=600, max_out=None)
    rapport = A.viz_report_payload(A.viz_json_tail(out) or {})
    if not isinstance(rapport, dict) or rapport.get("is_baseline"):
        return True, []
    pages = [p for p, _f, _h in viz_nuit.pages_en_ecart(rapport)]
    return not pages, pages


def _basculer(srv, site, slug, actif):
    rc, out = A.remote_bash(srv, site, f"run plugin {'activate' if actif else 'deactivate'} {slug}", timeout=120)
    return rc == 0, (out or "")[-300:]


def neutraliser(srv_name, s, quarantaine, dry):
    """Neutralisation des failles sans issue (option `neutraliser` du mode
    automatique) → bilan {neutralisees, refusees, reactivees, laissees}.

    Une extension active dont une faille critique ne se corrige pas ce soir
    (pas de correctif, ou correctif refusé faute de licence) est DÉSACTIVÉE —
    mais comme une mise à jour : référence VizProof avant, contrôle après, et
    réactivation immédiate si une page casse (une extension qui fournit un
    formulaire, un agenda, une boutique ne s'éteint pas sans qu'on le voie).
    Une extension mise en quarantaine est RÉACTIVÉE dès qu'une mise à jour la
    corrige, avec le même contrôle. Réactivée à la main par quelqu'un, elle
    n'est plus jamais désactivée : c'est une décision, on ne la combat pas."""
    dom = s.get("domain")
    if not isinstance(quarantaine.get(dom), dict):
        quarantaine[dom] = {}
    q = quarantaine[dom]
    bilan = {"neutralisees": [], "refusees": [], "reactivees": [], "laissees": []}
    srv, site = A.find_site(srv_name, dom)
    if not site:
        return bilan
    actives = {str(p.get("name")): p.get("status") for p in s.get("plugins_list") or [] if isinstance(p, dict)}
    candidates = A.failles_a_neutraliser(s)
    viz = bool((s.get("vizproof") or {}).get("connected") and (s.get("vizproof") or {}).get("has_cli"))

    # 1. Quarantaines à lever : plus de faille sans issue, ou réactivée à la main.
    for slug, info in list(q.items()):
        if not isinstance(info, dict) or slug.startswith("_"):
            continue
        if actives.get(slug) in ("active", "active-network"):
            info["reactivee_a_la_main"] = time.strftime("%Y-%m-%d %H:%M")
            q.setdefault("_ignorees", {})[slug] = info
            q.pop(slug, None)
            bilan["laissees"].append({"slug": slug, "raison": "réactivée à la main"})
            continue
        if slug in candidates or dry:
            continue
        if viz:
            A.remote_bash(srv, site, A.VIZ_BASELINE_CMD, timeout=A.VIZ_BASELINE_TIMEOUT, max_out=None)
        A.remote_bash(srv, site, f"run plugin update {slug}", timeout=300)
        ok, out = _basculer(srv, site, slug, True)
        sain, pages = _controle(srv, site, viz) if ok else (False, [out])
        if sain:
            q.pop(slug, None)
            bilan["reactivees"].append({"slug": slug})
        else:
            _basculer(srv, site, slug, False)
            bilan["refusees"].append({"slug": slug, "action": "réactivation", "pages": pages})

    # 2. Nouvelles neutralisations.
    ignorees = q.get("_ignorees") if isinstance(q.get("_ignorees"), dict) else {}
    for slug, info in candidates.items():
        if slug in q or slug in ignorees or not RE_SLUG.fullmatch(slug):
            continue
        if dry:
            bilan["neutralisees"].append(dict(info, slug=slug, simulation=True))
            continue
        if viz:
            A.remote_bash(srv, site, A.VIZ_BASELINE_CMD, timeout=A.VIZ_BASELINE_TIMEOUT, max_out=None)
        ok, out = _basculer(srv, site, slug, False)
        if not ok:
            bilan["refusees"].append(dict(info, slug=slug, action="désactivation", pages=[out]))
            continue
        sain, pages = _controle(srv, site, viz)
        if sain:
            q[slug] = dict(info, depuis=time.strftime("%Y-%m-%d %H:%M"))
            bilan["neutralisees"].append(dict(info, slug=slug))
        else:
            _basculer(srv, site, slug, True)
            if viz:   # la référence prise sans l'extension ne doit pas rester
                A.remote_bash(srv, site, A.VIZ_BASELINE_CMD, timeout=A.VIZ_BASELINE_TIMEOUT, max_out=None)
            bilan["refusees"].append(dict(info, slug=slug, action="désactivation", pages=pages))
    if not q:
        quarantaine.pop(dom, None)
    return bilan


def alerter_neutralisation(dom, n, dry):
    """Une alerte par geste : désactiver une extension se voit sur le site."""
    if dry:
        return
    for x in n.get("neutralisees") or []:
        A.alert(f"neutralisee:{dom}:{x['slug']}", None, A.carte(
            "🧯", dom, f"{x['slug']} désactivée : {x.get('raison')}",
            [", ".join(x.get("cves") or [])[:200], "contrôle après désactivation : aucune page cassée"],
            faire="Vérifier qu'aucune fonction utile n'a disparu (formulaire, agenda…). Elle sera "
                  "réactivée d'elle-même dès qu'une mise à jour la corrige.", onglet="securite"))
    for x in n.get("refusees") or []:
        A.alert(f"neutralisation_refusee:{dom}:{x['slug']}", None, A.carte(
            "⚠️", dom, f"{x['slug']} : {x.get('action')} annulée, le site cassait sans elle",
            ["pages touchées : " + ", ".join(x.get("pages") or [])[:200]],
            faire="La faille reste ouverte : remplacer l'extension, ou décider de la garder "
                  "en connaissance de cause.", onglet="securite"))
    for x in n.get("reactivees") or []:
        A.alert(f"reactivee:{dom}:{x['slug']}", None, A.carte(
            "✅", dom, f"{x['slug']} réactivée : un correctif est installé",
            [], faire="Rien à faire.", lien=False))


def traiter(srv_name, s, mode, refus, dry, run_garde=""):
    """Une mise à jour Contrôlée sur un site → bilan (dict) ou None (rien à faire)."""
    dom = s.get("domain")
    plugs, themes, ecartees = a_mettre_a_jour(s, refus)
    core = coeur_mineur(s, refus)
    if not core and refus.get("core") and refus.get("core") == s.get("core_update"):
        ecartees = ecartees + [f"WordPress {refus['core']}"]
    base = {"domain": dom, "server": srv_name, "ts": time.time(),
            "items": ([f"WordPress {core}"] if core else []) + plugs + [f"thème {t}" for t in themes],
            "ecartees": ecartees}
    if not plugs and not themes and not core:
        return dict(base, verdict="rien à faire") if ecartees else None

    pages, rid = ecart_ouvert(srv_name, s, run_garde)
    if pages:
        noms = ", ".join(sorted({p for p, _f, _h in pages}))
        return dict(base, verdict="bloqué", report_url=A.viz_lien_run(rid),
                    cause=f"écart VizProof non réglé ({noms}) : mettre à jour par-dessus en ferait "
                          "la nouvelle référence — à régler ou accepter dans VizProof")
    if dry:
        return dict(base, verdict="simulation")

    A.safe_update_run(srv_name, dom, slugs=plugs or None, do_backup=True, use_viz=True,
                      viz_rollback=bool(mode.get("rollback")),
                      themes=themes or None, with_themes=bool(themes), with_plugins=bool(plugs),
                      temoin=True, with_core=bool(core), core_minor=True)
    steps = list(A.SAFE.get("steps") or [])
    verdict = str(A.SAFE.get("verdict") or "")
    cause = next((f"{e['label']} : {str(e.get('detail') or '')[:200]}" for e in steps
                  if not e.get("ok") and not str(e.get("label", "")).startswith("Retour arrière")), "")
    rapport = next((e.get("report") for e in reversed(steps) if isinstance(e.get("report"), dict)), None)
    # Après un retour arrière, le dernier rapport VizProof montre encore la
    # casse : sans un scan de l'état rétabli, le site resterait « bloqué » les
    # nuits suivantes, pour une page déjà réparée.
    apres = None
    if verdict.startswith(("annulé (retour", "ÉCHEC")) and (s.get("vizproof") or {}).get("has_cli"):
        srv, site = A.find_site(srv_name, dom)
        if site:
            rcv, outv = A.remote_bash(srv, site, "run vizproof scan --wait --format=json",
                                      timeout=600, max_out=None)
            rapp2 = A.viz_report_payload(A.viz_json_tail(outv) or {})
            apres = (len(viz_nuit.pages_en_ecart(rapp2)) if isinstance(rapp2, dict)
                     and not rapp2.get("is_baseline") else None)
    echecs = dict(A.SAFE.get("echecs") or {})
    # Compte rendu par page : ce qui a bougé et pourquoi (pixels, SEO avec
    # l'avant/après de chaque champ, accessibilité, HTTP).
    pages = [{k: it.get(k) for k in ("page", "viewport", "status", "cause", "diff_percent",
                                     "seo_changes", "http_status", "masked_missing") if it.get(k) not in (None, "", [])}
             for it in (rapport or {}).get("items") or []
             if isinstance(it, dict) and (it.get("cause") or it.get("status") == "fail")][:16]
    rid = str((rapport or {}).get("run_id") or "")
    return dict(base, ecarts_apres=apres, verdict=verdict, echecs=echecs, pages=pages,
                cause=cause if verdict != "réussi" else "",
                run_id=rid,
                report_url=A.viz_lien_run(rid) or (rapport or {}).get("report_url") or "",
                steps=[{"label": e.get("label"), "ok": bool(e.get("ok")), "warn": bool(e.get("warn")),
                        "detail": str(e.get("detail") or "")[:400]} for e in steps],
                visees=versions_visees(s, plugs, themes, core))


def main():
    dry = "--dry-run" in sys.argv[1:]
    modes = A.auto_mode_load()
    precedent = load_json(PATH, {}) or {}
    refus_tous = precedent.get("refus") if isinstance(precedent.get("refus"), dict) else {}
    sites_avant = precedent.get("sites") if isinstance(precedent.get("sites"), dict) else {}
    quarantaine = load_json(A.QUARANTAINE_PATH, {}) or {}
    # Versions refusées parce que leur paquet ne se télécharge pas (licence) :
    # sous-ensemble de `refus`, sondé chaque nuit pour reprendre de lui-même.
    paquets_avant = (precedent.get("refus_paquet") if isinstance(precedent.get("refus_paquet"), dict)
                     else {})
    refus_paquet = {}
    gardes = dict(precedent.get("runs_gardes") or {}) if isinstance(precedent.get("runs_gardes"), dict) else {}
    sites, refus_neufs, natives = {}, {}, {}
    for srv_name, s in A.visible_sites():
        dom = s.get("domain")
        if dom not in modes or s.get("via") == "rest":
            continue
        refus = dict(refus_tous.get(dom)) if isinstance(refus_tous.get(dom), dict) else {}
        for slug, vers in list((paquets_avant.get(dom) or {}).items()):
            if refus.get(slug) != vers:
                continue
            if not dry and paquet_disponible(srv_name, s, slug):
                print(f"{dom} : {slug} {vers} de nouveau téléchargeable (licence renouvelée ?) → retentée")
                refus.pop(slug, None)
        n_nat = recouper_natives(srv_name, s, dry)
        try:
            if recouper_coeur(srv_name, s, dry):
                n_nat = (n_nat or 0) + 1
        except Exception as e:      # un contrôle, jamais une condition
            print(f"{dom} : contrôle du cœur impossible ({type(e).__name__})")
        if n_nat:
            natives[dom] = n_nat
        try:
            r = traiter(srv_name, s, modes[dom] if isinstance(modes[dom], dict) else {}, refus, dry,
                        run_garde=str(gardes.get(dom) or ""))
        except Exception as e:           # un site en panne n'arrête pas les autres
            r = {"domain": dom, "server": srv_name, "ts": time.time(), "items": [],
                 "verdict": "erreur", "cause": f"{type(e).__name__}: {e}"[:300]}
        # Refus : on garde ceux qui visent encore la version proposée, on ajoute
        # ceux d'une mise à jour annulée cette nuit.
        proposees = versions_visees(s, [str(p.get("name")) for p in s.get("plugins_updates_list") or []
                                        if isinstance(p, dict)],
                                    [str(t.get("name")) for t in s.get("themes_list") or []
                                     if isinstance(t, dict)],
                                    str(s.get("core_update") or ""))
        garde = {k: v for k, v in refus.items() if proposees.get(k) == v}
        if r and str(r.get("verdict", "")).startswith(("annulé (retour", "ÉCHEC")):
            garde.update(r.get("visees") or {})
        # Extension dont la mise à jour a échoué seule (paquet indisponible) :
        # elle seule est retenue, les autres ont été gardées.
        if r and r.get("echecs"):
            garde.update({k: v for k, v in r["echecs"].items() if v})
        # Paquets refusés encore valables (même version proposée, pas rétablis).
        pq = {k: v for k, v in (paquets_avant.get(dom) or {}).items() if garde.get(k) == v and refus.get(k) == v}
        pq.update({k: v for k, v in ((r or {}).get("echecs") or {}).items() if v})
        if pq:
            refus_paquet[dom] = pq
        if garde:
            refus_neufs[dom] = garde
        # Passage de fin jugé sain : il ne bloquera pas les nuits suivantes.
        if r and r.get("verdict") == "réussi" and r.get("run_id"):
            gardes[dom] = r["run_id"]
        if r and r.get("verdict") in ATTENTE:
            # Nuits d'attente consécutives : un site bloqué ne reçoit plus rien,
            # et la durée dit l'urgence (« depuis 3 nuits »).
            av = sites_avant.get(dom) if isinstance(sites_avant.get(dom), dict) else {}
            if av.get("verdict") in ATTENTE:
                r["nuits_attente"] = int(av.get("nuits_attente") or 1) + 1
                r["attente_depuis"] = av.get("attente_depuis") or av.get("ts")
            else:
                r["nuits_attente"], r["attente_depuis"] = 1, r.get("ts")
        if (modes[dom] if isinstance(modes[dom], dict) else {}).get("neutraliser"):
            try:
                n = neutraliser(srv_name, s, quarantaine, dry)
            except Exception as e:           # un site en panne n'arrête pas les autres
                n = {"erreur": f"{type(e).__name__}: {e}"[:300]}
            if any(n.get(k) for k in ("neutralisees", "refusees", "reactivees", "laissees", "erreur")):
                r = r or {"domain": dom, "server": srv_name, "ts": time.time(), "items": [],
                          "verdict": "rien à faire"}
                r["neutralisation"] = n
                alerter_neutralisation(dom, n, dry)
        if r:
            sites[dom] = r
            print(f"{dom:28} {r['verdict']:32} {', '.join(r.get('items') or []) or '-'}"
                  + (f" · {r['cause'][:120]}" if r.get("cause") else ""))
    if dry:
        return
    save_json(A.QUARANTAINE_PATH, quarantaine)
    save_json(PATH, {"generated_at": time.strftime("%Y-%m-%d %H:%M"), "ts": time.time(),
                     "sites": sites, "refus": refus_neufs, "natives_recoupees": natives,
                     "runs_gardes": gardes, "refus_paquet": refus_paquet})
    A.attendre_envois()
    print(f"{len(sites)} site(s) traité(s) cette nuit.")


if __name__ == "__main__":
    main()
