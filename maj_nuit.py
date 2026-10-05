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

Le cœur WordPress n'est pas concerné : ses correctifs mineurs restent appliqués
par WordPress/WP Toolkit — des correctifs de sécurité qu'une panne du dashboard
ne doit pas retarder.

Résultat dans data/maj_nuit.json (file d'incidents `inc_maj_nuit`, écran Mises
à jour, bilan de 8 h) ; viz_nuit.py ne repasse pas sur ces sites. Cron 4 h.
`--dry-run` : dit ce qui serait fait, sans rien lancer ni écrire.
"""
import os, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA, load_json, save_json  # noqa: E402
import actions_server as A  # noqa: E402
import viz_nuit  # noqa: E402

PATH = os.path.join(DATA, "maj_nuit.json")


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


def versions_visees(s, plugs, themes):
    """{composant: version visée} — clé `theme:<slug>` pour un thème."""
    v = {str(p.get("name")): str(p.get("to") or "") for p in s.get("plugins_updates_list") or []
         if isinstance(p, dict) and p.get("name") in plugs}
    for t in s.get("themes_list") or []:
        if isinstance(t, dict) and t.get("name") in themes:
            v["theme:" + str(t["name"])] = str(t.get("update_version") or "")
    return v


def ecart_ouvert(srv_name, s):
    """Pages en échec dans le dernier rapport VizProof du site, ou []."""
    v = s.get("vizproof") or {}
    if not (v.get("connected") and v.get("has_cli")):
        return []
    rapport = viz_nuit.lire_rapport(srv_name, s.get("domain"))
    if not isinstance(rapport, dict) or rapport.get("is_baseline"):
        return []
    return viz_nuit.pages_en_ecart(rapport)


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
        A.alert(f"natives:{s.get('domain')}:{time.strftime('%Y-%m-%d')}", "viz_anomaly",
                f"⚠️ <b>{A.esc_html(s.get('domain'))}</b> — {n} mise(s) à jour automatique(s) "
                "native(s) réactivée(s) alors que le site est en mode automatique du dashboard : "
                "recoupées. WordPress / WP Toolkit les auraient appliquées sans contrôle.")
    return n


def traiter(srv_name, s, mode, refus, dry):
    """Une mise à jour Contrôlée sur un site → bilan (dict) ou None (rien à faire)."""
    dom = s.get("domain")
    plugs, themes, ecartees = a_mettre_a_jour(s, refus)
    base = {"domain": dom, "server": srv_name, "ts": time.time(),
            "items": plugs + [f"thème {t}" for t in themes], "ecartees": ecartees}
    if not plugs and not themes:
        return dict(base, verdict="rien à faire") if ecartees else None

    pages = ecart_ouvert(srv_name, s)
    if pages:
        noms = ", ".join(sorted({p for p, _f, _h in pages}))
        return dict(base, verdict="bloqué",
                    cause=f"écart VizProof non réglé ({noms}) : mettre à jour par-dessus en ferait "
                          "la nouvelle référence — à régler ou accepter dans VizProof")
    if dry:
        return dict(base, verdict="simulation")

    A.safe_update_run(srv_name, dom, slugs=plugs or None, do_backup=True, use_viz=True,
                      with_core=False, viz_rollback=bool(mode.get("rollback")),
                      themes=themes or None, with_themes=bool(themes), with_plugins=bool(plugs),
                      temoin=True)
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
    return dict(base, ecarts_apres=apres, verdict=verdict, echecs=echecs, pages=pages,
                cause=cause if verdict != "réussi" else "",
                report_url=(rapport or {}).get("report_url") or "",
                steps=[{"label": e.get("label"), "ok": bool(e.get("ok")), "warn": bool(e.get("warn")),
                        "detail": str(e.get("detail") or "")[:400]} for e in steps],
                visees=versions_visees(s, plugs, themes))


def main():
    dry = "--dry-run" in sys.argv[1:]
    modes = A.auto_mode_load()
    precedent = load_json(PATH, {}) or {}
    refus_tous = precedent.get("refus") if isinstance(precedent.get("refus"), dict) else {}
    sites, refus_neufs, natives = {}, {}, {}
    for srv_name, s in A.visible_sites():
        dom = s.get("domain")
        if dom not in modes or s.get("via") == "rest":
            continue
        refus = refus_tous.get(dom) if isinstance(refus_tous.get(dom), dict) else {}
        n_nat = recouper_natives(srv_name, s, dry)
        if n_nat:
            natives[dom] = n_nat
        try:
            r = traiter(srv_name, s, modes[dom] if isinstance(modes[dom], dict) else {}, refus, dry)
        except Exception as e:           # un site en panne n'arrête pas les autres
            r = {"domain": dom, "server": srv_name, "ts": time.time(), "items": [],
                 "verdict": "erreur", "cause": f"{type(e).__name__}: {e}"[:300]}
        # Refus : on garde ceux qui visent encore la version proposée, on ajoute
        # ceux d'une mise à jour annulée cette nuit.
        proposees = versions_visees(s, [str(p.get("name")) for p in s.get("plugins_updates_list") or []
                                        if isinstance(p, dict)],
                                    [str(t.get("name")) for t in s.get("themes_list") or []
                                     if isinstance(t, dict)])
        garde = {k: v for k, v in refus.items() if proposees.get(k) == v}
        if r and str(r.get("verdict", "")).startswith(("annulé (retour", "ÉCHEC")):
            garde.update(r.get("visees") or {})
        # Extension dont la mise à jour a échoué seule (paquet indisponible) :
        # elle seule est retenue, les autres ont été gardées.
        if r and r.get("echecs"):
            garde.update({k: v for k, v in r["echecs"].items() if v})
        if garde:
            refus_neufs[dom] = garde
        if r:
            sites[dom] = r
            print(f"{dom:28} {r['verdict']:32} {', '.join(r.get('items') or []) or '-'}"
                  + (f" · {r['cause'][:120]}" if r.get("cause") else ""))
    if dry:
        return
    save_json(PATH, {"generated_at": time.strftime("%Y-%m-%d %H:%M"), "ts": time.time(),
                     "sites": sites, "refus": refus_neufs, "natives_recoupees": natives})
    A.attendre_envois()
    print(f"{len(sites)} site(s) traité(s) cette nuit.")


if __name__ == "__main__":
    main()
