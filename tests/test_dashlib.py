#!/usr/bin/env python3
"""Tests des briques communes (dashlib.py).

Ce module est importé par actions_server.py, collect.py, vulns.py, phperrors.py,
rotate.py et digest.py : une régression ici les casse tous en même temps, d'où
des tests qui lui sont propres plutôt que déduits de ses appelants.

    python3 -m unittest tests.test_dashlib -v
"""
import json
import os
import shlex
import stat
import sys
import tempfile
import threading
import time
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import dashlib  # noqa: E402


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def lire_json(path):
    with open(path) as fh:
        return json.load(fh)


class TmpDir(unittest.TestCase):
    """Un répertoire jetable contenant un faux data/ (pour les droits 0600)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.data = os.path.join(self.root, "data")
        os.makedirs(self.data)


# --------------------------------------------------------------------------- #
#  load_json : jamais d'exception, toujours le défaut                          #
# --------------------------------------------------------------------------- #
class TestLoadJson(TmpDir):

    def test_fichier_absent_rend_le_defaut(self):
        chemin = os.path.join(self.root, "nexistepas.json")
        self.assertEqual(dashlib.load_json(chemin, {"servers": []}), {"servers": []})
        temoin = ["defaut"]
        self.assertIs(dashlib.load_json(chemin, temoin), temoin)

    def test_fichier_corrompu_rend_le_defaut(self):
        chemin = os.path.join(self.root, "casse.json")
        with open(chemin, "w") as fh:
            fh.write('{"a": 1,,,')
        self.assertEqual(dashlib.load_json(chemin, {}), {})

    def test_fichier_vide_rend_le_defaut(self):
        chemin = os.path.join(self.root, "vide.json")
        open(chemin, "w").close()
        self.assertEqual(dashlib.load_json(chemin, []), [])

    def test_repertoire_rend_le_defaut(self):
        """Un chemin qui désigne un répertoire lève IsADirectoryError (une OSError)."""
        self.assertEqual(dashlib.load_json(self.data, None), None)

    def test_contenu_valide_est_rendu(self):
        chemin = os.path.join(self.root, "ok.json")
        dashlib.save_json(chemin, {"a": [1, 2], "é": "à"})
        self.assertEqual(dashlib.load_json(chemin, None), {"a": [1, 2], "é": "à"})


# --------------------------------------------------------------------------- #
#  save_json : droits, atomicité, options d'écriture                           #
# --------------------------------------------------------------------------- #
class TestSaveJson(TmpDir):

    def test_0600_sous_le_data_dir_donne(self):
        chemin = os.path.join(self.data, "secrets.json")
        dashlib.save_json(chemin, {"a": 1}, data_dir=self.data)
        self.assertEqual(mode_of(chemin), 0o600)
        self.assertEqual(lire_json(chemin), {"a": 1})

    def test_0644_hors_du_data_dir_donne(self):
        chemin = os.path.join(self.root, "fleet.json")
        dashlib.save_json(chemin, {"a": 1}, data_dir=self.data)
        self.assertEqual(mode_of(chemin), 0o644)

    def test_mode_explicite_gagne_sur_le_chemin(self):
        chemin = os.path.join(self.data, "public.json")
        dashlib.save_json(chemin, {"a": 1}, mode=0o644, data_dir=self.data)
        self.assertEqual(mode_of(chemin), 0o644)

    def test_data_dir_absent_retombe_sur_celui_du_depot(self):
        """Sans `data_dir`, la règle s'applique au data/ du dépôt : un chemin
        quelconque du disque est donc en 0644."""
        chemin = os.path.join(self.root, "ailleurs.json")
        dashlib.save_json(chemin, {"a": 1})
        self.assertEqual(mode_of(chemin), 0o644)
        self.assertEqual(dashlib.default_mode(os.path.join(dashlib.DATA_DIR, "x.json")),
                         0o600)

    def test_reecriture_conserve_le_mode(self):
        """La faille d'origine : le fichier repassait en 0644 à la réécriture."""
        chemin = os.path.join(self.data, "app_passwords.json")
        dashlib.save_json(chemin, {"n": 1}, data_dir=self.data)
        dashlib.save_json(chemin, {"n": 2}, data_dir=self.data)
        self.assertEqual(mode_of(chemin), 0o600)
        self.assertEqual(lire_json(chemin), {"n": 2})

    def test_aucun_temporaire_laisse(self):
        dashlib.save_json(os.path.join(self.data, "x.json"), {"a": 1})
        self.assertEqual([f for f in os.listdir(self.data) if f.startswith(".tmp-")], [])

    def test_temporaire_nettoye_si_serialisation_impossible(self):
        chemin = os.path.join(self.data, "ko.json")
        with self.assertRaises(TypeError):
            dashlib.save_json(chemin, {"a": {1, 2}})     # un set n'est pas sérialisable
        self.assertEqual(os.listdir(self.data), [])
        self.assertFalse(os.path.exists(chemin))

    def test_indent_none_produit_un_json_compact(self):
        compact = os.path.join(self.root, "c.json")
        indente = os.path.join(self.root, "i.json")
        dashlib.save_json(compact, {"a": 1, "b": 2}, indent=None)
        dashlib.save_json(indente, {"a": 1, "b": 2})     # indent=1 par défaut
        with open(compact) as fh:
            self.assertNotIn("\n", fh.read())
        with open(indente) as fh:
            self.assertIn("\n", fh.read())

    def test_fsync_ecrit_le_meme_contenu(self):
        chemin = os.path.join(self.root, "f.json")
        dashlib.save_json(chemin, {"a": 1}, fsync=True)
        self.assertEqual(lire_json(chemin), {"a": 1})

    def test_accents_non_echappes(self):
        chemin = os.path.join(self.root, "acc.json")
        dashlib.save_json(chemin, {"d": "créé"})
        with open(chemin) as fh:
            self.assertIn("créé", fh.read())


# --------------------------------------------------------------------------- #
#  update_json : lecture → modification → écriture, sous verrou                #
# --------------------------------------------------------------------------- #
class TestUpdateJson(TmpDir):

    def test_rend_et_ecrit_l_objet(self):
        chemin = os.path.join(self.data, "x.json")
        res = dashlib.update_json(chemin, lambda c: {"v": (c or {}).get("v", 0) + 5}, {})
        self.assertEqual(res, {"v": 5})
        self.assertEqual(lire_json(chemin), {"v": 5})

    def test_fn_rend_none_conserve_le_courant(self):
        chemin = os.path.join(self.data, "x.json")
        dashlib.save_json(chemin, {"v": 3})
        self.assertEqual(dashlib.update_json(chemin, lambda c: None, {}), {"v": 3})
        self.assertEqual(lire_json(chemin), {"v": 3})

    def test_concurrent_ne_perd_aucun_increment(self):
        chemin = os.path.join(self.data, "compteur.json")
        dashlib.save_json(chemin, {"n": 0})

        def incrementer(courant):
            valeur = (courant or {}).get("n", 0)
            time.sleep(0.002)             # élargit la fenêtre de course
            return {"n": valeur + 1}

        fils = [threading.Thread(target=dashlib.update_json,
                                 args=(chemin, incrementer, {}))
                for _ in range(10)]
        for t in fils:
            t.start()
        for t in fils:
            t.join()
        self.assertEqual(lire_json(chemin), {"n": 10})

    def test_verrou_reentrant_par_chemin(self):
        """Deux appels imbriqués sur le MÊME chemin ne doivent pas s'auto-bloquer."""
        chemin = os.path.join(self.data, "imbrique.json")
        verrou = dashlib.json_lock(chemin)
        self.assertIs(verrou, dashlib.json_lock(chemin))       # mémorisé par chemin
        self.assertIsNot(verrou, dashlib.json_lock(chemin + "2"))
        with verrou:
            dashlib.update_json(chemin, lambda c: {"ok": True}, {})
        self.assertEqual(lire_json(chemin), {"ok": True})

    def test_mode_et_data_dir_transmis(self):
        chemin = os.path.join(self.data, "prive.json")
        dashlib.update_json(chemin, lambda c: {"a": 1}, {}, data_dir=self.data)
        self.assertEqual(mode_of(chemin), 0o600)


# --------------------------------------------------------------------------- #
#  Quotage shell                                                               #
# --------------------------------------------------------------------------- #
class TestSq(unittest.TestCase):

    def test_apostrophe_et_injections(self):
        self.assertEqual(dashlib.sq("simple"), "'simple'")
        self.assertEqual(dashlib.sq("a'b"), "'a'\\''b'")
        self.assertEqual(dashlib.sq("; rm -rf /"), "'; rm -rf /'")
        self.assertEqual(dashlib.sq("'; id #"), "''\\''; id #'")

    def test_non_chaines_acceptees(self):
        self.assertEqual(dashlib.sq(42), "'42'")
        self.assertEqual(dashlib.sq(None), "'None'")

    def test_le_resultat_est_reellement_un_seul_mot_pour_le_shell(self):
        for brut in ("a'b", "; id #", "$(id)", "un deux", "`id`", "\\"):
            self.assertEqual(shlex.split(dashlib.sq(brut)), [str(brut)], brut)


# --------------------------------------------------------------------------- #
#  Identité d'un site                                                          #
# --------------------------------------------------------------------------- #
class TestNormDomain(unittest.TestCase):

    def test_normalisations(self):
        cas = {
            "https://WWW.Exemple.FR/boutique/": "exemple.fr",
            "http://exemple.fr:8080": "exemple.fr",
            "www.exemple.fr": "exemple.fr",
            "  Exemple.FR  ": "exemple.fr",
            "user@exemple.fr": "exemple.fr",
            "exemple.fr": "exemple.fr",
        }
        for brut, attendu in cas.items():
            self.assertEqual(dashlib.norm_domain(brut), attendu, brut)

    def test_vide_et_none(self):
        self.assertEqual(dashlib.norm_domain(None), "")
        self.assertEqual(dashlib.norm_domain(""), "")

    def test_wwwx_n_est_pas_ampute(self):
        self.assertEqual(dashlib.norm_domain("wwwx.exemple.fr"), "wwwx.exemple.fr")


class TestSiteKey(unittest.TestCase):

    def test_racine_rend_le_domaine_seul(self):
        for brut in ("exemple.fr", "https://www.exemple.fr", "https://exemple.fr/"):
            self.assertEqual(dashlib.site_key(brut), "exemple.fr", brut)

    def test_sous_repertoire_fait_partie_de_la_cle(self):
        self.assertEqual(dashlib.site_key("https://exemple.fr/Boutique/"),
                         "exemple.fr/boutique")
        self.assertEqual(dashlib.site_key("exemple.fr/boutique"), "exemple.fr/boutique")

    def test_deux_sites_du_meme_hote_ont_des_cles_distinctes(self):
        self.assertNotEqual(dashlib.site_key("exemple.fr"),
                            dashlib.site_key("exemple.fr/boutique"))

    def test_valeur_illisible_retombe_sur_le_domaine(self):
        self.assertEqual(dashlib.site_key(None), "")


# --------------------------------------------------------------------------- #
#  site_visible : la règle d'affichage officielle de l'interface               #
# --------------------------------------------------------------------------- #
class TestSiteVisible(unittest.TestCase):

    # ---- les quatre combinaisons de la nouvelle règle --------------------- #
    #
    # `followed` est POSÉ PAR LE COLLECTEUR : il vaut déjà « a un moniteur Kuma
    # (quand Kuma est là) ou figure dans followed.json ». `site_visible` n'a
    # donc qu'à croiser l'override et ce booléen — ce que ces quatre cas
    # décrivent, Kuma présent (le site porte un `kuma`) comme absent.

    def test_auto_et_suivi_avec_kuma(self):
        self.assertTrue(dashlib.site_visible(
            {"domain": "a.fr", "kuma": "a.fr", "followed": True}))

    def test_auto_et_non_suivi_avec_kuma(self):
        """Kuma est là mais ne supervise pas ce site, et personne ne l'a suivi."""
        self.assertFalse(dashlib.site_visible(
            {"domain": "a.fr", "kuma": None, "followed": False}))

    def test_auto_et_suivi_sans_kuma(self):
        """Sans Kuma : followed.json suffit à rendre le site visible."""
        self.assertTrue(dashlib.site_visible({"domain": "a.fr", "followed": True}))

    def test_auto_et_non_suivi_sans_kuma(self):
        """Un install découvert reste masqué tant qu'il n'est pas suivi."""
        self.assertFalse(dashlib.site_visible({"domain": "a.fr", "followed": False}))

    def test_override_masquer_gagne_sur_le_suivi(self):
        self.assertFalse(dashlib.site_visible(
            {"domain": "a.fr", "followed": True, "visible": False}))

    def test_override_afficher_gagne_sur_l_absence_de_suivi(self):
        self.assertTrue(dashlib.site_visible(
            {"domain": "a.fr", "followed": False, "visible": True}))

    # ---- compatibilité : fiche produite AVANT la bascule ------------------ #
    def test_moniteur_kuma_present_visible(self):
        self.assertTrue(dashlib.site_visible({"domain": "a.fr", "kuma": "a.fr"}))

    def test_sans_moniteur_kuma_masque(self):
        self.assertFalse(dashlib.site_visible({"domain": "a.fr", "kuma": None}))
        self.assertFalse(dashlib.site_visible({"domain": "a.fr", "kuma": ""}))

    def test_override_afficher_force_l_affichage_sans_kuma(self):
        self.assertTrue(dashlib.site_visible({"domain": "a.fr", "kuma": None,
                                              "visible": True}))

    def test_override_masquer_gagne_sur_tout(self):
        self.assertFalse(dashlib.site_visible({"domain": "a.fr", "kuma": "a.fr",
                                               "visible": False}))
        self.assertFalse(dashlib.site_visible({"domain": "a.fr", "via": "rest",
                                               "visible": False}))

    def test_site_rest_visible_d_office(self):
        self.assertTrue(dashlib.site_visible({"domain": "a.fr", "via": "rest",
                                              "kuma": None}))

    def test_cle_kuma_absente_reste_visible(self):
        """Une fiche qui n'a jamais été confrontée à Kuma n'est pas masquée."""
        self.assertTrue(dashlib.site_visible({"domain": "a.fr"}))

    def test_meme_regle_que_les_appelants(self):
        """actions_server, vulns et phperrors doivent partager LA fonction.

        C'est ce qui rend Kuma facultatif pour eux aussi : ils ne connaissent ni
        moniteur ni followed.json, seulement `site_visible`.
        """
        import actions_server
        import phperrors
        import vulns
        self.assertIs(actions_server.site_visible, dashlib.site_visible)
        self.assertIs(vulns.site_visible, dashlib.site_visible)
        self.assertIs(phperrors.A.site_visible, dashlib.site_visible)


# --------------------------------------------------------------------------- #
#  Sites suivis (data/followed.json) et migration de la bascule                #
# --------------------------------------------------------------------------- #
class TestFollowed(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = self.tmp.name
        dashlib._JSON_LOCKS.clear()

    def chemin(self):
        return os.path.join(self.data, "followed.json")

    def ecrire_fleet(self, fleet):
        with open(os.path.join(self.data, "fleet.json"), "w") as fh:
            json.dump(fleet, fh)

    # ---- lecture / écriture ---------------------------------------------- #
    def test_fichier_absent_rend_un_ensemble_vide(self):
        self.assertEqual(dashlib.load_followed(self.data), set())

    def test_suivre_puis_ne_plus_suivre(self):
        dashlib.set_followed("a.fr", True, self.data)
        dashlib.set_followed("b.fr/boutique", True, self.data)
        self.assertEqual(dashlib.load_followed(self.data), {"a.fr", "b.fr/boutique"})
        dashlib.set_followed("a.fr", False, self.data)
        self.assertEqual(dashlib.load_followed(self.data), {"b.fr/boutique"})

    def test_liste_ecrite_triee_et_sans_doublon(self):
        for _ in range(3):
            dashlib.set_followed("b.fr", True, self.data)
        dashlib.set_followed("a.fr", True, self.data)
        self.assertEqual(lire_json(self.chemin()), ["a.fr", "b.fr"])

    def test_fichier_en_0600(self):
        dashlib.set_followed("a.fr", True, self.data)
        self.assertEqual(mode_of(self.chemin()), 0o600)

    def test_forme_dictionnaire_toleree(self):
        with open(self.chemin(), "w") as fh:
            json.dump({"a.fr": True, "b.fr": False}, fh)
        self.assertEqual(dashlib.load_followed(self.data), {"a.fr"})

    # ---- migration -------------------------------------------------------- #
    def test_migration_reprend_exactement_les_sites_visibles(self):
        """20 sites visibles sur 58 installs, avant comme après la bascule.

        Fixture représentative du parc : quelques sites supervisés par Kuma, un
        site sans SSH, un masqué à la main, un forcé à l'affichage sans moniteur,
        et une longue traîne d'installs découverts que personne ne regarde.
        """
        sites = []
        for i in range(15):                       # supervisés par Kuma → visibles
            sites.append({"domain": f"kuma{i}.fr", "kuma": f"kuma{i}.fr"})
        for i in range(3):                        # sites sans SSH → visibles d'office
            sites.append({"domain": f"rest{i}.fr", "kuma": None, "via": "rest"})
        for i in range(2):                        # forcés à l'affichage sans moniteur
            sites.append({"domain": f"force{i}.fr", "kuma": None, "visible": True})
        sites.append({"domain": "masque.fr", "kuma": "masque.fr", "visible": False})
        for i in range(37):                       # installs découverts, non supervisés
            sites.append({"domain": f"install{i}.fr", "kuma": None})
        fleet = {"servers": [{"name": "s1", "sites": sites[:30]},
                             {"name": "s2", "sites": sites[30:]}]}
        self.assertEqual(len(sites), 58)
        avant = [s["domain"] for s in sites if dashlib.legacy_site_visible(s)]
        self.assertEqual(len(avant), 20)

        self.ecrire_fleet(fleet)
        suivis = dashlib.ensure_followed_migrated(self.data)
        self.assertEqual(suivis, sorted(avant))

        # Après la bascule, le collecteur pose `followed` d'après cette liste et
        # `site_visible` doit rendre EXACTEMENT la même sélection.
        suivis = dashlib.load_followed(self.data)
        apres = [s["domain"] for s in sites
                 if dashlib.site_visible(dict(s, followed=s["domain"] in suivis
                                              or s.get("via") == "rest"))]
        self.assertEqual(sorted(apres), sorted(avant))
        self.assertEqual(len(apres), 20)

    def test_migration_idempotente(self):
        self.ecrire_fleet({"servers": [{"name": "s1", "sites": [
            {"domain": "a.fr", "kuma": "a.fr"}]}]})
        self.assertEqual(dashlib.ensure_followed_migrated(self.data), ["a.fr"])
        # Deuxième appel : rien à faire, et surtout rien à réécrire.
        self.assertIsNone(dashlib.ensure_followed_migrated(self.data))
        # Même après un décochage complet, la migration ne se rejoue pas :
        # sinon Tommy verrait revenir tout ce qu'il vient d'écarter.
        dashlib.set_followed("a.fr", False, self.data)
        self.assertIsNone(dashlib.ensure_followed_migrated(self.data))
        self.assertEqual(dashlib.load_followed(self.data), set())

    def test_migration_sans_fleet_ecrit_une_liste_vide(self):
        """Installation neuve : rien à reprendre, mais le marqueur est posé."""
        self.assertEqual(dashlib.ensure_followed_migrated(self.data), [])
        self.assertTrue(os.path.exists(self.chemin()))
        self.assertIsNone(dashlib.ensure_followed_migrated(self.data))

    def test_migration_concurrente_ne_produit_qu_une_liste(self):
        self.ecrire_fleet({"servers": [{"name": "s1", "sites": [
            {"domain": f"k{i}.fr", "kuma": f"k{i}.fr"} for i in range(5)]}]})
        resultats, barriere = [], threading.Barrier(6)

        def courir():
            barriere.wait()
            resultats.append(dashlib.ensure_followed_migrated(self.data))

        fils = [threading.Thread(target=courir) for _ in range(6)]
        for f in fils:
            f.start()
        for f in fils:
            f.join(timeout=20)
        self.assertEqual(sum(1 for r in resultats if r is not None), 1)
        self.assertEqual(len(dashlib.load_followed(self.data)), 5)


# --------------------------------------------------------------------------- #
#  Garde anti-SSRF partagée par l'API et les sondes du collecteur              #
# --------------------------------------------------------------------------- #
class TestGardeSSRF(unittest.TestCase):

    def test_schema_refuse(self):
        for url in ("file:///etc/passwd", "javascript:alert(1)", "ftp://x.fr/"):
            self.assertIsNone(dashlib.validate_public_url(url)[0], url)

    def test_identifiants_dans_l_url_refuses(self):
        self.assertIsNone(dashlib.validate_public_url("https://a:b@exemple.fr/")[0])

    def test_loopback_refuse(self):
        u, err = dashlib.validate_public_url("http://127.0.0.1:8090/api/mgmt/state")
        self.assertIsNone(u)
        self.assertIn("adresse non autorisée", err)

    def test_une_seule_copie_de_la_garde(self):
        """Deux copies d'un contrôle de sécurité, c'est une copie qui diverge."""
        import actions_server
        import collect
        self.assertIs(actions_server.validate_public_url, dashlib.validate_public_url)
        self.assertIs(collect.validate_public_url, dashlib.validate_public_url)


# --------------------------------------------------------------------------- #
#  Expressions de validation partagées                                         #
# --------------------------------------------------------------------------- #
class TestValidation(unittest.TestCase):

    def test_valid_path_pattern(self):
        self.assertTrue(dashlib.valid_path_pattern("/var/www/vhosts/*/httpdocs"))
        self.assertFalse(dashlib.valid_path_pattern("/var/www/../etc"))
        self.assertFalse(dashlib.valid_path_pattern("var/www"))
        self.assertFalse(dashlib.valid_path_pattern("/a'; id;'"))
        self.assertFalse(dashlib.valid_path_pattern(None))

    def test_l_api_et_le_collecteur_partagent_la_meme_regle(self):
        """Deux copies qui divergent = un motif accepté à l'écriture puis
        exécuté sans contrôle par le collecteur."""
        import actions_server
        import collect
        self.assertIs(collect.PATTERN_RE, dashlib.PATH_PATTERN_RE)
        self.assertIs(actions_server.SRV_PATH_RE, dashlib.PATH_PATTERN_RE)
        self.assertIs(collect.valid_pattern, dashlib.valid_path_pattern)

    def test_slug_et_server_re(self):
        self.assertTrue(dashlib.SLUG_RE.match("exemple.fr"))
        self.assertTrue(dashlib.SLUG_RE.match("exemple.fr/boutique"))
        self.assertFalse(dashlib.SLUG_RE.match("../etc/passwd"))
        self.assertFalse(dashlib.SLUG_RE.match("exemple.fr/../x"))
        self.assertTrue(dashlib.SERVER_RE.match("plesk-mutu"))
        self.assertFalse(dashlib.SERVER_RE.match("Plesk_Mutu"))


if __name__ == "__main__":
    unittest.main()


class TestDomaineEnDouble(unittest.TestCase):
    """Un domaine présent sur deux serveurs ne doit s'afficher qu'une fois.

    Le cas est réel dans ce parc : une migration laisse la copie d'origine en
    place. Tant que la visibilité venait d'Uptime Kuma, un seul install portait
    le moniteur et l'autre disparaissait tout seul. Depuis que « suivi » se
    décide par domaine, les deux copies passeraient — la production a bien
    affiché 23 lignes pour 20 sites avant ce correctif.
    """

    def test_seule_la_copie_principale_est_visible(self):
        gagnant = {"domain": "exemple.fr", "followed": True, "primary": True}
        perdant = {"domain": "exemple.fr", "followed": True, "primary": False}
        self.assertTrue(dashlib.site_visible(gagnant))
        self.assertFalse(dashlib.site_visible(perdant))

    def test_affichage_force_prime_sur_la_copie(self):
        """`show` reste un ordre : il passe même sur une copie secondaire."""
        force = {"domain": "exemple.fr", "followed": False,
                 "primary": False, "visible": True}
        self.assertTrue(dashlib.site_visible(force))

    def test_sans_marqueur_le_site_reste_visible(self):
        """Une fiche d'avant le correctif n'a pas `primary` : elle ne disparaît pas."""
        self.assertTrue(dashlib.site_visible({"domain": "exemple.fr", "followed": True}))

