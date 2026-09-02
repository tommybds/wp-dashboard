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
        """actions_server, vulns et phperrors doivent partager LA fonction."""
        import actions_server
        import vulns
        self.assertIs(actions_server.site_visible, dashlib.site_visible)
        self.assertIs(vulns.site_visible, dashlib.site_visible)


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
