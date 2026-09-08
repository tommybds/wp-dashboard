#!/usr/bin/env python3
"""Branchement Uptime Kuma réglable depuis l'interface.

Les trois valeurs qui relient le dashboard à Kuma — slug de la status page,
conteneur Docker, base SQLite — vivaient dans `config.json`, lu UNE fois au
démarrage puis figé dans des constantes de module. Les changer voulait dire
éditer un fichier sur le serveur ET redémarrer le service.

Elles se surchargent maintenant dans `data/settings.json`, relu à chaque appel,
et `dashlib.kuma_conf()` est le SEUL point de lecture. Ce module vérifie :

  * l'ordre de fusion (défauts → config.json → data/settings.json → soumission),
  * chaque règle de validation, en acceptation ET en refus,
  * qu'une valeur vide efface la surcharge et redonne la main à config.json,
  * qu'un conteneur changé vaut TOUT DE SUITE (aucun redémarrage),
  * que le cache de détection de 60 s est vidé à l'écriture — sans quoi
    l'interface annoncerait « non configuré » pendant une minute,
  * que la route de test n'écrit rien,
  * qu'il ne reste AUCUNE lecture figée dans le code.

    python3 -m unittest tests.test_kuma_conf -v
"""
import ast
import json
import os
import tempfile
import unittest
from unittest import mock

import actions_server as A
import collect
import dashboard_config
import dashlib

# BaseTmp redirige BASE / DATA (et dashboard_config.DATA_DIR) vers un répertoire
# jetable ; KumaRoutesBase y ajoute un vrai serveur HTTP et une session valide.
# Ce sont des classes de BASE, sans méthode de test : les importer ne rejoue
# aucun test de test_backend.
from tests.test_backend import BaseTmp, KumaRoutesBase  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
#  1. kuma_conf() : l'ordre de fusion                                           #
# --------------------------------------------------------------------------- #
class TestFusion(unittest.TestCase):
    """défauts → config.json → data/settings.json → surcharge non persistée."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.data = os.path.join(self.root, "data")
        os.makedirs(self.data)

    def ecrire(self, nom, obj, dossier=None):
        with open(os.path.join(dossier or self.root, nom), "w") as fh:
            json.dump(obj, fh)

    def conf(self, **kw):
        return dashlib.kuma_conf(self.data, base=self.root, **kw)

    def test_sans_aucun_fichier_les_defauts_font_foi(self):
        c = self.conf()
        self.assertEqual(c["container"], "uptime-kuma")
        self.assertEqual(c["db"], "/app/data/kuma.db")
        self.assertEqual(c["slug"], "")
        self.assertEqual(c["enabled"], "auto")

    def test_config_json_surcharge_les_defauts(self):
        self.ecrire("config.json", {"kuma_container": "kuma-prod",
                                    "kuma_db": "/data/kuma.db",
                                    "kuma_slug": "parc"})
        c = self.conf()
        self.assertEqual((c["container"], c["db"], c["slug"]),
                         ("kuma-prod", "/data/kuma.db", "parc"))

    def test_settings_json_surcharge_config_json(self):
        self.ecrire("config.json", {"kuma_container": "kuma-prod", "kuma_slug": "ancien"})
        self.ecrire("settings.json", {"kuma_container": "kuma-neuf", "kuma_slug": "neuf"},
                    self.data)
        c = self.conf()
        self.assertEqual(c["container"], "kuma-neuf")
        self.assertEqual(c["slug"], "neuf")

    def test_une_valeur_vide_rend_la_main_a_config_json(self):
        """Effacer le champ dans l'interface ≠ effacer la valeur : c'est revenir
        à config.json. Sans cette règle, vider un champ couperait Kuma."""
        self.ecrire("config.json", {"kuma_container": "kuma-prod", "kuma_slug": "parc"})
        self.ecrire("settings.json", {"kuma_container": "", "kuma_slug": "   "}, self.data)
        c = self.conf()
        self.assertEqual(c["container"], "kuma-prod")
        self.assertEqual(c["slug"], "parc")

    def test_config_passe_en_argument_evite_une_seconde_lecture(self):
        self.ecrire("config.json", {"kuma_container": "sur-disque"})
        c = self.conf(config={"kuma_container": "en-memoire"})
        self.assertEqual(c["container"], "en-memoire")

    def test_la_surcharge_soumise_prime_sur_tout(self):
        """C'est la couche du bouton « Tester » : les valeurs saisies, non écrites."""
        self.ecrire("config.json", {"kuma_container": "kuma-prod"})
        self.ecrire("settings.json", {"kuma_container": "kuma-enregistre"}, self.data)
        c = self.conf(overrides={"kuma_container": "kuma-saisi"})
        self.assertEqual(c["container"], "kuma-saisi")
        # …et une saisie vide ne masque pas ce qui est enregistré.
        self.assertEqual(self.conf(overrides={"kuma_container": ""})["container"],
                         "kuma-enregistre")

    def test_le_slug_complete_l_url_de_la_status_page(self):
        self.ecrire("config.json", {"kuma_slug": "parc"})
        self.assertTrue(self.conf()["status_url"].endswith("/api/status-page/parc"))

    def test_un_slug_change_refait_l_url_avec_le_NOUVEAU_slug(self):
        """L'assemblage se fait dans kuma_conf, jamais au chargement de config.json :
        sinon l'URL garderait l'ANCIEN slug après un changement."""
        self.ecrire("config.json", {"kuma_slug": "ancien"})
        self.ecrire("settings.json", {"kuma_slug": "neuf"}, self.data)
        url = self.conf()["status_url"]
        self.assertTrue(url.endswith("/neuf"), url)
        self.assertNotIn("ancien", url)

    def test_une_url_complete_n_est_pas_recomplete(self):
        self.ecrire("config.json", {"kuma_slug": "parc",
                                    "kuma_status_url": "https://kuma.exemple.fr/api/sp/parc"})
        self.assertEqual(self.conf()["status_url"], "https://kuma.exemple.fr/api/sp/parc")

    def test_fichiers_illisibles_ne_font_pas_lever(self):
        with open(os.path.join(self.root, "config.json"), "w") as fh:
            fh.write("{ pas du json")
        with open(os.path.join(self.data, "settings.json"), "w") as fh:
            fh.write("[]")
        self.assertEqual(self.conf()["container"], "uptime-kuma")


# --------------------------------------------------------------------------- #
#  2. validation : chaque règle, en acceptation et en refus                     #
# --------------------------------------------------------------------------- #
class TestValidation(unittest.TestCase):

    def err(self, **patch):
        return dashlib.kuma_settings_errors(patch)

    # ---- slug ----
    def test_slug_accepte(self):
        for v in ("", "parc", "parc-x7k2m9", "PARC_2026", "a" * 64):
            self.assertEqual(self.err(kuma_slug=v), {}, v)

    def test_slug_refuse(self):
        for v in ("parc/prive", "parc prive", "parc.prive", "a" * 65, "é"):
            self.assertIn("kuma_slug", self.err(kuma_slug=v), v)

    # ---- conteneur ----
    def test_conteneur_accepte(self):
        for v in ("", "uptime-kuma", "kuma_1", "kuma.prod", "a" * 64):
            self.assertEqual(self.err(kuma_container=v), {}, v)

    def test_conteneur_refuse(self):
        for v in ("-kuma", ".kuma", "kuma prod", "kuma/prod", "a" * 65, "kuma;rm -rf /"):
            self.assertIn("kuma_container", self.err(kuma_container=v), v)

    # ---- base ----
    def test_base_accepte(self):
        for v in ("", "/app/data/kuma.db", "/data/kuma-2026.db", "/" + "a" * 200):
            self.assertEqual(self.err(kuma_db=v), {}, v)

    def test_base_refuse(self):
        for v in ("app/data/kuma.db",           # pas absolu
                  "/app/../etc/passwd",         # « .. »
                  "/app/data/kuma.db; rm -rf /",
                  "/app/data/$(id).db",
                  "/" + "a" * 201):
            self.assertIn("kuma_db", self.err(kuma_db=v), v)

    # ---- url de la status page ----
    def test_url_locale_acceptee_en_http(self):
        for v in ("", "http://127.0.0.1:3001/api/status-page/",
                  "http://localhost:3001/api/status-page/"):
            self.assertEqual(self.err(kuma_status_url=v), {}, v)

    def test_url_https_publique_passe_la_garde_ssrf(self):
        with mock.patch.object(dashlib, "public_ips", lambda h, p: (["93.184.216.34"], None)):
            self.assertEqual(self.err(kuma_status_url="https://kuma.exemple.fr/api/sp/"), {})

    def test_url_https_vers_une_adresse_privee_refusee(self):
        with mock.patch.object(dashlib, "public_ips",
                               lambda h, p: (None, "adresse non autorisée (10.0.0.1)")):
            self.assertIn("kuma_status_url",
                          self.err(kuma_status_url="https://interne.exemple.fr/api/sp/"))

    def test_url_http_non_locale_refusee(self):
        """Cette URL sert à joindre Kuma EN LOCAL : elle n'a pas à sortir en clair."""
        for v in ("http://kuma.exemple.fr/api/sp/", "http://10.0.0.5:3001/api/sp/",
                  "file:///etc/passwd", "gopher://x/", "http://user:mdp@127.0.0.1/"):
            self.assertIn("kuma_status_url", self.err(kuma_status_url=v), v)

    def test_une_cle_absente_du_lot_n_est_pas_validee(self):
        self.assertEqual(dashlib.kuma_settings_errors({"viz_scan_after_update": True}), {})


# --------------------------------------------------------------------------- #
#  3. routes : enregistrement, refus champ par champ, test sans écriture        #
# --------------------------------------------------------------------------- #
class KumaConfRoutes(KumaRoutesBase):
    """Un branchement de départ maîtrisé, indépendant du config.json du poste."""

    SONDE_REELLE = False

    def setUp(self):
        super().setUp()
        self._cfg = {k: dashboard_config.CONFIG.get(k) for k in
                     ("kuma_enabled", "kuma_container", "kuma_db", "kuma_slug",
                      "kuma_status_url")}
        dashboard_config.CONFIG.update({
            "kuma_enabled": "auto", "kuma_container": "kuma-config",
            "kuma_db": "/app/data/kuma.db", "kuma_slug": "slug-config",
            "kuma_status_url": "http://127.0.0.1:3001/api/status-page/"})
        self.addCleanup(lambda: dashboard_config.CONFIG.update(self._cfg))
        self._sp = A.SETTINGS_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        self.addCleanup(lambda: setattr(A, "SETTINGS_PATH", self._sp))
        # La détection de Kuma est mockée par défaut : les tests de routes ne
        # doivent lancer aucun docker. `SONDE_REELLE` la laisse en place pour
        # la classe qui vérifie justement le cache de détection.
        if not self.SONDE_REELLE:
            for cible, valeur in (("kuma_disponible", lambda *a, **k: True),
                                  ("kuma_statut",
                                   lambda *a, **k: {"enabled": True,
                                                    "reason": "sonde mockée"})):
                p = mock.patch.object(A, cible, valeur)
                p.start()
                self.addCleanup(p.stop)

    def reglages(self):
        try:
            with open(A.SETTINGS_PATH) as fh:
                return json.load(fh)
        except OSError:
            return None


class TestRouteEnregistrement(KumaConfRoutes):

    def test_enregistre_les_trois_valeurs_et_rend_l_etat(self):
        st, j = self.post("/api/mgmt/settings", {"settings": {
            "kuma_slug": "parc-neuf", "kuma_container": "kuma-neuf",
            "kuma_db": "/data/kuma.db"}})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(self.reglages()["kuma_container"], "kuma-neuf")
        # L'état repart avec la réponse : le front rafraîchit « connecté /
        # non configuré » sans recharger la page.
        self.assertEqual(j["kuma"]["container"], "kuma-neuf")
        self.assertEqual(j["kuma"]["slug"], "parc-neuf")
        self.assertTrue(j["kuma"]["status_url"].endswith("/parc-neuf"))

    def test_une_valeur_vide_efface_la_surcharge(self):
        self.post("/api/mgmt/settings", {"settings": {"kuma_container": "kuma-neuf"}})
        self.assertEqual(A.kuma_conf(A.DATA, A.CONFIG)["container"], "kuma-neuf")
        st, j = self.post("/api/mgmt/settings", {"settings": {"kuma_container": ""}})
        self.assertEqual(st, 200)
        self.assertEqual(A.kuma_conf(A.DATA, A.CONFIG)["container"], "kuma-config")
        self.assertEqual(j["kuma"]["container"], "kuma-config")

    def test_refus_400_avec_un_message_par_champ(self):
        st, j = self.post("/api/mgmt/settings", {"settings": {
            "kuma_slug": "parc prive", "kuma_container": "-kuma",
            "kuma_db": "/app/../etc/passwd"}})
        self.assertEqual(st, 400)
        self.assertEqual(set(j["errors"]), {"kuma_slug", "kuma_container", "kuma_db"})
        self.assertTrue(j["error"])
        for msg in j["errors"].values():
            self.assertTrue(msg.strip())
        self.assertIsNone(self.reglages(), "un lot refusé ne doit RIEN écrire")

    def test_un_seul_champ_faux_refuse_tout_le_lot(self):
        st, j = self.post("/api/mgmt/settings", {"settings": {
            "kuma_container": "kuma-neuf", "kuma_db": "relatif/kuma.db"}})
        self.assertEqual(st, 400)
        self.assertEqual(list(j["errors"]), ["kuma_db"])
        self.assertIsNone(self.reglages())

    def test_un_enregistrement_sans_kuma_ne_renvoie_pas_de_bloc_kuma(self):
        """Les autres réglages ne paient pas une sonde qui ne les concerne pas."""
        st, j = self.post("/api/mgmt/settings", {"settings": {"viz_scan_after_update": False}})
        self.assertEqual(st, 200)
        self.assertNotIn("kuma", j)


class TestPriseEnCompteImmediate(KumaConfRoutes):
    """Le vrai défaut corrigé : un changement ne doit PAS attendre un redémarrage."""

    def test_kuma_sql_utilise_le_nouveau_conteneur_sans_redemarrage(self):
        vus = []

        class Faux:
            returncode, stdout, stderr = 0, "1", ""

        def faux_run(argv, *a, **kw):
            vus.append(list(argv))
            return Faux()

        with mock.patch.object(A.subprocess, "run", faux_run):
            A.kuma_sql("SELECT 1;")
            self.assertEqual(vus[-1][2], "kuma-config")   # départ : config.json
            st, _ = self.post("/api/mgmt/settings", {"settings": {
                "kuma_container": "kuma-neuf", "kuma_db": "/autre/kuma.db"}})
            self.assertEqual(st, 200)
            A.kuma_sql("SELECT 1;")
        # Aucun redémarrage entre les deux appels : la SECONDE commande part
        # déjà vers le nouveau conteneur et la nouvelle base.
        self.assertEqual(vus[-1][2], "kuma-neuf")
        self.assertIn("/autre/kuma.db", vus[-1])

    def test_kuma_restart_vise_le_nouveau_conteneur(self):
        vus = []

        class Faux:
            returncode, stdout, stderr = 0, "", ""

        self.post("/api/mgmt/settings", {"settings": {"kuma_container": "kuma-neuf"}})
        with mock.patch.object(A.subprocess, "run",
                               lambda argv, *a, **kw: (vus.append(list(argv)), Faux())[1]):
            A.kuma_restart()
        self.assertEqual(vus[-1], ["docker", "restart", "kuma-neuf"])

    def test_le_slug_de_creation_suit_la_surcharge(self):
        sql = []
        self.post("/api/mgmt/settings", {"settings": {"kuma_slug": "parc-neuf"}})
        with mock.patch.object(A, "kuma_sql", lambda s: (sql.append(s), (0, ""))[1]), \
                mock.patch.object(A, "kuma_restart", lambda: None):
            A.kuma_create("exemple.fr", "exemple.fr", 9, "https://exemple.fr/", "http", "x")
        self.assertTrue(any('slug="parc-neuf"' in s for s in sql), sql)

    def test_le_collecteur_lit_lui_aussi_la_surcharge(self):
        """collect.py gardait KUMA_CONTAINER / KUMA_DB / KUMA_STATUS figés."""
        vus = []

        class Faux:
            returncode, stdout, stderr = 0, "", ""

        self.post("/api/mgmt/settings", {"settings": {
            "kuma_container": "kuma-neuf", "kuma_slug": "parc-neuf"}})
        with mock.patch.object(collect, "DATA", self.data), \
                mock.patch.object(collect, "kuma_disponible", lambda *a, **k: True), \
                mock.patch.object(collect.subprocess, "run",
                                  lambda argv, *a, **kw: (vus.append(list(argv)), Faux())[1]):
            collect.kuma_folder_map()
            self.assertEqual(vus[-1][2], "kuma-neuf")
            urls = []
            with mock.patch.object(collect.urllib.request, "urlopen",
                                   lambda u, **kw: urls.append(u) or (_ for _ in ()).throw(
                                       OSError("pas de réseau en test"))):
                collect.kuma_monitor_names()
        self.assertTrue(str(urls[0]).endswith("/parc-neuf"), urls)


class TestCacheDeDetection(KumaConfRoutes):
    """Le cache de 60 s doit être périmé à l'écriture, sinon l'interface ment."""

    SONDE_REELLE = True     # ici on veut la VRAIE détection, docker mocké plus bas

    def setUp(self):
        super().setUp()
        dashboard_config.reset_kuma_cache()
        self.addCleanup(dashboard_config.reset_kuma_cache)

    @staticmethod
    def _docker(joignable):
        class Faux:
            def __init__(self, rc):
                self.returncode, self.stdout, self.stderr = rc, "1", ""

        def run(argv, *a, **kw):
            return Faux(0 if argv[2] == joignable else 1)
        return run

    def test_kuma_disponible_est_recalcule_apres_un_changement(self):
        with mock.patch.object(dashboard_config.subprocess, "run", self._docker("kuma-neuf")):
            # config.json pointe « kuma-config » : injoignable.
            self.assertFalse(dashboard_config.kuma_disponible())
            st, j = self.post("/api/mgmt/settings",
                              {"settings": {"kuma_container": "kuma-neuf"}})
            self.assertEqual(st, 200)
            # Sans invalidation du cache, la réponse resterait « absent »
            # pendant une minute — et l'écran Réglages avec elle.
            self.assertTrue(j["kuma"]["enabled"], j["kuma"])
            self.assertTrue(dashboard_config.kuma_disponible())

    def test_le_cache_est_indexe_sur_le_couple_conteneur_base(self):
        with mock.patch.object(dashboard_config.subprocess, "run", self._docker("kuma-neuf")):
            self.assertFalse(dashboard_config.kuma_disponible())
            A.save_json(A.SETTINGS_PATH, {"kuma_container": "kuma-neuf"})
            # Écriture « à la main », donc AUCUN reset_kuma_cache : c'est la clé
            # du cache qui doit suffire à le périmer.
            self.assertTrue(dashboard_config.kuma_disponible())


class TestRouteTest(KumaConfRoutes):
    """POST /api/mgmt/kuma/test : les valeurs soumises, et rien d'écrit."""

    @staticmethod
    def _docker(rc, sortie):
        class Faux:
            returncode, stdout, stderr = rc, sortie, ""
        return lambda argv, *a, **kw: Faux()

    def test_succes_rend_les_deux_sondes(self):
        with mock.patch.object(A.subprocess, "run", self._docker(0, "42\n")), \
                mock.patch.object(A, "kuma_test_status_page",
                                  lambda u: {"ok": True, "message": "status page : 4 moniteur(s)",
                                             "moniteurs": 4, "field": "kuma_slug"}):
            st, j = self.post("/api/mgmt/kuma/test", {
                "kuma_container": "kuma-essai", "kuma_db": "/app/data/kuma.db",
                "kuma_slug": "parc-essai"})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["base"]["moniteurs"], 42)
        self.assertEqual(j["status_page"]["moniteurs"], 4)
        self.assertEqual(j["container"], "kuma-essai")

    def test_conteneur_introuvable_designe_le_bon_champ(self):
        with mock.patch.object(A.subprocess, "run",
                               self._docker(1, "Error: No such container: kuma-faux")), \
                mock.patch.object(A, "kuma_test_status_page",
                                  lambda u: {"ok": False, "message": "status page : HTTP 404",
                                             "moniteurs": None, "field": "kuma_slug"}):
            st, j = self.post("/api/mgmt/kuma/test", {"kuma_container": "kuma-faux"})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertFalse(j["base"]["ok"])
        self.assertEqual(j["base"]["field"], "kuma_container")
        self.assertIn("introuvable", j["base"]["message"])

    def test_base_illisible_designe_le_champ_base(self):
        with mock.patch.object(A.subprocess, "run",
                               self._docker(1, "Error: unable to open database file")), \
                mock.patch.object(A, "kuma_test_status_page",
                                  lambda u: {"ok": True, "message": "", "moniteurs": 1,
                                             "field": "kuma_slug"}):
            st, j = self.post("/api/mgmt/kuma/test", {"kuma_db": "/mauvais/kuma.db"})
        self.assertEqual(j["base"]["field"], "kuma_db")
        self.assertIn("illisible", j["base"]["message"])

    def test_la_route_n_ecrit_rien(self):
        with mock.patch.object(A.subprocess, "run", self._docker(0, "3\n")), \
                mock.patch.object(A, "kuma_test_status_page",
                                  lambda u: {"ok": True, "message": "", "moniteurs": 3,
                                             "field": "kuma_slug"}):
            st, _ = self.post("/api/mgmt/kuma/test", {
                "kuma_container": "kuma-essai", "kuma_db": "/essai/kuma.db",
                "kuma_slug": "essai"})
        self.assertEqual(st, 200)
        self.assertIsNone(self.reglages(), "le test ne doit RIEN enregistrer")
        self.assertEqual(A.kuma_conf(A.DATA, A.CONFIG)["container"], "kuma-config")

    def test_valeurs_invalides_refusees_en_400_avant_toute_sonde(self):
        def interdit(*a, **kw):
            raise AssertionError("docker lancé sur des valeurs refusées")

        with mock.patch.object(A.subprocess, "run", interdit):
            st, j = self.post("/api/mgmt/kuma/test", {"kuma_container": "kuma prod"})
        self.assertEqual(st, 400)
        self.assertIn("kuma_container", j["errors"])

    def test_la_route_repond_meme_quand_kuma_est_absent(self):
        """C'est là qu'on en a le plus besoin : Kuma n'est pas détecté, et on
        vient justement corriger la valeur qui l'empêche de l'être."""
        with mock.patch.object(A, "kuma_disponible", lambda *a, **k: False), \
                mock.patch.object(A.subprocess, "run", self._docker(0, "7\n")), \
                mock.patch.object(A, "kuma_test_status_page",
                                  lambda u: {"ok": True, "message": "", "moniteurs": 7,
                                             "field": "kuma_slug"}):
            st, j = self.post("/api/mgmt/kuma/test", {"kuma_container": "kuma-neuf"})
        self.assertEqual(st, 200)
        self.assertTrue(j["base"]["ok"])
        self.assertEqual(j["base"]["moniteurs"], 7)

    def test_les_autres_routes_kuma_restent_gardees_sans_kuma(self):
        with mock.patch.object(A, "kuma_disponible", lambda *a, **k: False):
            st, j = self.post("/api/mgmt/kuma/pause", {"monitor_id": 1, "active": 0})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertIn("Uptime Kuma", j["message"])


# --------------------------------------------------------------------------- #
#  4. plus AUCUNE lecture figée dans le code                                    #
# --------------------------------------------------------------------------- #
class TestAucuneLectureFigee(BaseTmp):
    """Une constante de module qui recopie config.json au démarrage annule tout
    le bénéfice : la valeur changée dans l'interface n'aurait d'effet qu'au
    redémarrage. L'analyse est faite sur l'AST et non au `grep`, pour qu'un
    commentaire qui CITE ces noms n'y ressemble pas."""

    FIGEES = {"KUMA_DB", "KUMA_CONTAINER", "KUMA_STATUS", "KUMA_SLUG", "SLUG"}
    MODULES = ("actions_server.py", "collect.py")

    def arbre(self, nom):
        with open(os.path.join(REPO, nom)) as fh:
            return ast.parse(fh.read())

    def test_aucune_constante_de_branchement_ne_subsiste(self):
        for nom in self.MODULES:
            for n in ast.walk(self.arbre(nom)):
                if isinstance(n, ast.Name) and n.id in self.FIGEES:
                    self.fail(f"{nom}:{n.lineno} : lecture figée « {n.id} » — "
                              f"passer par dashlib.kuma_conf()")

    def test_aucun_acces_direct_a_CONFIG_kuma_hors_dashboard_config(self):
        for nom in self.MODULES:
            for n in ast.walk(self.arbre(nom)):
                if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name)
                        and n.value.id == "CONFIG" and isinstance(n.slice, ast.Constant)
                        and str(n.slice.value).startswith("kuma")):
                    self.fail(f"{nom}:{n.lineno} : CONFIG[{n.slice.value!r}] lu directement — "
                              f"passer par dashlib.kuma_conf()")

    def test_kuma_conf_est_bien_le_point_de_lecture_partage(self):
        for mod in (A, collect):
            self.assertIs(mod.kuma_conf, dashlib.kuma_conf, mod.__name__)
        self.assertIs(dashboard_config.kuma_conf, dashlib.kuma_conf)

    def test_dashlib_ne_depend_toujours_de_rien(self):
        """kuma_conf vit dans dashlib : ce module doit rester sans dépendance
        interne, sinon dashboard_config ↔ dashlib deviendrait circulaire."""
        internes = {"actions_server", "dashboard_config", "collect", "vulns",
                    "phperrors", "rotate", "digest"}
        for n in ast.walk(self.arbre("dashlib.py")):
            if isinstance(n, ast.Import):
                self.assertFalse({a.name for a in n.names} & internes)
            elif isinstance(n, ast.ImportFrom):
                self.assertNotIn(n.module, internes)

    def test_la_page_bouchonnee_valide_comme_la_production(self):
        """tools/preview.py ne doit accepter que ce que le backend accepte."""
        import importlib.util
        chemin = os.path.join(REPO, "tools", "preview.py")
        # `tools/` ne part pas en production : seuls les modules du service y sont
        # copiés. Sur le serveur, ce test n'a pas d'objet — le faire échouer là
        # rendrait inutilisable la suite comme contrôle de déploiement (même
        # raison et même geste que tests/test_check_front.py).
        if not os.path.exists(chemin):
            raise unittest.SkipTest("tools/preview.py absent (déploiement sans tools/)")
        spec = importlib.util.spec_from_file_location("preview_kuma", chemin)
        preview = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preview)
        for cas in ({"kuma_slug": "parc prive"}, {"kuma_container": "-kuma"},
                    {"kuma_db": "/app/../etc/passwd"}, {"kuma_db": "relatif.db"},
                    {"kuma_status_url": "http://kuma.exemple.fr/"}):
            self.assertEqual(set(preview.erreurs_kuma(cas)),
                             set(dashlib.kuma_settings_errors(cas)), cas)
        for cas in ({"kuma_slug": "parc-x7k2m9"}, {"kuma_container": "uptime-kuma"},
                    {"kuma_db": "/app/data/kuma.db"}, {"kuma_slug": ""},
                    {"kuma_status_url": "http://127.0.0.1:3001/api/status-page/"}):
            self.assertEqual(preview.erreurs_kuma(cas), {}, cas)
            self.assertEqual(dashlib.kuma_settings_errors(cas), {}, cas)


if __name__ == "__main__":
    unittest.main()
