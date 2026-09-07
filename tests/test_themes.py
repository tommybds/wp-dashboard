#!/usr/bin/env python3
"""Tests du parcours complet des THÈMES : collecte → veille → action → MAJ sûre.

Le dashboard exécutait déjà `wp theme list` mais n'en gardait qu'un compteur.
Ce fichier tient le fil de bout en bout — la liste conservée par `collect.py`,
son croisement avec `/theme/<slug>/` de WPVulnerability, l'action `theme_update`
et son gel, la place des thèmes dans la mise à jour sûre.

Aucune sortie réseau ni SSH : `api_get`, `urlopen`, `remote_bash`, `find_site`
et `health_probe` sont bouchés, tous les chemins de données vont dans un
répertoire jetable.

    python3 -m unittest tests.test_themes -v
"""
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import actions_server as A       # noqa: E402
import collect                   # noqa: E402
import vulns                     # noqa: E402


def theme(name, version, status="inactive", **extra):
    """Une entrée telle que la rend `wp theme list --format=json`."""
    t = {"name": name, "title": name.title(), "status": status,
         "version": version, "update": "none", "update_version": None,
         "parent": None}
    t.update(extra)
    return t


# --------------------------------------------------------------------------- #
#  collect.py : la liste des thèmes est CONSERVÉE                              #
# --------------------------------------------------------------------------- #
class TestCollecteThemes(unittest.TestCase):

    @staticmethod
    def post(raw, rc=0):
        return collect.postprocess({"domain": "a.fr", "path": "/p", "owner": "www",
                                    "fields": {"themes": raw}, "rcs": {"themes": rc}})

    def test_champs_demandes_a_wp_cli(self):
        """Les champs demandés existent tous dans `wp theme list`.

        `parent` n'en fait pas partie : le réclamer fait échouer la commande
        entière (« Invalid field: parent », vérifié en wp-cli 2.12), et donc
        perdre tous les thèmes. La parenté se lit dans `status`, que wp-cli met
        à « parent » pour le parent d'un thème enfant actif.
        """
        ligne = [l for l in collect.REMOTE_SCRIPT.splitlines()
                 if "emitfield themes" in l]
        self.assertEqual(len(ligne), 1, "commande `theme list` introuvable")
        for champ in ("name", "title", "status", "version",
                      "update_version", "update"):
            self.assertIn(champ, ligne[0], champ)
        self.assertNotIn("parent", ligne[0])

    def test_liste_conservee_et_bien_formee(self):
        s = self.post(json.dumps([
            theme("divi", "4.27.0", status="parent"),
            theme("divi-child", "1.0", status="active", parent="Divi"),
            theme("twentytwentyfour", "1.2", update="available",
                  update_version="1.3"),
        ]))
        self.assertEqual(s["themes_updates"], 1)          # compteur inchangé
        self.assertEqual(len(s["themes_list"]), 3)
        self.assertEqual(sorted(s["themes_list"][0]),
                         ["name", "parent", "status", "title", "update",
                          "update_version", "version"])
        enfant = s["themes_list"][1]
        self.assertEqual(enfant["name"], "divi-child")
        self.assertEqual(enfant["parent"], "Divi")
        self.assertEqual(enfant["status"], "active")
        maj = s["themes_list"][2]
        self.assertEqual((maj["update"], maj["update_version"]), ("available", "1.3"))

    def test_parent_absent_de_wp_cli_reste_none(self):
        """Une vieille version de wp-cli ne connaît pas le champ `parent`."""
        s = self.post(json.dumps([{"name": "astra", "status": "active",
                                   "version": "4.6.0", "update": "none"}]))
        self.assertEqual(s["themes_list"][0]["parent"], None)
        self.assertEqual(s["themes_list"][0]["title"], None)
        self.assertEqual(s["themes_list"][0]["name"], "astra")

    def test_json_illisible_ne_fabrique_rien(self):
        for brut, rc in (("Error: something exploded", 0), ("[]", 1), ("", 0)):
            with self.subTest(brut=brut, rc=rc):
                s = self.post(brut, rc)
                self.assertIsNone(s["themes_updates"])
                self.assertIsNone(s["themes_list"])

    def test_entrees_non_dict_ecartees(self):
        s = self.post(json.dumps(["astra", None, theme("astra", "4.6.0")]))
        self.assertEqual(len(s["themes_list"]), 1)
        self.assertEqual(s["themes_updates"], 0)

    def test_rest_compteur_seul_laisse_la_liste_a_none(self):
        """L'agent n'envoie qu'un nombre : on n'invente pas de liste."""
        s = collect.map_rest_inventory({"url": "https://a.fr"},
                                       {"home": "https://a.fr", "themes_updates": 2})
        self.assertEqual(s["themes_updates"], 2)
        self.assertIsNone(s["themes_list"])

    def test_rest_avec_liste_est_traite_comme_le_ssh(self):
        """Le jour où l'agent enverra la liste, elle sera reprise telle quelle."""
        s = collect.map_rest_inventory(
            {"url": "https://a.fr"},
            {"home": "https://a.fr",
             "themes": [theme("astra", "4.6.0", status="active", update=True)]})
        self.assertEqual(s["themes_updates"], 1)
        self.assertEqual(s["themes_list"][0]["name"], "astra")


# --------------------------------------------------------------------------- #
#  vulns.py : /theme/<slug>/ interrogé, croisé, et `kind` sur les 4 familles    #
# --------------------------------------------------------------------------- #
def vuln(name, max_version=None, max_operator=None, severity="critical"):
    """Un enregistrement de l'API, réduit à ce que lit `extract_vulns`."""
    op = {}
    if max_version:
        op = {"max_operator": max_operator or "lt", "max_version": max_version}
    return {"uuid": "u-" + name[:6], "name": name, "description": "",
            "cve": "CVE-2026-9", "link": None, "severity": severity,
            "score": None, "operator": op, "unfixed": False}


class VulnsBase(unittest.TestCase):
    """FEED / FOUND / FLEET redirigés, aucun appel réseau."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._sauv = {k: getattr(vulns, k)
                      for k in ("FEED_PATH", "FOUND_PATH", "FLEET_PATH", "PAUSE")}
        vulns.FEED_PATH = os.path.join(self.tmp.name, "vuln_feed.json")
        vulns.FOUND_PATH = os.path.join(self.tmp.name, "vulns_found.json")
        vulns.FLEET_PATH = os.path.join(self.tmp.name, "fleet.json")
        vulns.PAUSE = 0
        self.addCleanup(self._restaurer)

    def _restaurer(self):
        for k, v in self._sauv.items():
            setattr(vulns, k, v)

    def poser_fleet(self, **site):
        s = {"domain": "a.fr", "kuma": "a.fr", "core_version": "6.5.2",
             "php_version": "8.2.1", "plugins_list": [], "themes_list": []}
        s.update(site)
        vulns.save_json(vulns.FLEET_PATH,
                        {"servers": [{"name": "vps1", "sites": [s]}]})

    def poser_feed(self, **familles):
        cache = {}
        for famille, entrees in familles.items():
            cache[famille] = {cle: {"fetched": 9e9, "vulns": vs}
                              for cle, vs in entrees.items()}
        vulns.save_json(vulns.FEED_PATH, cache)


class TestVulnsFetchThemes(VulnsBase):

    def test_le_chemin_theme_est_interroge(self):
        self.poser_fleet(themes_list=[theme("divi", "4.27.0", status="active")],
                         plugins_list=[{"name": "akismet", "version": "5.3"}])
        appels = []

        def faux_api(path):
            appels.append(path)
            return {"name": path, "vulnerability": []}, None

        with mock.patch.object(vulns, "api_get", faux_api):
            with mock.patch("sys.stdout", io.StringIO()):
                ok, msg = vulns.do_fetch()
        self.assertTrue(ok, msg)
        self.assertIn("/theme/divi/", appels)
        self.assertIn("/plugin/akismet/", appels)
        self.assertIn("1 thèmes", msg)      # le compte figure dans le bilan
        cache = vulns.load_json(vulns.FEED_PATH, {})
        self.assertIn("divi", cache.get("theme", {}))

    def test_un_slug_de_theme_n_est_interroge_qu_une_fois(self):
        """Le même thème sur deux sites = un seul appel."""
        s = {"domain": "b.fr", "kuma": "b.fr", "core_version": "6.5.2",
             "php_version": "8.2.1", "plugins_list": [],
             "themes_list": [theme("divi", "4.27.0")]}
        vulns.save_json(vulns.FLEET_PATH, {"servers": [{"name": "vps1", "sites": [
            dict(s, domain="a.fr", kuma="a.fr"), s]}]})
        appels = []
        with mock.patch.object(vulns, "api_get",
                               lambda p: (appels.append(p), ({}, None))[1]):
            with mock.patch("sys.stdout", io.StringIO()):
                vulns.do_fetch()
        self.assertEqual(appels.count("/theme/divi/"), 1)

    def test_themes_list_absente_ne_casse_rien(self):
        self.poser_fleet(themes_list=None)
        with mock.patch.object(vulns, "api_get", lambda p: ({}, None)):
            with mock.patch("sys.stdout", io.StringIO()):
                ok, _ = vulns.do_fetch()
        self.assertTrue(ok)


class TestVulnsScanThemes(VulnsBase):

    def trouvailles(self):
        r = vulns.do_scan()
        return r["sites"][0]["findings"] if r["sites"] else []

    def test_theme_vulnerable_croise_et_marque_kind(self):
        self.poser_fleet(themes_list=[theme("divi", "4.9.0", status="active",
                                            update="available",
                                            update_version="4.27.4")])
        self.poser_feed(theme={"divi": [vuln("Divi <= 4.9.4 - XSS", "4.9.5")]})
        f = self.trouvailles()
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["kind"], "theme")
        self.assertEqual(f[0]["component"], "divi")
        self.assertEqual(f[0]["version"], "4.9.0")
        self.assertEqual(f[0]["update_to"], "4.27.4")
        self.assertEqual(f[0]["status"], "active")

    def test_version_corrigee_n_est_pas_signalee(self):
        self.poser_fleet(themes_list=[theme("divi", "4.27.0")])
        self.poser_feed(theme={"divi": [vuln("Divi <= 4.9.4 - XSS", "4.9.5")]})
        self.assertEqual(self.trouvailles(), [])

    def test_borne_du_titre_ecarte_le_faux_positif(self):
        """Fiche sans intervalle : la borne écrite dans le titre fait foi."""
        self.poser_fleet(themes_list=[theme("divi", "4.27.0")])
        self.poser_feed(theme={"divi": [vuln("Divi <= 4.9.4 - Stored XSS")]})
        self.assertEqual(self.trouvailles(), [])
        # …et la même fiche sur une version réellement concernée ressort
        self.poser_fleet(themes_list=[theme("divi", "4.9.0")])
        self.assertEqual(len(self.trouvailles()), 1)

    def test_sans_borne_du_tout_on_reste_conservateur(self):
        self.poser_fleet(themes_list=[theme("divi", "4.27.0")])
        self.poser_feed(theme={"divi": [vuln("Divi — faille non bornée")]})
        self.assertEqual(len(self.trouvailles()), 1)

    def test_theme_enfant_inconnu_ne_double_pas_le_parent(self):
        """L'enfant n'a pas de fiche : une seule trouvaille, celle du parent."""
        self.poser_fleet(themes_list=[
            theme("divi", "4.9.0", status="parent"),
            theme("divi-child", "4.9.0", status="active", parent="Divi")])
        self.poser_feed(theme={"divi": [vuln("Divi <= 4.9.4 - XSS", "4.9.5")],
                               "divi-child": []})
        f = self.trouvailles()
        self.assertEqual([(x["kind"], x["component"]) for x in f], [("theme", "divi")])

    def test_meme_slug_en_theme_et_en_extension_donne_deux_trouvailles(self):
        self.poser_fleet(themes_list=[theme("astra", "4.6.0")],
                         plugins_list=[{"name": "astra", "version": "4.6.0"}])
        self.poser_feed(theme={"astra": [vuln("Astra theme <= 4.6.1", "4.6.2")]},
                        plugin={"astra": [vuln("Astra plugin <= 4.6.1", "4.6.2")]})
        f = self.trouvailles()
        self.assertEqual(sorted(x["kind"] for x in f), ["plugin", "theme"])

    def test_les_quatre_familles_portent_kind(self):
        self.poser_fleet(themes_list=[theme("divi", "4.9.0")],
                         plugins_list=[{"name": "akismet", "version": "5.3"}])
        self.poser_feed(theme={"divi": [vuln("Divi <= 4.9.4", "4.9.5")]},
                        plugin={"akismet": [vuln("Akismet <= 5.4", "5.4")]},
                        core={"6.5.2": [vuln("WordPress 6.5.2")]},
                        php={"8.2.1": [vuln("PHP 8.2.1")]})
        r = vulns.do_scan()
        genres = {v["kind"] for v in r["sites"][0]["findings"]}
        self.assertEqual(genres, {"theme", "plugin", "core"})
        self.assertEqual({v["kind"] for v in r["php"][0]["findings"]}, {"php"})

    def test_theme_sans_version_ignore(self):
        self.poser_fleet(themes_list=[theme("divi", None)])
        self.poser_feed(theme={"divi": [vuln("Divi <= 9.0", "9.0")]})
        self.assertEqual(self.trouvailles(), [])


# --------------------------------------------------------------------------- #
#  actions_server.py : action `theme_update` et gel des thèmes                 #
# --------------------------------------------------------------------------- #
class ActionsBase(unittest.TestCase):
    """UPDATE_POLICY_PATH et le journal redirigés ; rien ne part en SSH."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = os.path.join(self.tmp.name, "data")
        os.makedirs(self.data)
        self._sauv = {k: getattr(A, k) for k in
                      ("DATA", "UPDATE_POLICY_PATH", "LOG", "ROLLBACK_INDEX_PATH")}
        A.DATA = self.data
        A.UPDATE_POLICY_PATH = os.path.join(self.data, "update_policy.json")
        A.ROLLBACK_INDEX_PATH = os.path.join(self.data, "rollback_index.json")
        A.LOG = os.path.join(self.data, "actions.log")
        A._JSON_LOCKS.clear()
        self.addCleanup(self._restaurer)

    def _restaurer(self):
        for k, v in self._sauv.items():
            setattr(A, k, v)
        A._JSON_LOCKS.clear()


class TestGelDesThemes(ActionsBase):

    def test_action_declaree(self):
        label, needs_arg, cmd = A.ACTIONS["theme_update"]
        self.assertTrue(needs_arg)
        self.assertEqual(cmd, "theme update {arg}")
        self.assertIn("theme_update", A.VIZ_AFTER_UPDATE_ACTIONS)

    def test_gel_et_degel_d_un_theme(self):
        self.assertEqual(A.set_frozen_plugin("a.fr", "divi", True, kind="theme"),
                         ["divi"])
        self.assertEqual(A.frozen_themes("a.fr"), ["divi"])
        self.assertEqual(A.frozen_plugins("a.fr"), [])      # listes disjointes
        A.set_frozen_plugin("a.fr", "divi", False, kind="theme")
        self.assertEqual(A.frozen_themes("a.fr"), [])

    def test_les_deux_listes_cohabitent(self):
        A.set_frozen_plugin("a.fr", "revslider", True)
        A.set_frozen_plugin("a.fr", "divi", True, kind="theme")
        self.assertEqual(A.frozen_plugins("a.fr"), ["revslider"])
        self.assertEqual(A.frozen_themes("a.fr"), ["divi"])
        # dégeler le thème ne doit PAS emporter l'extension gelée
        A.set_frozen_plugin("a.fr", "divi", False, kind="theme")
        self.assertEqual(A.frozen_plugins("a.fr"), ["revslider"])

    def test_fichier_existant_relu_sans_migration(self):
        """Format historique : `frozen` = extensions, rien d'autre."""
        A.save_json(A.UPDATE_POLICY_PATH, {"a.fr": {"frozen": ["revslider"]}})
        self.assertEqual(A.frozen_plugins("a.fr"), ["revslider"])
        self.assertEqual(A.frozen_themes("a.fr"), [])

    def test_prefixe_theme_dans_frozen_relu_comme_un_theme(self):
        """Migration EN LECTURE d'un `frozen` contenant « theme:<slug> »."""
        A.save_json(A.UPDATE_POLICY_PATH,
                    {"a.fr": {"frozen": ["revslider", "theme:divi"]}})
        self.assertEqual(A.frozen_plugins("a.fr"), ["revslider"])
        self.assertEqual(A.frozen_themes("a.fr"), ["divi"])

    def test_theme_update_refuse_si_gele(self):
        A.set_frozen_plugin("a.fr", "divi", True, kind="theme")
        rc, msg = A.run_action("vps1", "a.fr", "theme_update", "divi")
        self.assertEqual(rc, A.FROZEN_RC)
        self.assertIn("divi", msg)
        self.assertIn("gelé", msg)

    def test_un_theme_gele_ne_gele_pas_l_extension_de_meme_nom(self):
        A.set_frozen_plugin("a.fr", "astra", True, kind="theme")
        with mock.patch.object(A, "find_site", lambda s, d: (None, None)), \
             mock.patch.object(A, "rest_target", lambda s, d: None):
            rc, _ = A.run_action("vps1", "a.fr", "plugin_update", "astra")
        self.assertNotEqual(rc, A.FROZEN_RC)   # refusé plus loin (site inconnu)

    def test_themes_update_all_devient_update_except(self):
        A.set_frozen_plugin("a.fr", "divi", True, kind="theme")
        vus = {}

        def faux_find(server, domain):
            vus["appelé"] = True
            return None, None

        with mock.patch.object(A, "find_site", faux_find), \
             mock.patch.object(A, "rest_target", lambda s, d: None):
            # l'action est réécrite AVANT la résolution du site : on l'observe
            # via l'argument formaté que reçoit ACTIONS
            rc, _ = A.run_action("vps1", "a.fr", "themes_update_all", None)
        self.assertTrue(vus.get("appelé"))
        self.assertEqual(A.ACTIONS["themes_update_except"][2],
                         "theme update --all --exclude={arg}")

    def test_exclusion_reellement_transmise_a_wp_cli(self):
        """La commande distante doit porter `--exclude=divi,storefront`."""
        A.set_frozen_plugin("a.fr", "divi", True, kind="theme")
        A.set_frozen_plugin("a.fr", "storefront", True, kind="theme")
        vues = []
        srv = {"name": "vps1", "host": "h", "port": 22}
        site = {"domain": "a.fr", "path": "/p", "owner": "www"}
        with mock.patch.object(A, "find_site", lambda s, d: (srv, site)), \
             mock.patch.object(A, "run_wp_remote",
                               lambda sv, si, args, timeout=300: (vues.append(args), (0, ""))[1]):
            rc, _ = A.run_action("vps1", "a.fr", "themes_update_all", None)
        self.assertEqual(rc, 0)
        self.assertEqual(vues, ["theme update --all --exclude=divi,storefront"])


# --------------------------------------------------------------------------- #
#  MAJ sûre : archive, met à jour et restaure un thème                          #
# --------------------------------------------------------------------------- #
class TestMajSureThemes(unittest.TestCase):
    """`safe_update_run` jouée pour de vrai, tous ses appels distants bouchés."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = os.path.join(self.tmp.name, "data")
        os.makedirs(self.data)
        self._sauv = {k: getattr(A, k) for k in
                      ("DATA", "SETTINGS_PATH", "ROLLBACK_INDEX_PATH",
                       "UPDATE_POLICY_PATH", "LOG")}
        A.DATA = self.data
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        A.ROLLBACK_INDEX_PATH = os.path.join(self.data, "rollback_index.json")
        A.UPDATE_POLICY_PATH = os.path.join(self.data, "update_policy.json")
        A.LOG = os.path.join(self.data, "actions.log")
        A._JSON_LOCKS.clear()
        self.addCleanup(self._restaurer)
        A.SAFE.update({"running": False, "domain": "", "steps": [], "verdict": ""})

        self.sain = True            # la page d'accueil répond-elle après la MAJ ?
        self.bash = []
        srv = {"name": "s1", "host": "203.0.113.1", "port": 22}
        site = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www",
                "siteurl": "https://a.fr", "core_version": "6.5.2"}
        for cible, valeur in (
                ("find_site", lambda s, d: (srv, site)),
                ("viz_available", lambda s, x: False),
                ("health_probe", self._probe),
                ("remote_bash", self._bash),
                ("alert", lambda *a, **k: None),
        ):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _restaurer(self):
        for k, v in self._sauv.items():
            setattr(A, k, v)
        A._JSON_LOCKS.clear()

    def _probe(self, site):
        """Site cassé UNIQUEMENT entre la mise à jour et le retour arrière."""
        if self.sain or not self.maj_faite() or self.restauration_faite():
            return True, 200, 5000, "HTTP 200, 5000 octets"
        return False, 500, 0, "HTTP 500"

    def maj_faite(self):
        return any(b.startswith("run theme update") or b.startswith("run plugin update")
                   for b in self.bash)

    def restauration_faite(self):
        return any("theme__*.tgz" in b for b in self.bash)

    def _bash(self, srv, site, body, timeout=300):
        self.bash.append(body)
        if "plugin list --update=available" in body:
            return 0, ""                       # aucune extension à mettre à jour
        if "theme list --update=available" in body:
            return 0, "divi"
        if "theme list --fields=name,version" in body:
            return 0, "name,version\ndivi,4.9.0\ntwentytwentyfour,1.2"
        if "plugin list --fields=name,version" in body:
            return 0, "name,version"
        if "BESOIN_MO" in body:                # bloc d'archivage
            return 0, ("PLUGDIR=/var/www/a.fr/wp-content/plugins\n"
                       "THEMEDIR=/var/www/a.fr/wp-content/themes\nDB_MO=12\n"
                       "BESOIN_MO=30\nLIBRE_MO=90000\narchivé divi\n"
                       "BDD_MO=3\narchivé (base)\nTAILLE_ARCHIVES_MO=4")
        if "theme__*.tgz" in body:             # bloc de retour arrière
            return 0, "restauré divi"
        return 0, "Success: Updated 1 of 1 themes."

    def etape(self, libelle):
        return next((x for x in A.SAFE["steps"] if libelle in x["label"]), None)

    def lancer(self, **kw):
        A.safe_update_run("s1", "a.fr", do_backup=False, use_viz=False, **kw)
        return dict(A.SAFE)

    # ---- chemin nominal -------------------------------------------------- #
    def test_theme_archive_puis_mis_a_jour(self):
        st = self.lancer()
        self.assertEqual(st["verdict"], "réussi",
                         [x["label"] + "/" + x["detail"][:60] for x in st["steps"]])
        archive = next(b for b in self.bash if "BESOIN_MO" in b)
        self.assertIn("THEMES=('divi')", archive)
        self.assertIn('tar czf', archive)
        self.assertIn('theme__"$t".tgz', archive)
        self.assertIn("wp theme path", archive)
        self.assertIn("run theme update 'divi'", self.bash)
        self.assertIsNotNone(self.etape("Mise à jour des thèmes"))
        self.assertIn("1 thème(s) : divi", self.etape("À mettre à jour")["detail"])

    def test_espace_disque_compte_les_themes(self):
        self.lancer()
        archive = next(b for b in self.bash if "BESOIN_MO" in b)
        self.assertIn('du -sm "$THEMEDIR/$t"', archive)

    def test_manifeste_et_index_portent_les_themes(self):
        self.lancer()
        archive = next(b for b in self.bash if "BESOIN_MO" in b)
        manifeste = json.loads([l for l in archive.splitlines()
                                if l.startswith('{"domain"')][0])
        self.assertEqual(manifeste["themes"], {"divi": "4.9.0"})
        idx = A.load_json(A.ROLLBACK_INDEX_PATH, {})
        self.assertEqual(idx["a.fr"][0]["themes"], ["divi"])
        self.assertEqual(idx["a.fr"][0]["theme_versions"], {"divi": "4.9.0"})

    def test_restriction_par_slug(self):
        st = self.lancer(themes=["autre-theme"])
        self.assertEqual(st["verdict"], "rien à faire")

    def test_with_themes_false_les_laisse_de_cote(self):
        st = self.lancer(with_themes=False)
        self.assertEqual(st["verdict"], "rien à faire")
        self.assertFalse(any("theme list --update=available" in b for b in self.bash))

    def test_theme_gele_ecarte_et_dit_dans_le_journal(self):
        A.set_frozen_plugin("a.fr", "divi", True, kind="theme")
        st = self.lancer()
        self.assertEqual(st["verdict"], "rien à faire")
        e = self.etape("Thèmes gelés, écartés")
        self.assertIsNotNone(e)
        self.assertEqual(e["detail"], "divi")

    # ---- régression : retour arrière ------------------------------------- #
    def test_regression_restaure_le_theme(self):
        self.sain = False
        st = self.lancer()
        self.assertEqual(st["verdict"], "annulé (retour arrière)")
        rb = next(b for b in self.bash if "theme__*.tgz" in b)
        self.assertIn("THEMEDIR=", rb)
        self.assertIn('tar xzf "$f" -C "$THEMEDIR"', rb)
        self.assertIn("1 élément(s)", self.etape("Retour arrière")["detail"])


# --------------------------------------------------------------------------- #
#  Rétablissement d'une version : wordpress.org côté thèmes                     #
# --------------------------------------------------------------------------- #
class TestWporgVersionsThemes(unittest.TestCase):

    def faux_urlopen(self, payload, capture):
        class Rep:
            def __enter__(_s):
                return _s

            def __exit__(*_a):
                return False

            def read(_s, n=None):
                return json.dumps(payload).encode()

        def _open(req, timeout=None):
            capture.append(req.full_url)
            return Rep()

        return _open

    def test_url_de_l_api_des_themes(self):
        vus = []
        payload = {"version": "4.6.1", "versions": {"4.6.0": "u", "4.5.0": "u",
                                                    "4.6.1": "u", "trunk": "u"}}
        with mock.patch("urllib.request.urlopen", self.faux_urlopen(payload, vus)):
            r = A.wporg_versions("astra", kind="theme")
        self.assertIn("/themes/info/1.2/", vus[0])
        self.assertIn("action=theme_information", vus[0])
        self.assertIn("request%5Bslug%5D=astra", vus[0].replace("[", "%5B").replace("]", "%5D"))
        self.assertIn("versions", vus[0])
        self.assertIsNone(r["error"])
        self.assertEqual(r["current"], "4.6.1")
        self.assertEqual(r["versions"], ["4.6.1", "4.6.0", "4.5.0"])   # décroissant

    def test_extension_inchangee(self):
        vus = []
        payload = {"version": "5.4", "versions": {"5.3": "u", "5.4": "u"}}
        with mock.patch("urllib.request.urlopen", self.faux_urlopen(payload, vus)):
            r = A.wporg_versions("akismet")
        self.assertIn("/plugins/info/1.0/akismet.json", vus[0])
        self.assertEqual(r["versions"], ["5.4", "5.3"])

    def test_theme_premium_absent_du_depot(self):
        vus = []
        with mock.patch("urllib.request.urlopen",
                        self.faux_urlopen({"error": "Theme not found"}, vus)):
            r = A.wporg_versions("divi", kind="theme")
        self.assertEqual(r["versions"], [])
        self.assertIn("not found", r["error"])

    def test_slug_invalide(self):
        r = A.wporg_versions("../etc", kind="theme")
        self.assertEqual(r["error"], "thème invalide")


if __name__ == "__main__":
    unittest.main()
