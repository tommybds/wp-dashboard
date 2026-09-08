#!/usr/bin/env python3
"""Tests des tâches périodiques du dashboard : collecte, erreurs PHP, bilan.

Aucun accès réseau ni SSH : `subprocess.run` est neutralisé, les appels
distants sont remplacés par des sorties de journal fabriquées, et les dossiers
data/ et public/ sont redirigés vers un répertoire temporaire.

    python3 -m unittest tests.test_collect -v
"""
import contextlib
import datetime
import io
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import collect            # noqa: E402
import dashboard_config   # noqa: E402
import dashlib            # noqa: E402
import digest             # noqa: E402
import phperrors          # noqa: E402
import vulns              # noqa: E402

MOIS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def faux_subprocess(*a, **kw):
    """Aucun processus externe ne doit être lancé pendant les tests."""
    raise AssertionError("subprocess.run appelé pendant un test : %r" % (a,))


@contextlib.contextmanager
def muet():
    """Avale la sortie standard des scripts (ils sont bavards par conception)."""
    with contextlib.redirect_stdout(io.StringIO()):
        yield


def lire(chemin, mode="r"):
    with open(chemin, mode) as fh:
        return fh.read()


def lire_json(chemin):
    with open(chemin) as fh:
        return json.load(fh)


def site(domain, plugins=None, admins=None, updraft=None, **extra):
    """Un site tel que le produit postprocess(), réduit à l'utile."""
    s = {"domain": domain, "path": f"/var/www/vhosts/{domain}/httpdocs",
         "owner": "www", "core_version": "6.5.2", "php_version": "8.2.1",
         "siteurl": f"https://{domain}", "errors": {}, "kuma": domain,
         "plugins_list": plugins if plugins is not None else [
             {"name": "akismet", "status": "active", "version": "5.3"}],
         "admins": admins if admins is not None else [
             {"login": "adm", "email": "adm@example.com"}],
         "updraft": updraft}
    s.update(extra)
    return s


def fleet(*servers):
    return {"generated_at": "2026-09-02 10:00", "servers": list(servers)}


def srv(name, sites, **extra):
    e = {"name": name, "host": "203.0.113.1", "complete": True, "sites": list(sites)}
    e.update(extra)
    return e


def sortie_ssh(domain, path=None, owner="www", plugins=(), done=True, sep="\x1f"):
    """Sortie brute du script distant pour un site (format @@SITE@@/@@F@@)."""
    path = path if path is not None else f"/var/www/vhosts/{domain}/httpdocs"
    out = [f"@@SITE@@{domain}{sep}{path}{sep}{owner}"]

    def champ(nom, valeur, rc=0):
        out.extend([f"@@F@@{nom}", valeur, f"@@ENDF@@{rc}"])

    champ("core_version", "6.5.2")
    champ("siteurl", f"https://{domain}")
    champ("blogname", domain)
    champ("plugins", json.dumps(list(plugins)))
    champ("admins", json.dumps([{"ID": 1, "user_login": "adm",
                                 "user_email": "adm@example.com"}]))
    if done:
        out.append("@@DONE@@")
    return "\n".join(out) + "\n"


class TempDirs(unittest.TestCase):
    """Redirige data/ et public/ vers un répertoire temporaire."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wpdash-test-")
        self.data = os.path.join(self.tmp, "data")
        self.pub = os.path.join(self.tmp, "public")
        os.makedirs(self.data)
        os.makedirs(self.pub)
        self.patchs = [
            mock.patch.object(collect, "BASE", self.tmp),
            mock.patch.object(collect, "DATA", self.data),
            mock.patch.object(collect, "PUB", self.pub),
            mock.patch.object(collect, "CHANGES_PATH", os.path.join(self.data, "changes.jsonl")),
            mock.patch.object(collect, "REST_SITES_PATH", os.path.join(self.data, "rest_sites.json")),
            mock.patch.object(collect.subprocess, "run", faux_subprocess),
            # Kuma est facultatif : sa détection lancerait `docker exec`, et les
            # sondes ouvriraient de vraies connexions. Les deux sont neutralisées
            # par défaut ; les tests qui les visent les réactivent explicitement.
            mock.patch.object(collect, "kuma_disponible", lambda *a, **k: False),
            mock.patch.object(collect, "probe_fleet", lambda fleet, *a, **k: 0),
        ]
        for p in self.patchs:
            p.start()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for p in self.patchs:
            self.addCleanup(p.stop)

    def ecrire(self, nom, obj):
        chemin = os.path.join(self.tmp, nom) if "/" not in nom else os.path.join(self.tmp, nom)
        with open(chemin, "w") as fh:
            json.dump(obj, fh)
        return chemin

    def fleet_json(self):
        return lire_json(os.path.join(self.data, "fleet.json"))


# --------------------------------------------------------------------------- #
#  diff_fleets                                                                #
# --------------------------------------------------------------------------- #
class TestDiffFleets(unittest.TestCase):
    def test_updraft_none_d_un_cote_ne_change_rien(self):
        """Un `wp option get` raté met updraft à None : ne rien journaliser.

        Sans la garde, chaque échec passager produisait « daily → None » puis
        « None → daily » à la collecte suivante — deux lignes de bruit dans
        changes.jsonl et dans le bilan Telegram."""
        avant = fleet(srv("s1", [site("a.fr", updraft={"interval": "daily",
                                                       "interval_db": "daily",
                                                       "retain": "10", "retain_db": "10"})]))
        apres = fleet(srv("s1", [site("a.fr", updraft=None)]))
        self.assertEqual(collect.diff_fleets(avant, apres, "t"), [])
        # et dans l'autre sens (retour à la normale)
        self.assertEqual(collect.diff_fleets(apres, avant, "t"), [])

    def test_updraft_reel_change_est_journalise(self):
        avant = fleet(srv("s1", [site("a.fr", updraft={"interval": "daily"})]))
        apres = fleet(srv("s1", [site("a.fr", updraft={"interval": "weekly"})]))
        ch = collect.diff_fleets(avant, apres, "t")
        self.assertEqual([c["kind"] for c in ch], ["updraft"])
        self.assertIn("daily → weekly", ch[0]["detail"])

    def test_plugin_ajoute_est_un_warn(self):
        avant = fleet(srv("s1", [site("a.fr")]))
        apres = fleet(srv("s1", [site("a.fr", plugins=[
            {"name": "akismet", "status": "active", "version": "5.3"},
            {"name": "inconnu", "status": "active", "version": "1.0"}])]))
        ch = collect.diff_fleets(avant, apres, "t")
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["kind"], "plugin_add")
        self.assertEqual(ch[0]["severity"], "warn")
        self.assertIn("inconnu", ch[0]["detail"])

    def test_admin_ajoute_est_un_warn(self):
        avant = fleet(srv("s1", [site("a.fr")]))
        apres = fleet(srv("s1", [site("a.fr", admins=[
            {"login": "adm", "email": "adm@example.com"},
            {"login": "pirate", "email": "x@evil.example"}])]))
        ch = collect.diff_fleets(avant, apres, "t")
        self.assertEqual([(c["kind"], c["severity"]) for c in ch], [("admin_add", "warn")])


# --------------------------------------------------------------------------- #
#  Serveur injoignable : conservation de l'entrée précédente                   #
# --------------------------------------------------------------------------- #
class TestMergeStale(unittest.TestCase):
    def test_entree_precedente_conservee(self):
        prev = {"s1": srv("s1", [site("a.fr")], complete=True)}
        echec = {"name": "s1", "host": "203.0.113.1", "complete": False,
                 "error": "TimeoutExpired", "sites": []}
        out = collect.merge_stale(echec, prev, "2026-09-02 12:00")
        self.assertEqual(len(out["sites"]), 1)
        self.assertTrue(out["stale"])
        self.assertFalse(out["complete"])
        self.assertEqual(out["error"], "TimeoutExpired")
        self.assertEqual(out["last_attempt"], "2026-09-02 12:00")

    def test_sans_entree_precedente_on_garde_l_echec(self):
        out = collect.merge_stale({"name": "s9", "complete": False, "sites": []},
                                  {}, "t")
        self.assertEqual(out["sites"], [])
        self.assertNotIn("stale", out)

    def test_collecte_complete_intacte(self):
        e = {"name": "s1", "complete": True, "sites": [site("a.fr")]}
        self.assertIs(collect.merge_stale(e, {"s1": srv("s1", [])}, "t"), e)

    def test_history_ne_compte_pas_zero_site_pour_un_serveur_stale(self):
        """La courbe de tendance ne doit pas plonger quand un serveur tombe."""
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(collect, "DATA", d):
                f = fleet(srv("s1", [site("a.fr"), site("b.fr")],
                              complete=False, stale=True))
                collect.append_history(f)
                ligne = json.loads(lire(os.path.join(d, "collect_history.jsonl")))
        self.assertEqual(ligne["sites"], 2)
        self.assertEqual(ligne["stale_servers"], 1)


# --------------------------------------------------------------------------- #
#  main() --only                                                              #
# --------------------------------------------------------------------------- #
class TestOnly(TempDirs):
    def setUp(self):
        super().setUp()
        self.ecrire("servers.json", [
            {"name": "s1", "host": "203.0.113.1", "port": 22,
             "patterns": ["/var/www/vhosts/*/httpdocs"]},
            {"name": "s2", "host": "203.0.113.2", "port": 22,
             "patterns": ["/var/www/vhosts/*/httpdocs"]},
        ])
        # annotate_kuma ne doit joindre ni Docker ni Kuma
        p = mock.patch.object(collect.urllib.request, "urlopen",
                              side_effect=OSError("réseau coupé pendant les tests"))
        p.start()
        self.addCleanup(p.stop)

    def ecrire_fleet(self, obj):
        with open(os.path.join(self.data, "fleet.json"), "w") as fh:
            json.dump(obj, fh)

    def test_serveur_inconnu_sort_en_2_sans_toucher_fleet(self):
        depart = fleet(srv("s1", [site("a.fr")]))
        self.ecrire_fleet(depart)
        chemin = os.path.join(self.data, "fleet.json")
        avant = lire(chemin, "rb")
        with mock.patch.object(sys, "argv", ["collect.py", "--only", "nexistepas"]):
            with self.assertRaises(SystemExit) as cm, muet():
                collect.main()
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(lire(chemin, "rb"), avant)

    def test_only_connu_ne_perd_pas_les_autres_serveurs(self):
        """Régression : --only doit fusionner, jamais remplacer l'inventaire."""
        self.ecrire_fleet(fleet(srv("s1", [site("vieux.fr")]),
                                srv("s2", [site("b.fr"), site("c.fr")])))
        with mock.patch.object(collect, "ssh_collect",
                               return_value=(sortie_ssh("a.fr"), 0)):
            with mock.patch.object(sys, "argv", ["collect.py", "--only", "s1"]), muet():
                collect.main()
        f = self.fleet_json()
        par_nom = {s["name"]: s for s in f["servers"]}
        self.assertEqual(sorted(par_nom), ["s1", "s2"])
        self.assertEqual([s["domain"] for s in par_nom["s1"]["sites"]], ["a.fr"])
        self.assertEqual(sorted(s["domain"] for s in par_nom["s2"]["sites"]),
                         ["b.fr", "c.fr"])

    def test_only_serveur_injoignable_conserve_ses_sites(self):
        self.ecrire_fleet(fleet(srv("s1", [site("a.fr")]), srv("s2", [site("b.fr")])))
        with mock.patch.object(collect, "ssh_collect", return_value=("", -1)):
            with mock.patch.object(sys, "argv", ["collect.py", "--only", "s1"]), muet():
                collect.main()
        par_nom = {s["name"]: s for s in self.fleet_json()["servers"]}
        self.assertEqual([s["domain"] for s in par_nom["s1"]["sites"]], ["a.fr"])
        self.assertTrue(par_nom["s1"]["stale"])

    def test_only_match_cree_l_entree_serveur_absente(self):
        """Le serveur n'est pas encore dans fleet.json : ses sites étaient jetés."""
        self.ecrire_fleet(fleet(srv("s2", [site("b.fr")])))
        with mock.patch.object(collect, "ssh_collect",
                               return_value=(sortie_ssh("a.fr"), 0)):
            with mock.patch.object(sys, "argv",
                                   ["collect.py", "--only", "s1", "--match", "a.fr"]), muet():
                collect.main()
        par_nom = {s["name"]: s for s in self.fleet_json()["servers"]}
        self.assertIn("s1", par_nom)
        self.assertEqual([s["domain"] for s in par_nom["s1"]["sites"]], ["a.fr"])
        self.assertEqual([s["domain"] for s in par_nom["s2"]["sites"]], ["b.fr"])

    def test_exception_sur_un_serveur_n_avorte_pas_la_collecte(self):
        def parfois_ko(server, extra, limit=0, match=""):
            if server["name"] == "s1":
                raise KeyError("port")
            return sortie_ssh("b.fr"), 0

        with mock.patch.object(collect, "ssh_collect", side_effect=parfois_ko):
            with mock.patch.object(sys, "argv", ["collect.py"]), muet():
                collect.main()
        par_nom = {s["name"]: s for s in self.fleet_json()["servers"]}
        self.assertEqual([s["domain"] for s in par_nom["s2"]["sites"]], ["b.fr"])
        self.assertFalse(par_nom["s1"]["complete"])
        self.assertIn("KeyError", par_nom["s1"]["error"])


# --------------------------------------------------------------------------- #
#  Écritures : atomicité, permissions                                         #
# --------------------------------------------------------------------------- #
class TestEcritures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wpdash-io-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_mode_et_absence_de_temporaire(self):
        for nom, mode in (("prive.json", 0o600), ("public.json", 0o644)):
            chemin = os.path.join(self.tmp, nom)
            collect.save_json_atomic(chemin, {"a": 1}, mode)
            self.assertEqual(stat.S_IMODE(os.stat(chemin).st_mode), mode)
            self.assertEqual(lire_json(chemin), {"a": 1})
        self.assertEqual(sorted(os.listdir(self.tmp)), ["prive.json", "public.json"])

    def test_pas_de_temporaire_residuel_en_cas_d_echec(self):
        chemin = os.path.join(self.tmp, "ko.json")
        with self.assertRaises(TypeError):
            collect.save_json_atomic(chemin, {"a": {1, 2}}, 0o600)  # set : non sérialisable
        self.assertEqual(os.listdir(self.tmp), [])

    def test_ecrasement_conserve_le_mode(self):
        chemin = os.path.join(self.tmp, "f.json")
        collect.save_json_atomic(chemin, {"n": 1}, 0o600)
        collect.save_json_atomic(chemin, {"n": 2}, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(chemin).st_mode), 0o600)
        self.assertEqual(lire_json(chemin), {"n": 2})

    def test_append_line_cree_en_0600(self):
        chemin = os.path.join(self.tmp, "j.jsonl")
        collect.append_line(chemin, '{"a":1}')
        collect.append_line(chemin, '{"a":2}')
        self.assertEqual(stat.S_IMODE(os.stat(chemin).st_mode), 0o600)
        self.assertEqual(lire(chemin).count("\n"), 2)


# --------------------------------------------------------------------------- #
#  Quotage shell et validation des motifs                                     #
# --------------------------------------------------------------------------- #
class TestQuotage(unittest.TestCase):
    def test_sq_apostrophe(self):
        self.assertEqual(collect.sq("a'b"), "'a'\\''b'")
        self.assertEqual(collect.sq("simple"), "'simple'")
        self.assertEqual(collect.sq("; rm -rf /"), "'; rm -rf /'")
        # une injection classique reste enfermée dans les quotes
        self.assertEqual(collect.sq("'; id #"), "''\\''; id #'")

    def test_motifs_invalides_rejetes(self):
        server = {"name": "s1", "patterns": [
            "/var/www/vhosts/*/httpdocs",
            "/var/www/'; id #",            # injection
            "/var/www/../../etc",          # remontée
            "/var/www/$(id)",              # substitution
        ]}
        with mock.patch("builtins.print"):
            pats = collect.effective_patterns(server, [])
        self.assertEqual(pats, ["/var/www/vhosts/*/httpdocs"])

    def test_commande_distante_quotee(self):
        vus = {}

        def faux_run(cmd, **kw):
            vus["cmd"] = cmd
            raise collect.subprocess.TimeoutExpired("ssh", 1)

        server = {"name": "s1", "host": "h", "patterns": ["/var/www/*/htdocs"]}
        with mock.patch.object(collect.subprocess, "run", faux_run):
            out, rc = collect.ssh_collect(server, [], 0, "a'b.fr")
        self.assertEqual((out, rc), ("", -1))
        self.assertIn("'a'\\''b.fr'", vus["cmd"][-1])
        self.assertIn("'/var/www/*/htdocs'", vus["cmd"][-1])
        self.assertIn("22", vus["cmd"])          # port par défaut


# --------------------------------------------------------------------------- #
#  Analyse de la sortie distante                                              #
# --------------------------------------------------------------------------- #
class TestParsing(unittest.TestCase):
    def test_extract_json_apres_un_warning_contenant_un_crochet(self):
        brut = ("PHP Warning:  Undefined array key [0] in /x/y.php on line 3\n"
                '[{"name":"akismet","status":"active","version":"5.3"}]')
        self.assertEqual(collect.extract_json(brut),
                         [{"name": "akismet", "status": "active", "version": "5.3"}])

    def test_extract_json_indente_sur_plusieurs_lignes(self):
        brut = 'Deprecated: [x] machin\n[\n  {\n   "name": "a"\n  }\n]'
        self.assertEqual(collect.extract_json(brut), [{"name": "a"}])

    def test_extract_json_repli_et_absence(self):
        self.assertIsNone(collect.extract_json(""))
        self.assertIsNone(collect.extract_json("aucun json ici"))
        self.assertEqual(collect.extract_json('{"a": 1}'), {"a": 1})

    def test_split_site_header_avec_pipe_dans_le_chemin(self):
        d, p, o = collect.split_site_header("a.fr\x1f/var/www/mon|dossier\x1fwww")
        self.assertEqual((d, p, o), ("a.fr", "/var/www/mon|dossier", "www"))

    def test_split_site_header_ancien_format(self):
        d, p, o = collect.split_site_header("a.fr|/var/www/mon|dossier|www")
        self.assertEqual((d, p, o), ("a.fr", "/var/www/mon|dossier", "www"))

    def test_parse_sites_et_postprocess(self):
        sites = collect.parse_sites(sortie_ssh("a.fr", plugins=[
            {"name": "akismet", "status": "active", "version": "5.3"}]))
        self.assertEqual(len(sites), 1)
        s = collect.postprocess(sites[0])
        self.assertEqual(s["domain"], "a.fr")
        self.assertEqual(s["core_version"], "6.5.2")
        self.assertEqual(s["plugins_total"], 1)
        self.assertEqual(s["errors"], {})

    def test_postprocess_core_update_non_dict(self):
        """`wp core check-update` renvoyant autre chose qu'une liste d'objets."""
        raw = {"domain": "a.fr", "path": "/p", "owner": "www",
               "fields": {"core_update": '["6.6"]'}, "rcs": {"core_update": 0}}
        self.assertIsNone(collect.postprocess(raw)["core_update"])


# --------------------------------------------------------------------------- #
#  vizproof : « pas de CLI » et « pas encore connecté » sont deux états         #
# --------------------------------------------------------------------------- #
class TestVizproof(unittest.TestCase):
    # Sortie de `wp vizproof status --format=json` sur un site non configuré :
    # rc 1, mais le JSON est bien imprimé.
    NON_CONFIG = json.dumps({"configured": False, "connected": False,
                             "has_credentials": False, "site_id": None,
                             "pages_count": 0, "plugin_version": "1.3.6",
                             "last_run": None})
    CONFIG = json.dumps({"configured": True, "connected": True,
                         "has_credentials": True, "site_id": "elwave-fr",
                         "pages_count": 4, "plugin_version": "1.3.6",
                         "last_run": {"at": "2026-09-01 04:54", "anomalies": 0}})

    def viz(self, raw, rc):
        return collect.postprocess({"domain": "a.fr", "path": "/p", "owner": "www",
                                    "fields": {"vizproof": raw},
                                    "rcs": {"vizproof": rc}})["vizproof"]

    def test_rc1_avec_json_donne_un_resume(self):
        """Le cœur du correctif : rc 1 + JSON = plugin installé, pas encore connecté."""
        v = self.viz(self.NON_CONFIG, 1)
        self.assertIsNotNone(v)
        self.assertEqual((v["has_cli"], v["configured"], v["connected"]), (True, False, False))
        self.assertFalse(v["has_credentials"])
        self.assertIsNone(v["site_id"])
        self.assertEqual(v["version"], "1.3.6")

    def test_rc1_sans_json_reste_none(self):
        """« 'vizproof' is not a registered command » : rien à lire, pas de CLI."""
        self.assertIsNone(self.viz("Error: 'vizproof' is not a registered wp command.", 1))

    def test_rc1_avec_json_sans_cle_configured_reste_none(self):
        """Un JSON qui n'est pas celui de `vizproof status` ne compte pas."""
        self.assertIsNone(self.viz('{"autre": true}', 1))

    def test_rc0_inchange(self):
        v = self.viz(self.CONFIG, 0)
        self.assertEqual((v["configured"], v["connected"], v["has_credentials"]),
                         (True, True, True))
        self.assertEqual(v["site_id"], "elwave-fr")
        self.assertEqual(v["pages"], 4)
        self.assertEqual(v["last_run"], {"at": "2026-09-01 04:54", "anomalies": 0})

    def test_autres_rc_ignores(self):
        for rc in (2, 90, 99, 127):
            self.assertIsNone(self.viz(self.NON_CONFIG, rc), rc)

    def test_plugin_ancien_sans_cle_configured(self):
        """1.3.4 : pas de `configured` dans le JSON — on la déduit de la connexion."""
        v = collect.vizproof_summary({"connected": True, "pages": 2, "version": "1.3.4"})
        self.assertTrue(v["configured"])
        self.assertTrue(v["has_credentials"])
        self.assertTrue(v["has_cli"])

    def test_site_id_seul_vaut_configure(self):
        v = collect.vizproof_summary({"connected": False, "site_id": "x-fr"})
        self.assertTrue(v["configured"])
        self.assertFalse(v["connected"])

    def test_non_dict_reste_none(self):
        for x in (None, [], "texte", 3):
            self.assertIsNone(collect.vizproof_summary(x))

    def test_les_champs_precedents_sont_conserves(self):
        v = collect.vizproof_summary({"connected": True, "pages": 7, "version": "1.3.6",
                                      "last_run": {"anomalies": 1}})
        for k in ("version", "connected", "pages", "last_run"):
            self.assertIn(k, v)

    def test_meme_resume_par_l_agent_rest(self):
        """La collecte REST passe par vizproof_summary : mêmes clés qu'en SSH."""
        site = collect.map_rest_inventory({"url": "https://a.fr"},
                                          {"vizproof": json.loads(self.NON_CONFIG)})
        self.assertEqual(site["vizproof"]["has_cli"], True)
        self.assertEqual(site["vizproof"]["configured"], False)


# --------------------------------------------------------------------------- #
#  vulns.version_compare                                                      #
# --------------------------------------------------------------------------- #
class TestVersionCompare(unittest.TestCase):
    # Les 14 cas de référence, alignés sur PHP version_compare().
    CAS = [
        ("1.0", "1.0.0", -1),
        ("1.0.0", "1.0", 1),
        ("1.0", "1.0", 0),
        ("1.0.0", "1.0.0", 0),
        ("1.0-beta", "1.0", -1),
        ("1.0", "1.0-beta", 1),
        ("1.0-RC2", "1.0", -1),
        ("1.0", "1.0-RC2", 1),
        ("1.0-alpha", "1.0-beta", -1),
        ("1.0-dev", "1.0-alpha", -1),
        ("1.0-rc1", "1.0-rc2", -1),
        ("3.100.1", "3.111.2", -1),
        ("2.10", "2.9", 1),
        ("1.0", "1.0.1", -1),
    ]

    def test_cas_de_reference(self):
        for a, b, attendu in self.CAS:
            with self.subTest(a=a, b=b):
                self.assertEqual(vulns.version_compare(a, b), attendu)

    def test_pl_est_au_dessus_des_chiffres(self):
        """PHP documente l'ordre « … < rc < # < pl = p », où « # » est un NOMBRE."""
        self.assertEqual(vulns.version_compare("1.0-pl1", "1.0"), 1)
        self.assertEqual(vulns.version_compare("1.0.1", "1.0.pl"), -1)
        self.assertEqual(vulns.version_compare("1.0.pl", "1.0.1"), 1)
        self.assertEqual(vulns.version_compare("1.0-p1", "1.0-pl1"), 0)

    def test_chiffres_unicode_ne_levent_pas(self):
        """« ² » passe isdigit() mais pas int() : ValueError au milieu du scan."""
        self.assertEqual(vulns.version_compare("1.0²", "1.0.3"), -1)
        self.assertEqual(vulns.version_compare("1.0.3", "1.0²"), 1)
        self.assertEqual(vulns.version_compare("1.0²", "1.0²"), 0)

    def test_chaine_inconnue_sous_dev(self):
        self.assertEqual(vulns.version_compare("1.0-machin", "1.0-dev"), -1)

    def test_affects_operateur_nul_conservateur(self):
        self.assertTrue(vulns.affects(None, "1.0"))
        self.assertTrue(vulns.affects({}, "1.0"))          # dict vide : bornes absentes
        self.assertFalse(vulns.affects({"max_operator": "lt"}, ""))
        self.assertTrue(vulns.affects({"max_operator": "lt", "max_version": "2.0"}, "1.9"))
        self.assertFalse(vulns.affects({"max_operator": "lt", "max_version": "2.0"}, "2.1"))

    def test_skip_slugs_generiques_seulement(self):
        self.assertIn("object-cache.php", vulns.SKIP_SLUGS)
        # rien de spécifique à un parc en dur : cela passe par vuln_skip_slugs
        self.assertNotIn("zzz-incident-harden", vulns.SKIP_SLUGS - set(
            str(x) for x in (vulns._CONFIG.get("vuln_skip_slugs") or [])))


# --------------------------------------------------------------------------- #
#  phperrors                                                                  #
# --------------------------------------------------------------------------- #
def horodate(mode, quand=None):
    q = quand or datetime.datetime.now() - datetime.timedelta(minutes=5)
    if mode == "nginx":
        return q.strftime("%Y/%m/%d %H:%M:%S")
    return f"{q.day:02d}-{MOIS[q.month - 1]}-{q.year} {q.strftime('%H:%M:%S')}"


class TestPhpErrors(unittest.TestCase):
    def scan(self, corps, domains=("a.fr", "b.fr"), hours=24):
        with mock.patch.object(phperrors, "_run_remote", return_value=(0, corps)), muet():
            return phperrors.remote_scan({"name": "s1"}, list(domains), hours)

    def test_trois_formats_de_message(self):
        tp, tn = horodate("plesk"), horodate("nginx")
        corps = "\n".join([
            "@@FENETRE@@1",
            # 1. Plesk, « in <fichier> on line <n> » capturé par la regex
            f'@@PLESK@@[{tp}] WARNING: [pool a.fr] child 7 said into stderr: '
            f'"PHP message: PHP Warning:  Undefined array key 417 '
            f'in /var/www/vhosts/a.fr/httpdocs/wp-content/plugins/x/y.php on line 42"',
            # 2. nginx, même forme via FastCGI
            f'@@NGINX@@b.fr\t{tn} [error] 5172#5172: *47 FastCGI sent in stderr: '
            f'"PHP message: PHP Notice:  bidule '
            f'in /var/www/b.fr/wp-content/themes/t/f.php on line 7" while reading',
            # 3. exception non capturée : « in <fichier>:<n> » + pile d'appels
            f'@@NGINX@@b.fr\t{tn} [error] 1#1: *2 FastCGI sent in stderr: '
            f'"PHP message: PHP Fatal error:  Uncaught Error: boom '
            f'in /var/www/b.fr/wp-content/plugins/z/z.php:12',
            "@@FIN@@",
        ])
        lignes, err, tronques = self.scan(corps)
        self.assertIsNone(err)
        self.assertEqual(tronques, [])
        self.assertEqual(len(lignes), 3)
        par_sev = {l["severity"]: l for l in lignes}
        self.assertEqual(par_sev["Warning"]["domain"], "a.fr")
        self.assertEqual(par_sev["Warning"]["line"], 42)
        self.assertTrue(par_sev["Warning"]["file"].endswith("/x/y.php"))
        # le chemin est retiré du message pour que les occurrences se regroupent
        self.assertNotIn("/wp-content/", par_sev["Warning"]["message"])
        self.assertEqual(par_sev["Notice"]["line"], 7)
        self.assertEqual(par_sev["Fatal error"]["line"], 12)
        self.assertTrue(par_sev["Fatal error"]["file"].endswith("/z/z.php"))

    # ---- pile d'appels des exceptions non capturées ---------------------- #
    @staticmethod
    def pile_plesk(tp, dom="a.fr", tronque=True):
        """Le journal d'une exception non capturée, tel que FPM l'écrit :
        le message, puis un cadre par ligne, chacun dans le même bruit."""
        pfx = f'@@PLESK@@[{tp}] WARNING: [pool {dom}] child 7 said into stderr: '
        coupe = ' Object(WP_REST_Request), Object(WP_REST_Request), Object(WP_..."' \
            if tronque else '"'
        return [
            pfx + '"PHP message: PHP Fatal error:  Uncaught Error: Call to undefined '
                  'method WP_Error::get_method() in /var/www/a.fr/wp-includes/'
                  'rest-api/class-wp-rest-server.php:1120',
            pfx + '"Stack trace:"',
            pfx + '"#0 /var/www/a.fr/wp-includes/rest-api/class-wp-rest-server.php(1120): '
                  'WP_REST_Server->serve_batch_request_v1()"',
            pfx + '"#1 /var/www/a.fr/wp-includes/rest-api/class-wp-rest-server.php(431):'
                + coupe,
            pfx + '"#4 /var/www/a.fr/wp-includes/rest-api.php(420): '
                  'WP_REST_Server->serve_request(\'/batch/v1\')"',
            pfx + '"thrown in /var/www/a.fr/wp-includes/rest-api/class-wp-rest-server.php '
                  'on line 1120"',
        ]

    def test_pile_d_appels_rattachee_a_l_exception(self):
        tp = horodate("plesk")
        lignes, err, _ = self.scan("\n".join(self.pile_plesk(tp) + ["@@FIN@@"]))
        self.assertIsNone(err)
        self.assertEqual(len(lignes), 1)          # les cadres ne sont pas des erreurs
        e = lignes[0]
        # « Stack trace: » est un en-tête, pas un cadre : il ne compte pas.
        self.assertEqual(len(e["trace"]), 4)
        self.assertTrue(e["trace"][0].startswith("#0 "))
        self.assertIn("serve_request('/batch/v1')", e["trace"][2])
        self.assertTrue(e["trace"][3].startswith("thrown in "))
        # Le bruit FPM et les guillemets sont retirés de chaque cadre.
        for cadre in e["trace"]:
            self.assertNotIn("said into stderr", cadre)
            self.assertFalse(cadre.endswith('"'))
        self.assertTrue(e["trace_truncated"])     # FPM a coupé le cadre #1

    def test_pile_complete_n_est_pas_dite_tronquee(self):
        tp = horodate("plesk")
        lignes, _, _ = self.scan("\n".join(self.pile_plesk(tp, tronque=False) + ["@@FIN@@"]))
        self.assertFalse(lignes[0].get("trace_truncated"))

    def test_pile_plafonnee_a_douze_cadres(self):
        tp = horodate("plesk")
        pfx = f'@@PLESK@@[{tp}] WARNING: [pool a.fr] child 7 said into stderr: '
        corps = [pfx + '"PHP message: PHP Fatal error:  Uncaught Error: boom '
                       'in /var/www/a.fr/x.php:1', pfx + '"Stack trace:"']
        corps += [pfx + f'"#{i} /var/www/a.fr/f{i}.php(2): fn()"' for i in range(30)]
        lignes, _, _ = self.scan("\n".join(corps + ["@@FIN@@"]))
        self.assertEqual(len(lignes[0]["trace"]), phperrors.MAX_TRACE)

    def test_pile_rattachee_au_bon_site_quand_deux_s_entrelacent(self):
        """Un journal Plesk porte tous les sites : les cadres de b.fr ne
        doivent pas atterrir sur l'exception de a.fr."""
        tp = horodate("plesk")
        corps = self.pile_plesk(tp, dom="a.fr", tronque=False)[:3]
        corps += self.pile_plesk(tp, dom="b.fr", tronque=False)[:3]
        lignes, _, _ = self.scan("\n".join(corps + ["@@FIN@@"]))
        self.assertEqual(len(lignes), 2)
        for e in lignes:
            self.assertEqual(len(e["trace"]), 1)

    def test_une_erreur_ordinaire_ne_recolte_aucune_pile(self):
        tp = horodate("plesk")
        pfx = f'@@PLESK@@[{tp}] WARNING: [pool a.fr] child 7 said into stderr: '
        corps = [pfx + '"PHP message: PHP Warning:  x in /a/b.php on line 1"',
                 pfx + '"#0 /a/b.php(1): fn()"']
        lignes, _, _ = self.scan("\n".join(corps + ["@@FIN@@"]))
        self.assertEqual(len(lignes), 1)
        self.assertNotIn("trace", lignes[0])

    def test_pile_sur_une_seule_ligne_nginx(self):
        tn = horodate("nginx")
        corps = (f'@@NGINX@@b.fr\t{tn} [error] 1#1: *2 FastCGI sent in stderr: '
                 f'"PHP message: PHP Fatal error:  Uncaught Error: boom '
                 f'in /var/www/b.fr/wp-content/plugins/z/z.php:12 Stack trace: '
                 f'#0 /var/www/b.fr/index.php(17): fn() #1 {{main}}'
                 f' thrown in /var/www/b.fr/z.php on line 12"\n@@FIN@@')
        lignes, _, _ = self.scan(corps)
        self.assertEqual(len(lignes), 1)
        self.assertEqual(len(lignes[0]["trace"]), 2)
        self.assertTrue(lignes[0]["trace"][0].startswith("#0 "))
        # le message reste court : la pile ne le pollue pas
        self.assertNotIn("Stack trace", lignes[0]["message"])

    def test_le_groupe_porte_la_pile_de_l_occurrence_la_plus_recente(self):
        base = {"domain": "a.fr", "severity": "Fatal error", "message": "boom",
                "file": "/a.php", "line": 1}
        sites = phperrors.agrege([
            dict(base, ts="2026-09-02 10:00:00", trace=["#0 vieux"]),
            dict(base, ts="2026-09-03 06:31:00", trace=["#0 recent"],
                 trace_truncated=True),
            dict(base, ts="2026-09-03 05:00:00", trace=["#0 entre-deux"]),
        ])
        g = sites[0]["groups"][0]
        self.assertEqual(g["count"], 3)
        self.assertEqual(g["trace"], ["#0 recent"])
        self.assertTrue(g["trace_truncated"])
        self.assertEqual(g["sample_ts"], "2026-09-03 06:31:00")

    def test_le_script_remonte_aussi_les_lignes_de_pile(self):
        s = phperrors.build_script(["a.fr"], 24)
        self.assertIn("Stack trace:", s)
        self.assertIn("#[0-9]+ ", s)
        self.assertIn("thrown in ", s)

    def test_domaine_inconnu_ignore(self):
        tp = horodate("plesk")
        corps = (f'@@PLESK@@[{tp}] WARNING: [pool inconnu.fr] child 7 said into stderr: '
                 f'"PHP message: PHP Warning:  x in /a/b.php on line 1"\n@@FIN@@')
        lignes, err, _ = self.scan(corps)
        self.assertEqual(lignes, [])
        self.assertIsNone(err)

    def test_hors_fenetre_avec_tolerance(self):
        vieux = datetime.datetime.now() - datetime.timedelta(hours=40)
        tp = horodate("plesk", vieux)
        corps = (f'@@PLESK@@[{tp}] WARNING: [pool a.fr] child 7 said into stderr: '
                 f'"PHP message: PHP Warning:  x in /a/b.php on line 1"\n@@FIN@@')
        self.assertEqual(self.scan(corps, hours=24)[0], [])
        # 40 h < 48 h + 3 h de tolérance de fuseau : la ligne est conservée
        self.assertEqual(len(self.scan(corps, hours=48)[0]), 1)

    def test_marqueur_de_troncature(self):
        corps = ("@@TRONQUE@@/var/log/plesk-php82-fpm/error.log|31337 lignes retenues, "
                 "plafond 20000\n@@FIN@@")
        lignes, err, tronques = self.scan(corps)
        self.assertIsNone(err)
        self.assertEqual(lignes, [])
        self.assertEqual(tronques, [{"file": "/var/log/plesk-php82-fpm/error.log",
                                     "reason": "31337 lignes retenues, plafond 20000"}])

    def test_absence_de_fin_est_une_erreur(self):
        """Le marqueur survivait à une troncature de sortie : l'analyse était
        silencieusement partielle."""
        tp = horodate("plesk")
        corps = (f'@@PLESK@@[{tp}] WARNING: [pool a.fr] child 7 said into stderr: '
                 f'"PHP message: PHP Warning:  x in /a/b.php on line 1"')
        lignes, err, tronques = self.scan(corps)
        self.assertEqual(lignes, [])
        self.assertIn("@@FIN@@", err)

    def test_appel_sans_troncature(self):
        """run_remote_script doit être appelé avec max_out=None."""
        vus = {}

        def faux(srv, script, timeout=300, max_out=6000):
            vus["max_out"] = max_out
            vus["script"] = script
            return 0, "@@FIN@@"

        with mock.patch.object(phperrors.A, "run_remote_script", faux), muet():
            phperrors.remote_scan({"name": "s1"}, ["a.fr"], 24)
        self.assertIsNone(vus["max_out"])

    def test_script_filtre_cote_serveur(self):
        s = phperrors.build_script(["a.fr", "mauvais domaine !"], 24)
        self.assertIn("a.fr", s)
        self.assertNotIn("mauvais domaine", s)     # domaine hors forme, écarté
        self.assertIn('date -d "-$i hours"', s)    # borne calculée sur le serveur
        self.assertIn("@@FIN@@", s)
        self.assertIn("CAP=20000", s)
        self.assertIn("[pool ", s)

    def test_un_serveur_lent_n_avorte_pas_la_passe(self):
        """subprocess.TimeoutExpired sur un serveur : les autres continuent."""
        def parfois_ko(server, domains, hours):
            if server["name"] == "lent":
                raise phperrors.A.subprocess.TimeoutExpired("ssh", 300)
            return [{"domain": "a.fr", "ts": "2026-09-02 10:00:00",
                     "severity": "Warning", "message": "x", "file": "/a.php",
                     "line": 1}], None, []

        with mock.patch.object(phperrors, "remote_scan", side_effect=parfois_ko):
            with mock.patch.object(phperrors.A, "load_json",
                                   return_value={"servers": [
                                       {"name": "lent", "sites": [
                                           {"domain": "z.fr", "kuma": "z.fr", "path": "/p"}]},
                                       {"name": "ok", "sites": [
                                           {"domain": "a.fr", "kuma": "a.fr", "path": "/p"}]}]}):
                with mock.patch.object(phperrors.A, "servers_list",
                                       return_value=[{"name": "lent"}, {"name": "ok"}]):
                    with mock.patch.object(phperrors, "save_json_atomic") as sauve:
                        with mock.patch.object(sys, "argv", ["phperrors.py"]), muet():
                            phperrors.main()
        res = sauve.call_args[0][1]
        self.assertIn("lent", res["servers_failed"])
        self.assertIn("TimeoutExpired", res["servers_failed"]["lent"])
        self.assertEqual(res["sites_with_errors"], 1)


# --------------------------------------------------------------------------- #
#  digest                                                                     #
# --------------------------------------------------------------------------- #
class TestDigest(unittest.TestCase):
    def test_load_recent_ignore_ts_null(self):
        maintenant = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        with tempfile.TemporaryDirectory() as d:
            chemin = os.path.join(d, "changes.jsonl")
            with open(chemin, "w") as fh:
                fh.write(json.dumps({"ts": None, "domain": "a.fr", "kind": "core",
                                     "severity": "info", "detail": "x"}) + "\n")
                fh.write(json.dumps({"ts": 1234567890, "domain": "a.fr"}) + "\n")
                fh.write('{"pas_de_ts": 1}\n')
                fh.write("pas du json\n")
                fh.write("\n")
                fh.write(json.dumps({"ts": maintenant, "domain": "b.fr", "kind": "core",
                                     "severity": "warn", "detail": "ok"}) + "\n")
                fh.write(json.dumps([1, 2, 3]) + "\n")
            with mock.patch.object(digest, "CHANGES_PATH", chemin):
                out = digest.load_recent(24)
        self.assertEqual([c["domain"] for c in out], ["b.fr"])

    def test_build_message(self):
        maintenant = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        ch = [{"ts": maintenant, "domain": "a.fr", "kind": "admin_add",
               "severity": "warn", "detail": "+ admin pirate"}]
        texte, n_sites, n_warn = digest.build_message(ch, 24)
        self.assertEqual((n_sites, n_warn), (1, 1))
        self.assertIn("pirate", texte)


# --------------------------------------------------------------------------- #
#  Sondes maison : disponibilité HTTP                                          #
#                                                                              #
#  Contre un VRAI serveur HTTP sur 127.0.0.1 : c'est le seul moyen d'éprouver   #
#  le repli HEAD → GET, le suivi des redirections et le délai dépassé tels que  #
#  urllib les vit. Aucune sortie réseau : la garde anti-SSRF (qui refuserait    #
#  le loopback, à raison) est neutralisée le temps du test.                     #
# --------------------------------------------------------------------------- #
def url_acceptee(url):
    """Garde SSRF neutralisée : pas de DNS, le loopback est autorisé ici."""
    return urllib.parse.urlsplit(str(url or "")), None


class ServeurLocal:
    """Petit serveur HTTP jetable, piloté par une fonction de réponse."""

    def __init__(self, repondre):
        self.vus = []
        essai = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _traiter(self):
                essai.vus.append((self.command, self.path))
                code, entetes, corps = repondre(self.command, self.path)
                if code is None:          # « ne réponds pas » : provoque le délai
                    time.sleep(3)
                    return
                self.send_response(code)
                for k, v in (entetes or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(corps or b"")))
                self.end_headers()
                if self.command != "HEAD" and corps:
                    self.wfile.write(corps)

            do_GET = do_HEAD = _traiter

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.fil = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.fil.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/"

    def fermer(self):
        self.srv.shutdown()
        self.srv.server_close()


class TestSondeHttp(unittest.TestCase):

    def setUp(self):
        p = mock.patch.object(collect, "validate_public_url", url_acceptee)
        p.start()
        self.addCleanup(p.stop)

    def servir(self, repondre):
        srv = ServeurLocal(repondre)
        self.addCleanup(srv.fermer)
        return srv

    def test_succes(self):
        srv = self.servir(lambda m, p: (200, {}, b"ok"))
        res = collect.probe_site(srv.url)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["error"], "")
        self.assertIsInstance(res["ms"], int)
        self.assertTrue(res["checked_at"])
        # HEAD suffit : rien n'est téléchargé quand le site répond normalement.
        self.assertEqual([m for m, _ in srv.vus], ["HEAD"])

    def test_erreur_serveur(self):
        srv = self.servir(lambda m, p: (500, {}, b"boum"))
        res = collect.probe_site(srv.url)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], 500)
        self.assertIn("500", res["error"])

    def test_repli_get_quand_head_est_refuse(self):
        """Beaucoup d'hébergements répondent 405 à un HEAD et servent le GET."""
        srv = self.servir(lambda m, p: (405, {}, b"") if m == "HEAD" else (200, {}, b"ok"))
        res = collect.probe_site(srv.url)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], 200)
        self.assertEqual([m for m, _ in srv.vus], ["HEAD", "GET"])

    def test_delai_depasse(self):
        srv = self.servir(lambda m, p: (None, {}, b""))
        res = collect.probe_site(srv.url, timeout=0.6)
        self.assertFalse(res["ok"])
        self.assertIsNone(res["status"])
        self.assertTrue(res["error"])

    def test_delai_total_borne_malgre_le_repli_get(self):
        """Le repli GET n'a droit qu'au temps RESTANT : un site muet coûte
        `timeout` secondes, pas deux fois plus."""
        srv = self.servir(lambda m, p: (None, {}, b""))
        t0 = time.time()
        collect.probe_site(srv.url, timeout=1.0)
        self.assertLess(time.time() - t0, 2.0)

    def test_port_ferme(self):
        srv = ServeurLocal(lambda m, p: (200, {}, b""))
        port = srv.port
        srv.fermer()
        res = collect.probe_site(f"http://127.0.0.1:{port}/")
        self.assertFalse(res["ok"])
        self.assertTrue(res["error"])

    def test_redirection_suivie(self):
        def repondre(m, p):
            if p == "/":
                return 302, {"Location": "/final"}, b""
            return 200, {}, b"ok"
        srv = self.servir(repondre)
        res = collect.probe_site(srv.url)
        self.assertTrue(res["ok"])
        self.assertEqual([p for _, p in srv.vus], ["/", "/final"])

    def test_boucle_de_redirection_bornee(self):
        srv = self.servir(lambda m, p: (302, {"Location": "/encore"}, b""))
        res = collect.probe_site(srv.url, max_redirects=2)
        self.assertFalse(res["ok"])
        self.assertLessEqual(len(srv.vus), 6)

    def test_garde_ssrf_appliquee(self):
        """Sans la neutralisation, le loopback est refusé — c'est bien la garde
        partagée avec l'API qui tranche, jamais une copie locale."""
        with mock.patch.object(collect, "validate_public_url",
                               dashlib.validate_public_url):
            res = collect.probe_site("http://127.0.0.1:9/")
        self.assertFalse(res["ok"])
        self.assertIn("adresse non autorisée", res["error"])


# --------------------------------------------------------------------------- #
#  Sondes maison : certificat TLS                                              #
# --------------------------------------------------------------------------- #
# Certificat auto-signé EXPIRÉ (CN=localhost, valide du 01/01/2020 au
# 01/01/2021), avec sa clé. Il ne protège rien : il n'existe que pour prouver
# qu'un certificat périmé — le cas que la surveillance doit justement voir —
# reste LISIBLE. Une vérification complète échouerait sur ces deux motifs
# (auto-signé, expiré) et ne rendrait aucune date.
CERT_EXPIRE_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIUer6HmvB58FG5NxPY9aSvsZdoV40wDQYJKoZIhvcNAQEL
BQAwPDESMBAGA1UEAwwJbG9jYWxob3N0MSYwJAYDVQQKDB1BdXRvcml0ZSBkZSB0
ZXN0IHdwLWRhc2hib2FyZDAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBa
MDwxEjAQBgNVBAMMCWxvY2FsaG9zdDEmMCQGA1UECgwdQXV0b3JpdGUgZGUgdGVz
dCB3cC1kYXNoYm9hcmQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr
Vr6WJSVLVwP8U/rE1tLoah0aSO1l3/MP8qUy2BBpjQAEDHVPuo+/H40wkt8tnPgl
XzKIGNgOSLXYumdk4PJyAl78vN0CD3fvoZBky1fW7q5dJ/pBHSido7scxTmXVzI3
GH8PuLWhIUU1Ek2GU2MhyFdPxhaCsoZJZWBI0xkI9qzLkjaPppDJW2a68WDPeJra
nm6rqDh4ZbTWaVZQUEyquV5WX2hpxowK1csbgHoIoqjntBYiClR9aaQh4qOyrnKt
1QlaOhp2FkVc4HTO55eLe/aC5vSYaEW8U5N2CpaihnxzeINeXbjEWccW8AgyKlP4
OSu1u14x4hh5Eg8elijRAgMBAAGjUzBRMB0GA1UdDgQWBBTacbG62+yICbTsfeys
RvqwybH83TAfBgNVHSMEGDAWgBTacbG62+yICbTsfeysRvqwybH83TAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBVpF/vB98DMXAzSHgk43tP6Cq9
JddFZ3ONF3a+AkMxJAPlzwwe1Tnz+u5q2jv423H48F/5/5jAxPJV3lI2RIot7rX1
KTwBXLdM+KHlctvcDdV86TSmAwby4xS3fvOSPsfBGOG+dBvESe775dAzSrKCx72X
1EpCgxRsC+2f5CuZTM08F9U6g4MJVPmbgIjfX18dI8mi1KX4NcF38ctmx6Cr1cae
JnvbnUuSezroAiBPj6mmkYV0PLagur6Hkc1JnTyCvkAkybI+AOyFO7V2k9SFUSZM
gGw26z+XFE0SIV9P2LT964rxG8bKMAW+wLLrzZYMuIODDeb2iVKI+oOORsxi
-----END CERTIFICATE-----
"""
CLE_EXPIREE_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrVr6WJSVLVwP8
U/rE1tLoah0aSO1l3/MP8qUy2BBpjQAEDHVPuo+/H40wkt8tnPglXzKIGNgOSLXY
umdk4PJyAl78vN0CD3fvoZBky1fW7q5dJ/pBHSido7scxTmXVzI3GH8PuLWhIUU1
Ek2GU2MhyFdPxhaCsoZJZWBI0xkI9qzLkjaPppDJW2a68WDPeJranm6rqDh4ZbTW
aVZQUEyquV5WX2hpxowK1csbgHoIoqjntBYiClR9aaQh4qOyrnKt1QlaOhp2FkVc
4HTO55eLe/aC5vSYaEW8U5N2CpaihnxzeINeXbjEWccW8AgyKlP4OSu1u14x4hh5
Eg8elijRAgMBAAECggEAPIIzZ2Hx5EP0J+HejzJQpHyJD5XOpOosdCbceXK9hREi
/ssJiOEZT8VMPum3gGvNZKFUfqTLdGvwMHxP9FvOsz2sHvRx1n7w+8Mic74uJL0A
/ewW4HT0OYuvkk8CcjR8iuGPSdWQ6zkNMFto3nXHbhBK6WTK4Vg7vWLcWIuYbUXf
yh5RxX353laqUdYjRl2wYj7+T3MFhcy1xxoWCbn+aRdeylWkIOhUDr2qzPZZXeqd
AdVLfXMFRVucNSEMd4ITq4BiQSb+cR66jcoN2tHw+Ba6y/AxkQWK3cQxvpHiUaJY
EY58JwKJD+X/fEARQ1j5rBJVSE58iYJt8h9jtgBd+wKBgQDiehakpeQnA5ypZ8Qs
NvmCyxmYn8+pz6ygfsrTovB32jzbAqQRbXzIbPd9TXxJQpIgWJRd5dTh65YaohSv
L/mDniIkc9d3RaecJPyUjwyXSa2tTkiq4WAVFkhsKiGr8fjFMRjmZknLzAuMWEDF
eRdhIorafNnzGTDH3Pk/zdx26wKBgQDBrJto/V4kSLviUuDfZhNXTszGn1cF2pEI
T16Fd3fufGR3wrZoMh9KXag4kmQE1jEQg+ee2mhlt9mA9ovjFVuZIMPnLZfIxHm/
aAgdlXEYRSCejjIKO9yVYJBHAVz5lUDct9+QV9G8doE3V0OjM/VdqSewzFpmLg6l
yhy9AVFoMwKBgQCns8Iqn5DHdvw90VHJb9fpCx3kD4rFcrugiOMGPiSUi2z+vADj
ytBY1Z+aEJOU6A+ulgkfUr4FoN6g0B5C72JzHNipZ4JIlrKbhCPomdi3+l358/sJ
ViRA2SQ9vCD84wvUcRvAGERS/cAbZ4pm79jpG5v4V/VH9wJRLQcAQR8ciwKBgCJX
nhMm4luivhYqxg83BXT01yDdPkwebps/n64g+hZC3nnSABBH2v6PzvWBF9U3uemI
yjiD2AE5cYsJrNJuhhiIE9TZY9HI7SHAq7e7ORupnlgfNMZVyQ5/2fWNS1RCYAcD
X9QzjlBR3yXWBntZCkg6Z3xVMC5wOk6xoRjus+W7AoGAY0W6c9mUReJn5rjDk31E
8yYq/o5NI+Pr4jjOUQegrltRjiVCNztVsgpNS6uU3RiaXSETP43BjT6CdXlq6E8i
mLmXko2I5tbSMuSM+V8wA8MREOjdA+xKxzOUrRCmwZW+ZrCakmLYmm4OvxS388Yu
5nQ6qoWakB938cwEQL/VmsM=
-----END PRIVATE KEY-----
"""


class ServeurTls:
    """Serveur TLS jetable qui présente le certificat qu'on lui donne."""

    def __init__(self, cert_pem, cle_pem, repertoire):
        cert = os.path.join(repertoire, "c.pem")
        cle = os.path.join(repertoire, "k.pem")
        for chemin, texte in ((cert, cert_pem), (cle, cle_pem)):
            with open(chemin, "w") as fh:
                fh.write(texte)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=cle)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False

        def boucle():
            while not self.stop:
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(64)
                except Exception:
                    pass          # le client abandonne la poignée de main : normal
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        self.fil = threading.Thread(target=boucle, daemon=True)
        self.fil.start()

    def fermer(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class TestSondeCertificat(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wpdash-tls-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_certificat_expire_reste_lisible(self):
        """LE cas qui justifie la seconde passe sans vérification.

        Avec `create_default_context()` seul, la poignée de main échoue et on ne
        saurait rien de la date de fin — le site disparaîtrait de la page des
        certificats le jour même où il faut l'y voir en rouge.
        """
        srv = ServeurTls(CERT_EXPIRE_PEM, CLE_EXPIREE_PEM, self.tmp)
        self.addCleanup(srv.fermer)
        cert = collect.read_cert("localhost", srv.port, timeout=5)
        self.assertEqual(cert["not_after"], "2021-01-01")
        self.assertLess(cert["days_left"], 0)
        self.assertIn("Autorite de test", cert["issuer"])
        self.assertEqual(cert["host"], "localhost")
        self.assertTrue(cert["error"], "le motif de rejet doit rester lisible")

    def test_hote_injoignable(self):
        cert = collect.read_cert("localhost", 9, timeout=2)
        self.assertIsNone(cert["days_left"])
        self.assertTrue(cert["error"])

    def test_hote_manquant(self):
        self.assertEqual(collect.read_cert("")["error"], "hôte manquant")

    def test_decodage_der(self):
        der = ssl.PEM_cert_to_DER_cert(CERT_EXPIRE_PEM)
        info = collect._decode_cert_der(der)
        self.assertEqual(info.get("notAfter"), "Jan  1 00:00:00 2021 GMT")
        # et aucun fichier temporaire ne survit à l'appel
        self.assertEqual([f for f in os.listdir(tempfile.gettempdir())
                          if f.startswith(".cert-")], [])

    def test_decodage_der_vide(self):
        self.assertEqual(collect._decode_cert_der(b""), {})


# --------------------------------------------------------------------------- #
#  probe_fleet : qui est sondé, et qui ne l'est pas                            #
# --------------------------------------------------------------------------- #
class TestProbeFleet(unittest.TestCase):

    def test_seuls_les_sites_suivis_sont_sondes(self):
        sondes = []
        f = fleet(srv("s1", [site("a.fr", followed=True),
                             site("b.fr", followed=False),
                             site("c.fr", followed=True, via="rest")]))
        with mock.patch.object(collect, "probe_one", lambda s: sondes.append(s["domain"])):
            with muet():
                n = collect.probe_fleet(f)
        self.assertEqual(n, 2)
        self.assertEqual(sorted(sondes), ["a.fr", "c.fr"])

    def test_restriction_a_un_seul_site(self):
        """Re-scan d'un site : les autres gardent la sonde de la collecte
        précédente plutôt que de rouvrir 20 connexions pour rien."""
        sondes = []
        f = fleet(srv("s1", [site("a.fr", followed=True), site("b.fr", followed=True)]))
        with mock.patch.object(collect, "probe_one", lambda s: sondes.append(s["domain"])):
            with muet():
                collect.probe_fleet(f, {"b.fr"})
        self.assertEqual(sondes, ["b.fr"])

    def test_aucun_site_suivi_ne_lance_rien(self):
        f = fleet(srv("s1", [site("a.fr", followed=False)]))
        with mock.patch.object(collect, "probe_one",
                               lambda s: self.fail("sonde lancée sur un site non suivi")):
            self.assertEqual(collect.probe_fleet(f), 0)

    def test_probe_one_sonde_url_et_certificat(self):
        vus = {}

        def faux_probe(url, **kw):
            vus["url"] = url
            return {"ok": True, "status": 200, "ms": 12, "error": "",
                    "checked_at": "2026-09-08T10:00:00"}

        def faux_cert(host, port=443, **kw):
            vus["cert"] = (host, port)
            return {"issuer": "R11", "not_after": "2026-12-01",
                    "days_left": 84, "host": host, "error": ""}

        s = {"domain": "a.fr", "siteurl": "https://a.fr"}
        with mock.patch.object(collect, "probe_site", faux_probe):
            with mock.patch.object(collect, "read_cert", faux_cert):
                collect.probe_one(s)
        self.assertEqual(vus["url"], "https://a.fr")
        self.assertEqual(vus["cert"], ("a.fr", 443))
        self.assertTrue(s["probe"]["ok"])
        self.assertEqual(s["cert"]["days_left"], 84)

    def test_site_en_http_simple_n_a_pas_de_certificat(self):
        s = {"domain": "a.fr", "siteurl": "http://a.fr", "cert": {"vieux": 1}}
        with mock.patch.object(collect, "probe_site", lambda url, **kw: {"ok": True}):
            with mock.patch.object(collect, "read_cert",
                                   lambda *a, **k: self.fail("TLS lu sur un site en http")):
                collect.probe_one(s)
        self.assertNotIn("cert", s)

    def test_url_deduite_du_domaine_sans_siteurl(self):
        self.assertEqual(collect.probe_target({"domain": "a.fr"}), "https://a.fr")
        self.assertEqual(collect.probe_target({}), "")


# --------------------------------------------------------------------------- #
#  Uptime Kuma facultatif : annotation et absence totale de docker              #
# --------------------------------------------------------------------------- #
class TestKumaFacultatif(TempDirs):

    def test_kuma_absent_ne_lance_aucun_docker_ni_reseau(self):
        """`collect.subprocess.run` et `urlopen` échouent si on les appelle."""
        with mock.patch.object(collect.urllib.request, "urlopen",
                               side_effect=AssertionError("appel réseau vers Kuma")):
            f = fleet(srv("s1", [site("a.fr", kuma=None)]))
            with muet():
                collect.annotate_kuma(f)      # subprocess.run lève déjà (TempDirs)
        s = f["servers"][0]["sites"][0]
        self.assertIsNone(s["kuma"])
        self.assertIs(s["followed"], False)
        self.assertEqual(s["label"], "a.fr")
        self.assertIsNone(s["client"])

    def test_site_suivi_visible_sans_kuma(self):
        with open(os.path.join(self.data, "followed.json"), "w") as fh:
            json.dump(["a.fr"], fh)
        f = fleet(srv("s1", [site("a.fr", kuma=None), site("b.fr", kuma=None)]))
        with muet():
            collect.annotate_kuma(f)
        par_dom = {s["domain"]: s for s in f["servers"][0]["sites"]}
        self.assertTrue(par_dom["a.fr"]["followed"])
        self.assertFalse(par_dom["b.fr"]["followed"])
        self.assertTrue(dashlib.site_visible(par_dom["a.fr"]))
        self.assertFalse(dashlib.site_visible(par_dom["b.fr"]))

    def test_label_et_client_viennent_des_overrides_sans_kuma(self):
        with open(os.path.join(self.data, "overrides.json"), "w") as fh:
            json.dump({"a.fr": {"label": "Boutique Dupont", "client": "Dupont SA"}}, fh)
        f = fleet(srv("s1", [site("a.fr", kuma=None)]))
        with muet():
            collect.annotate_kuma(f)
        s = f["servers"][0]["sites"][0]
        self.assertEqual(s["label"], "Boutique Dupont")
        self.assertEqual(s["client"], "Dupont SA")

    def test_site_rest_reste_suivi_d_office(self):
        f = fleet(srv("rest", [site("a.fr", kuma=None, via="rest")]))
        with muet():
            collect.annotate_kuma(f)
        self.assertTrue(f["servers"][0]["sites"][0]["followed"])

    def test_write_fleet_migre_puis_annote(self):
        """La bascule reprend la sélection lisible dans le fleet.json du disque."""
        ancien = fleet(srv("s1", [site("a.fr", kuma="a.fr"), site("b.fr", kuma=None)]))
        with open(os.path.join(self.data, "fleet.json"), "w") as fh:
            json.dump(ancien, fh)
        nouveau = fleet(srv("s1", [site("a.fr", kuma=None), site("b.fr", kuma=None)]))
        with muet():
            collect.write_fleet(nouveau)
        with open(os.path.join(self.data, "followed.json")) as fh:
            self.assertEqual(json.load(fh), ["a.fr"])
        par_dom = {s["domain"]: s for s in self.fleet_json()["servers"][0]["sites"]}
        self.assertTrue(par_dom["a.fr"]["followed"])
        self.assertFalse(par_dom["b.fr"]["followed"])


class TestVeillesSansKuma(unittest.TestCase):
    """`vulns.py` et `phperrors.py` ne connaissent QUE `site_visible`.

    C'est ce qui les rend indépendants d'Uptime Kuma : sur une flotte où aucune
    fiche ne porte de clé `kuma`, ils doivent voir exactement les sites suivis.
    """

    FLOTTE = {"servers": [{"name": "s1", "sites": [
        {"domain": "suivi.fr", "followed": True, "core_version": "6.5.2",
         "php_version": "8.2.1", "path": "/var/www/suivi",
         "plugins_list": [{"name": "akismet", "version": "5.3"}]},
        {"domain": "decouvert.fr", "followed": False, "core_version": "5.9",
         "php_version": "7.4.3", "path": "/var/www/decouvert",
         "plugins_list": [{"name": "plugin-fantome", "version": "1.0"}]},
    ]}]}

    def test_vulns_ne_voit_que_les_sites_suivis(self):
        retenus, slugs, _themes, cores, phps = vulns.fleet_targets(self.FLOTTE)
        self.assertEqual(sorted(retenus), ["suivi.fr"])
        self.assertEqual(slugs, {"akismet"})
        self.assertEqual((cores, phps), ({"6.5.2"}, {"8.2.1"}))

    def test_phperrors_ne_releve_que_les_sites_suivis(self):
        vus = []
        for srv in self.FLOTTE["servers"]:
            for site_ in srv["sites"]:
                if phperrors.A.site_visible(site_):
                    vus.append(site_["domain"])
        self.assertEqual(vus, ["suivi.fr"])


class TestDetectionKuma(unittest.TestCase):
    """`kuma_disponible()` : la porte d'entrée unique de tout `docker exec`."""

    def setUp(self):
        dashboard_config.reset_kuma_cache()
        self.addCleanup(dashboard_config.reset_kuma_cache)
        self._reglage = dashboard_config.CONFIG.get("kuma_enabled")
        self.addCleanup(lambda: dashboard_config.CONFIG.__setitem__(
            "kuma_enabled", self._reglage))

    @staticmethod
    def _docker_interdit(*a, **kw):
        raise AssertionError("docker lancé alors que Kuma est désactivé : %r" % (a,))

    def test_desactive_ne_lance_aucun_docker(self):
        dashboard_config.CONFIG["kuma_enabled"] = False
        with mock.patch.object(dashboard_config.subprocess, "run", self._docker_interdit):
            self.assertFalse(dashboard_config.kuma_disponible())
            self.assertIn("désactivé", dashboard_config.kuma_statut()["reason"])

    def test_force_a_vrai_ne_sonde_pas_non_plus(self):
        dashboard_config.CONFIG["kuma_enabled"] = True
        with mock.patch.object(dashboard_config.subprocess, "run", self._docker_interdit):
            self.assertTrue(dashboard_config.kuma_disponible())

    def test_auto_sonde_une_seule_fois_par_minute(self):
        dashboard_config.CONFIG["kuma_enabled"] = "auto"
        appels = []

        def faux_run(cmd, **kw):
            appels.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "1\n", "")

        with mock.patch.object(dashboard_config.subprocess, "run", faux_run):
            for _ in range(5):
                self.assertTrue(dashboard_config.kuma_disponible())
        self.assertEqual(len(appels), 1, "le cache doit éviter un docker par appel")
        self.assertEqual(appels[0][:3], ["docker", "exec",
                                         dashboard_config.CONFIG["kuma_container"]])

    def test_auto_conteneur_absent(self):
        dashboard_config.CONFIG["kuma_enabled"] = "auto"
        with mock.patch.object(dashboard_config.subprocess, "run",
                               side_effect=FileNotFoundError("docker")):
            statut = dashboard_config.kuma_statut()
        self.assertFalse(statut["enabled"])
        self.assertIn("docker", statut["reason"])

    def test_force_relit_malgre_le_cache(self):
        dashboard_config.CONFIG["kuma_enabled"] = "auto"
        appels = []

        def faux_run(cmd, **kw):
            appels.append(cmd)
            return subprocess.CompletedProcess(cmd, 1, "", "No such container")

        with mock.patch.object(dashboard_config.subprocess, "run", faux_run):
            dashboard_config.kuma_disponible()
            dashboard_config.kuma_disponible(force=True)
        self.assertEqual(len(appels), 2)


if __name__ == "__main__":
    unittest.main()
