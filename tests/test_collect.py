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
import stat
import sys
import tempfile
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import collect            # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
