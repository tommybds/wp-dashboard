#!/usr/bin/env python3
"""Tests de l'API du dashboard (actions_server.py).

Aucune sortie réseau, aucun ssh, aucun docker : les seuls sockets ouverts le
sont sur 127.0.0.1 par les tests qui ont besoin d'un vrai serveur HTTP (garde
de session, non-suivi des redirections). Tous les chemins de données sont
redirigés vers un répertoire temporaire.

    python3 -m unittest tests.test_backend -v
"""
import ast
import base64
import datetime
import hashlib
import hmac
import http.client
import inspect
import io
import json
import os
import re
import shutil
import stat
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import actions_server as A

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRON_FIXTURE = os.path.join(REPO, "deploy", "wp-dashboard.cron")
SERVERS_EXAMPLE = os.path.join(REPO, "servers.example.json")


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def lire_json(path):
    with open(path) as fh:
        return json.load(fh)


class BaseTmp(unittest.TestCase):
    """Redirige BASE / DATA / CRON_PATH vers un répertoire jetable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.data = os.path.join(self.root, "data")
        os.makedirs(self.data)
        self._sauv = {k: getattr(A, k) for k in
                      ("BASE", "DATA", "CRON_PATH", "SECRETS_PATH", "SESSION_SECRET_PATH",
                       "WPAUTH_PATH", "WPSTATE_PATH", "UPDATE_POLICY_PATH", "LOG")}
        A.BASE = self.root
        A.DATA = self.data
        A.CRON_PATH = os.path.join(self.root, "wp-dashboard.cron")
        A.SECRETS_PATH = os.path.join(self.data, "site_secrets.json")
        A.SESSION_SECRET_PATH = os.path.join(self.data, ".session_secret")
        A.WPAUTH_PATH = os.path.join(self.data, "app_passwords.json")
        A.WPSTATE_PATH = os.path.join(self.data, "wp_states.json")
        A.UPDATE_POLICY_PATH = os.path.join(self.data, "update_policy.json")
        A.LOG = os.path.join(self.data, "actions.log")
        A._SESSION_SECRET = None
        A._JSON_LOCKS.clear()
        A.INGEST_SEEN.clear()
        self.addCleanup(self._restaurer)

    def _restaurer(self):
        for k, v in self._sauv.items():
            setattr(A, k, v)
        A._SESSION_SECRET = None
        A._JSON_LOCKS.clear()
        A.INGEST_SEEN.clear()
        self.tmp.cleanup()


# --------------------------------------------------------------------------- #
#  cron : la collecte est UNE ligne parmi cinq                                  #
# --------------------------------------------------------------------------- #
class TestSchedule(BaseTmp):

    AUTRES = ["phperrors.py", "vulns.py", "digest.py", "rotate.py"]

    def poser_fixture(self):
        shutil.copyfile(CRON_FIXTURE, A.CRON_PATH)
        with open(A.CRON_PATH) as fh:
            return fh.read().splitlines()

    def lignes(self):
        with open(A.CRON_PATH) as fh:
            return fh.read().splitlines()

    def test_fixture_contient_bien_cinq_taches(self):
        avant = self.poser_fixture()
        for tache in self.AUTRES:
            self.assertTrue(any(tache in l for l in avant), tache)
        self.assertTrue(any("collect.py" in l for l in avant))

    def test_preserve_les_quatre_autres_taches(self):
        avant = self.poser_fixture()
        gardees = [l for l in avant if "collect.py" not in l]
        ok, err = A.write_schedule(60)
        self.assertTrue(ok, err)
        apres = self.lignes()
        # les 4 autres tâches (et leurs commentaires) sont recopiées à l'identique
        for l in gardees:
            self.assertIn(l, apres, f"ligne perdue : {l}")
        for tache in self.AUTRES:
            self.assertEqual(sum(1 for l in apres if tache in l), 1, tache)

    def test_remplace_bien_la_ligne_collect(self):
        self.poser_fixture()
        ok, _ = A.write_schedule(360)
        self.assertTrue(ok)
        collect = [l for l in self.lignes() if "collect.py" in l]
        self.assertEqual(len(collect), 1)
        self.assertTrue(collect[0].startswith(A.cron_expr(360) + " root "), collect[0])
        self.assertEqual(A.read_schedule()["interval_minutes"], 360)

    def test_desactivation_puis_reactivation(self):
        avant = self.poser_fixture()
        gardees = [l for l in avant if "collect.py" not in l]
        self.assertTrue(A.write_schedule(0)[0])
        apres = self.lignes()
        self.assertNotIn("collect.py", "\n".join(apres))
        self.assertIn(A.CRON_DISABLED, apres)
        for l in gardees:
            self.assertIn(l, apres)
        self.assertEqual(A.read_schedule()["interval_minutes"], 0)
        # réactivation : la ligne de désactivation redevient une ligne de collecte
        self.assertTrue(A.write_schedule(30)[0])
        apres = self.lignes()
        self.assertNotIn(A.CRON_DISABLED, apres)
        self.assertEqual(sum(1 for l in apres if "collect.py" in l), 1)
        for l in gardees:
            self.assertIn(l, apres)

    def test_preserve_une_ligne_ajoutee_a_la_main(self):
        self.poser_fixture()
        with open(A.CRON_PATH, "a") as fh:
            fh.write("# perso\n5 5 * * * root /usr/local/bin/mon-script.sh\n")
        A.write_schedule(120)
        apres = "\n".join(self.lignes())
        self.assertIn("5 5 * * * root /usr/local/bin/mon-script.sh", apres)
        self.assertIn("# perso", apres)

    def test_cree_le_fichier_absent(self):
        self.assertFalse(os.path.exists(A.CRON_PATH))
        self.assertTrue(A.write_schedule(15)[0])
        lignes = self.lignes()
        self.assertEqual(lignes[0], A.CRON_HEADER)
        self.assertIn("collect.py", lignes[1])
        self.assertEqual(mode_of(A.CRON_PATH), 0o644)

    def test_pas_de_tmp_residuel(self):
        self.poser_fixture()
        A.write_schedule(720)
        restes = [f for f in os.listdir(self.root) if f.startswith(".tmp-")]
        self.assertEqual(restes, [])

    def test_intervalle_refuse(self):
        self.poser_fixture()
        for mauvais in (7, "abc", None, -30):
            ok, err = A.write_schedule(mauvais)
            self.assertFalse(ok)
            self.assertTrue(err)
        # le fichier n'a pas bougé
        self.assertEqual(self.lignes(), self.poser_fixture())

    def test_cron_expr_pour_chaque_choix(self):
        attendu = {
            0: "*/0 * * * *",   # jamais écrit : 0 passe par la ligne de désactivation
            15: "*/15 * * * *",
            30: "*/30 * * * *",
            60: f"{A.CRON_MINUTE} * * * *",
            120: f"{A.CRON_MINUTE} */2 * * *",
            180: f"{A.CRON_MINUTE} */3 * * *",
            360: f"{A.CRON_MINUTE} */6 * * *",
            720: f"{A.CRON_MINUTE} */12 * * *",
            1440: f"{A.CRON_MINUTE} 3 * * *",
        }
        self.assertEqual(sorted(attendu), sorted(A.SCHEDULE_CHOICES))
        for minutes in A.SCHEDULE_CHOICES:
            self.assertEqual(A.cron_expr(minutes), attendu[minutes], minutes)
            self.assertEqual(len(A.cron_expr(minutes).split()), 5, minutes)

    def test_aller_retour_de_chaque_choix(self):
        for minutes in A.SCHEDULE_CHOICES:
            self.poser_fixture()
            self.assertTrue(A.write_schedule(minutes)[0], minutes)
            self.assertEqual(A.read_schedule()["interval_minutes"], minutes, minutes)

    def test_read_schedule_ne_casse_pas_sur_un_cron_edite_a_la_main(self):
        with open(A.CRON_PATH, "w") as fh:
            fh.write("*/abc * * * * root cd /opt && python3 collect.py\n")
        res = A.read_schedule()                       # ne doit pas lever
        self.assertEqual(res["interval_minutes"], 0)
        with open(A.CRON_PATH, "w") as fh:
            fh.write("collect.py tout seul\n")
        self.assertEqual(A.read_schedule()["interval_minutes"], 0)


# --------------------------------------------------------------------------- #
#  écriture atomique : droits, absence de résidu, concurrence                   #
# --------------------------------------------------------------------------- #
class TestSaveJson(BaseTmp):

    def test_0600_sous_data(self):
        p = os.path.join(self.data, "secrets.json")
        A.save_json(p, {"a": 1})
        self.assertEqual(mode_of(p), 0o600)
        self.assertEqual(lire_json(p), {"a": 1})

    def test_0644_hors_data(self):
        p = os.path.join(self.root, "public_fleet.json")
        A.save_json(p, {"a": 1})
        self.assertEqual(mode_of(p), 0o644)

    def test_mode_explicite_gagne(self):
        p = os.path.join(self.root, "servers.json")
        A.save_json(p, [], mode=0o600)
        self.assertEqual(mode_of(p), 0o600)

    def test_aucun_tmp_laisse(self):
        p = os.path.join(self.data, "x.json")
        A.save_json(p, {"a": 1})
        self.assertEqual([f for f in os.listdir(self.data) if f.startswith(".tmp-")], [])

    def test_tmp_nettoye_si_serialisation_impossible(self):
        p = os.path.join(self.data, "x.json")
        with self.assertRaises(TypeError):
            A.save_json(p, {"a": object()})
        self.assertEqual([f for f in os.listdir(self.data) if f.startswith(".tmp-")], [])
        self.assertFalse(os.path.exists(p))

    def test_droits_poses_avant_le_renommage(self):
        """Le fichier ne doit jamais exister, même brièvement, en 0644 sous data/."""
        p = os.path.join(self.data, "app_passwords.json")
        A.save_json(p, {"a": 1})
        A.save_json(p, {"a": 2})          # réécriture : les droits ne remontent pas
        self.assertEqual(mode_of(p), 0o600)

    def test_update_json_concurrent(self):
        p = os.path.join(self.data, "compteur.json")
        A.save_json(p, {"n": 0})

        def incrementer(courant):
            time.sleep(0.002)             # élargit la fenêtre de course
            return {"n": (courant or {}).get("n", 0) + 1}

        fils = [threading.Thread(target=A.update_json, args=(p, incrementer, {}))
                for _ in range(10)]
        for t in fils:
            t.start()
        for t in fils:
            t.join()
        self.assertEqual(lire_json(p), {"n": 10})

    def test_update_json_rend_l_objet_ecrit(self):
        p = os.path.join(self.data, "x.json")
        res = A.update_json(p, lambda c: {"v": (c or {}).get("v", 0) + 5}, {})
        self.assertEqual(res, {"v": 5})
        self.assertEqual(lire_json(p), {"v": 5})


class TestCredentialsMode(BaseTmp):
    """La faille d'origine : app_passwords.json repassait en 0644 après un oubli."""

    def test_wp_cred_forget_laisse_le_fichier_en_0600(self):
        A.wp_cred_save("exemple.fr", {"user": "bot", "password": "x", "url": "https://exemple.fr",
                                      "domain": "exemple.fr"})
        self.assertEqual(mode_of(A.WPAUTH_PATH), 0o600)
        self.assertTrue(A.wp_cred_forget("exemple.fr"))
        self.assertEqual(mode_of(A.WPAUTH_PATH), 0o600)
        self.assertEqual(lire_json(A.WPAUTH_PATH), {})

    def test_secrets_de_site_en_0600(self):
        A.set_site_secret("exemple.fr", "s" * 32)
        self.assertEqual(mode_of(A.SECRETS_PATH), 0o600)
        self.assertTrue(A.forget_site_secret("exemple.fr"))
        self.assertEqual(mode_of(A.SECRETS_PATH), 0o600)

    def test_politique_de_gel(self):
        self.assertEqual(A.set_frozen_plugin("exemple.fr", "revslider", True), ["revslider"])
        self.assertEqual(A.frozen_plugins("exemple.fr"), ["revslider"])
        self.assertEqual(A.set_frozen_plugin("exemple.fr", "revslider", False), [])
        self.assertEqual(A.frozen_plugins("exemple.fr"), [])


# --------------------------------------------------------------------------- #
#  validation des serveurs déclarés                                            #
# --------------------------------------------------------------------------- #
class TestValidateServer(unittest.TestCase):

    def base(self, **kw):
        s = {"name": "plesk", "host": "203.0.113.20", "port": 10022,
             "patterns": ["/var/www/vhosts/*/httpdocs"]}
        s.update(kw)
        return s

    def test_accepte_les_serveurs_de_l_exemple(self):
        exemples = lire_json(SERVERS_EXAMPLE)
        # les entrées sans « key » (la clé du 3e exemple n'existe pas sur cette machine)
        valides = [s for s in exemples if not s.get("key")]
        self.assertTrue(valides)
        for s in valides:
            ok, err = A.validate_server(s)
            self.assertTrue(ok, f"{s.get('name')} refusé : {err}")

    def test_refuse_un_user_qui_est_une_option_ssh(self):
        ok, err = A.validate_server(self.base(user="-oProxyCommand=x"))
        self.assertFalse(ok)
        self.assertIn("utilisateur", err)

    def test_refuse_un_host_qui_est_une_option_ssh(self):
        for mauvais in ("-x", "-oProxyCommand=id", "hote avec espace", "a;b"):
            ok, err = A.validate_server(self.base(host=mauvais))
            self.assertFalse(ok, mauvais)
            self.assertIn("hôte", err)

    def test_refuse_un_pattern_avec_injection_shell(self):
        for mauvais in ["/a'; id;'", '/a"; id', "/a$(id)", "/a|id", "../etc", "/a/../b", "relatif/x"]:
            ok, err = A.validate_server(self.base(patterns=[mauvais]))
            self.assertFalse(ok, mauvais)
            self.assertIn("chemin", err)

    def test_refuse_nom_port_cle_parallel(self):
        self.assertFalse(A.validate_server(self.base(name="Majuscule"))[0])
        self.assertFalse(A.validate_server(self.base(name="-x"))[0])
        self.assertFalse(A.validate_server(self.base(port=0))[0])
        self.assertFalse(A.validate_server(self.base(port=70000))[0])
        self.assertFalse(A.validate_server(self.base(port="abc"))[0])
        self.assertFalse(A.validate_server(self.base(key="/etc/passwd"))[0])
        self.assertFalse(A.validate_server(self.base(key="/root/.ssh/../../etc/passwd"))[0])
        self.assertFalse(A.validate_server(self.base(parallel=0))[0])
        self.assertFalse(A.validate_server(self.base(parallel=99))[0])
        self.assertFalse(A.validate_server(self.base(patterns=[]))[0])
        self.assertFalse(A.validate_server(self.base(patterns="/a"))[0])
        self.assertFalse(A.validate_server("pas un objet")[0])

    def test_accepte_les_champs_optionnels_corrects(self):
        self.assertTrue(A.validate_server(self.base(user="mon-login-ssh"))[0])
        self.assertTrue(A.validate_server(self.base(parallel=8, priority=3))[0])
        self.assertTrue(A.validate_server(self.base(host="2001:db8::1"))[0])

    def test_ssh_target_refuse_une_option(self):
        self.assertEqual(A.ssh_target({"host": "203.0.113.1"}), "root@203.0.113.1")
        with self.assertRaises(ValueError):
            A.ssh_target({"host": "203.0.113.1", "user": "-oProxyCommand=id"})
        with self.assertRaises(ValueError):
            A.ssh_target({"host": "-oProxyCommand=id"})

    def test_docroot_path(self):
        self.assertTrue(A.valid_path_pattern("/var/www/vhosts/*/httpdocs"))
        self.assertFalse(A.valid_path_pattern("/var/www/../etc"))
        self.assertFalse(A.valid_path_pattern("var/www"))
        self.assertFalse(A.valid_path_pattern("/a'; id;'"))


# --------------------------------------------------------------------------- #
#  run_remote_script : bornage de sortie et durcissement de la ligne ssh        #
# --------------------------------------------------------------------------- #
class TestRunRemoteScript(unittest.TestCase):

    def lancer(self, **kw):
        vus = {}

        def faux_run(cmd, **kwargs):
            vus["cmd"] = cmd

            class R:
                returncode = 0
                stdout = "x" * 9000
                stderr = ""
            return R()

        vrai = A.subprocess.run
        A.subprocess.run = faux_run
        try:
            rc, out = A.run_remote_script({"host": "h", "port": 22, "key": None}, "script", **kw)
        finally:
            A.subprocess.run = vrai
        return vus["cmd"], rc, out

    def test_tronque_par_defaut(self):
        _, rc, out = self.lancer()
        self.assertEqual(rc, 0)
        self.assertEqual(len(out), 6000)

    def test_max_out_none_ne_tronque_pas(self):
        _, _, out = self.lancer(max_out=None)
        self.assertEqual(len(out), 9000)

    def test_max_out_explicite(self):
        _, _, out = self.lancer(max_out=100)
        self.assertEqual(len(out), 100)

    def test_ligne_ssh_durcie(self):
        cmd, _, _ = self.lancer()
        self.assertIn("StrictHostKeyChecking=accept-new", cmd)
        # « -- » juste avant la cible : un host commençant par « - » ne peut plus
        # être lu comme une option par ssh
        self.assertEqual(cmd[cmd.index("--") + 1], "root@h")

    def test_signature_positionnelle_conservee(self):
        params = list(inspect.signature(A.run_remote_script).parameters)
        self.assertEqual(params[:3], ["srv", "script", "timeout"])
        self.assertEqual(params[3], "max_out")
        self.assertEqual(inspect.signature(A.run_remote_script).parameters["max_out"].default, 6000)


# --------------------------------------------------------------------------- #
#  redirections : le mot de passe d'application ne doit jamais suivre un 302    #
# --------------------------------------------------------------------------- #
class RedirServer(BaseHTTPRequestHandler):
    recu = []

    def do_GET(self):
        RedirServer.recu.append((self.path, self.headers.get("Authorization")))
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/cible")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        corps = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *a):
        pass


class TestNoRedirect(unittest.TestCase):

    def setUp(self):
        RedirServer.recu = []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), RedirServer)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)

    def req(self, chemin):
        return urllib.request.Request(
            f"http://127.0.0.1:{self.port}{chemin}",
            headers={"Authorization": "Basic " + base64.b64encode(b"admin:secret").decode()})

    def test_302_remonte_en_erreur_sans_second_appel(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            A._open_no_redirect(self.req("/redir"), timeout=5, ssrf_guard=False)
        self.assertEqual(ctx.exception.code, 302)
        ctx.exception.close()
        chemins = [c for c, _ in RedirServer.recu]
        self.assertEqual(chemins, ["/redir"])          # /cible jamais atteint

    def test_l_autorisation_ne_part_pas_vers_la_cible_de_redirection(self):
        try:
            A._open_no_redirect(self.req("/redir"), timeout=5, ssrf_guard=False)
        except urllib.error.HTTPError as e:
            e.close()
        vers_cible = [h for c, h in RedirServer.recu if c == "/cible"]
        self.assertEqual(vers_cible, [])

    def test_reponse_normale_lue_et_bornee(self):
        st, corps = A._open_no_redirect(self.req("/ok"), timeout=5, ssrf_guard=False)
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(corps.decode()), {"ok": True})
        st, corps = A._open_no_redirect(self.req("/ok"), timeout=5, ssrf_guard=False, max_bytes=4)
        self.assertEqual(len(corps), 4)

    def test_garde_ssrf_refuse_la_boucle_locale(self):
        with self.assertRaises(urllib.error.URLError):
            A._open_no_redirect(self.req("/ok"), timeout=5)   # ssrf_guard actif

    def test_les_cinq_appelants_passent_par_le_helper(self):
        """Aucune des fonctions portant un secret ne doit rappeler urlopen()."""
        for fn in (A.wp_verify, A._wp_req, A.wp_install_plugin, A.agent_post,
                   A.telegram_send_sync):
            src = inspect.getsource(fn)
            self.assertIn("_open_no_redirect", src, fn.__name__)
            self.assertNotIn("urlopen", src, fn.__name__)


# --------------------------------------------------------------------------- #
#  ingestion : HMAC + anti-rejeu                                               #
# --------------------------------------------------------------------------- #
class TestVerifyIngest(BaseTmp):

    SECRET = "S" * 40

    def setUp(self):
        super().setUp()
        A.set_site_secret("exemple.fr", self.SECRET)

    def entetes(self, raw, ts=None, secret=None):
        ts = str(int(time.time())) if ts is None else str(ts)
        sig = hmac.new((secret or self.SECRET).encode(), ts.encode() + b"." + raw,
                       hashlib.sha256).hexdigest()
        return {"X-Viz-Site": "exemple.fr", "X-Viz-Timestamp": ts, "X-Viz-Signature": sig}

    def test_signature_valide_acceptee_une_fois(self):
        raw = b'{"event":"activated_plugin"}'
        h = self.entetes(raw)
        site, err = A.verify_ingest(h, raw)
        self.assertIsNone(err)
        self.assertEqual(site, "exemple.fr")

    def test_rejeu_refuse(self):
        raw = b'{"event":"activated_plugin"}'
        h = self.entetes(raw)
        self.assertIsNone(A.verify_ingest(h, raw)[1])
        site, err = A.verify_ingest(h, raw)          # même signature, rejouée
        self.assertIsNone(site)
        self.assertEqual(err, "rejeu")

    def test_deux_evenements_distincts_passent(self):
        for n in range(3):
            raw = json.dumps({"event": "x", "n": n}).encode()
            self.assertIsNone(A.verify_ingest(self.entetes(raw), raw)[1], n)

    def test_signature_invalide_n_entre_pas_au_cache(self):
        raw = b"{}"
        h = self.entetes(raw, secret="mauvais" * 5)
        self.assertEqual(A.verify_ingest(h, raw)[1], "signature invalide")
        self.assertEqual(A.INGEST_SEEN, {})

    def test_horodatage_perime(self):
        raw = b"{}"
        h = self.entetes(raw, ts=int(time.time()) - A.INGEST_SKEW - 60)
        self.assertEqual(A.verify_ingest(h, raw)[1], "horodatage périmé")

    def test_purge_du_cache_anti_rejeu(self):
        A.ingest_replay("vieille", now=time.time() - A.INGEST_SKEW * 3)
        self.assertFalse(A.ingest_replay("neuve"))
        self.assertNotIn("vieille", A.INGEST_SEEN)


# --------------------------------------------------------------------------- #
#  appels alert() : la signature est alert(clé, règle, texte)                   #
# --------------------------------------------------------------------------- #
class TestAlertCalls(unittest.TestCase):

    def appels_alert(self, source):
        arbre = ast.parse(textwrap.dedent(source))
        return [n for n in ast.walk(arbre)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "alert"]

    def test_creation_du_compte_dedie_alerte_avec_trois_arguments(self):
        appels = self.appels_alert(inspect.getsource(A.wp_provision_bot))
        self.assertEqual(len(appels), 1)
        self.assertEqual(len(appels[0].args), 3,
                         "alert(clé, règle, texte) : la règle manquait")
        self.assertIsInstance(appels[0].args[1], ast.Constant)
        self.assertIn(appels[0].args[1].value, A.ALERT_DEFAULTS["rules"])

    def test_tous_les_appels_alert_du_module(self):
        with open(os.path.join(REPO, "actions_server.py")) as fh:
            arbre = ast.parse(fh.read())
        appels = [n for n in ast.walk(arbre)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                  and n.func.id == "alert"]
        self.assertTrue(appels)
        for c in appels:
            self.assertEqual(len(c.args), 3, f"alert() ligne {c.lineno}")

    def test_alert_reellement_envoyee(self):
        """Contrôle dynamique : la règle passée est bien acceptée par alert()."""
        envois = []
        vrais = (A.alerts_cfg, A.send_telegram, A.save_json, A.load_json)
        A.alerts_cfg = lambda: {"enabled": True, "rules": {"new_admin": True}}
        A.send_telegram = lambda texte: envois.append(texte)
        A.save_json = lambda *a, **k: None
        A.load_json = lambda p, d: {}
        try:
            self.assertTrue(A.alert("admin_dedie:exemple.fr", "new_admin", "coucou"))
        finally:
            (A.alerts_cfg, A.send_telegram, A.save_json, A.load_json) = vrais
        self.assertEqual(envois, ["coucou"])


# --------------------------------------------------------------------------- #
#  _body : plafond et longueurs aberrantes                                     #
# --------------------------------------------------------------------------- #
class FauxHandler(A.Handler):
    def __init__(self, entetes, corps=b""):   # pas de socket : on court-circuite
        self.headers = entetes
        self.rfile = io.BytesIO(corps)


class TestBody(unittest.TestCase):

    def test_corps_normal(self):
        corps = b'{"a": 1}'
        h = FauxHandler({"Content-Length": str(len(corps))}, corps)
        self.assertEqual(h._body(), {"a": 1})

    def test_corps_absent(self):
        self.assertEqual(FauxHandler({})._body(), {})

    def test_longueur_negative_refusee(self):
        with self.assertRaises(ValueError):
            FauxHandler({"Content-Length": "-1"})._body()

    def test_longueur_non_numerique_refusee(self):
        with self.assertRaises(ValueError):
            FauxHandler({"Content-Length": "beaucoup"})._body()

    def test_au_dela_de_1_mo_refuse(self):
        self.assertEqual(A.MAX_BODY_BYTES, 1024 * 1024)
        with self.assertRaises(ValueError):
            FauxHandler({"Content-Length": str(A.MAX_BODY_BYTES + 1)})._body()

    def test_exactement_1_mo_accepte(self):
        corps = b'{"a":"' + b"x" * (A.MAX_BODY_BYTES - 10) + b'"}'
        h = FauxHandler({"Content-Length": str(A.MAX_BODY_BYTES)}, corps[:A.MAX_BODY_BYTES])
        self.assertIsInstance(h._body(), dict)

    def test_json_invalide_leve_valueerror(self):
        with self.assertRaises(ValueError):
            FauxHandler({"Content-Length": "3"}, b"{[}")._body()


# --------------------------------------------------------------------------- #
#  garde de session globale sur do_GET                                          #
# --------------------------------------------------------------------------- #
class TestDoGetAuth(BaseTmp):

    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")

    def get(self, chemin, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", chemin, headers=({"Cookie": cookie} if cookie else {}))
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def test_sans_cookie_401_sur_mgmt_state(self):
        st, corps = self.get("/api/mgmt/state")
        self.assertEqual(st, 401)
        self.assertEqual(json.loads(corps), {"error": "non authentifié"})

    def test_sans_cookie_401_sur_les_autres_routes(self):
        for chemin in ("/api/actions/log", "/api/sec/certs", "/api/mgmt/sshkeys",
                       "/api/mgmt/agent.zip", "/api/mgmt/alerts", "/api/mgmt/schedule",
                       "/api/site/timeline?server=a&domain=b", "/api/inconnue"):
            self.assertEqual(self.get(chemin)[0], 401, chemin)

    def test_cookie_invalide_401(self):
        self.assertEqual(self.get("/api/actions/log", "dash_session=nimportequoi")[0], 401)

    def test_auth_check_sans_cookie_401(self):
        self.assertEqual(self.get("/api/auth/check")[0], 401)

    def test_auth_check_avec_cookie_200(self):
        self.assertEqual(self.get("/api/auth/check", self.cookie)[0], 200)

    def test_route_authentifiee_repond(self):
        st, corps = self.get("/api/actions/log", self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(corps), {"log": []})

    def test_wp_callback_reste_hors_garde(self):
        st, _ = self.get("/api/wp_callback?state=inexistant")
        self.assertEqual(st, 302)          # jeton refusé → redirection, pas 401

    def test_route_inconnue_authentifiee_donne_404(self):
        self.assertEqual(self.get("/api/inconnue", self.cookie)[0], 404)


# --------------------------------------------------------------------------- #
#  divers : lecture par la fin, code mort retiré, module importable             #
# --------------------------------------------------------------------------- #
class TestDivers(BaseTmp):

    def test_tail_lines(self):
        p = os.path.join(self.data, "gros.log")
        with open(p, "w") as fh:
            for i in range(5000):
                fh.write(f"ligne {i}\n")
        self.assertEqual(A.tail_lines(p, 3), ["ligne 4997", "ligne 4998", "ligne 4999"])
        self.assertEqual(len(A.tail_lines(p, 10000)), 5000)
        self.assertIsNone(A.tail_lines(os.path.join(self.data, "absent"), 5))
        self.assertEqual(A.tail_lines(p, 0), [])

    def test_read_log_du_plus_recent_au_plus_ancien(self):
        for i in range(3):
            A.append_log({"ts": f"2026-09-0{i + 1} 10:00:00", "domain": "x", "n": i})
        self.assertEqual([e["n"] for e in A.read_log(10)], [2, 1, 0])
        self.assertEqual([e["n"] for e in A.read_log(2)], [2, 1])

    def test_read_jsonl_tail_ignore_les_lignes_illisibles(self):
        p = os.path.join(self.data, "x.jsonl")
        with open(p, "w") as fh:
            fh.write('{"a":1}\ntronqu\n{"a":2}\n')
        self.assertEqual(A.read_jsonl_tail(p, 10), [{"a": 1}, {"a": 2}])

    def test_wporg_versions_rend_toujours_un_dict(self):
        res = A.wporg_versions("slug invalide !!")
        self.assertIsInstance(res, dict)
        self.assertEqual(set(res) >= {"current", "versions", "error"}, True)
        self.assertEqual(res["versions"], [])

    def test_kuma_sql_sans_docker(self):
        vrai = A.subprocess.run

        def boum(*a, **k):
            raise FileNotFoundError("docker")

        A.subprocess.run = boum
        try:
            rc, out = A.kuma_sql("SELECT 1;")
            self.assertNotEqual(rc, 0)
            self.assertIn("docker indisponible", out)
            self.assertEqual(A.kuma_state(), ([], []))     # ne lève pas
            self.assertEqual(A.kuma_monitor_urls(), [])
            A.kuma_restart()                              # ne lève pas
        finally:
            A.subprocess.run = vrai

    def test_kuma_create_refuse_les_libelles_douteux(self):
        rc, out = A.kuma_create("exemple.fr", "nom\x00malin", 1, "https://exemple.fr/", "http", "x")
        self.assertEqual(rc, 91)
        rc, _ = A.kuma_create("exemple.fr", "n" * 300, 1, "https://exemple.fr/", "http", "x")
        self.assertEqual(rc, 91)

    def test_plugin_rollback_refuse_un_point_avec_double_point(self):
        rc, msg = A.plugin_rollback("srv", "exemple.fr", "monplugin",
                                    arc_dir="/tmp/.wpdash-rollback/..")
        self.assertIn(rc, (91, 92))       # 92 si le site n'existe pas : contrôlé plus haut

    def test_bulk_accepte_dash_disconnect(self):
        self.assertIn("dash_disconnect", A.BULK_EXTRA_ACTIONS)
        self.assertIn("dash_connect", A.BULK_EXTRA_ACTIONS)
        self.assertIn("rescan", A.BULK_EXTRA_ACTIONS)
        src = inspect.getsource(A._bulk_worker)
        self.assertIn("dash_disconnect", src)

    def test_routes_mortes_retirees(self):
        with open(os.path.join(REPO, "actions_server.py")) as fh:
            src = fh.read()
        for mort in ('"/api/sec/diff"', '"/api/actions/list"', '"/api/auth/me"',
                     '"/api/mgmt/site_secret"'):
            self.assertNotIn(mort, src, mort)
        self.assertIn("def compute_diff", src)   # la fonction sert à evaluate_alerts

    def test_imports_en_tete(self):
        with open(os.path.join(REPO, "actions_server.py")) as fh:
            arbre = ast.parse(fh.read())
        noms = set()
        for n in arbre.body:                       # niveau module uniquement
            if isinstance(n, ast.Import):
                noms |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                noms |= {a.name for a in n.names}
        self.assertIn("functools", noms)
        self.assertIn("version_compare", noms)
        # plus aucun import à l'intérieur d'une fonction
        for n in ast.walk(arbre):
            if isinstance(n, (ast.Import, ast.ImportFrom)) and n not in arbre.body:
                self.fail(f"import hors du préambule, ligne {n.lineno}")

    def test_le_module_ne_demarre_pas_le_serveur_a_l_import(self):
        with open(os.path.join(REPO, "actions_server.py")) as fh:
            arbre = ast.parse(fh.read())
        gardes = [n for n in arbre.body if isinstance(n, ast.If)]
        self.assertTrue(gardes, "le lancement doit vivre sous if __name__ == '__main__'")
        dedans = "".join(ast.dump(g) for g in gardes)
        self.assertIn("serve_forever", dedans)
        for n in arbre.body:
            if not isinstance(n, ast.If):
                self.assertNotIn("serve_forever", ast.dump(n))


# --------------------------------------------------------------------------- #
#  VizProof : connexion d'un site (le jeton ne doit fuir NULLE PART)            #
# --------------------------------------------------------------------------- #
JETON = "vzp_LIVE_abcdef0123456789"


class TestVizConnect(BaseTmp):
    """`run_remote_script` est bouché : on inspecte le script envoyé au serveur."""

    def setUp(self):
        super().setUp()
        self.envoyes = []
        self.reponse = (0, '{"connected":true,"configured":true,"site_id":"a-fr",'
                           '"api_base_url":"https://vizproof.com","pages_count":3,'
                           '"plugin_version":"1.3.6"}')
        srv = {"name": "s1", "host": "203.0.113.1", "port": 22, "patterns": ["/x/*"]}
        site = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www"}
        for cible, valeur in (("run_remote_script", self._faux),
                              ("find_site", lambda s, d: (srv, site))):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _faux(self, srv, script, timeout=300, max_out=6000):
        self.envoyes.append(script)
        return self.reponse

    def connect(self, **kw):
        kw.setdefault("site_id", "a-fr")
        return A.viz_connect_run("s1", "a.fr", **kw)

    def log(self):
        if not os.path.exists(A.LOG):
            return []
        with open(A.LOG) as fh:
            return [json.loads(l) for l in fh]

    def log_brut(self):
        with open(A.LOG) as fh:
            return fh.read()

    # ---- le jeton : sur stdin, et seulement là ----
    def test_le_jeton_est_sur_stdin_pas_dans_la_commande(self):
        rc, _ = self.connect(token=JETON)
        self.assertEqual(rc, 0)
        script = self.envoyes[0]
        ligne_cmd = [l for l in script.splitlines() if "vizproof connect" in l][0]
        self.assertNotIn(JETON, ligne_cmd)          # rien sur la ligne de commande
        self.assertIn("--token-stdin", ligne_cmd)
        # le jeton est bien transmis, mais dans le document ici qui alimente stdin
        self.assertIn(JETON, script)
        self.assertRegex(script, r"<<'VIZTOK_[0-9a-f]{16}'\n" + re.escape(JETON))

    def test_le_jeton_n_est_pas_dans_le_journal(self):
        self.reponse = (0, "connecté (jeton " + JETON + " accepté)")
        rc, out = self.connect(token=JETON)
        self.assertNotIn(JETON, out)
        self.assertIn("***", out)
        entrees = [e for e in self.log() if e["action"] == "viz_connect"]
        self.assertEqual(len(entrees), 1)
        self.assertNotIn(JETON, json.dumps(entrees[0], ensure_ascii=False))

    def test_le_jeton_n_est_dans_aucune_ligne_du_journal(self):
        self.reponse = (1, "refusé : " + JETON)
        self.connect(token=JETON)
        self.assertNotIn(JETON, self.log_brut())

    def test_le_code_de_connexion_est_masque_aussi(self):
        self.reponse = (0, "code ABC-123 consommé")
        rc, out = self.connect(code="ABC-123")
        self.assertNotIn("ABC-123", out)
        self.assertNotIn("ABC-123", self.log_brut())

    def test_sans_jeton_pas_de_token_stdin(self):
        self.connect(code="ABC-123")
        self.assertNotIn("--token-stdin", self.envoyes[0])
        self.assertIn("--code='ABC-123'", self.envoyes[0])

    # ---- traduction du plugin trop ancien ----
    def test_not_a_registered_subcommand_donne_rc_99(self):
        self.reponse = (1, "Error: 'connect' is not a registered subcommand of 'vizproof'.")
        rc, out = self.connect(token=JETON)
        self.assertEqual(rc, A.VIZ_OLD_RC)
        self.assertEqual(rc, 99)
        self.assertEqual(out, A.VIZ_OLD_MSG)
        self.assertIn("1.3.6", out)

    def test_un_autre_echec_garde_son_rc(self):
        self.reponse = (7, "API injoignable")
        rc, out = self.connect(token=JETON)
        self.assertEqual(rc, 7)
        self.assertEqual(out, "API injoignable")

    def test_rc_99_est_journalise(self):
        self.reponse = (1, "Error: 'connect' is not a registered subcommand.")
        self.connect(token=JETON)
        e = [x for x in self.log() if x["action"] == "viz_connect"][0]
        self.assertEqual(e["rc"], 99)

    # ---- construction de la commande ----
    def test_options_facultatives_absentes_par_defaut(self):
        self.connect(token=JETON)
        cmd = [l for l in self.envoyes[0].splitlines() if "vizproof connect" in l][0]
        self.assertNotIn("--api-base", cmd)
        self.assertNotIn("--scope", cmd)
        self.assertIn("--site-id='a-fr'", cmd)
        self.assertIn("--format=json", cmd)

    def test_options_transmises_quotees(self):
        self.connect(token=JETON, api_base="https://viz.example.com", scope="selected_pages")
        cmd = [l for l in self.envoyes[0].splitlines() if "vizproof connect" in l][0]
        self.assertIn("--api-base='https://viz.example.com'", cmd)
        self.assertIn("--scope='selected_pages'", cmd)

    def test_site_inconnu_sans_ssh(self):
        with mock.patch.object(A, "find_site", lambda s, d: (None, None)):
            rc, out = self.connect(token=JETON)
        self.assertEqual(rc, 92)
        self.assertEqual(self.envoyes, [])


class TestVizEntrees(unittest.TestCase):
    """L'identifiant part dans une commande distante : le jeu est fermé."""

    def test_site_id_acceptes(self):
        for v in ("a", "elwave-fr", "SITE_42", "a" * 80):
            self.assertTrue(A.VIZ_SITE_ID_RE.match(v), v)

    def test_site_id_refuses(self):
        for v in ("", "a" * 81, "a b", "a'; rm -rf /", "a.fr", "a/b", "a$(id)", "a\nb", "é"):
            self.assertFalse(A.VIZ_SITE_ID_RE.match(v), repr(v))

    def test_jeton_sur_une_seule_ligne(self):
        self.assertTrue(A.VIZ_TOKEN_RE.match("vzp_LIVE_abc.def-123:456/=+~"))
        for v in ("court", "a" * 513, "avec espace", "avec\nsaut", "avec'quote", "`id`"):
            self.assertFalse(A.VIZ_TOKEN_RE.match(v), repr(v))

    def test_portees(self):
        self.assertEqual(A.VIZ_SCOPES, ("site", "selected_pages"))


class TestVizConnectRoute(BaseTmp):
    """Validation d'entrée de POST /api/actions/viz_connect, sans toucher au réseau."""

    BON = {"server": "s1", "domain": "a.fr", "site_id": "a-fr", "token": JETON}

    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")
        self.appels = []
        p = mock.patch.object(A, "viz_connect_run", self._faux)
        p.start()
        self.addCleanup(p.stop)

    def _faux(self, *a, **kw):
        self.appels.append((a, kw))
        return 0, "ok"

    def post(self, chemin, corps):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("POST", chemin, body=json.dumps(corps).encode(),
                      headers={"Cookie": self.cookie, "X-Dash": "1",
                               "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def test_site_id_invalide_refuse_avant_tout_ssh(self):
        # « » ne figure plus ici : un identifiant vide déclenche désormais la
        # résolution par URL (cf. TestVizConnectSansSiteId).
        for mauvais in ("a b", "a'; id", "a" * 81, "a.fr"):
            st, j = self.post("/api/actions/viz_connect", dict(self.BON, site_id=mauvais))
            self.assertEqual(st, 400, mauvais)
            self.assertIn("identifiant", j["error"])
        self.assertEqual(self.appels, [])

    def test_cible_invalide_refusee(self):
        st, _ = self.post("/api/actions/viz_connect", dict(self.BON, server="../x"))
        self.assertEqual(st, 400)
        st, _ = self.post("/api/actions/viz_connect", dict(self.BON, domain="a b"))
        self.assertEqual(st, 400)
        self.assertEqual(self.appels, [])

    def test_ni_jeton_ni_code(self):
        corps = dict(self.BON)
        corps.pop("token")
        st, j = self.post("/api/actions/viz_connect", corps)
        self.assertEqual(st, 400)
        self.assertIn("requis", j["error"])

    def test_jeton_et_code_exclusifs(self):
        st, j = self.post("/api/actions/viz_connect", dict(self.BON, code="ABC-123"))
        self.assertEqual(st, 400)
        self.assertIn("exclusifs", j["error"])

    def test_jeton_multiligne_refuse(self):
        st, _ = self.post("/api/actions/viz_connect", dict(self.BON, token="a\nb"))
        self.assertEqual(st, 400)
        self.assertEqual(self.appels, [])

    def test_portee_inconnue_refusee(self):
        st, _ = self.post("/api/actions/viz_connect", dict(self.BON, scope="tout"))
        self.assertEqual(st, 400)

    def test_api_base_non_publique_refusee(self):
        """La garde SSRF existante s'applique : ni boucle locale, ni http://."""
        for u in ("https://127.0.0.1/api", "http://vizproof.com", "ftp://x/y"):
            st, _ = self.post("/api/actions/viz_connect", dict(self.BON, api_base=u))
            self.assertEqual(st, 400, u)
            self.assertEqual(self.appels, [])

    def test_appel_nominal_transmet_tout(self):
        with mock.patch.object(A, "logged_action", lambda *a, **k: (0, "")):
            st, j = self.post("/api/actions/viz_connect", dict(self.BON, scope="site"))
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        a = self.appels[0][0]
        self.assertEqual(a, ("s1", "a.fr", "a-fr", None, "site", JETON, ""))

    def test_le_jeton_ne_revient_pas_dans_la_reponse(self):
        with mock.patch.object(A, "logged_action", lambda *a, **k: (0, "")):
            _st, j = self.post("/api/actions/viz_connect", self.BON)
        self.assertNotIn(JETON, json.dumps(j))

    def test_rc_99_repond_200_avec_ok_false(self):
        with mock.patch.object(A, "viz_connect_run",
                               lambda *a, **k: (A.VIZ_OLD_RC, A.VIZ_OLD_MSG)):
            st, j = self.post("/api/actions/viz_connect", self.BON)
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertEqual(j["rc"], 99)

    def test_disconnect_valide_sa_cible(self):
        st, _ = self.post("/api/actions/viz_disconnect", {"server": "s1", "domain": "a b"})
        self.assertEqual(st, 400)

    def test_disconnect_passe_par_la_liste_blanche(self):
        vus = []
        with mock.patch.object(A, "logged_action",
                               lambda s, d, act, arg, **k: (vus.append(act), (0, "ok"))[1]):
            st, _j = self.post("/api/actions/viz_disconnect",
                               {"server": "s1", "domain": "a.fr"})
        self.assertEqual(st, 200)
        self.assertEqual(vus[0], "viz_disconnect")
        self.assertIn("viz_disconnect", A.ACTIONS)

    def test_viz_connect_n_est_pas_dans_la_liste_blanche_generique(self):
        """Il ne doit PAS être atteignable par /api/actions/run : le jeton y
        passerait en argument, donc dans la ligne de commande et le journal."""
        self.assertNotIn("viz_connect", A.ACTIONS)


# --------------------------------------------------------------------------- #
#  Réglages persistants + décision sur anomalie visuelle                        #
# --------------------------------------------------------------------------- #
class TestSettings(BaseTmp):

    def setUp(self):
        super().setUp()
        self._sp = A.SETTINGS_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        self.addCleanup(lambda: setattr(A, "SETTINGS_PATH", self._sp))

    def test_defaut_avertir_sans_annuler(self):
        self.assertFalse(A.SETTINGS_DEFAULTS["viz_anomaly_rollback"])
        self.assertIs(A.settings_cfg()["viz_anomaly_rollback"], False)
        self.assertEqual(A.settings_cfg(), dict(A.SETTINGS_DEFAULTS))

    def test_ecriture_et_relecture(self):
        self.assertTrue(A.settings_write({"viz_anomaly_rollback": True})["viz_anomaly_rollback"])
        self.assertTrue(A.settings_cfg()["viz_anomaly_rollback"])
        self.assertTrue(lire_json(A.SETTINGS_PATH)["viz_anomaly_rollback"])
        A.settings_write({"viz_anomaly_rollback": False})
        self.assertFalse(A.settings_cfg()["viz_anomaly_rollback"])

    def test_cle_inconnue_ignoree(self):
        A.settings_write({"viz_anomaly_rollback": True, "rm_rf": "/"})
        self.assertNotIn("rm_rf", lire_json(A.SETTINGS_PATH))

    def test_valeur_d_un_autre_type_ramenee_au_bon_type(self):
        A.settings_write({"viz_anomaly_rollback": "oui"})
        self.assertIs(A.settings_cfg()["viz_anomaly_rollback"], True)
        A.settings_write({"viz_anomaly_rollback": 0})
        self.assertIs(A.settings_cfg()["viz_anomaly_rollback"], False)

    def test_fichier_illisible_rend_les_defauts(self):
        with open(A.SETTINGS_PATH, "w") as fh:
            fh.write("{cassé")
        self.assertEqual(A.settings_cfg(), dict(A.SETTINGS_DEFAULTS))

    def test_fichier_en_0600(self):
        A.settings_write({"viz_anomaly_rollback": True})
        self.assertEqual(mode_of(A.SETTINGS_PATH), 0o600)


# --------------------------------------------------------------------------- #
#  VizProof : jeton de compte enregistré + résolution du site par l'URL         #
#                                                                              #
#  Tout le réseau est bouché au niveau de `_open_no_redirect` : on inspecte     #
#  donc l'URL, la méthode, l'en-tête Authorization et le corps réellement       #
#  construits par viz_api_call().                                              #
# --------------------------------------------------------------------------- #
VRT = "vrt_abcdefghij0123456789"


def page_sites(sites, total=None):
    """Réponse paginée de GET /api/sites, telle que docs/API.md la décrit."""
    return {"data": sites, "total": len(sites) if total is None else total,
            "page": 1, "limit": A.VIZ_PAGE_LIMIT}


class VizApiBase(BaseTmp):
    """Transport HTTP et garde DNS bouchés ; data/settings.json jetable."""

    def setUp(self):
        super().setUp()
        self._sp, self._fp = A.SETTINGS_PATH, A.FLEET_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        A.FLEET_PATH = os.path.join(self.data, "fleet.json")
        self.addCleanup(lambda: (setattr(A, "SETTINGS_PATH", self._sp),
                                 setattr(A, "FLEET_PATH", self._fp)))
        self.appels = []        # requêtes sortantes observées
        self.reponses = []      # file de (statut, objet JSON) ou d'exceptions
        for cible, valeur in (("_open_no_redirect", self._transport),
                              ("validate_public_url", self._url_ok)):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def _url_ok(url):
        """Pas de DNS dans les tests : l'URL est acceptée telle quelle."""
        return urllib.parse.urlsplit(str(url or "")), None

    def _transport(self, req, timeout=20, max_bytes=None, ssrf_guard=True):
        self.appels.append({"method": req.get_method(), "url": req.full_url,
                            "auth": req.get_header("Authorization"),
                            "body": json.loads(req.data.decode()) if req.data else None,
                            "timeout": timeout})
        if not self.reponses:
            raise AssertionError("appel HTTP non prévu : " + req.full_url)
        r = self.reponses.pop(0)
        if isinstance(r, Exception):
            raise r
        st, obj = r
        return st, json.dumps(obj).encode()

    @staticmethod
    def http_error(code, corps=b'{"error":"nope"}'):
        return urllib.error.HTTPError("https://vizproof.com/api/sites", code,
                                      "erreur", {}, io.BytesIO(corps))

    def poser_fleet(self, domain="elwave.fr", siteurl="https://www.elwave.fr"):
        A.save_json(A.FLEET_PATH, {"servers": [{"name": "s1", "sites": [
            {"domain": domain, "siteurl": siteurl, "path": "/var/www/x", "owner": "www"}]}]})


class TestVizResolveSite(VizApiBase):

    ELWAVE = {"id": "clx_elwave", "name": "Elwave", "domains": '["elwave.fr","www.elwave.fr"]'}
    AUTRE = {"id": "clx_autre", "name": "Autre", "domains": '["autre.fr"]'}

    def test_correspondance_exacte(self):
        self.reponses = [(200, page_sites([self.AUTRE, self.ELWAVE]))]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertTrue(r["ok"])
        self.assertEqual(r["site_id"], "clx_elwave")
        self.assertEqual(r["name"], "Elwave")
        self.assertEqual(r["matched_domain"], "elwave.fr")
        self.assertFalse(r["created"])
        self.assertFalse(r["ambiguous"])

    def test_la_requete_est_un_get_bearer_pagine(self):
        self.reponses = [(200, page_sites([self.ELWAVE]))]
        A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        a = self.appels[0]
        self.assertEqual(a["method"], "GET")
        self.assertEqual(a["auth"], "Bearer " + VRT)
        self.assertEqual(a["url"], f"https://vizproof.com/api/sites?limit={A.VIZ_PAGE_LIMIT}&page=1")
        self.assertEqual(a["timeout"], 20)
        self.assertIsNone(a["body"])

    def test_www_du_site_contre_domaine_nu(self):
        self.reponses = [(200, page_sites([{"id": "s2", "name": "E", "domains": '["elwave.fr"]'}]))]
        r = A.viz_resolve_site("elwave.fr", "https://www.elwave.fr/blog/", VRT)
        self.assertEqual(r["site_id"], "s2")
        self.assertEqual(r["matched_domain"], "elwave.fr")

    def test_domaine_nu_contre_www_declare(self):
        self.reponses = [(200, page_sites([{"id": "s3", "name": "E", "domains": '["www.elwave.fr"]'}]))]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertEqual(r["site_id"], "s3")
        self.assertEqual(r["matched_domain"], "www.elwave.fr")

    def test_domains_null_ou_illisible_n_explose_pas(self):
        lot = [{"id": "a", "name": "Neuf", "domains": None},
               {"id": "b", "name": "Cassé", "domains": "{pas du json"},
               {"id": "c", "name": "Nombre", "domains": 12},
               "pas un objet",
               dict(self.ELWAVE)]
        self.reponses = [(200, page_sites(lot))]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertEqual(r["site_id"], "clx_elwave")

    def test_aucune_correspondance_cree_le_site(self):
        self.reponses = [(200, page_sites([self.AUTRE])),
                         (201, {"id": "clx_neuf", "name": "elwave.fr", "domains": None})]
        r = A.viz_resolve_site("elwave.fr", "https://www.elwave.fr/", VRT)
        self.assertTrue(r["ok"])
        self.assertTrue(r["created"])
        self.assertEqual(r["site_id"], "clx_neuf")
        self.assertEqual(r["name"], "elwave.fr")
        self.assertEqual(r["matched_domain"], "")
        creation = self.appels[1]
        self.assertEqual(creation["method"], "POST")
        self.assertEqual(creation["url"], "https://vizproof.com/api/sites")
        self.assertEqual(creation["body"], {"name": "elwave.fr"})   # l'hôte, sans www
        self.assertEqual(creation["auth"], "Bearer " + VRT)

    def test_pagination_sur_deux_pages(self):
        pleine = [{"id": f"s{i}", "name": str(i), "domains": '["x%d.fr"]' % i}
                  for i in range(A.VIZ_PAGE_LIMIT)]
        self.reponses = [(200, page_sites(pleine, total=A.VIZ_PAGE_LIMIT + 1)),
                         (200, page_sites([self.ELWAVE], total=A.VIZ_PAGE_LIMIT + 1))]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertEqual(r["site_id"], "clx_elwave")
        self.assertEqual(len(self.appels), 2)
        self.assertIn("page=2", self.appels[1]["url"])

    def test_plafond_a_500_sites_puis_creation(self):
        pleine = [{"id": f"s{i}", "name": str(i), "domains": '["x%d.fr"]' % i}
                  for i in range(A.VIZ_PAGE_LIMIT)]
        pages = A.VIZ_SITES_MAX // A.VIZ_PAGE_LIMIT
        self.reponses = [(200, page_sites(pleine, total=10000)) for _ in range(pages)]
        self.reponses.append((201, {"id": "clx_neuf", "name": "elwave.fr"}))
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertTrue(r["created"])
        self.assertEqual(len(self.appels), pages + 1)   # pas de 6e page

    def test_ambiguite_prend_le_premier_et_le_signale(self):
        self.reponses = [(200, page_sites([
            {"id": "un", "name": "Elwave prod", "domains": '["elwave.fr"]'},
            {"id": "deux", "name": "Elwave bis", "domains": '["www.elwave.fr"]'}]))]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertEqual(r["site_id"], "un")
        self.assertTrue(r["ambiguous"])

    def test_deux_domaines_du_meme_site_ne_sont_pas_une_ambiguite(self):
        self.reponses = [(200, page_sites([self.ELWAVE]))]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertFalse(r["ambiguous"])

    def test_sans_jeton_message_explicite_et_zero_appel(self):
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", "")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], A.VIZ_NO_TOKEN_MSG)
        self.assertEqual(self.appels, [])

    def test_siteurl_aberrant_replie_sur_le_domaine(self):
        """Un siteurl « javascript:… » (site compromis) ne devient pas un nom de site."""
        self.reponses = [(200, page_sites([])), (201, {"id": "n", "name": "elwave.fr"})]
        r = A.viz_resolve_site("elwave.fr", "javascript:alert(1)", VRT)
        self.assertEqual(r["host"], "elwave.fr")
        self.assertEqual(self.appels[1]["body"], {"name": "elwave.fr"})

    def test_erreur_401_remonte_sans_creer(self):
        self.reponses = [self.http_error(401)]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertFalse(r["ok"])
        self.assertIn("401", r["error"])
        self.assertEqual(len(self.appels), 1)          # aucune création tentée

    def test_redirection_refusee(self):
        self.reponses = [self.http_error(302)]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertIn("redirection refusée", r["error"])

    def test_le_jeton_ne_fuit_pas_dans_le_message_d_erreur(self):
        self.reponses = [self.http_error(400, ('{"error":"jeton ' + VRT + ' invalide"}').encode())]
        r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertNotIn(VRT, json.dumps(r, ensure_ascii=False))

    def test_base_api_surchargee(self):
        self.reponses = [(200, page_sites([self.ELWAVE]))]
        A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT, "https://viz.example.com/")
        self.assertTrue(self.appels[0]["url"].startswith("https://viz.example.com/api/sites?"))

    def test_base_api_du_reglage(self):
        A.settings_write({"vizproof_api_base": "https://viz.example.org"})
        self.reponses = [(200, page_sites([self.ELWAVE]))]
        A.viz_resolve_site("elwave.fr", "https://elwave.fr", VRT)
        self.assertTrue(self.appels[0]["url"].startswith("https://viz.example.org/api/sites?"))


class VizRouteBase(VizApiBase):
    """Serveur HTTP local + session valide, pour les routes protégées."""

    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")

    def _appel(self, methode, chemin, corps=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            entetes = {"Cookie": self.cookie, "X-Dash": "1", "Content-Type": "application/json"}
            c.request(methode, chemin,
                      body=json.dumps(corps).encode() if corps is not None else None,
                      headers=entetes)
            r = c.getresponse()
            brut = r.read()
            return r.status, brut.decode("utf-8"), json.loads(brut or b"{}")
        finally:
            c.close()

    def post(self, chemin, corps):
        return self._appel("POST", chemin, corps)

    def get(self, chemin):
        return self._appel("GET", chemin)

    def log_brut(self):
        if not os.path.exists(A.LOG):
            return ""
        with open(A.LOG) as fh:
            return fh.read()


class TestVizTokenReglages(VizRouteBase):
    """Le jeton s'enregistre, ne ressort jamais, et s'efface sur demande."""

    def enregistrer(self, jeton=VRT, **extra):
        return self.post("/api/mgmt/settings", dict({"settings": {"vizproof_token": jeton}}, **extra))

    def test_enregistre_puis_temoin_seulement(self):
        st, brut, j = self.enregistrer()
        self.assertEqual(st, 200)
        self.assertTrue(j["settings"]["vizproof_token_set"])
        self.assertEqual(j["settings"]["vizproof_token_tail"], VRT[-4:])
        self.assertNotIn("vizproof_token", j["settings"])
        self.assertNotIn(VRT, brut)

    def test_get_ne_renvoie_jamais_le_jeton(self):
        self.enregistrer()
        st, brut, j = self.get("/api/mgmt/settings")
        self.assertEqual(st, 200)
        self.assertNotIn(VRT, brut)
        self.assertTrue(j["settings"]["vizproof_token_set"])
        self.assertEqual(j["settings"]["vizproof_token_tail"], VRT[-4:])
        self.assertNotIn("vizproof_token", j["settings"])
        self.assertNotIn("vizproof_token", j["defaults"])

    def test_stocke_en_clair_dans_un_fichier_0600(self):
        self.enregistrer()
        self.assertEqual(lire_json(A.SETTINGS_PATH)["vizproof_token"], VRT)
        self.assertEqual(mode_of(A.SETTINGS_PATH), 0o600)
        self.assertEqual(A.viz_token_stored(), VRT)

    def test_le_jeton_n_atterrit_pas_dans_actions_log(self):
        self.enregistrer()
        self.assertNotIn(VRT, self.log_brut())

    def test_champ_vide_conserve_le_jeton(self):
        self.enregistrer()
        st, _b, j = self.post("/api/mgmt/settings", {"settings": {"vizproof_token": ""}})
        self.assertEqual(st, 200)
        self.assertTrue(j["settings"]["vizproof_token_set"])
        self.assertEqual(A.viz_token_stored(), VRT)

    def test_champ_absent_conserve_le_jeton(self):
        self.enregistrer()
        self.post("/api/mgmt/settings", {"settings": {"viz_anomaly_rollback": True}})
        self.assertEqual(A.viz_token_stored(), VRT)
        self.assertTrue(A.settings_cfg()["viz_anomaly_rollback"])

    def test_effacement_explicite(self):
        self.enregistrer()
        st, _b, j = self.post("/api/mgmt/settings",
                              {"settings": {"vizproof_token": ""}, "vizproof_token_clear": True})
        self.assertEqual(st, 200)
        self.assertFalse(j["settings"]["vizproof_token_set"])
        self.assertEqual(j["settings"]["vizproof_token_tail"], "")
        self.assertEqual(A.viz_token_stored(), "")

    def test_effacement_depuis_le_bloc_settings(self):
        self.enregistrer()
        self.post("/api/mgmt/settings",
                  {"settings": {"vizproof_token": "", "vizproof_token_clear": True}})
        self.assertEqual(A.viz_token_stored(), "")

    def test_format_refuse(self):
        for mauvais in ("abc", "vrt_court", "vrt_" + "a" * 201, "vrt_avec espace",
                        "Bearer vrt_abcdefghij", "vrt_abcdefghij\nsuite"):
            st, _b, j = self.enregistrer(mauvais)
            self.assertEqual(st, 400, mauvais)
            self.assertIn("jeton VizProof invalide", j["error"])
        self.assertEqual(A.viz_token_stored(), "")

    def test_format_accepte(self):
        for bon in ("vrt_abcdefgh", "vrt_" + "a" * 200, "vrt_A-b_c0123456789"):
            st, _b, _j = self.enregistrer(bon)
            self.assertEqual(st, 200, bon)
            self.assertEqual(A.viz_token_stored(), bon)

    def test_base_api_https_obligatoire(self):
        st, _b, j = self.post("/api/mgmt/settings",
                              {"settings": {"vizproof_api_base": "http://vizproof.com"}})
        self.assertEqual(st, 400)
        self.assertIn("https", j["error"])

    def test_base_api_enregistree_sans_slash_final(self):
        st, _b, j = self.post("/api/mgmt/settings",
                              {"settings": {"vizproof_api_base": "https://viz.example.com/"}})
        self.assertEqual(st, 200)
        self.assertEqual(j["settings"]["vizproof_api_base"], "https://viz.example.com")
        self.assertEqual(A.viz_api_base(), "https://viz.example.com")

    def test_base_api_vide_revient_au_defaut(self):
        A.settings_write({"vizproof_api_base": "https://viz.example.com"})
        self.post("/api/mgmt/settings", {"settings": {"vizproof_api_base": ""}})
        self.assertEqual(A.viz_api_base(), A.VIZ_API_BASE_DEFAULT)


class TestVizProofTestRoute(VizRouteBase):
    """POST /api/mgmt/vizproof/test → {ok, total, error}."""

    def test_ok_rend_le_nombre_de_sites(self):
        A.settings_write({"vizproof_token": VRT})
        self.reponses = [(200, page_sites([{"id": "a", "name": "A"}], total=42))]
        st, brut, j = self.post("/api/mgmt/vizproof/test", {})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["total"], 42)
        self.assertIsNone(j["error"])
        self.assertNotIn(VRT, brut)
        self.assertEqual(self.appels[0]["url"], "https://vizproof.com/api/sites?limit=1")
        self.assertEqual(self.appels[0]["auth"], "Bearer " + VRT)

    def test_401_rend_ok_false_sans_500(self):
        A.settings_write({"vizproof_token": VRT})
        self.reponses = [self.http_error(401)]
        st, brut, j = self.post("/api/mgmt/vizproof/test", {})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertIsNone(j["total"])
        self.assertIn("401", j["error"])
        self.assertNotIn(VRT, brut)

    def test_sans_jeton_enregistre(self):
        st, _b, j = self.post("/api/mgmt/vizproof/test", {})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], A.VIZ_NO_TOKEN_MSG)
        self.assertEqual(self.appels, [])

    def test_le_corps_ne_peut_pas_imposer_un_jeton(self):
        """Aucun jeton n'est accepté ici : seul celui des Réglages est testé."""
        st, _b, j = self.post("/api/mgmt/vizproof/test", {"vizproof_token": VRT, "token": VRT})
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], A.VIZ_NO_TOKEN_MSG)


class TestVizResolveRoute(VizRouteBase):

    def test_apercu_sans_rien_ecrire_cote_wordpress(self):
        A.settings_write({"vizproof_token": VRT})
        self.poser_fleet()
        self.reponses = [(200, page_sites([{"id": "clx1", "name": "Elwave",
                                            "domains": '["elwave.fr"]'}]))]
        with mock.patch.object(A, "run_remote_script",
                               lambda *a, **k: self.fail("aucun ssh attendu")):
            st, brut, j = self.post("/api/actions/viz_resolve",
                                    {"server": "s1", "domain": "elwave.fr"})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["site_id"], "clx1")
        self.assertEqual(j["name"], "Elwave")
        self.assertFalse(j["created"])
        self.assertEqual(j["matched_domain"], "elwave.fr")
        self.assertNotIn(VRT, brut)

    def test_sans_jeton_message_dedie(self):
        st, _b, j = self.post("/api/actions/viz_resolve", {"server": "s1", "domain": "elwave.fr"})
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], A.VIZ_NO_TOKEN_MSG)

    def test_cible_invalide(self):
        A.settings_write({"vizproof_token": VRT})
        for corps in ({"server": "../x", "domain": "a.fr"}, {"server": "s1", "domain": "a b"}):
            st, _b, _j = self.post("/api/actions/viz_resolve", corps)
            self.assertEqual(st, 400)
        self.assertEqual(self.appels, [])

    def test_base_api_non_publique_refusee(self):
        A.settings_write({"vizproof_token": VRT})
        with mock.patch.object(A, "validate_public_url",
                               lambda u: (None, "adresse non autorisée")):
            st, _b, _j = self.post("/api/actions/viz_resolve",
                                   {"server": "s1", "domain": "a.fr",
                                    "api_base": "https://127.0.0.1"})
        self.assertEqual(st, 400)


class TestVizConnectSansSiteId(VizRouteBase):
    """viz_connect résout le site par URL puis passe l'identifiant trouvé."""

    def setUp(self):
        super().setUp()
        self.scripts = []
        self.reponse_ssh = (0, '{"connected":true,"site_id":"clx1"}')
        srv = {"name": "s1", "host": "203.0.113.1", "port": 22, "patterns": ["/x/*"]}
        site = {"domain": "elwave.fr", "path": "/var/www/x", "owner": "www"}
        for cible, valeur in (("run_remote_script", self._ssh),
                              ("find_site", lambda s, d: (srv, site)),
                              ("logged_action", lambda *a, **k: (0, ""))):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)
        A.settings_write({"vizproof_token": VRT})
        self.poser_fleet()

    def _ssh(self, srv, script, timeout=300, max_out=6000):
        self.scripts.append(script)
        return self.reponse_ssh

    def connect(self, **corps):
        return self.post("/api/actions/viz_connect",
                         dict({"server": "s1", "domain": "elwave.fr"}, **corps))

    def test_site_existant_resolu_puis_transmis(self):
        self.reponses = [(200, page_sites([{"id": "clx1", "name": "Elwave",
                                            "domains": '["www.elwave.fr"]'}]))]
        st, brut, j = self.connect()
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["site_id"], "clx1")
        self.assertFalse(j["site_created"])
        self.assertEqual(j["site_name"], "Elwave")
        cmd = [l for l in self.scripts[0].splitlines() if "vizproof connect" in l][0]
        self.assertIn("--site-id='clx1'", cmd)
        self.assertIn("--token-stdin", cmd)
        self.assertNotIn(VRT, cmd)                      # jamais sur la ligne de commande
        self.assertIn(VRT, self.scripts[0])             # mais bien sur stdin (document ici)
        self.assertNotIn(VRT, brut)                     # ni dans la réponse

    def test_site_cree_quand_aucun_ne_correspond(self):
        self.reponses = [(200, page_sites([])),
                         (201, {"id": "clx_neuf", "name": "elwave.fr"})]
        _st, _b, j = self.connect()
        self.assertTrue(j["ok"])
        self.assertTrue(j["site_created"])
        self.assertEqual(j["site_id"], "clx_neuf")
        entree = [e for e in json.loads("[" + ",".join(self.log_brut().splitlines()) + "]")
                  if e["action"] == "viz_connect"][0]
        self.assertEqual(entree["arg"], "clx_neuf")
        self.assertTrue(entree["site_created"])
        self.assertNotIn(VRT, self.log_brut())

    def test_echec_de_resolution_ne_touche_pas_au_site(self):
        self.reponses = [self.http_error(401)]
        st, _b, j = self.connect()
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertEqual(j["rc"], A.VIZ_RESOLVE_RC)
        self.assertIn("401", j["error"])
        self.assertEqual(self.scripts, [])              # aucun ssh

    def test_site_id_fourni_court_circuite_la_resolution(self):
        _st, _b, j = self.connect(site_id="impose")
        self.assertTrue(j["ok"])
        self.assertEqual(j["site_id"], "impose")
        self.assertEqual(self.appels, [])               # aucun appel à l'API VizProof
        self.assertIn("--site-id='impose'", self.scripts[0])

    def test_jeton_ponctuel_du_corps_prime_pour_wp_cli(self):
        self.reponses = [(200, page_sites([{"id": "clx1", "name": "E",
                                            "domains": '["elwave.fr"]'}]))]
        _st, brut, j = self.connect(token=JETON)
        self.assertTrue(j["ok"])
        self.assertIn(JETON, self.scripts[0])           # c'est lui qui part sur stdin
        self.assertEqual(self.appels[0]["auth"], "Bearer " + VRT)  # l'API garde celui des Réglages
        self.assertNotIn(JETON, brut)
        self.assertNotIn(VRT, brut)

    def test_code_de_connexion_sans_site_id(self):
        self.reponses = [(200, page_sites([{"id": "clx1", "name": "E",
                                            "domains": '["elwave.fr"]'}]))]
        _st, _b, j = self.connect(code="ABC-123")
        self.assertTrue(j["ok"])
        self.assertIn("--code='ABC-123'", self.scripts[0])
        self.assertNotIn("--token-stdin", self.scripts[0])

    def test_sans_jeton_enregistre_ni_corps_refus(self):
        A.settings_write({"vizproof_token": ""})
        st, _b, j = self.connect()
        self.assertEqual(st, 400)
        self.assertIn(A.VIZ_NO_TOKEN_MSG, j["error"])
        self.assertEqual(self.scripts, [])


class TestVizDecide(unittest.TestCase):
    """La décision est isolée : rc du scan × réglage → (bloquant, libellé, anomalie)."""

    def test_scan_propre(self):
        for rb in (False, True):
            bloq, lbl, anom = A.viz_decide(0, rb)
            self.assertEqual((bloq, anom), (False, False))
            self.assertIn("aucune anomalie", lbl)

    def test_anomalies_sans_rollback_avertissent(self):
        bloq, lbl, anom = A.viz_decide(A.VIZ_ANOMALY_RC, False)
        self.assertFalse(bloq)          # pas de retour arrière
        self.assertTrue(anom)
        self.assertIn("avertissement", lbl)
        self.assertIn("conservée", lbl)
        self.assertIn("(réglage)", lbl)

    def test_anomalies_avec_rollback_annulent(self):
        bloq, lbl, anom = A.viz_decide(A.VIZ_ANOMALY_RC, True)
        self.assertTrue(bloq)
        self.assertTrue(anom)
        self.assertIn("retour arrière", lbl)
        self.assertIn("(réglage)", lbl)

    def test_echec_technique_bloque_quel_que_soit_le_reglage(self):
        """rc 1 ou 90, ce n'est pas « le rendu a changé », c'est « le scan a raté »."""
        for rc in (1, 3, 90, 93):
            for rb in (False, True):
                bloq, _lbl, anom = A.viz_decide(rc, rb)
                self.assertTrue(bloq, (rc, rb))
                self.assertFalse(anom, (rc, rb))

    def test_url_de_rapport_extraite(self):
        out = 'Deprecated: [x]\n{"anomalies":2,"report_url":"https://vizproof.com/r/42"}'
        self.assertEqual(A.viz_report_url(out), "https://vizproof.com/r/42")

    def test_url_de_rapport_non_http_ignoree(self):
        self.assertIsNone(A.viz_report_url('{"report_url":"javascript:alert(1)"}'))
        self.assertIsNone(A.viz_report_url('{"anomalies":1}'))
        self.assertIsNone(A.viz_report_url("pas de json"))
        self.assertIsNone(A.viz_report_url(""))


# Le bloc bash de retour arrière est le SEUL à citer les archives d'extensions :
# c'est notre marqueur pour dire « un retour arrière a bien été tenté ».
ROLLBACK_MARQUEUR = "plugin__*.tgz"


class TestSafeUpdateViz(BaseTmp):
    """Bout du fil : le verdict de la MAJ sûre selon le scan visuel et le réglage.

    `safe_update_run` est exécutée pour de vrai, tous ses appels distants
    bouchonnés — c'est le seul moyen de vérifier que le rc 2 ne déclenche PLUS
    de retour arrière par défaut.
    """

    def setUp(self):
        super().setUp()
        self._sp, self._ri = A.SETTINGS_PATH, A.ROLLBACK_INDEX_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        A.ROLLBACK_INDEX_PATH = os.path.join(self.data, "rollback_index.json")
        self.addCleanup(lambda: setattr(A, "SETTINGS_PATH", self._sp))
        self.addCleanup(lambda: setattr(A, "ROLLBACK_INDEX_PATH", self._ri))
        A.SAFE.update({"running": False, "domain": "", "steps": [], "verdict": ""})
        self.rc_scan = A.VIZ_ANOMALY_RC
        self.bash = []
        srv = {"name": "s1", "host": "203.0.113.1", "port": 22, "patterns": ["/x/*"]}
        site = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www",
                "siteurl": "https://a.fr", "core_version": "6.5.2",
                "plugins_list": [{"name": "akismet", "version": "5.3",
                                  "update": "available", "update_version": "5.4"}]}
        for cible, valeur in (
                ("find_site", lambda s, d: (srv, site)),
                ("viz_available", lambda s, x: True),
                ("health_probe", lambda x: (True, 200, 5000, "HTTP 200, 5000 octets")),
                ("remote_bash", self._bash),
                ("alert", lambda *a, **k: None),
        ):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _bash(self, srv, site, body, timeout=300):
        """Sorties distantes plausibles, une par étape que la fonction lit."""
        self.bash.append(body)
        if "vizproof scan" in body:
            return self.rc_scan, '{"anomalies":2,"report_url":"https://vizproof.com/r/9"}'
        if "plugin list --update=available" in body:
            return 0, "akismet"
        if "plugin list --fields=name,version" in body:
            return 0, "name,version\nakismet,5.3"
        if "BESOIN_MO" in body:                      # bloc d'archivage
            return 0, ("PLUGDIR=/var/www/a.fr/wp-content/plugins\nDB_MO=12\n"
                       "BESOIN_MO=30\nLIBRE_MO=90000\narchivé akismet\n"
                       "BDD_MO=3\narchivé (base)\nTAILLE_ARCHIVES_MO=4")
        if ROLLBACK_MARQUEUR in body:                # bloc de retour arrière
            return 0, "restauré akismet"
        return 0, "Success: Updated 1 of 1 plugins."

    def lancer(self, viz_rollback=None):
        A.safe_update_run("s1", "a.fr", slugs=["akismet"], do_backup=False,
                          viz_rollback=viz_rollback)
        return dict(A.SAFE)

    def etape_viz(self, st):
        return next((x for x in st["steps"] if "VizProof" in x["label"]), None)

    def test_par_defaut_anomalies_conservees(self):
        st = self.lancer()
        self.assertEqual(st["verdict"], "réussie avec anomalies visuelles",
                         [x["label"] + "/" + x["detail"][:80] for x in st["steps"]])
        e = self.etape_viz(st)
        self.assertTrue(e["warn"])
        self.assertIn("avertissement", e["detail"])
        self.assertIn("https://vizproof.com/r/9", e["detail"])   # lien du rapport
        self.assertFalse(any(ROLLBACK_MARQUEUR in b for b in self.bash),
                         "retour arrière déclenché alors qu'on ne le voulait pas")

    def test_reglage_actif_declenche_le_retour_arriere(self):
        A.settings_write({"viz_anomaly_rollback": True})
        st = self.lancer()
        self.assertNotEqual(st["verdict"], "réussie avec anomalies visuelles")
        self.assertIn("retour arrière", self.etape_viz(st)["detail"])
        self.assertTrue(any(ROLLBACK_MARQUEUR in b for b in self.bash),
                        "aucun retour arrière tenté")

    def test_surcharge_par_execution_gagne_sur_le_reglage(self):
        A.settings_write({"viz_anomaly_rollback": True})
        self.assertEqual(self.lancer(viz_rollback=False)["verdict"],
                         "réussie avec anomalies visuelles")
        A.settings_write({"viz_anomaly_rollback": False})
        self.assertNotEqual(self.lancer(viz_rollback=True)["verdict"],
                            "réussie avec anomalies visuelles")

    def test_scan_propre_donne_le_verdict_habituel(self):
        self.rc_scan = 0
        st = self.lancer()
        self.assertEqual(st["verdict"], "réussi")
        self.assertFalse(self.etape_viz(st)["warn"])

    def test_echec_technique_du_scan_annule_meme_sans_reglage(self):
        self.rc_scan = 90
        st = self.lancer()
        self.assertNotIn("réussi", st["verdict"])


# --------------------------------------------------------------------------- #
#  Contrôle visuel automatique après une mise à jour unitaire                   #
#                                                                              #
#  `_spawn` est exécuté SYNCHRONEMENT : en production le contrôle part dans un  #
#  thread (la route /api/actions/run répond sans l'attendre), ici on veut       #
#  observer son résultat sans course. `remote_bash` est doublé par une SÉQUENCE  #
#  de réponses `wp vizproof status` : c'est elle, et non l'horloge, qui pilote   #
#  l'attente du run que le plugin lance lui-même (`_viz_sleep` ne dort pas).     #
# --------------------------------------------------------------------------- #
class TestVizAfterUpdate(BaseTmp):

    SITE_RELIE = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www",
                  "siteurl": "https://a.fr",
                  "vizproof": {"has_cli": True, "configured": True, "connected": True,
                               "last_run": {"id": "run-old", "status": "completed",
                                            "at": "2026-09-01T09:00:00+00:00"}}}

    def setUp(self):
        super().setUp()
        self._sp = A.SETTINGS_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        self.addCleanup(lambda: setattr(A, "SETTINGS_PATH", self._sp))
        A.VIZ_LAST.clear()
        self.addCleanup(A.VIZ_LAST.clear)
        # Délais raccourcis et sommeil neutralisé : l'attente est pilotée par la
        # SÉQUENCE de réponses `wp vizproof status`, pas par l'horloge.
        for cle, val in (("VIZ_POLL_S", 1), ("VIZ_WAIT_NEW_S", 3), ("VIZ_WAIT_DONE_S", 6)):
            p = mock.patch.object(A, cle, val)
            p.start()
            self.addCleanup(p.stop)
        self.site = {k: (json.loads(json.dumps(v)) if isinstance(v, dict) else v)
                     for k, v in self.SITE_RELIE.items()}
        self.srv = {"name": "s1", "host": "203.0.113.1", "port": 22}
        self.cli = True
        self.relie_sonde = True
        self.rc_scan = 0
        self.sortie_scan = '{"anomalies":0,"report_url":"https://vizproof.com/r/1"}'
        # Le plugin scanne de lui-même : réponses successives de `wp vizproof
        # status` (la dernière est répétée tant qu'on interroge).
        self.statuts = [self.run_neuf(statut="queued"), self.run_neuf()]
        self.option = {"enable_update_scan_by_default": True}
        self.option_rc = 0
        self.actions = []          # (action, source) réellement exécutées
        self.alertes = []
        self.phases = []           # phases publiées pendant l'attente
        for cible, valeur in (
                ("find_site", lambda s, d: (self.srv, self.site)),
                ("viz_available", lambda s, x: self.cli),
                ("viz_linked_probe", lambda s, x: self.relie_sonde),
                ("logged_action", self._logged),
                ("remote_bash", self._remote),
                ("_viz_sleep", lambda _s: None),
                ("alert", lambda k, r, t: self.alertes.append((k, r, t))),
                ("_spawn", lambda fn, *a: fn(*a)),
        ):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    # ---- fabriques ----
    def iso(self, delta=0):
        return (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(seconds=delta)).isoformat()

    def run_neuf(self, statut="completed", anomalies=0, rid="run-neuf", delta=1):
        return {"id": rid, "at": self.iso(delta), "status": statut,
                "anomalies": anomalies, "url": "https://vizproof.com/r/9"}

    # ---- doublures ----
    def _logged(self, server, domain, action, arg, source="manuel"):
        self.actions.append((action, source))
        if action == "viz_scan":
            self.phases.append(A.viz_last_get(domain).get("phase"))
            return self.rc_scan, self.sortie_scan
        return 0, "ok"

    def _remote(self, srv, site, body, timeout=300):
        if "vizproof status" in body:
            self.phases.append(A.viz_last_get("a.fr").get("phase"))
            st = self.statuts.pop(0) if len(self.statuts) > 1 else (self.statuts or [None])[0]
            corps = {"configured": True}
            if st:
                corps["last_run"] = st
            return 0, json.dumps(corps)
        if "option get" in body:
            return self.option_rc, ("" if self.option is None else json.dumps(self.option))
        return 0, ""

    def faites(self):
        return [a for a, _s in self.actions]

    def journal(self, action):
        """Entrées de data/actions.log portant cette action."""
        if not os.path.exists(A.LOG):
            return []
        with open(A.LOG) as fh:
            return [json.loads(l) for l in fh if l.strip()
                    and json.loads(l).get("action") == action]

    # ---- réglage ----
    def test_reglage_actif_par_defaut(self):
        self.assertIs(A.SETTINGS_DEFAULTS["viz_scan_after_update"], True)
        self.assertIs(A.settings_cfg()["viz_scan_after_update"], True)

    # ---- cas nominal : c'est le PLUGIN qui scanne ----
    def test_le_verdict_vient_du_scan_du_plugin(self):
        viz = A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        self.assertTrue(viz["ran"])
        self.assertTrue(viz["pending"], "la route ne doit pas attendre le scan")
        self.assertEqual(viz["phase"], A.VIZ_PHASE_WAIT)
        # aucun scan lancé par nous : le plugin l'avait déjà fait
        self.assertEqual(self.faites(), ["rescan"])
        self.assertTrue(all(s == A.VIZ_AFTER_SOURCE for _a, s in self.actions))
        fin = A.viz_last_get("a.fr")
        self.assertTrue(fin["ran"])
        self.assertFalse(fin["pending"])
        self.assertEqual(fin["source"], A.VIZ_SRC_PLUGIN)
        self.assertEqual(fin["rc"], 0)
        self.assertFalse(fin["anomalies"])
        self.assertEqual(fin["anomalies_count"], 0)
        self.assertEqual(fin["run_id"], "run-neuf")
        self.assertEqual(fin["report_url"], "https://vizproof.com/r/9")
        self.assertIsNone(fin["phase"])
        self.assertEqual(self.alertes, [])

    def test_les_phases_sont_publiees_pendant_l_attente(self):
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        # 1re interrogation : on attend encore ; 2e : le run est repéré, il tourne
        self.assertEqual(self.phases, [A.VIZ_PHASE_WAIT, A.VIZ_PHASE_RUNNING])

    def test_verdict_journalise_meme_sans_action_de_notre_part(self):
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        entrees = self.journal("viz_verdict")
        self.assertEqual(len(entrees), 1)
        e = entrees[0]
        self.assertEqual(e["source"], A.VIZ_AFTER_SOURCE)
        self.assertEqual(e["arg"], "run-neuf")
        self.assertEqual(e["rc"], 0)
        self.assertIn(A.VIZ_SRC_PLUGIN, e["output_tail"])

    def test_toutes_les_actions_de_mise_a_jour_sont_couvertes(self):
        for act in A.VIZ_AFTER_UPDATE_ACTIONS:
            A.VIZ_LAST.clear()
            self.statuts = [self.run_neuf(statut="queued"), self.run_neuf()]
            self.assertTrue(A.viz_after_update("s1", "a.fr", act, 0, time.time())["ran"], act)
            self.assertEqual(A.viz_last_get("a.fr")["source"], A.VIZ_SRC_PLUGIN, act)

    # ---- anomalies ----
    def test_anomalies_du_plugin_alertent(self):
        self.statuts = [self.run_neuf(statut="queued"),
                        self.run_neuf(anomalies=3)]
        A.viz_after_update("s1", "a.fr", "plugins_update_all", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertTrue(fin["ran"])
        self.assertTrue(fin["anomalies"])
        self.assertEqual(fin["anomalies_count"], 3)
        self.assertEqual(fin["rc"], A.VIZ_ANOMALY_RC)
        self.assertEqual(fin["source"], A.VIZ_SRC_PLUGIN)
        self.assertEqual(len(self.alertes), 1)
        cle, regle, texte = self.alertes[0]
        self.assertEqual((cle, regle), ("viz_anomaly:a.fr", "viz_anomaly"))
        self.assertIn("a.fr", texte)
        self.assertEqual(self.journal("viz_verdict")[0]["rc"], A.VIZ_ANOMALY_RC)
        # une anomalie visuelle n'empêche pas la remise à jour de l'inventaire
        self.assertEqual(self.faites(), ["rescan"])

    def test_run_du_plugin_en_echec_n_est_pas_un_ok(self):
        self.statuts = [self.run_neuf(statut="failed")]
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertEqual(fin["status"], "échec")
        self.assertNotEqual(fin["rc"], 0)
        self.assertFalse(fin["anomalies"])
        self.assertEqual(self.alertes, [])

    def test_run_toujours_en_file_ne_donne_pas_de_verdict(self):
        self.statuts = [self.run_neuf(statut="queued")]
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertTrue(fin["ran"])
        self.assertIsNone(fin["rc"])
        self.assertEqual(fin["status"], "en cours")
        self.assertEqual(self.journal("viz_verdict"), [])   # pas de verdict, rien à tracer
        self.assertNotIn("viz_scan", self.faites())

    # ---- le plugin n'a rien lancé ----
    def test_aucun_nouveau_run_et_option_active_ne_lance_rien(self):
        self.statuts = [dict(self.site["vizproof"]["last_run"], at=self.iso(1))]
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertFalse(fin["ran"])
        self.assertEqual(fin["reason"], "le plugin n'a lancé aucun scan")
        self.assertNotIn("viz_scan", self.faites())          # surtout pas de doublon tardif
        self.assertIsNone(fin["source"])

    def test_aucun_run_du_tout_et_option_active(self):
        self.statuts = []
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        self.assertEqual(A.viz_last_get("a.fr")["reason"], "le plugin n'a lancé aucun scan")
        self.assertNotIn("viz_scan", self.faites())

    def test_option_inactive_repli_sur_le_scan_du_dashboard(self):
        self.statuts = []
        self.option = {"enable_update_scan_by_default": False}
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertEqual(self.faites(), ["viz_scan", "rescan"])
        self.assertTrue(fin["ran"])
        self.assertEqual(fin["source"], A.VIZ_SRC_DASHBOARD)
        self.assertEqual(fin["rc"], 0)
        self.assertEqual(fin["report_url"], "https://vizproof.com/r/1")
        self.assertIn(A.VIZ_PHASE_DASHBOARD, self.phases)

    def test_option_illisible_repli_sur_le_scan_du_dashboard(self):
        self.statuts = []
        self.option_rc, self.option = 1, None
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        self.assertEqual(self.faites(), ["viz_scan", "rescan"])
        self.assertEqual(A.viz_last_get("a.fr")["source"], A.VIZ_SRC_DASHBOARD)

    def test_scan_dashboard_en_anomalies_alerte_aussi(self):
        self.statuts = []
        self.option = {"enable_update_scan_by_default": 0}
        self.rc_scan = A.VIZ_ANOMALY_RC
        self.sortie_scan = '{"anomalies":2,"report_url":"https://vizproof.com/r/7"}'
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertTrue(fin["anomalies"])
        self.assertEqual(fin["anomalies_count"], 2)
        self.assertEqual(fin["source"], A.VIZ_SRC_DASHBOARD)
        self.assertEqual(len(self.alertes), 1)

    def test_scan_dashboard_en_echec_technique_n_alerte_pas(self):
        self.statuts = []
        self.option = {"enable_update_scan_by_default": False}
        self.rc_scan, self.sortie_scan = 90, "wp-cli: erreur"
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertFalse(fin["anomalies"])
        self.assertEqual(fin["rc"], 90)
        self.assertEqual(self.alertes, [])

    def test_site_repondant_non_configure_n_est_pas_compte_comme_scan(self):
        self.statuts = []
        self.option = {"enable_update_scan_by_default": False}
        self.rc_scan, self.sortie_scan = 1, "Error: le site n'est pas configuré"
        A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertFalse(fin["ran"])
        self.assertEqual(fin["reason"], "non relié")

    # ---- reconnaissance du run ----
    def test_viz_run_is_new_exige_un_id_neuf_ET_une_date_recente(self):
        t0 = time.time()
        neuf = self.run_neuf(rid="r2", delta=2)
        self.assertTrue(A.viz_run_is_new(neuf, "r1", t0))
        # même identifiant, date récente : c'est le run d'avant, pas le nôtre
        self.assertFalse(A.viz_run_is_new(dict(neuf, id="r1"), "r1", t0))
        # identifiant neuf mais run antérieur à la mise à jour
        self.assertFalse(A.viz_run_is_new(self.run_neuf(rid="r2", delta=-600), "r1", t0))
        # tolérance d'horloge : 30 s avant la MAJ compte encore
        self.assertTrue(A.viz_run_is_new(self.run_neuf(rid="r2", delta=-30), "r1", t0))
        # date illisible ou absente : on ne devine pas
        self.assertFalse(A.viz_run_is_new(dict(neuf, at=""), "r1", t0))
        self.assertFalse(A.viz_run_is_new(dict(neuf, at="hier"), "r1", t0))
        self.assertFalse(A.viz_run_is_new({}, "", t0))

    def test_viz_prev_run_id_lit_l_inventaire(self):
        self.assertEqual(A.viz_prev_run_id(self.site), "run-old")
        self.assertEqual(A.viz_prev_run_id({}), "")
        self.assertEqual(A.viz_prev_run_id({"vizproof": {"last_run": None}}), "")

    def test_viz_run_done_ne_bloque_que_sur_la_file(self):
        for st in A.VIZ_RUN_PENDING:
            self.assertFalse(A.viz_run_done({"status": st}), st)
        for st in ("completed", "failed", "", "inconnu"):
            self.assertTrue(A.viz_run_done({"status": st}), st)

    def test_viz_truthy_lit_les_options_wordpress(self):
        for v in (True, 1, "1", "true", "yes"):
            self.assertTrue(A.viz_truthy(v), v)
        for v in (False, 0, "", "0", "false", None):
            self.assertFalse(A.viz_truthy(v), v)

    # ---- refus ----
    def test_pas_de_scan_si_desactive(self):
        A.settings_write({"viz_scan_after_update": False})
        viz = A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        self.assertFalse(viz["ran"])
        self.assertEqual(viz["reason"], "désactivé")
        self.assertEqual(self.actions, [])

    def test_pas_de_scan_si_la_mise_a_jour_a_echoue(self):
        viz = A.viz_after_update("s1", "a.fr", "plugin_update", 1, time.time())
        self.assertFalse(viz["ran"])
        self.assertEqual(viz["reason"], "mise à jour en échec")
        self.assertEqual(self.actions, [])

    def test_pas_de_scan_si_le_site_n_est_pas_relie(self):
        self.site["vizproof"] = {"has_cli": True, "configured": False, "connected": False}
        viz = A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        self.assertFalse(viz["ran"])
        self.assertEqual(viz["reason"], "non relié")
        self.assertEqual(self.actions, [])

    def test_pas_de_scan_si_la_cli_est_absente(self):
        self.cli = False
        viz = A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        self.assertTrue(viz["pending"])          # l'inventaire ne le savait pas
        fin = A.viz_last_get("a.fr")
        self.assertFalse(fin["ran"])
        self.assertEqual(fin["reason"], "CLI absente")
        self.assertEqual(self.actions, [])

    def test_action_hors_perimetre_n_a_pas_de_bloc_viz(self):
        for act in ("cache_flush", "rescan", "updraft_backup", "verify_checksums"):
            self.assertIsNone(A.viz_after_update("s1", "a.fr", act, 0), act)
        self.assertEqual(self.actions, [])

    # ---- inventaire muet : on demande au site ----
    def test_inventaire_sans_fiche_vizproof_sonde_le_site(self):
        self.site.pop("vizproof")
        self.relie_sonde = False
        self.assertTrue(A.viz_after_update("s1", "a.fr", "core_update", 0,
                                           time.time())["pending"])
        self.assertEqual(A.viz_last_get("a.fr")["reason"], "non relié")
        self.assertEqual(self.actions, [])
        self.relie_sonde = True
        self.statuts = [self.run_neuf()]
        A.viz_after_update("s1", "a.fr", "core_update", 0, time.time())
        self.assertEqual(A.viz_last_get("a.fr")["source"], A.VIZ_SRC_PLUGIN)

    def test_viz_site_linked_lit_les_deux_temoins(self):
        self.assertIsNone(A.viz_site_linked({}))
        self.assertIsNone(A.viz_site_linked({"vizproof": None}))
        self.assertIsNone(A.viz_site_linked(
            {"vizproof": {"configured": None, "connected": None}}))
        self.assertFalse(A.viz_site_linked({"vizproof": {"connected": False}}))
        self.assertTrue(A.viz_site_linked({"vizproof": {"connected": True}}))
        # `configured` n'existe qu'à partir du plugin 1.3.6 : l'un OU l'autre suffit
        self.assertTrue(A.viz_site_linked({"vizproof": {"configured": True,
                                                        "connected": False}}))

    def test_une_erreur_du_thread_ne_reste_pas_en_attente(self):
        def boum(_s, _x):
            raise RuntimeError("ssh mort")
        with mock.patch.object(A, "viz_available", boum):
            A.viz_after_update("s1", "a.fr", "plugin_update", 0, time.time())
        fin = A.viz_last_get("a.fr")
        self.assertFalse(fin["pending"])
        self.assertEqual(fin["reason"], "erreur")
        self.assertIn("ssh mort", fin["message"])

    def test_memoire_bornee(self):
        for i in range(A.VIZ_LAST_MAX + 12):
            A.viz_last_set(f"s{i}.fr", {"ts": f"2026-09-02 10:{i:02d}:00"})
        self.assertLessEqual(len(A.VIZ_LAST), A.VIZ_LAST_MAX)


class TestRunRouteViz(BaseTmp):
    """La réponse de /api/actions/run garde son contrat et gagne `viz`."""

    def setUp(self):
        super().setUp()
        self._sp = A.SETTINGS_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        self.addCleanup(lambda: setattr(A, "SETTINGS_PATH", self._sp))
        A.VIZ_LAST.clear()
        self.addCleanup(A.VIZ_LAST.clear)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")
        # `has_cli` absent de l'inventaire : le site est relié mais PAS éligible
        # au job `viz_update` (cf. TestVizUpdateJob), donc la route répond en
        # synchrone et le bloc `viz` part en tâche de fond — le cas testé ici.
        site = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www",
                "vizproof": {"configured": True, "connected": True}}
        for cible, valeur in (
                ("find_site", lambda s, d: ({"name": "s1"}, site)),
                ("viz_available", lambda s, x: True),
                ("logged_action", self._logged),
                ("remote_bash", self._remote),
                ("_viz_sleep", lambda _s: None),
                ("alert", lambda *a, **k: None),
                ("_spawn", lambda fn, *a: fn(*a)),
        ):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _logged(self, server, domain, action, arg, source="manuel"):
        if action == "viz_scan":
            return 0, '{"anomalies":0,"report_url":"https://vizproof.com/r/4"}'
        return 0, "ok"

    def _remote(self, srv, site, body, timeout=300):
        """Le plugin a lancé son propre scan pendant la mise à jour."""
        if "vizproof status" in body:
            at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return 0, json.dumps({"configured": True,
                                  "last_run": {"id": "run-42", "at": at,
                                               "status": "completed", "anomalies": 0,
                                               "url": "https://vizproof.com/r/42"}})
        return 0, ""

    def post(self, chemin, corps):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("POST", chemin, body=json.dumps(corps).encode(),
                      headers={"Cookie": self.cookie, "X-Dash": "1",
                               "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def get(self, chemin):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", chemin, headers={"Cookie": self.cookie, "X-Dash": "1"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def test_contrat_conserve_et_bloc_viz_ajoute(self):
        st, j = self.post("/api/actions/run",
                          {"server": "s1", "domain": "a.fr",
                           "action": "plugin_update", "arg": "akismet"})
        self.assertEqual(st, 200)
        for k in ("ok", "rc", "output", "error"):
            self.assertIn(k, j)
        self.assertTrue(j["ok"])
        self.assertEqual(j["rc"], 0)
        self.assertEqual(j["output"], "ok")
        self.assertIsNone(j["error"])
        self.assertTrue(j["viz"]["ran"])
        self.assertTrue(j["viz"]["pending"])
        self.assertEqual(j["viz"]["phase"], A.VIZ_PHASE_WAIT)
        # le verdict se récupère ensuite, la route n'ayant pas attendu le scan
        st2, j2 = self.get("/api/actions/viz_last?domain=a.fr")
        self.assertEqual(st2, 200)
        v = j2["viz"]
        self.assertEqual(v["rc"], 0)
        # verdict du scan lancé par le PLUGIN : le dashboard n'a rien scanné
        self.assertEqual(v["source"], A.VIZ_SRC_PLUGIN)
        self.assertEqual(v["run_id"], "run-42")
        self.assertEqual(v["anomalies_count"], 0)
        self.assertIsNone(v["phase"])
        self.assertEqual(v["report_url"], "https://vizproof.com/r/42")

    def test_action_hors_perimetre_sans_bloc_viz(self):
        _st, j = self.post("/api/actions/run",
                           {"server": "s1", "domain": "a.fr", "action": "cache_flush"})
        self.assertNotIn("viz", j)

    def test_scan_desactive_dit_pourquoi(self):
        A.settings_write({"viz_scan_after_update": False})
        _st, j = self.post("/api/actions/run",
                           {"server": "s1", "domain": "a.fr", "action": "core_update"})
        self.assertFalse(j["viz"]["ran"])
        self.assertEqual(j["viz"]["reason"], "désactivé")

    def test_un_controle_visuel_en_erreur_ne_casse_pas_la_reponse(self):
        with mock.patch.object(A, "viz_after_update",
                               mock.Mock(side_effect=RuntimeError("boum"))):
            st, j = self.post("/api/actions/run",
                              {"server": "s1", "domain": "a.fr",
                               "action": "core_update"})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertFalse(j["viz"]["ran"])

    def test_viz_last_valide_sa_cible(self):
        st, _j = self.get("/api/actions/viz_last?domain=" + urllib.parse.quote("a b"))
        self.assertEqual(st, 400)

    def test_viz_last_vide_avant_tout_scan(self):
        _st, j = self.get("/api/actions/viz_last?domain=jamais.fr")
        self.assertIsNone(j["viz"])


if __name__ == "__main__":
    unittest.main()


class TestVizResolveApercu(unittest.TestCase):
    """L'aperçu (create=False) ne crée jamais de site VizProof."""

    def test_apercu_ne_cree_pas(self):
        import actions_server as A
        appels = []

        def faux_api(path, token, base=None, data=None, **kw):
            appels.append((path, data))
            if data is not None:
                raise AssertionError("POST inattendu en mode aperçu")
            return 200, {"data": [{"id": "x1", "name": "Autre", "domains": '["autre.fr"]'}], "total": 1}, None

        with unittest.mock.patch.object(A, "viz_api_call", faux_api):
            r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", "vrt_" + "a" * 20, create=False)
        self.assertTrue(r["ok"]); self.assertTrue(r.get("would_create")); self.assertEqual(r["site_id"], "")
        self.assertFalse(any(d is not None for _, d in appels))

    def test_connexion_cree(self):
        import actions_server as A

        def faux_api(path, token, base=None, data=None, **kw):
            if data is not None:
                return 200, {"id": "nouveau1", "name": data["name"]}, None
            return 200, {"data": [], "total": 0}, None

        with unittest.mock.patch.object(A, "viz_api_call", faux_api):
            r = A.viz_resolve_site("elwave.fr", "https://elwave.fr", "vrt_" + "a" * 20)
        self.assertTrue(r["ok"]); self.assertTrue(r["created"]); self.assertEqual(r["site_id"], "nouveau1")


# --------------------------------------------------------------------------- #
#  Job « baseline → mise à jour → verdict » d'un site relié à VizProof          #
#                                                                              #
#  `_spawn` synchrone : en production le job tourne dans un thread et la route  #
#  répond aussitôt ; ici la réponse est déjà celle d'un job TERMINÉ, ce qui     #
#  permet d'observer la séquence complète sans course. L'instantané renvoyé par #
#  la route reste, lui, celui d'avant le démarrage (toutes étapes en attente).  #
# --------------------------------------------------------------------------- #
class TestVizUpdateJob(BaseTmp):

    def setUp(self):
        super().setUp()
        self._sp = A.SETTINGS_PATH
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        self.addCleanup(lambda: setattr(A, "SETTINGS_PATH", self._sp))
        A.VIZ_LAST.clear()
        A.VIZUP.clear()
        self.addCleanup(A.VIZ_LAST.clear)
        self.addCleanup(A.VIZUP.clear)
        self._safe = dict(A.SAFE)
        self.addCleanup(lambda: A.SAFE.update(self._safe))
        for cle, val in (("VIZ_POLL_S", 1), ("VIZ_WAIT_NEW_S", 3), ("VIZ_WAIT_DONE_S", 6)):
            p = mock.patch.object(A, cle, val)
            p.start()
            self.addCleanup(p.stop)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")
        self.site = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www",
                     "vizproof": {"has_cli": True, "configured": True, "connected": True,
                                  "last_run": {"id": "run-old", "status": "completed",
                                               "at": "2026-09-01T09:00:00+00:00"}}}
        self.rc_baseline = 0
        self.rc_maj = 0
        self.anomalies = 0
        self.actions = []          # (action, arg, source)
        self.alertes = []
        for cible, valeur in (
                ("find_site", lambda s, d: ({"name": "s1"}, self.site)),
                ("viz_available", lambda s, x: True),
                ("logged_action", self._logged),
                ("remote_bash", self._remote),
                ("_viz_sleep", lambda _s: None),
                ("alert", lambda *a, **k: self.alertes.append(a)),
                ("_spawn", lambda fn, *a: fn(*a)),
        ):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _logged(self, server, domain, action, arg, source="manuel"):
        self.actions.append((action, arg, source))
        if action == "viz_baseline":
            return self.rc_baseline, ("" if not self.rc_baseline else "Error: pas de page suivie")
        if action == "viz_scan":
            return 0, '{"anomalies":0}'
        return (self.rc_maj, "ok" if not self.rc_maj else "Error: échec de la mise à jour")

    def _remote(self, srv, site, body, timeout=300):
        """Le plugin a lancé son propre scan pendant la mise à jour."""
        if "vizproof status" in body:
            at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return 0, json.dumps({"configured": True,
                                  "last_run": {"id": "run-42", "at": at,
                                               "status": "completed",
                                               "anomalies": self.anomalies,
                                               "url": "https://vizproof.com/r/42"}})
        return 0, ""

    def post(self, chemin, corps):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request("POST", chemin, body=json.dumps(corps).encode(),
                      headers={"Cookie": self.cookie, "X-Dash": "1",
                               "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def get(self, chemin):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request("GET", chemin, headers={"Cookie": self.cookie, "X-Dash": "1"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def maj(self, action="plugin_update", arg="akismet"):
        return self.post("/api/actions/run",
                         {"server": "s1", "domain": "a.fr", "action": action, "arg": arg})

    def etape(self, job, cle):
        return next((s for s in job["steps"] if s["key"] == cle), None)

    def faites(self):
        return [a for a, _g, _s in self.actions]

    # ---- déclenchement ----
    def test_job_demarre_et_la_route_repond_sans_attendre(self):
        st, j = self.maj()
        self.assertEqual(st, 200)
        self.assertEqual(j["job"], "viz_update")
        self.assertEqual((j["domain"], j["server"], j["action"], j["arg"]),
                         ("a.fr", "s1", "plugin_update", "akismet"))
        self.assertTrue(j["ok"])
        # l'instantané rendu est celui d'AVANT le démarrage
        self.assertEqual([s["key"] for s in j["steps"]],
                         ["baseline", "update", "viz", "rescan"])
        self.assertTrue(all(s["status"] == A.VIZUP_WAIT for s in j["steps"]))
        # …et la séquence réellement jouée : baseline, MAJ, re-scan
        self.assertEqual(self.faites(), ["viz_baseline", "plugin_update", "rescan"])
        self.assertEqual(self.actions[0][2], A.VIZ_PRE_SOURCE)

    def test_statut_du_job_expose_toute_la_sequence(self):
        self.maj()
        st, job = self.get("/api/actions/viz_update_status?domain=a.fr")
        self.assertEqual(st, 200)
        self.assertFalse(job["running"])
        self.assertEqual(job["domain"], "a.fr")
        self.assertEqual(job["action"], "plugin_update")
        self.assertEqual(job["arg"], "akismet")
        self.assertTrue(job["started"] and job["finished"])
        for cle in ("baseline", "update", "rescan"):
            self.assertEqual(self.etape(job, cle)["status"], A.VIZUP_OK, cle)
        viz = self.etape(job, "viz")
        self.assertEqual(viz["status"], A.VIZUP_OK)
        self.assertEqual(job["result"]["rc"], 0)
        self.assertEqual(job["result"]["output"], "ok")
        self.assertEqual(job["result"]["viz"]["source"], A.VIZ_SRC_PLUGIN)
        self.assertEqual(job["result"]["viz"]["run_id"], "run-42")
        # le verdict reste aussi lisible là où l'UI le lisait déjà
        _st, jl = self.get("/api/actions/viz_last?domain=a.fr")
        self.assertEqual(jl["viz"]["source"], A.VIZ_SRC_PLUGIN)

    def test_site_non_relie_garde_la_reponse_synchrone(self):
        self.site["vizproof"] = {"has_cli": False, "configured": False, "connected": False}
        st, j = self.maj()
        self.assertEqual(st, 200)
        self.assertNotIn("job", j)
        for k in ("ok", "rc", "output", "error"):
            self.assertIn(k, j)
        self.assertEqual(j["rc"], 0)
        self.assertIn("plugin_update", self.faites())
        self.assertEqual(A.vizup_get("a.fr"), None)

    def test_cli_absente_garde_la_reponse_synchrone(self):
        # `configured` sans `has_cli` : l'inventaire ne garantit pas la commande
        self.site["vizproof"] = {"has_cli": False, "configured": True, "connected": True}
        _st, j = self.maj()
        self.assertNotIn("job", j)

    def test_les_deux_reglages_eteints_gardent_la_reponse_synchrone(self):
        A.settings_write({"viz_baseline_before_update": False,
                          "viz_scan_after_update": False})
        _st, j = self.maj()
        self.assertNotIn("job", j)
        self.assertEqual(j["rc"], 0)

    def test_action_hors_perimetre_ne_declenche_pas_de_job(self):
        _st, j = self.post("/api/actions/run",
                           {"server": "s1", "domain": "a.fr", "action": "cache_flush"})
        self.assertNotIn("job", j)

    # ---- composition des étapes ----
    def test_sans_baseline_quand_le_reglage_est_eteint(self):
        A.settings_write({"viz_baseline_before_update": False})
        _st, j = self.maj()
        self.assertEqual([s["key"] for s in j["steps"]], ["update", "viz", "rescan"])
        self.assertNotIn("viz_baseline", self.faites())

    def test_sans_controle_visuel_quand_le_reglage_est_eteint(self):
        A.settings_write({"viz_scan_after_update": False})
        _st, j = self.maj()
        self.assertEqual([s["key"] for s in j["steps"]], ["baseline", "update", "rescan"])
        _st2, job = self.get("/api/actions/viz_update_status?domain=a.fr")
        self.assertIsNone(job["result"]["viz"])

    def test_reglages_par_defaut(self):
        self.assertIs(A.SETTINGS_DEFAULTS["viz_baseline_before_update"], True)
        self.assertIs(A.SETTINGS_DEFAULTS["viz_baseline_required"], False)

    # ---- baseline ----
    def test_baseline_en_echec_avertit_mais_ne_bloque_pas(self):
        self.rc_baseline = 1
        self.maj()
        _st, job = self.get("/api/actions/viz_update_status?domain=a.fr")
        self.assertEqual(self.etape(job, "baseline")["status"], A.VIZUP_WARN)
        self.assertEqual(self.etape(job, "update")["status"], A.VIZUP_OK)
        self.assertEqual(job["result"]["rc"], 0)
        self.assertIn("plugin_update", self.faites())

    def test_baseline_requise_annule_la_mise_a_jour(self):
        A.settings_write({"viz_baseline_required": True})
        self.rc_baseline = 1
        self.maj()
        _st, job = self.get("/api/actions/viz_update_status?domain=a.fr")
        self.assertEqual(self.etape(job, "baseline")["status"], A.VIZUP_ERR)
        self.assertEqual(self.etape(job, "update")["status"], A.VIZUP_ERR)
        self.assertNotIn("plugin_update", self.faites())   # rien n'a été mis à jour
        self.assertNotIn("rescan", self.faites())
        self.assertEqual(job["result"]["rc"], 1)

    # ---- mise à jour en échec ----
    def test_mise_a_jour_en_echec_n_est_pas_controlee_visuellement(self):
        self.rc_maj = 1
        self.maj()
        _st, job = self.get("/api/actions/viz_update_status?domain=a.fr")
        self.assertEqual(self.etape(job, "update")["status"], A.VIZUP_ERR)
        self.assertEqual(self.etape(job, "viz")["status"], A.VIZUP_WARN)
        self.assertIsNone(job["result"]["viz"])
        self.assertIn("rescan", self.faites())

    # ---- anomalies ----
    def test_anomalies_mettent_l_etape_en_avertissement_et_alertent(self):
        self.anomalies = 3
        self.maj()
        _st, job = self.get("/api/actions/viz_update_status?domain=a.fr")
        self.assertEqual(self.etape(job, "viz")["status"], A.VIZUP_WARN)
        self.assertEqual(job["result"]["viz"]["anomalies_count"], 3)
        self.assertEqual(job["result"]["rc"], 0)          # la MAJ, elle, a réussi
        self.assertEqual(len(self.alertes), 1)

    # ---- verrous ----
    def test_un_seul_job_par_site(self):
        A.VIZUP["a.fr"] = {"running": True, "domain": "a.fr", "steps": [],
                           "started": "2026-09-02 10:00:00"}
        st, j = self.maj()
        self.assertEqual(st, 409)
        self.assertIn("déjà en cours", j["error"])
        self.assertEqual(self.actions, [])

    def test_pas_de_job_pendant_une_maj_sure_du_meme_site(self):
        A.SAFE.update(running=True, domain="a.fr")
        st, j = self.maj()
        self.assertEqual(st, 409)
        self.assertIn("sûre", j["error"])
        self.assertEqual(self.actions, [])

    def test_une_maj_sure_ailleurs_ne_gene_pas(self):
        A.SAFE.update(running=True, domain="b.fr")
        st, j = self.maj()
        self.assertEqual(st, 200)
        self.assertEqual(j["job"], "viz_update")

    def test_maj_sure_refusee_pendant_un_job(self):
        A.VIZUP["a.fr"] = {"running": True, "domain": "a.fr", "steps": [],
                           "started": "2026-09-02 10:00:00"}
        st, j = self.post("/api/actions/safe_update", {"server": "s1", "domain": "a.fr"})
        self.assertEqual(st, 409)
        self.assertIn("contrôle visuel", j["error"])
        self.assertFalse(A.SAFE["running"])   # la réservation ne doit pas être prise

    # ---- statut ----
    def test_statut_vide_pour_un_domaine_sans_job(self):
        _st, j = self.get("/api/actions/viz_update_status?domain=jamais.fr")
        self.assertFalse(j["running"])
        self.assertEqual(j["steps"], [])
        self.assertIsNone(j["result"])

    def test_statut_valide_sa_cible(self):
        st, _j = self.get("/api/actions/viz_update_status?domain="
                          + urllib.parse.quote("a b"))
        self.assertEqual(st, 400)

    def test_memoire_bornee(self):
        for i in range(A.VIZUP_MAX + 5):
            A.VIZUP[f"s{i}.fr"] = {"running": False, "domain": f"s{i}.fr", "steps": [],
                                   "started": f"2026-09-02 10:{i:02d}:00"}
        self.maj()
        self.assertLessEqual(len(A.VIZUP), A.VIZUP_MAX)
        self.assertIn("a.fr", A.VIZUP)          # le job en cours n'est jamais purgé


# --------------------------------------------------------------------------- #
#  VizProof : pages surveillées (lecture, écriture, repli 1.3.7, validation)    #
#                                                                             #
#  `run_remote_script` est bouché : on inspecte le script envoyé, et on rejoue  #
#  la sortie que chaque version du plugin produirait. Aucun ssh, aucun réseau.  #
# --------------------------------------------------------------------------- #
PAGES_138 = json.dumps({
    "scope": "selected_pages", "selected": [12], "critical": [12],
    "pages": [
        {"id": 12, "title": "Accueil", "url": "https://a.fr/", "type": "front",
         "selected": True, "critical": True},
        {"id": 18, "title": "Contact", "url": "https://a.fr/contact/", "type": "page",
         "selected": False, "critical": False},
    ],
    "message": "",
})
PAGES_137_ERR = "Error: 'pages' is not a registered subcommand of 'vizproof'."


class VizPagesBase(BaseTmp):
    def setUp(self):
        super().setUp()
        self.envoyes = []
        self.reponses = []          # [(motif attendu dans le script, (rc, sortie))]
        self.srv = {"name": "s1", "host": "203.0.113.1", "port": 22, "patterns": ["/x/*"]}
        self.site = {"domain": "a.fr", "path": "/var/www/a.fr", "owner": "www",
                     "siteurl": "https://a.fr"}
        for cible, valeur in (("run_remote_script", self._ssh),
                              ("find_site", lambda s, d: (self.srv, self.site)),
                              ("rest_target", lambda s, d: None)):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _ssh(self, srv, script, timeout=300, max_out=6000):
        self.envoyes.append(script)
        if self.reponses:
            return self.reponses.pop(0)
        return 0, ""

    def log(self):
        if not os.path.exists(A.LOG):
            return []
        with open(A.LOG) as fh:
            return [json.loads(l) for l in fh]


class TestVizPagesLecture(VizPagesBase):

    def test_lecture_138_normalisee(self):
        self.reponses = [(0, PAGES_138)]
        rc, j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(rc, 0)
        self.assertEqual(j["source"], "plugin")
        self.assertEqual(j["scope"], "selected_pages")
        self.assertEqual(j["selected"], [12])
        self.assertEqual(j["limit"], 20)
        self.assertEqual([p["id"] for p in j["pages"]], [12, 18])
        self.assertEqual(j["pages"][0]["type"], "front")
        self.assertIn("wp vizproof pages", "".join(self.envoyes).replace("run ", "wp "))

    def test_commande_de_lecture(self):
        self.reponses = [(0, PAGES_138)]
        A.viz_pages_read("s1", "a.fr")
        self.assertIn("run vizproof pages --format=json", self.envoyes[0])
        self.assertNotIn(" set ", self.envoyes[0])

    def test_type_inconnu_ramene_a_page(self):
        self.reponses = [(0, json.dumps({"scope": "site", "selected": [], "critical": [],
                                         "pages": [{"id": 5, "type": "archive"}]}))]
        _rc, j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(j["pages"][0]["type"], "page")

    def test_sortie_illisible(self):
        self.reponses = [(0, "PHP Notice: quelque chose")]
        rc, j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(rc, 95)
        self.assertFalse(j["ok"])

    def test_site_sans_ssh_rend_97(self):
        with mock.patch.object(A, "find_site", lambda s, d: (None, None)), \
             mock.patch.object(A, "rest_target", lambda s, d: {"domain": "a.fr"}):
            rc, j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(rc, A.REST_UNSUPPORTED_RC)
        self.assertEqual(rc, 97)
        self.assertFalse(j["ok"])
        self.assertEqual(self.envoyes, [])

    def test_site_inconnu(self):
        with mock.patch.object(A, "find_site", lambda s, d: (None, None)):
            rc, _j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(rc, 92)


class TestVizPagesRepli137(VizPagesBase):
    """Le plugin 1.3.7 n'a pas `wp vizproof pages` : on lit et on écrit les options."""

    POSTS = json.dumps([
        {"ID": 12, "post_title": "Accueil", "url": "https://a.fr/"},
        {"ID": 18, "post_title": "Contact", "url": "https://a.fr/contact/"},
    ])

    def sortie_repli(self, front="12", opt=None):
        o = json.dumps(opt if opt is not None else
                       {"selected_wordpress_page_ids": [18], "scan_scope": "selected_pages"})
        return "\n".join([self.POSTS, A.VIZ_PAGES_SEP_OPT, o, A.VIZ_PAGES_SEP_FRONT, front])

    def test_bascule_sur_le_repli(self):
        self.reponses = [(1, PAGES_137_ERR), (0, self.sortie_repli())]
        rc, j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(rc, 0)
        self.assertEqual(j["source"], "repli-1.3.7")
        self.assertEqual(j["selected"], [18])
        self.assertEqual(j["scope"], "selected_pages")
        # la page d'accueil statique est repérée par page_on_front
        self.assertEqual(j["pages"][0]["id"], 12)
        self.assertEqual(j["pages"][0]["type"], "front")
        self.assertTrue(j["pages"][1]["selected"])
        self.assertIn("1.3.7", j["message"])

    def test_le_repli_utilise_post_list_et_les_options(self):
        self.reponses = [(1, PAGES_137_ERR), (0, self.sortie_repli())]
        A.viz_pages_read("s1", "a.fr")
        script = self.envoyes[1]
        self.assertIn("post list --post_type=page --post_status=publish", script)
        self.assertIn("option get vizproof_timeline_options --format=json", script)
        self.assertIn("option get page_on_front", script)

    def test_accueil_flux_d_articles_en_tete_et_sans_identifiant(self):
        self.reponses = [(1, PAGES_137_ERR), (0, self.sortie_repli(front="0"))]
        _rc, j = A.viz_pages_read("s1", "a.fr")
        self.assertEqual(j["pages"][0]["id"], 0)
        self.assertEqual(j["pages"][0]["type"], "home")

    def test_ecriture_ecrit_les_ids_wordpress_et_pas_les_ids_vizproof(self):
        self.reponses = [(1, PAGES_137_ERR), (0, "Success"), (0, self.sortie_repli())]
        rc, j = A.viz_pages_write("s1", "a.fr", [12, 18], "selected_pages")
        self.assertEqual(rc, 0)
        script = self.envoyes[1]
        self.assertIn("option patch update vizproof_timeline_options "
                      "selected_wordpress_page_ids '[12, 18]' --format=json", script)
        # `selected_page_ids` porte des identifiants de pages VIZPROOF : y écrire
        # des identifiants WordPress casserait les captures.
        self.assertNotIn("selected_page_ids '", script)
        self.assertIn("option patch update vizproof_timeline_options scan_scope "
                      "'selected_pages'", script)
        self.assertEqual(j["source"], "repli-1.3.7")

    def test_le_repli_ne_touche_a_rien_d_autre_dans_l_option(self):
        self.reponses = [(1, PAGES_137_ERR), (0, "Success"), (0, self.sortie_repli())]
        A.viz_pages_write("s1", "a.fr", [12], "site")
        script = self.envoyes[1]
        self.assertNotIn("option update vizproof_timeline_options", script)
        self.assertEqual(script.count("option patch update"), 2)


class TestVizPagesEcriture(VizPagesBase):

    def test_commande_138(self):
        self.reponses = [(0, PAGES_138)]
        rc, j = A.viz_pages_write("s1", "a.fr", [12, 18], "selected_pages")
        self.assertEqual(rc, 0)
        self.assertIn("run vizproof pages set --ids='12,18' --scope='selected_pages' "
                      "--format=json", self.envoyes[0])
        self.assertEqual(j["selected"], [12])          # la réponse du plugin fait foi

    def test_portee_site_sans_selection_n_envoie_pas_ids(self):
        self.reponses = [(0, PAGES_138)]
        A.viz_pages_write("s1", "a.fr", [], "site")
        self.assertNotIn("--ids", self.envoyes[0])
        self.assertIn("--scope='site'", self.envoyes[0])

    def test_ecriture_journalisee(self):
        self.reponses = [(0, PAGES_138)]
        A.viz_pages_write("s1", "a.fr", [12], "selected_pages")
        e = [x for x in self.log() if x["action"] == "viz_pages"]
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["rc"], 0)
        self.assertEqual(e[0]["domain"], "a.fr")
        self.assertIn("selected_pages", e[0]["arg"])

    def test_echec_journalise_aussi(self):
        self.reponses = [(3, "Error: page 999 introuvable")]
        rc, j = A.viz_pages_write("s1", "a.fr", [999], "selected_pages")
        self.assertEqual(rc, 3)
        self.assertFalse(j["ok"])
        self.assertEqual([x["rc"] for x in self.log() if x["action"] == "viz_pages"], [3])

    def test_site_sans_ssh_journalise_97(self):
        with mock.patch.object(A, "find_site", lambda s, d: (None, None)), \
             mock.patch.object(A, "rest_target", lambda s, d: {"domain": "a.fr"}):
            rc, _j = A.viz_pages_write("s1", "a.fr", [12], "site")
        self.assertEqual(rc, 97)
        self.assertEqual([x["rc"] for x in self.log() if x["action"] == "viz_pages"], [97])


class TestVizPagesRoute(BaseTmp):
    """Validation d'entrée des deux routes, sans toucher au ssh."""

    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")
        self.ecrits = []
        p = mock.patch.object(A, "viz_pages_write", self._write)
        p.start()
        self.addCleanup(p.stop)

    def _write(self, server, domain, ids, scope, source="ui"):
        self.ecrits.append((server, domain, list(ids), scope))
        return 0, {"ok": True, "source": "plugin", "limit": 20, "scope": scope,
                   "selected": list(ids), "critical": [], "pages": [], "message": ""}

    def post(self, corps):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("POST", "/api/actions/viz_pages", body=json.dumps(corps).encode(),
                      headers={"Cookie": self.cookie, "X-Dash": "1",
                               "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def get(self, chemin):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", chemin, headers={"Cookie": self.cookie})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    BON = {"server": "s1", "domain": "a.fr", "ids": [12], "scope": "selected_pages"}

    def test_nominal(self):
        st, j = self.post(self.BON)
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["rc"], 0)
        self.assertEqual(self.ecrits, [("s1", "a.fr", [12], "selected_pages")])

    def test_cible_invalide(self):
        for mauvais in ({"server": "../x"}, {"domain": "a b"}):
            st, _j = self.post(dict(self.BON, **mauvais))
            self.assertEqual(st, 400, mauvais)
        self.assertEqual(self.ecrits, [])

    def test_ids_doivent_etre_entiers(self):
        for mauvais in ("12", {"a": 1}, None):
            st, _j = self.post(dict(self.BON, ids=mauvais))
            self.assertEqual(st, 400, mauvais)
        st, _j = self.post(dict(self.BON, ids=[1.5]))
        self.assertEqual(st, 400)
        st, _j = self.post(dict(self.BON, ids=[-3]))
        self.assertEqual(st, 400)
        self.assertEqual(self.ecrits, [])

    def test_portee_inconnue(self):
        for mauvais in ("", "tout", "SITE"):
            st, _j = self.post(dict(self.BON, scope=mauvais))
            self.assertEqual(st, 400, mauvais)

    def test_limite_de_vingt_pages(self):
        st, j = self.post(dict(self.BON, ids=list(range(1, 22))))
        self.assertEqual(st, 400)
        self.assertIn("20", j["error"])
        st, _j = self.post(dict(self.BON, ids=list(range(1, 21))))
        self.assertEqual(st, 200)

    def test_pages_choisies_sans_page(self):
        st, j = self.post(dict(self.BON, ids=[]))
        self.assertEqual(st, 400)
        self.assertIn("au moins une page", j["error"])

    def test_accueil_flux_d_articles_seulement_en_portee_site(self):
        st, j = self.post(dict(self.BON, ids=[0, 12]))
        self.assertEqual(st, 400)
        self.assertIn("tout le site", j["error"])
        # en portée « site », l'identifiant 0 est simplement retiré de l'envoi
        st, _j = self.post(dict(self.BON, ids=[0, 12], scope="site"))
        self.assertEqual(st, 200)
        self.assertEqual(self.ecrits[-1][2], [12])

    def test_doublons_retires(self):
        st, _j = self.post(dict(self.BON, ids=[12, 12, 18]))
        self.assertEqual(st, 200)
        self.assertEqual(self.ecrits[-1][2], [12, 18])

    # ---- lecture ----
    def test_get_valide_sa_cible(self):
        st, _j = self.get("/api/actions/viz_pages?server=s1&domain=" + urllib.parse.quote("a b"))
        self.assertEqual(st, 400)

    def test_get_site_sans_ssh_repond_200_rc_97(self):
        with mock.patch.object(A, "viz_pages_read",
                               lambda s, d: (97, {"ok": False, "error": "sans SSH"})):
            st, j = self.get("/api/actions/viz_pages?server=s1&domain=a.fr")
        self.assertEqual(st, 200)
        self.assertEqual(j["rc"], 97)
        self.assertFalse(j["ok"])

    def test_get_echec_dur_repond_500(self):
        with mock.patch.object(A, "viz_pages_read",
                               lambda s, d: (7, {"ok": False, "error": "ssh mort"})):
            st, j = self.get("/api/actions/viz_pages?server=s1&domain=a.fr")
        self.assertEqual(st, 500)
        self.assertEqual(j["rc"], 7)

    def test_viz_pages_n_est_pas_une_action_wp_cli(self):
        """Elle ne doit pas être atteignable par /api/actions/run."""
        self.assertNotIn("viz_pages", A.ACTIONS)
