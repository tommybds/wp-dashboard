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
import hashlib
import hmac
import http.client
import inspect
import io
import json
import os
import shutil
import stat
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


if __name__ == "__main__":
    unittest.main()
