#!/usr/bin/env python3
"""Modes d'exécution de wp-cli sur un serveur (`exec_mode`).

Le dashboard passait toujours par `su`, ce qui exigeait root sur les huit
serveurs du parc. Trois modes coexistent désormais : « su » (historique),
« direct » (l'ancien `no_su`) et « sudo » (compte dédié sans droits, autorisé
par une règle sudoers). Ces tests vérifient, sans toucher à un seul serveur :

  * la commande distante RÉELLEMENT produite pour chacun des trois modes,
    par comparaison de chaîne sur le script généré ;
  * qu'aucun chemin ne contient plus « su -s » quand le mode ne l'exige pas ;
  * la migration en lecture de `no_su` ;
  * la validation du champ ;
  * le message dédié quand `sudo -n` est refusé ;
  * un journal PHP illisible → `servers_failed` renseigné, pas d'analyse
    silencieusement vide.

    python3 -m unittest tests.test_exec_mode -v
"""
import http.client
import json
import os
import re
import subprocess
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import actions_server as A
import collect
import dashlib
import phperrors

from tests.test_backend import BaseTmp

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SITE = {"domain": "a.fr", "path": "/var/www/a.fr/htdocs", "owner": "www-data"}


def run_bash(cmd, input=None, env=None):
    """subprocess.run avec `close_fds=False`.

    Volontaire, et propre aux tests : la suite complète laisse assez de
    descripteurs ouverts pour que la fermeture massive faite par défaut
    (RLIMIT_NOFILE d'un million sur macOS) fasse planter l'enfant AVANT
    d'exécuter bash. Ce que l'on teste ici, c'est le script, pas la façon dont
    Python le lance.
    """
    return subprocess.run(cmd, input=input, env=env, capture_output=True,
                          text=True, timeout=30, close_fds=False)


def srv(mode=None, **kw):
    s = {"name": "s1", "host": "203.0.113.5", "port": 22,
         "patterns": ["/var/www/*/htdocs"]}
    if mode is not None:
        s["exec_mode"] = mode
    s.update(kw)
    return s


def script_wp(mode, body="run core version", timeout=60):
    """Script distant d'une action wp-cli, tel qu'il partirait dans `bash -s`."""
    return A.REMOTE_TEMPLATE.format(docroot=A.sq(SITE["path"]), domain=A.sq(SITE["domain"]),
                                    owner=A.sq(SITE["owner"]), mode=mode,
                                    timeout=timeout, body=body)


# --------------------------------------------------------------------------- #
#  Lecture du mode : exec_mode, no_su hérité, valeurs inconnues                #
# --------------------------------------------------------------------------- #
class TestLectureDuMode(unittest.TestCase):

    def test_defaut_su(self):
        self.assertEqual(dashlib.exec_mode(srv()), "su")
        self.assertEqual(dashlib.exec_mode({}), "su")
        self.assertEqual(dashlib.exec_mode(None), "su")

    def test_les_trois_valeurs(self):
        for m in ("su", "direct", "sudo"):
            self.assertEqual(dashlib.exec_mode(srv(m)), m)

    def test_no_su_herite_vaut_direct(self):
        # Fichier écrit AVANT l'arrivée d'exec_mode : il doit continuer à
        # marcher tel quel, sans migration de fichier.
        self.assertEqual(dashlib.exec_mode({"no_su": True}), "direct")
        self.assertEqual(dashlib.exec_mode({"no_su": False}), "su")

    def test_exec_mode_prime_sur_no_su(self):
        self.assertEqual(dashlib.exec_mode({"no_su": True, "exec_mode": "sudo"}), "sudo")

    def test_valeur_inconnue_retombe_sur_le_defaut(self):
        # `exec_mode` ne lève jamais : c'est validate_server qui refuse à
        # l'écriture. Ici, on veut surtout ne pas produire un mode inventé.
        for mauvais in ("SU", "sudo-u", "root", 42, ""):
            self.assertEqual(dashlib.exec_mode({"exec_mode": mauvais}), "su", repr(mauvais))

    def test_meme_lecture_partout(self):
        # collect.py et actions_server.py partagent la fonction de dashlib :
        # deux copies qui divergent, c'est un serveur qui se collecte dans un
        # mode et s'actionne dans un autre.
        self.assertIs(collect.exec_mode, dashlib.exec_mode)
        self.assertIs(A.exec_mode, dashlib.exec_mode)


# --------------------------------------------------------------------------- #
#  Commande distante produite par chaque mode                                  #
# --------------------------------------------------------------------------- #
class TestCommandeDistante(unittest.TestCase):

    SU = 'timeout 60 su -s /bin/bash "$OWN" -c "$1" 2>&1'
    SUDO = 'out=$(timeout 60 sudo -n -u "$OWN" /bin/bash -c "$1" 2>&1); rc=$?'
    DIRECT = 'timeout 60 bash -c "$1" 2>&1'

    def test_les_trois_branches_sont_ecrites_une_fois_pour_toutes(self):
        # Les trois branches figurent dans le script ; c'est `MODE` qui tranche
        # à l'exécution. On vérifie donc la VALEUR de MODE, puis (plus bas) le
        # comportement réel avec un faux sudo / su.
        for mode in ("su", "direct", "sudo"):
            s = script_wp(mode)
            self.assertIn(f"MODE={mode}\n", s)
            self.assertIn(self.SU, s)
            self.assertIn(self.SUDO, s)
            self.assertIn(self.DIRECT, s)

    def test_mode_pose_par_le_serveur(self):
        appels = []

        def faux(server, script, timeout=300, max_out=6000):
            appels.append(script)
            return 0, "ok"

        with mock.patch.object(A, "run_remote_script", faux):
            for serveur, attendu in ((srv(), "su"), (srv("direct"), "direct"),
                                     (srv("sudo"), "sudo"), ({**srv(), "no_su": True}, "direct")):
                appels.clear()
                A.run_wp_remote(serveur, SITE, "core version", timeout=60)
                self.assertIn(f"MODE={attendu}\n", appels[0])

    def test_allow_root_seulement_quand_wp_finit_en_root(self):
        # « direct » ne doit JAMAIS ajouter --allow-root : sur un mutualisé le
        # compte de connexion n'est pas root, et wp-cli refuserait l'option.
        for s in (script_wp("su"), script_wp("sudo"), script_wp("direct")):
            self.assertIn('case "$MODE" in su|sudo) [ "$OWN" = "root" ] && extra="--allow-root" ;; esac', s)

    def test_les_trois_gabarits_portent_le_mode(self):
        dep = A.REMOTE_DEPLOY_TEMPLATE.format(docroot="'/d'", owner="'www-data'", mode="sudo",
                                              fname="x.php", marker="M", content="<?php", timeout=60)
        rem = A.REMOTE_REMOVE_TEMPLATE.format(docroot="'/d'", owner="'www-data'", mode="sudo",
                                              fname="x.php", timeout=60)
        for s in (script_wp("sudo"), dep, rem):
            self.assertIn("MODE=sudo\n", s)
            self.assertIn(self.SUDO, s)

    def test_chown_du_mu_plugin_reserve_au_mode_su(self):
        # En « direct » et en « sudo », le fichier vient d'être créé PAR le
        # compte du site : le chown est inutile, et il échouerait faute de root.
        dep = A.REMOTE_DEPLOY_TEMPLATE.format(docroot="'/d'", owner="'www-data'", mode="sudo",
                                              fname="x.php", marker="M", content="<?php", timeout=60)
        self.assertIn('if [ "$MODE" = "su" ]; then', dep)
        self.assertIn('chown "$OWN":"$GRP" "$F"', dep)

    def test_repli_php_plesk_passe_par_asuser(self):
        # Le repli « wp cassé par la version de PHP » relance php explicitement :
        # il doit repasser par asuser, sinon il tourne sous le mauvais compte.
        for s in (script_wp("sudo"), collect.REMOTE_SCRIPT):
            self.assertIn('asuser "$base $php -d display_errors=0', s)

    def test_aucun_su_en_dur_hors_de_la_branche_su(self):
        """Aucun chemin du script ne bascule de compte sans passer par asuser.

        C'est la vraie garantie : `su -s` et `sudo -n -u` n'apparaissent QUE
        dans `asuser` / `asuser_bin`, jamais recopiés ailleurs.
        """
        for nom, s, t in (("REMOTE_TEMPLATE", script_wp("sudo"), 60),
                          ("collect", collect.REMOTE_SCRIPT, 75)):
            permis = {
                f'timeout {t} su -s /bin/bash "$OWN" -c "$1" 2>&1',
                f'timeout {t} su -s /bin/bash "$OWN" -c "$1"',
                f'out=$(timeout {t} sudo -n -u "$OWN" /bin/bash -c "$1" 2>&1); rc=$?',
                f'timeout {t} sudo -n -u "$OWN" /bin/bash -c "$1"',
            }
            lignes = [ligne.strip() for ligne in s.splitlines()
                      if ("su -s /bin/bash" in ligne or "sudo -n -u" in ligne)
                      and not ligne.strip().startswith("#")]
            self.assertTrue(lignes, nom)
            for ligne in lignes:
                # une branche de `case` porte son étiquette (« sudo)   … ;; »)
                nue = re.sub(r"^\S*\)\s*", "", ligne)
                nue = re.sub(r"\s*;;$", "", nue)
                self.assertIn(nue, permis,
                              f"{nom} : bascule de compte hors d'asuser → {ligne}")

    def test_archives_et_restaurations_ne_supposent_plus_root(self):
        # tar/rm bruts dans les fichiers du site : ils tournaient en root. Ils
        # passent désormais par tar_site / untar_site / onsite, qui savent
        # basculer vers le compte du site quand le mode l'exige.
        s = script_wp("sudo", body="")
        for helper in ("tar_site()", "untar_site()", "onsite()", "asuser_bin()"):
            self.assertIn(helper, s)


# --------------------------------------------------------------------------- #
#  Comportement RÉEL du script, avec un faux sudo / su / wp                    #
# --------------------------------------------------------------------------- #
class TestExecutionReelle(unittest.TestCase):
    """Le script est exécuté par bash, avec sudo/su/wp/timeout remplacés.

    C'est ce qui prouve que le mode « sudo » appelle bien `sudo -n -u <compte>`
    et non `su`, et que le refus de sudoers produit la phrase attendue.
    """

    FAUX = {
        "timeout": '#!/bin/bash\nshift; exec "$@"\n',
        "sudo": ('#!/bin/bash\n'
                 'echo "APPEL:sudo $*" >> "$TRACE"\n'
                 'if [ -n "$SUDO_REFUSE" ]; then echo "sudo: a password is required" >&2; exit 1; fi\n'
                 'shift 3; exec "$@"\n'),
        "su": '#!/bin/bash\necho "APPEL:su $*" >> "$TRACE"\nshift 4; exec bash -c "$1"\n',
        "wp": '#!/bin/bash\necho 6.7.1\n',
    }

    def setUp(self):
        import tempfile
        # Garde-fou d'environnement : sur certaines machines (macOS + une
        # limite RLIMIT_NOFILE d'un million), lancer un processus après la
        # suite complète finit en SIGSEGV dans l'enfant — rien à voir avec le
        # script testé. `close_fds=False` (cf. `run_bash`) l'évite ; si malgré
        # tout bash ne démarre pas, on saute ces cas-là en le DISANT plutôt que
        # de rendre la suite instable.
        sonde = run_bash(["/bin/bash", "-c", "echo ok"])
        if sonde.returncode != 0 or sonde.stdout.strip() != "ok":
            self.skipTest("bash injoignable depuis cet interpréteur "
                          f"(rc {sonde.returncode}) — exécution réelle non testable ici")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(os.path.join(self.tmp.name, "docroot"))
        os.makedirs(self.bin)
        for nom, corps in self.FAUX.items():
            p = os.path.join(self.bin, nom)
            with open(p, "w") as fh:
                fh.write(corps)
            os.chmod(p, 0o755)
        self.trace = os.path.join(self.tmp.name, "trace")

    def lancer(self, mode, **env):
        script = A.REMOTE_TEMPLATE.format(
            docroot=A.sq(os.path.join(self.tmp.name, "docroot")), domain="'a.fr'",
            owner="'sitely'", mode=mode, timeout=60, body="run core version")
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"],
                 TRACE=self.trace, **env)
        r = run_bash(["/bin/bash", "-s"], input=script, env=e)
        appels = ""
        if os.path.exists(self.trace):
            with open(self.trace) as fh:
                appels = fh.read()
        return r, appels

    def test_su_bascule_par_su(self):
        r, appels = self.lancer("su")
        self.assertIn("APPEL:su -s /bin/bash sitely -c", appels)
        self.assertNotIn("APPEL:sudo", appels)

    def test_direct_ne_bascule_pas(self):
        r, appels = self.lancer("direct")
        self.assertEqual(appels, "")
        self.assertIn("6.7.1", r.stdout)

    def test_sudo_bascule_par_sudo_n(self):
        r, appels = self.lancer("sudo")
        self.assertIn("APPEL:sudo -n -u sitely /bin/bash -c", appels)
        self.assertNotIn("APPEL:su ", appels)
        self.assertIn("6.7.1", r.stdout)

    def test_sudo_refuse_donne_un_message_comprehensible(self):
        r, _ = self.lancer("sudo", SUDO_REFUSE="1")
        sortie = r.stdout + r.stderr
        self.assertIn("n’a pas le droit d’exécuter wp en tant que sitely", sortie)
        self.assertIn(dashlib.SUDO_DENIED_MARK, sortie)
        # …et surtout pas le charabia de sudo, qui envoie chercher ailleurs.
        self.assertNotIn("a password is required", sortie)
        self.assertTrue(dashlib.sudo_denied(sortie))

    def test_sudo_absent_dit_pourquoi(self):
        os.remove(os.path.join(self.bin, "sudo"))
        # PATH réduit au faux répertoire : le vrai sudo du système ne doit pas
        # prendre le relais et demander un mot de passe pendant les tests.
        script = A.REMOTE_TEMPLATE.format(
            docroot=A.sq(os.path.join(self.tmp.name, "docroot")), domain="'a.fr'",
            owner="'sitely'", mode="sudo", timeout=60, body="run core version")
        r = run_bash(["/bin/bash", "-s"], input=script,
                     env={"PATH": self.bin, "TRACE": self.trace})
        self.assertIn("sudo absent du serveur", r.stdout + r.stderr)


# --------------------------------------------------------------------------- #
#  Collecteur : le mode part bien dans la commande ssh                         #
# --------------------------------------------------------------------------- #
class TestCollecteur(unittest.TestCase):

    def argument_mode(self, server):
        vus = {}

        def faux_run(cmd, **kw):
            vus["cmd"] = cmd
            raise collect.subprocess.TimeoutExpired("ssh", 1)

        with mock.patch.object(collect.subprocess, "run", faux_run):
            collect.ssh_collect(server, [], 0, "")
        # bash -s -- <limit> <match> <mode> <parallel> <patterns…>
        return vus["cmd"][-1].split()[5]

    def test_mode_transmis_au_script_distant(self):
        self.assertEqual(self.argument_mode(srv()), "'su'")
        self.assertEqual(self.argument_mode(srv("direct")), "'direct'")
        self.assertEqual(self.argument_mode(srv("sudo")), "'sudo'")
        self.assertEqual(self.argument_mode({**srv(), "no_su": True}), "'direct'")

    def test_script_distant_lit_le_mode_en_troisieme_argument(self):
        self.assertIn('MODE="${3:-su}"', collect.REMOTE_SCRIPT)
        # Repli sur l'ancien « 1 »/« 0 » : une collecte lancée avec un script
        # neuf mais des arguments anciens ne doit pas basculer en root.
        self.assertIn('case "$MODE" in 1) MODE=direct ;; 0|"") MODE=su ;; esac',
                      collect.REMOTE_SCRIPT)


# --------------------------------------------------------------------------- #
#  Validation du champ                                                         #
# --------------------------------------------------------------------------- #
class TestValidation(unittest.TestCase):

    def test_accepte_les_trois_valeurs_et_l_absence(self):
        for m in (None, "", "su", "direct", "sudo"):
            s = srv()
            if m is not None:
                s["exec_mode"] = m
            ok, err = A.validate_server(s)
            self.assertTrue(ok, f"{m!r} refusé : {err}")

    def test_refuse_une_valeur_inconnue_avec_un_message_clair(self):
        for mauvais in ("SU", "sudo -u", "root", "direct ", 1, True):
            ok, err = A.validate_server(srv(mauvais))
            self.assertFalse(ok, repr(mauvais))
            self.assertIn("exec_mode invalide", err)
            self.assertIn("su, direct, sudo", err)

    def test_no_su_reste_accepte(self):
        ok, err = A.validate_server({**srv(), "no_su": True})
        self.assertTrue(ok, err)

    def test_l_exemple_du_depot_reste_valide(self):
        with open(os.path.join(REPO, "servers.example.json")) as fh:
            exemples = json.load(fh)
        modes = {s.get("exec_mode") for s in exemples}
        self.assertIn("sudo", modes)     # l'exemple montre le mode sans root
        for s in exemples:
            if s.get("key"):
                continue                 # clé absente de cette machine
            ok, err = A.validate_server(s)
            self.assertTrue(ok, f"{s.get('name')} refusé : {err}")


# --------------------------------------------------------------------------- #
#  « Tester la connexion » : SSH d'un côté, mode de l'autre                     #
# --------------------------------------------------------------------------- #
class TestRouteTest(BaseTmp):

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.root, "servers.json"), "w") as fh:
            json.dump([srv("sudo")], fh)
        with open(os.path.join(self.data, "fleet.json"), "w") as fh:
            json.dump({"servers": [{"name": "s1", "sites": [SITE]}]}, fh)
        self.srvh = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srvh.server_address[1]
        threading.Thread(target=self.srvh.serve_forever, daemon=True).start()
        self.addCleanup(self.srvh.shutdown)
        self.addCleanup(self.srvh.server_close)
        self.cookie = "dash_session=" + A.make_token("tommy")
        self.cle = os.path.join(A.SSH_DIR, "id_dash_essai")

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

    def appeler(self, ssh_rc, ssh_out, script_rc=0, script_out="6.7.1", corps=None):
        """POST /api/mgmt/sshkeys/test avec la session ssh ET le script bouchonnés."""
        vus = {}

        class R:
            returncode, stdout, stderr = ssh_rc, ssh_out, ""

        def faux_script(server, script, timeout=300, max_out=6000):
            vus["script"] = script
            return script_rc, script_out

        with mock.patch.object(A, "valid_key_path", lambda k: True), \
             mock.patch.object(A.subprocess, "run", lambda *a, **k: R()), \
             mock.patch.object(A, "run_remote_script", faux_script):
            st, j = self.post("/api/mgmt/sshkeys/test",
                              corps or {"server": "s1", "key": self.cle})
        return st, j, vus

    def test_ssh_en_echec_ne_teste_pas_le_mode(self):
        st, j, vus = self.appeler(255, "Permission denied (publickey).")
        self.assertEqual(st, 200)
        self.assertFalse(j["ok"])
        self.assertNotIn("script", vus)          # aucun wp lancé pour rien
        self.assertNotIn("mode_ok", j)

    def test_ssh_ok_et_mode_ok(self):
        st, j, vus = self.appeler(0, "OK depuis vps")
        self.assertTrue(j["ok"])
        self.assertTrue(j["mode_ok"])
        self.assertTrue(j["mode_checked"])
        self.assertFalse(j["mode_sudo"])
        self.assertEqual(j["mode"], "sudo")
        self.assertIn("run core version", vus["script"])
        self.assertIn("MODE=sudo\n", vus["script"])

    def test_echec_sudo_distinct_d_un_echec_ssh(self):
        refus = ("le compte wpdash n’a pas le droit d’exécuter wp en tant que "
                 "www-data : règle sudoers manquante")
        st, j, _ = self.appeler(0, "OK", script_rc=95, script_out=refus)
        self.assertTrue(j["ok"])            # la session SSH, elle, fonctionne
        self.assertFalse(j["mode_ok"])
        self.assertTrue(j["mode_sudo"])     # …c'est bien sudo qui refuse
        self.assertIn("règle sudoers manquante", j["mode_output"])

    def test_mode_du_formulaire_prime_sur_l_enregistre(self):
        # Le serveur est enregistré en « sudo » ; l'utilisateur essaie « su »
        # dans le formulaire avant d'enregistrer.
        st, j, vus = self.appeler(0, "OK", corps={"server": "s1", "key": self.cle,
                                                 "exec_mode": "su"})
        self.assertEqual(j["mode"], "su")
        self.assertIn("MODE=su\n", vus["script"])

    def test_mode_non_verifiable_sans_site_collecte(self):
        with open(os.path.join(self.data, "fleet.json"), "w") as fh:
            json.dump({"servers": [{"name": "s1", "sites": []}]}, fh)
        st, j, vus = self.appeler(0, "OK")
        self.assertTrue(j["ok"])
        self.assertFalse(j["mode_checked"])
        self.assertNotIn("script", vus)
        self.assertIn("lancez une collecte", j["mode_output"])


# --------------------------------------------------------------------------- #
#  Erreurs PHP : journal illisible sans root                                   #
# --------------------------------------------------------------------------- #
class TestJournauxIllisibles(unittest.TestCase):
    """Sans root, /var/log/nginx/<dom>.error.log est en <compte>:adm 640.

    Le fichier EXISTE (donc `[ -f ]` passe) mais ne s'ouvre pas : l'analyse
    revenait vide, ce qui se lit « aucune erreur PHP » — le contraire de la
    vérité. Elle doit rester non bloquante, mais dire pourquoi.
    """

    LIGNE = ('@@NGINX@@a.fr\t2099/01/01 10:00:00 [error] 1#1: *1 FastCGI sent in stderr: '
             '"PHP message: PHP Warning:  Ceci in /var/www/a.fr/x.php on line 3"')

    def scan(self, sortie):
        with mock.patch.object(phperrors, "_run_remote", lambda *a, **k: (0, sortie)):
            return phperrors.remote_scan({"name": "s1"}, ["a.fr"], 24)

    def test_script_ne_lit_pas_un_journal_illisible_en_silence(self):
        s = phperrors.build_script(["a.fr"], 24)
        self.assertIn('if [ ! -r "$f" ]; then', s)
        self.assertIn("@@ILLISIBLE@@", s)
        self.assertIn("@@JOURNAUX@@$VUS|$LUS", s)

    def test_aucun_journal_lisible(self):
        lignes, err, _ = self.scan(
            "@@FENETRE@@1\n"
            "@@ILLISIBLE@@/var/log/nginx/a.fr.error.log\n"
            "@@JOURNAUX@@1|0\n@@FIN@@\n")
        self.assertEqual(lignes, [])
        self.assertIn(phperrors.ILLISIBLE_MSG, err)
        self.assertIn("groupe adm", err)
        self.assertIn("AUCUN journal lisible", err)
        self.assertIn("/var/log/nginx/a.fr.error.log", err)

    def test_journal_illisible_partiel_reste_non_bloquant(self):
        lignes, err, _ = self.scan(
            "@@FENETRE@@1\n"
            "@@ILLISIBLE@@/var/log/plesk-php82-fpm/error.log\n"
            + self.LIGNE + "\n@@JOURNAUX@@2|1\n@@FIN@@\n")
        self.assertEqual(len(lignes), 1)                 # ce qui est lisible est analysé
        self.assertEqual(lignes[0]["domain"], "a.fr")
        self.assertIn(phperrors.ILLISIBLE_MSG, err)
        self.assertIn("1 journal(aux) ignoré(s)", err)
        self.assertNotIn("AUCUN", err)

    def test_tout_lisible_ne_signale_rien(self):
        lignes, err, _ = self.scan(
            "@@FENETRE@@1\n" + self.LIGNE + "\n@@JOURNAUX@@1|1\n@@FIN@@\n")
        self.assertEqual(len(lignes), 1)
        self.assertIsNone(err)

    def test_le_message_atterrit_dans_servers_failed(self):
        # `main()` recopie l'erreur d'un serveur dans servers_failed sans la
        # confondre avec un échec de connexion : les deux passent par le même
        # canal, c'est le message qui distingue.
        self.assertIsNotNone(phperrors.message_illisibles(["/var/log/nginx/a.fr.error.log"], 0))
        self.assertIsNone(phperrors.message_illisibles([], 3))

    def test_beaucoup_de_journaux_sont_comptes_plutot_qu_alignes(self):
        msg = phperrors.message_illisibles([f"/var/log/nginx/s{i}.error.log" for i in range(9)], 0)
        self.assertIn("(+6)", msg)
        self.assertLess(len(msg), 400)


if __name__ == "__main__":
    unittest.main()
