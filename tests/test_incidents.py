#!/usr/bin/env python3
"""Tests de la file « à traiter » : GET /api/incidents et GET /api/mgmt/counts.

Aucune sortie réseau, aucun ssh, aucun docker : `kuma_sql` et `ssl_certs` sont
bouchés, toutes les sources sont des fixtures JSON écrites dans un répertoire
temporaire. Les seuls sockets ouverts le sont sur 127.0.0.1 par les tests qui
vérifient la garde de session.

    python3 -m unittest tests.test_incidents -v
"""
import datetime
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import actions_server as A            # noqa: E402

HEURE = 3600.0


def ts_local(epoch):
    """Epoch → « YYYY-MM-DD HH:MM:SS » local, format des fichiers du dépôt."""
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def ts_utc(epoch):
    """Epoch → « YYYY-MM-DD HH:MM:SS » UTC, format de la colonne `time` de Kuma."""
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def site(domain, **extra):
    """Site de fleet.json : visible par défaut (il porte un moniteur Kuma)."""
    s = {"domain": domain, "kuma": domain, "via": "ssh", "php_version": "8.2.10",
         "core_update": "", "plugins_updates": 0, "themes_updates": 0}
    s.update(extra)
    return s


class IncidentsBase(unittest.TestCase):
    """Toutes les sources redirigées vers un répertoire jetable et bouchées."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.data = os.path.join(self.root, "data")
        os.makedirs(self.data)
        self._sauv = {k: getattr(A, k) for k in
                      ("BASE", "DATA", "FLEET_PATH", "PHPERR_PATH", "VULNS_FOUND_PATH",
                       "CHECKSUMS_PATH", "SETTINGS_PATH", "SESSION_SECRET_PATH", "LOG",
                       "ACKS_PATH")}
        A.BASE = self.root
        A.DATA = self.data
        A.FLEET_PATH = os.path.join(self.data, "fleet.json")
        A.PHPERR_PATH = os.path.join(self.data, "php_errors.json")
        A.VULNS_FOUND_PATH = os.path.join(self.data, "vulns_found.json")
        A.CHECKSUMS_PATH = os.path.join(self.data, "checksums.json")
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        A.SESSION_SECRET_PATH = os.path.join(self.data, ".session_secret")
        A.LOG = os.path.join(self.data, "actions.log")
        A.ACKS_PATH = os.path.join(self.data, "incident_acks.json")
        A._SESSION_SECRET = None
        A._JSON_LOCKS.clear()
        self.addCleanup(self._restaurer)
        self.vider_cache()

        # Kuma : aucun battement, aucun certificat, tant qu'un test n'en pose pas.
        self.battements = {}
        self.certs = {"certs": []}
        self.sql = []
        for cible, valeur in (("kuma_sql", self._kuma_sql),
                              ("ssl_certs", lambda: self.certs)):
            p = mock.patch.object(A, cible, valeur)
            p.start()
            self.addCleanup(p.stop)

    def _restaurer(self):
        for k, v in self._sauv.items():
            setattr(A, k, v)
        A._SESSION_SECRET = None
        A._JSON_LOCKS.clear()
        self.vider_cache()

    @staticmethod
    def vider_cache():
        A._INCIDENTS_CACHE.update({"ts": 0.0, "payload": None, "extra": None})

    def _kuma_sql(self, sql):
        """Rend les battements posés par le test, au format tabulé de kuma_sql."""
        self.sql.append(sql)
        # 5e colonne = `active` du moniteur (0 = en pause), comme la requête
        # réelle : c'est elle qui distingue « injoignable » de « surveillance
        # coupée exprès ».
        lignes = ["\t".join((nom, str(hb.get("status", 1)), hb.get("time", ""),
                             hb.get("msg", ""), "0" if hb.get("active") is False else "1"))
                  for nom, hb in self.battements.items()]
        return 0, "\n".join(lignes)

    # ---- fixtures -------------------------------------------------------- #
    def poser_fleet(self, *serveurs):
        A.save_json(A.FLEET_PATH, {"servers": list(serveurs)})

    def serveur(self, nom="vps1", sites=(), **extra):
        e = {"name": nom, "host": "1.2.3.4", "complete": True, "sites": list(sites)}
        e.update(extra)
        return e

    def poser_json(self, chemin, obj):
        A.save_json(chemin, obj)

    def reglages(self, **rules):
        A.save_json(A.SETTINGS_PATH, {"incident_rules": rules})

    # ---- raccourcis ------------------------------------------------------ #
    def snapshot(self):
        payload, extra = A.incidents_snapshot()
        self.assertEqual(payload["errors"], [], "source en échec inattendue")
        return payload, extra

    def kinds(self):
        return [i["kind"] for i in self.snapshot()[0]["incidents"]]

    def par_kind(self, kind):
        return [i for i in self.snapshot()[0]["incidents"] if i["kind"] == kind]

    def bucket(self, kind):
        """Le `bucket` du premier incident de ce type (échoue s'il n'y en a pas)."""
        lot = self.par_kind(kind)
        self.assertTrue(lot, f"aucun incident « {kind} » dans les fixtures")
        return lot[0]["bucket"]

    # ---- acquittements ---------------------------------------------------- #
    def acquitter(self, inc_id, mode="ignore", jours=None, raison="", empreinte=None,
                  vu=None):
        """Écrit une entrée d'acquittement, empreinte calculée si non fournie."""
        if empreinte is None:
            p = A.incidents_snapshot()[0]
            inc = next((i for i in p["incidents"] + p["acked"] if i["id"] == inc_id), None)
            empreinte = A.incident_fingerprint(inc) if inc else ""
        e = A.incident_ack_write(
            inc_id, mode, (time.time() + jours * 86400) if jours else None,
            raison, "tommy", empreinte)
        if vu is not None:                # « vu à » forcé, pour éprouver la purge
            def _muter(cur):
                cur[inc_id]["last_seen"] = vu
                return cur
            A.update_json(A.ACKS_PATH, _muter, {})
        self.vider_cache()
        return e


# --------------------------------------------------------------------------- #
#  down : dernier battement Kuma                                               #
# --------------------------------------------------------------------------- #
class TestDown(IncidentsBase):

    def test_battement_en_echec_donne_un_incident_critique(self):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.battements = {"elwave.fr": {"status": 0, "time": ts_utc(time.time() - 9 * HEURE),
                                         "msg": "timeout of 48000ms exceeded"}}
        inc = self.par_kind("down")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "critical")
        self.assertEqual(inc[0]["site"], "elwave.fr")
        self.assertEqual(inc[0]["server"], "vps1")
        self.assertEqual(inc[0]["action"], {"label": "Re-scan", "act": "rescan", "arg": ""})
        self.assertIn("timeout", inc[0]["detail"])
        self.assertAlmostEqual(inc[0]["age_h"], 9, delta=0.2)
        self.assertIsNotNone(inc[0]["since"])

    def test_battement_ok_ne_declenche_rien(self):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.battements = {"elwave.fr": {"status": 1, "time": ts_utc(time.time())}}
        self.assertEqual(self.par_kind("down"), [])

    def test_site_non_visible_ignore(self):
        # `visible: False` = masqué explicitement dans data/overrides.json
        self.poser_fleet(self.serveur(sites=[site("masque.fr", visible=False)]))
        self.battements = {"masque.fr": {"status": 0, "time": ts_utc(time.time())}}
        self.assertEqual(self.par_kind("down"), [])

    def test_site_sans_moniteur_ignore(self):
        self.poser_fleet(self.serveur(sites=[{"domain": "rest.fr", "via": "rest",
                                              "kuma": None}]))
        self.battements = {"rest.fr": {"status": 0, "time": ts_utc(time.time())}}
        self.assertEqual(self.par_kind("down"), [])

    def test_lecture_des_battements_passe_par_une_seule_requete(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr"), site("b.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time())}}
        self.snapshot()
        self.assertEqual(len(self.sql), 1, self.sql)
        self.assertIn("heartbeat", self.sql[0])
        self.assertIn("MAX(id)", self.sql[0])


# --------------------------------------------------------------------------- #
#  php_fatal                                                                   #
# --------------------------------------------------------------------------- #
class TestPhpFatal(IncidentsBase):

    def poser(self, severity="Fatal error", domain="elwave.fr"):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.poser_json(A.PHPERR_PATH, {"window_hours": 24, "sites": [
            {"domain": domain, "groups": [
                {"severity": severity, "message": "Call to undefined function x()",
                 "file": "/var/www/wp-content/plugins/z/z.php", "short": "wp-content/plugins/z/z.php",
                 "line": 42, "count": 17, "first": ts_local(time.time() - 5 * HEURE),
                 "last": ts_local(time.time())}]}]})

    def test_erreur_fatale_donne_un_incident(self):
        self.poser()
        inc = self.par_kind("php_fatal")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "critical")
        self.assertIn("Call to undefined function x()", inc[0]["detail"])
        self.assertIn("wp-content/plugins/z/z.php:42", inc[0]["detail"])
        self.assertIn("×17", inc[0]["detail"])
        self.assertEqual(inc[0]["link"], {"tab": "securite", "sub": "phperrors"})
        self.assertAlmostEqual(inc[0]["age_h"], 5, delta=0.2)

    def test_avertissement_ne_declenche_pas(self):
        self.poser(severity="Warning")
        self.assertEqual(self.par_kind("php_fatal"), [])

    def test_parse_error_compte_aussi(self):
        self.poser(severity="Parse error")
        self.assertEqual(len(self.par_kind("php_fatal")), 1)

    def test_site_hors_parc_ignore(self):
        self.poser(domain="inconnu.fr")
        self.assertEqual(self.par_kind("php_fatal"), [])


# --------------------------------------------------------------------------- #
#  vuln_critical_fixable                                                       #
# --------------------------------------------------------------------------- #
class TestVulns(IncidentsBase):

    @staticmethod
    def trouvaille(severity="critical", update_to="3.100.2", component="ml-slider",
                   kind="plugin"):
        return {"kind": kind, "component": component, "version": "3.100.1",
                "title": "Stored XSS", "cve": "CVE-2026-1", "severity": severity,
                "update_to": update_to}

    def poser(self, *findings, **kw):
        self.poser_fleet(self.serveur(sites=[site("ffhbi.fr", **kw)]))
        self.poser_json(A.VULNS_FOUND_PATH, {"sites": [
            {"domain": "ffhbi.fr", "server": "vps1", "count": len(findings),
             "worst": "critical", "findings": list(findings)}]})

    def test_critique_corrigeable_donne_une_action_de_mise_a_jour(self):
        self.poser(self.trouvaille())
        inc = self.par_kind("vuln_critical_fixable")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["action"], {"label": "MAJ ml-slider → 3.100.2",
                                            "act": "plugin_update", "arg": "ml-slider"})
        self.assertIn("CVE-2026-1", inc[0]["detail"])
        self.assertEqual(inc[0]["id"], "vuln_critical_fixable:ffhbi.fr:ml-slider")

    def test_coeur_propose_core_update(self):
        self.poser(self.trouvaille(kind="core", component="WordPress", update_to="7.1"))
        inc = self.par_kind("vuln_critical_fixable")
        self.assertEqual(inc[0]["action"]["act"], "core_update")
        self.assertEqual(inc[0]["action"]["arg"], "")

    def test_sans_correctif_pas_d_incident(self):
        self.poser(self.trouvaille(update_to=""))
        self.assertEqual(self.par_kind("vuln_critical_fixable"), [])

    def test_high_ignore_par_defaut(self):
        self.poser(self.trouvaille(severity="high"))
        self.assertEqual(self.par_kind("vuln_critical_fixable"), [])

    def test_high_compte_si_le_reglage_est_actif(self):
        self.poser(self.trouvaille(severity="high"))
        self.reglages(vuln_high_is_incident=True)
        self.assertEqual(len(self.par_kind("vuln_critical_fixable")), 1)

    def test_une_seule_entree_par_site_et_composant(self):
        self.poser(self.trouvaille(), self.trouvaille(update_to="3.100.3"))
        self.assertEqual(len(self.par_kind("vuln_critical_fixable")), 1)

    def test_site_rest_garde_l_incident_sans_action(self):
        self.poser(self.trouvaille(), via="rest")
        inc = self.par_kind("vuln_critical_fixable")
        self.assertEqual(len(inc), 1)
        self.assertIsNone(inc[0]["action"])


# --------------------------------------------------------------------------- #
#  checksums_modified                                                          #
# --------------------------------------------------------------------------- #
class TestChecksums(IncidentsBase):

    SORTIE = ("Warning: File doesn't verify against checksum: wp-admin/a.php\n"
              "Warning: File doesn't verify against checksum: wp-includes/b.php")

    def poser(self, ok):
        self.poser_fleet(self.serveur(sites=[site("terracandido.fr")]))
        self.poser_json(A.CHECKSUMS_PATH, {"terracandido.fr": {
            "ts": ts_local(time.time() - 30 * HEURE), "ok": ok, "output_tail": self.SORTIE}})

    def test_verification_en_echec_donne_un_incident_critique(self):
        self.poser(False)
        inc = self.par_kind("checksums_modified")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "critical")
        self.assertIn("2 fichier(s)", inc[0]["detail"])
        self.assertEqual(inc[0]["link"], {"tab": "securite", "sub": "checksums"})
        self.assertAlmostEqual(inc[0]["age_h"], 30, delta=0.2)

    def test_verification_reussie_ne_declenche_rien(self):
        self.poser(True)
        self.assertEqual(self.par_kind("checksums_modified"), [])

    def test_site_hors_parc_ignore(self):
        self.poser_fleet(self.serveur(sites=[site("autre.fr")]))
        self.poser_json(A.CHECKSUMS_PATH, {"disparu.fr": {"ts": ts_local(time.time()),
                                                          "ok": False, "output_tail": ""}})
        self.assertEqual(self.par_kind("checksums_modified"), [])


# --------------------------------------------------------------------------- #
#  admin_unknown                                                               #
# --------------------------------------------------------------------------- #
class TestAdmins(IncidentsBase):

    def poser(self, logins_reference, admins):
        self.poser_fleet(self.serveur(sites=[site("la-kage.fr", admins=admins)]))
        if logins_reference is not None:
            self.poser_json(os.path.join(A.DATA, "admins_baseline.json"),
                            {"la-kage.fr": {"logins": logins_reference,
                                            "set_at": "2026-08-24 10:00"}})

    def test_compte_absent_de_la_reference(self):
        self.poser(["tommy"], [{"login": "tommy"}, {"login": "adminlin",
                                                    "registered": ts_local(time.time() - 72 * HEURE)}])
        inc = self.par_kind("admin_unknown")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["id"], "admin_unknown:la-kage.fr:adminlin")
        self.assertIn("adminlin", inc[0]["detail"])
        self.assertAlmostEqual(inc[0]["age_h"], 72, delta=0.2)

    def test_comptes_connus_ne_declenchent_rien(self):
        self.poser(["tommy", "client"], [{"login": "tommy"}, {"login": "client"}])
        self.assertEqual(self.par_kind("admin_unknown"), [])

    def test_site_sans_reference_ignore(self):
        self.poser(None, [{"login": "inconnu"}])
        self.assertEqual(self.par_kind("admin_unknown"), [])


# --------------------------------------------------------------------------- #
#  server_stale                                                                #
# --------------------------------------------------------------------------- #
class TestServerStale(IncidentsBase):

    def test_serveur_injoignable_donne_un_avertissement(self):
        self.poser_fleet(self.serveur("legacy", [site("vieux.fr")], stale=True,
                                      complete=False, error="ssh: connection timed out",
                                      last_attempt=ts_local(time.time() - 12 * HEURE)))
        inc = self.par_kind("server_stale")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "warning")
        self.assertEqual(inc[0]["server"], "legacy")
        self.assertEqual(inc[0]["site"], "")
        self.assertIsNone(inc[0]["action"])
        self.assertIn("connection timed out", inc[0]["detail"])
        self.assertAlmostEqual(inc[0]["age_h"], 12, delta=0.2)

    def test_serveur_sain_ne_declenche_rien(self):
        self.poser_fleet(self.serveur("vps1", [site("ok.fr")]))
        self.assertEqual(self.par_kind("server_stale"), [])


# --------------------------------------------------------------------------- #
#  backup_late                                                                 #
# --------------------------------------------------------------------------- #
class TestBackup(IncidentsBase):

    def poser(self, age_h=None, **kw):
        up = {"interval": 30, "service": "sftp"}
        if age_h is not None:
            up["last_backup_ts"] = time.time() - age_h * HEURE
        self.poser_fleet(self.serveur(sites=[site("sumotori.fr", updraft=up, **kw)]))

    def test_sauvegarde_recente_ne_declenche_rien(self):
        self.poser(age_h=9)
        self.assertEqual(self.par_kind("backup_late"), [])

    def test_au_dela_du_seuil_donne_un_avertissement(self):
        self.poser(age_h=70)
        inc = self.par_kind("backup_late")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "warning")
        self.assertEqual(inc[0]["action"], {"label": "Sauvegarder",
                                            "act": "updraft_backup", "arg": ""})
        self.assertIn("seuil 48 h", inc[0]["detail"])
        self.assertAlmostEqual(inc[0]["age_h"], 70, delta=0.2)

    def test_seuil_configurable(self):
        self.poser(age_h=70)
        self.reglages(backup_max_age_h=96)
        self.assertEqual(self.par_kind("backup_late"), [])

    def test_aucune_sauvegarde_connue(self):
        self.poser(age_h=None)
        inc = self.par_kind("backup_late")
        self.assertEqual(len(inc), 1)
        self.assertIn("aucune sauvegarde", inc[0]["detail"])
        self.assertIsNone(inc[0]["since"])
        self.assertEqual(inc[0]["age_h"], 0.0)

    def test_site_sans_updraft_ignore(self):
        self.poser_fleet(self.serveur(sites=[site("sansplugin.fr", updraft=None)]))
        self.assertEqual(self.par_kind("backup_late"), [])

    def test_site_rest_garde_l_incident_sans_action(self):
        self.poser(age_h=70, via="rest")
        inc = self.par_kind("backup_late")
        self.assertEqual(len(inc), 1)
        self.assertIsNone(inc[0]["action"])


# --------------------------------------------------------------------------- #
#  cert_expiring                                                               #
# --------------------------------------------------------------------------- #
class TestCerts(IncidentsBase):

    def poser(self, jours):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.certs = {"certs": [{"monitor": "elwave.fr", "days": jours,
                                 "valid_to": "2026-09-20T00:00:00Z"}]}

    def test_certificat_confortable_ne_declenche_rien(self):
        self.poser(60)
        self.assertEqual(self.par_kind("cert_expiring"), [])

    def test_sous_le_seuil_donne_un_avertissement(self):
        self.poser(14)
        inc = self.par_kind("cert_expiring")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "warning")
        self.assertEqual(inc[0]["server"], "vps1")
        self.assertIn("expire dans 14 jour(s)", inc[0]["detail"])

    def test_moins_de_sept_jours_est_critique(self):
        self.poser(3)
        self.assertEqual(self.par_kind("cert_expiring")[0]["severity"], "critical")

    def test_certificat_expire_est_critique(self):
        self.poser(-2)
        inc = self.par_kind("cert_expiring")
        self.assertEqual(inc[0]["severity"], "critical")
        self.assertIn("expiré depuis 2 jour(s)", inc[0]["detail"])

    def test_seuils_configurables(self):
        self.poser(14)
        self.reglages(cert_warn_days=10)
        self.assertEqual(self.par_kind("cert_expiring"), [])

    def test_jours_inconnus_ignores(self):
        self.poser(None)
        self.assertEqual(self.par_kind("cert_expiring"), [])


# --------------------------------------------------------------------------- #
#  php_eol                                                                     #
# --------------------------------------------------------------------------- #
class TestPhpEol(IncidentsBase):

    def test_une_entree_par_serveur_regroupant_les_sites(self):
        self.poser_fleet(
            self.serveur("plesk-legacy", [site("a.fr", php_version="7.4.33"),
                                          site("b.fr", php_version="7.4.30"),
                                          site("c.fr", php_version="8.3.1")]),
            self.serveur("vps1", [site("d.fr", php_version="8.2.10")]))
        inc = self.par_kind("php_eol")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "warning")
        self.assertEqual(inc[0]["server"], "plesk-legacy")
        self.assertEqual(inc[0]["site"], "")
        self.assertEqual(inc[0]["id"], "php_eol:plesk-legacy:7.4")
        self.assertIn("2 site(s)", inc[0]["detail"])
        self.assertIn("a.fr", inc[0]["detail"])
        self.assertNotIn("c.fr", inc[0]["detail"])

    def test_deux_versions_sur_le_meme_serveur_donnent_deux_entrees(self):
        self.poser_fleet(self.serveur("mutu", [site("a.fr", php_version="7.4.33"),
                                               site("b.fr", php_version="8.0.30")]))
        self.assertEqual(len(self.par_kind("php_eol")), 2)

    def test_version_supportee_ne_declenche_rien(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr", php_version="8.3.1")]))
        self.assertEqual(self.par_kind("php_eol"), [])

    def test_liste_configurable(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr", php_version="8.2.10")]))
        self.reglages(php_eol_versions=["8.2"])
        self.assertEqual(len(self.par_kind("php_eol")), 1)


# --------------------------------------------------------------------------- #
#  extra : le hors-ligne de chaque incident                                    #
# --------------------------------------------------------------------------- #
class TestExtra(IncidentsBase):
    """`extra` porte ce que `title`/`detail` ne peuvent pas dire en une ligne.

    Son contenu dépend du `kind` — c'est un dictionnaire libre, pas un schéma :
    ces tests fixent, pour chaque règle, les clés sur lesquelles l'interface
    s'appuie pour déplier un incident.
    """

    def test_php_fatal_recopie_la_pile_et_la_fenetre(self):
        self.poser_fleet(self.serveur(sites=[site("instantdhier.fr")]))
        self.poser_json(A.PHPERR_PATH, {"window_hours": 24, "sites": [
            {"domain": "instantdhier.fr", "groups": [
                {"severity": "Fatal error",
                 "message": "Uncaught Error: Call to undefined method WP_Error::get_method()",
                 "file": "/var/www/wp-includes/rest-api/class-wp-rest-server.php",
                 "short": "wp-includes/rest-api/class-wp-rest-server.php", "line": 1120,
                 "count": 5, "first": ts_local(time.time() - 8 * HEURE),
                 "last": ts_local(time.time()),
                 "sample_ts": ts_local(time.time()),
                 "trace": ["#0 /var/www/wp-includes/rest-api/class-wp-rest-server.php(1120): "
                           "WP_REST_Server->serve_batch_request_v1()",
                           "#4 /var/www/wp-includes/rest-api.php(420): "
                           "WP_REST_Server->serve_request('/batch/v1')"],
                 "trace_truncated": True}]}]})
        e = self.par_kind("php_fatal")[0]["extra"]
        self.assertEqual(len(e["trace"]), 2)
        self.assertIn("serve_batch_request_v1", e["trace"][0])
        self.assertTrue(e["trace_truncated"])
        self.assertEqual(e["count"], 5)
        self.assertEqual(e["line"], 1120)
        self.assertEqual(e["file"], "wp-includes/rest-api/class-wp-rest-server.php")
        self.assertTrue(e["first"] and e["last"] and e["sample_ts"])

    def test_php_fatal_sans_pile_garde_une_liste_vide(self):
        """Un groupe collecté avant la capture des piles ne doit pas casser."""
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.poser_json(A.PHPERR_PATH, {"sites": [{"domain": "a.fr", "groups": [
            {"severity": "Fatal error", "message": "boom", "file": "/a.php",
             "short": "a.php", "line": 3, "count": 1,
             "first": ts_local(time.time()), "last": ts_local(time.time())}]}]})
        e = self.par_kind("php_fatal")[0]["extra"]
        self.assertEqual(e["trace"], [])
        self.assertFalse(e["trace_truncated"])
        self.assertEqual(e["sample_ts"], "")

    def test_vuln_porte_les_cve_et_les_deux_versions(self):
        self.poser_fleet(self.serveur(sites=[site("ffhbi.fr")]))
        commun = {"kind": "plugin", "component": "ml-slider", "version": "3.100.1",
                  "severity": "critical", "update_to": "3.100.2"}
        self.poser_json(A.VULNS_FOUND_PATH, {"sites": [{"domain": "ffhbi.fr", "findings": [
            dict(commun, title="Stored XSS", cve="CVE-2026-1"),
            dict(commun, title="RCE", cve="CVE-2026-2"),
            {"kind": "plugin", "component": "autre", "version": "1.0",
             "severity": "critical", "update_to": "1.1", "cve": "CVE-2026-9",
             "title": "x"}]}]})
        e = [i for i in self.par_kind("vuln_critical_fixable")
             if i["extra"]["slug"] == "ml-slider"][0]["extra"]
        self.assertEqual(e["cve"], ["CVE-2026-1", "CVE-2026-2"])
        self.assertEqual((e["from"], e["to"]), ("3.100.1", "3.100.2"))

    def test_checksums_liste_les_fichiers_plafonnee_a_vingt(self):
        sortie = "\n".join(f"Warning: File doesn't verify against checksum: wp-admin/f{i}.php"
                           for i in range(25))
        self.poser_fleet(self.serveur(sites=[site("terracandido.fr")]))
        self.poser_json(A.CHECKSUMS_PATH, {"terracandido.fr": {
            "ts": ts_local(time.time()), "ok": False, "output_tail": sortie}})
        e = self.par_kind("checksums_modified")[0]["extra"]
        self.assertEqual(len(e["files"]), 20)
        self.assertEqual(e["files"][0], "wp-admin/f0.php")

    def test_admin_inconnu_porte_le_compte(self):
        self.poser_fleet(self.serveur(sites=[site("la-kage.fr", admins=[
            {"login": "adminlin", "email": "x@y.fr", "registered": "2026-08-11 04:12:00"}])]))
        self.poser_json(os.path.join(A.DATA, "admins_baseline.json"),
                        {"la-kage.fr": {"logins": ["tommy"]}})
        e = self.par_kind("admin_unknown")[0]["extra"]
        self.assertEqual(e, {"login": "adminlin", "email": "x@y.fr",
                             "registered": "2026-08-11 04:12:00"})

    def test_down_porte_le_message_du_moniteur(self):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.battements = {"elwave.fr": {"status": 0, "msg": "timeout of 48000ms exceeded",
                                         "time": ts_utc(time.time() - HEURE)}}
        e = self.par_kind("down")[0]["extra"]
        self.assertEqual(e["msg"], "timeout of 48000ms exceeded")
        self.assertTrue(e["since"])

    def test_serveur_injoignable_porte_l_erreur_ssh(self):
        essai = ts_local(time.time() - 3 * HEURE)
        self.poser_fleet(self.serveur("legacy", [site("v.fr")], stale=True,
                                      error="ssh: connect timeout", last_attempt=essai))
        self.assertEqual(self.par_kind("server_stale")[0]["extra"],
                         {"error": "ssh: connect timeout", "last_attempt": essai})

    def test_sauvegarde_en_retard_porte_age_et_destination(self):
        self.poser_fleet(self.serveur(sites=[site("sumotori.fr", updraft={
            "service": "sftp", "last_backup_ts": time.time() - 70 * HEURE})]))
        e = self.par_kind("backup_late")[0]["extra"]
        self.assertEqual(e["service"], "sftp")
        self.assertAlmostEqual(e["age_h"], 70, delta=0.2)
        self.assertTrue(e["last_backup"])

    def test_sauvegarde_jamais_faite_laisse_l_age_a_null(self):
        self.poser_fleet(self.serveur(sites=[site("sumotori.fr",
                                                  updraft={"service": "sftp"})]))
        e = self.par_kind("backup_late")[0]["extra"]
        self.assertIsNone(e["age_h"])
        self.assertEqual(e["last_backup"], "")

    def test_certificat_porte_les_jours_et_la_date(self):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.certs = {"certs": [{"monitor": "elwave.fr", "days": 6,
                                 "valid_to": "2026-09-09T00:00:00Z"}]}
        self.assertEqual(self.par_kind("cert_expiring")[0]["extra"],
                         {"days_left": 6, "expires": "2026-09-09T00:00:00Z"})

    def test_php_eol_porte_tous_les_sites_pas_seulement_les_douze_du_detail(self):
        self.poser_fleet(self.serveur("mutu", [site(f"s{i:02d}.fr", php_version="7.4.33")
                                               for i in range(15)]))
        e = self.par_kind("php_eol")[0]["extra"]
        self.assertEqual(e["version"], "7.4")
        self.assertEqual(len(e["sites"]), 15)


# --------------------------------------------------------------------------- #
#  tri, dédoublonnage, robustesse des sources                                   #
# --------------------------------------------------------------------------- #
class TestAgregation(IncidentsBase):

    def parc_complet(self):
        """Un incident de chaque famille utile au tri."""
        maintenant = time.time()
        self.poser_fleet(
            self.serveur("vps1", [
                site("down-recent.fr"),
                site("down-ancien.fr"),
                site("backup.fr", updraft={"last_backup_ts": maintenant - 100 * HEURE}),
            ]),
            self.serveur("legacy", [site("vieux.fr")], stale=True,
                         error="injoignable", last_attempt=ts_local(maintenant - 200 * HEURE)))
        self.battements = {
            "down-recent.fr": {"status": 0, "time": ts_utc(maintenant - 2 * HEURE), "msg": "500"},
            "down-ancien.fr": {"status": 0, "time": ts_utc(maintenant - 240 * HEURE), "msg": "dns"},
        }

    def test_critiques_avant_avertissements_puis_les_plus_anciens(self):
        self.parc_complet()
        inc = self.snapshot()[0]["incidents"]
        self.assertEqual([i["severity"] for i in inc],
                         ["critical", "critical", "warning", "warning"])
        self.assertEqual([i["id"] for i in inc[:2]],
                         ["down:down-ancien.fr:", "down:down-recent.fr:"])
        # parmi les avertissements : serveur stale (200 h) avant backup (100 h)
        self.assertEqual([i["kind"] for i in inc[2:]], ["server_stale", "backup_late"])

    def test_compteurs_coherents_avec_la_liste(self):
        self.parc_complet()
        payload = self.snapshot()[0]
        # 2 critiques (down) + 2 avertissements (serveur stale, sauvegarde) ;
        # le serveur stale est un chantier, il compte dans `plan` et PAS dans
        # la pastille.
        self.assertEqual(payload["counts"], {"critical": 2, "warning": 2,
                                             "now_critical": 2, "now_warning": 1,
                                             "plan": 1, "acked": 0})
        self.assertEqual(len(payload["incidents"]),
                         payload["counts"]["critical"] + payload["counts"]["warning"])
        self.assertEqual(len(payload["incidents"]),
                         payload["counts"]["now_critical"] + payload["counts"]["now_warning"]
                         + payload["counts"]["plan"])
        self.assertIsNotNone(payload["generated_at"])

    def test_dedoublonnage_par_identifiant(self):
        # Même domaine sur deux serveurs (copie legacy) : un seul incident.
        vieux = {"last_backup_ts": time.time() - 100 * HEURE}
        self.poser_fleet(self.serveur("vps1", [site("dup.fr", updraft=vieux)]),
                         self.serveur("vps2", [site("dup.fr", updraft=vieux)]))
        inc = self.par_kind("backup_late")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["id"], "backup_late:dup.fr:")

    def test_les_identifiants_sont_uniques(self):
        self.parc_complet()
        ids = [i["id"] for i in self.snapshot()[0]["incidents"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_deux_appels_rendent_le_meme_ordre(self):
        self.parc_complet()
        premier = [i["id"] for i in A.incidents_snapshot()[0]["incidents"]]
        second = [i["id"] for i in A.incidents_snapshot()[0]["incidents"]]
        self.assertEqual(premier, second)

    # ---- une source cassée n'emporte pas les autres ---------------------- #
    def test_kuma_indisponible_laisse_les_autres_sources(self):
        self.parc_complet()
        with mock.patch.object(A, "kuma_sql", lambda sql: (95, "docker indisponible")):
            payload, _ = A.incidents_snapshot()
        self.assertEqual([e["source"] for e in payload["errors"]], ["kuma"])
        self.assertIn("docker indisponible", payload["errors"][0]["error"])
        self.assertEqual([i["kind"] for i in payload["incidents"]],
                         ["server_stale", "backup_late"])

    def test_fichier_de_vulnerabilites_illisible(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time())}}
        with open(A.VULNS_FOUND_PATH, "w") as fh:
            fh.write("{ ceci n'est pas du JSON")
        payload, _ = A.incidents_snapshot()
        sources = [e["source"] for e in payload["errors"]]
        self.assertIn("vulns", sources)
        self.assertIn("counters", sources)      # même fichier, autre lecture
        self.assertEqual([i["kind"] for i in payload["incidents"]], ["down"])

    def test_certificats_en_erreur_signales_sans_tout_annuler(self):
        self.parc_complet()
        self.certs = {"certs": [], "error": "docker exec: no such container"}
        payload, _ = A.incidents_snapshot()
        self.assertEqual([e["source"] for e in payload["errors"]], ["certs"])
        self.assertEqual(payload["counts"], {"critical": 2, "warning": 2,
                                             "now_critical": 2, "now_warning": 1,
                                             "plan": 1, "acked": 0})

    def test_fleet_illisible_ne_leve_pas(self):
        with open(A.FLEET_PATH, "w") as fh:
            fh.write("pas du json")
        payload, extra = A.incidents_snapshot()
        self.assertEqual([e["source"] for e in payload["errors"]], ["fleet"])
        self.assertEqual(payload["incidents"], [])
        self.assertEqual(extra["updates_sites"], 0)

    def test_sources_absentes_ne_sont_pas_des_erreurs(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        payload, _ = A.incidents_snapshot()
        self.assertEqual(payload["errors"], [])
        self.assertEqual(payload["incidents"], [])


# --------------------------------------------------------------------------- #
#  compteurs de la barre latérale                                              #
# --------------------------------------------------------------------------- #
class TestCompteurs(IncidentsBase):

    def poser(self):
        self.poser_fleet(self.serveur(sites=[
            site("a.fr", plugins_updates=4, admins=[{"login": "pirate"}]),
            site("b.fr", core_update="7.1"),
            site("c.fr")]))
        self.poser_json(os.path.join(A.DATA, "admins_baseline.json"),
                        {"a.fr": {"logins": ["tommy"], "set_at": "2026-08-24 10:00"}})
        self.poser_json(A.VULNS_FOUND_PATH, {"sites": [
            {"domain": "a.fr", "findings": [
                {"kind": "plugin", "component": "x", "severity": "critical", "update_to": "2.0"},
                {"kind": "plugin", "component": "y", "severity": "medium", "update_to": "1.4"},
                {"kind": "plugin", "component": "z", "severity": "high", "update_to": ""}]}]})

    def test_compteurs_derives_du_meme_agregat(self):
        self.poser()
        compteurs = A.sidebar_counts()
        self.assertEqual(compteurs["incidents"], {"critical": 2, "warning": 0,
                                                  "now_critical": 2, "now_warning": 0,
                                                  "plan": 0, "acked": 0})
        self.assertEqual(compteurs["securite"], {"vulns_fixable": 2, "admins_unknown": 1})
        self.assertEqual(compteurs["parc"], {"updates_sites": 2})

    def test_incidents_et_compteurs_disent_la_meme_chose(self):
        self.poser()
        payload, _ = A.incidents_snapshot()
        self.assertEqual(A.sidebar_counts()["incidents"], payload["counts"])

    def test_cache_de_trente_secondes(self):
        self.poser()
        premier = A.sidebar_counts()
        self.poser_fleet(self.serveur(sites=[]))         # le parc change…
        self.assertEqual(A.sidebar_counts(), premier)    # …le cache tient
        self.vider_cache()
        self.assertEqual(A.sidebar_counts()["parc"]["updates_sites"], 0)

    def test_cache_perime_recalcule(self):
        self.poser()
        A.sidebar_counts()
        A._INCIDENTS_CACHE["ts"] = time.time() - A.INCIDENT_CACHE_TTL - 1
        self.poser_fleet(self.serveur(sites=[]))
        self.assertEqual(A.sidebar_counts()["parc"]["updates_sites"], 0)


# --------------------------------------------------------------------------- #
#  réglages                                                                    #
# --------------------------------------------------------------------------- #
class TestReglages(IncidentsBase):

    def test_valeurs_par_defaut(self):
        self.assertEqual(A.incident_rules(), A.INCIDENT_RULES_DEFAULTS)
        self.assertEqual(A.INCIDENT_RULES_DEFAULTS["backup_max_age_h"], 48)
        self.assertEqual(A.INCIDENT_RULES_DEFAULTS["cert_warn_days"], 21)
        self.assertIs(A.INCIDENT_RULES_DEFAULTS["vuln_high_is_incident"], False)

    def test_ecriture_partielle_conserve_les_autres_seuils(self):
        A.settings_write({"incident_rules": {"backup_max_age_h": 24}})
        rules = A.incident_rules()
        self.assertEqual(rules["backup_max_age_h"], 24)
        self.assertEqual(rules["cert_warn_days"], 21)

    def test_cle_inconnue_ignoree_et_type_ramene(self):
        A.settings_write({"incident_rules": {"inventee": 1, "cert_warn_days": "30",
                                             "vuln_high_is_incident": 1}})
        rules = A.incident_rules()
        self.assertNotIn("inventee", rules)
        self.assertEqual(rules["cert_warn_days"], 30)
        self.assertIs(rules["vuln_high_is_incident"], True)

    def test_plan_kinds_par_defaut_et_ecriture_partielle(self):
        self.assertEqual(A.INCIDENT_RULES_DEFAULTS["plan_kinds"],
                         ["php_eol", "server_stale"])
        A.settings_write({"incident_rules": {"backup_max_age_h": 24}})
        self.assertEqual(A.incident_rules()["plan_kinds"], ["php_eol", "server_stale"])
        A.settings_write({"incident_rules": {"plan_kinds": ["backup_late"]}})
        self.assertEqual(A.incident_rules()["plan_kinds"], ["backup_late"])
        self.assertEqual(A.incident_rules()["backup_max_age_h"], 48)

    def test_plan_kinds_ramene_a_des_chaines(self):
        A.settings_write({"incident_rules": {"plan_kinds": ["php_eol", 42]}})
        self.assertEqual(A.incident_rules()["plan_kinds"], ["php_eol", "42"])

    def test_liste_de_versions_ramenee_a_des_chaines(self):
        A.settings_write({"incident_rules": {"php_eol_versions": [7.4, "8.0"]}})
        self.assertEqual(A.incident_rules()["php_eol_versions"], ["7.4", "8.0"])

    def test_valeur_d_un_autre_type_ne_casse_pas(self):
        A.settings_write({"incident_rules": "n'importe quoi"})
        self.assertEqual(A.incident_rules(), A.INCIDENT_RULES_DEFAULTS)

    def test_les_defauts_ne_sont_pas_partages(self):
        # dict() est une copie de surface : sans copie profonde, écrire dans les
        # réglages lus corromprait SETTINGS_DEFAULTS pour tout le processus.
        lus = A.settings_cfg()["incident_rules"]
        lus["backup_max_age_h"] = 999
        lus["php_eol_versions"].append("9.9")
        self.assertEqual(A.INCIDENT_RULES_DEFAULTS["backup_max_age_h"], 48)
        self.assertNotIn("9.9", A.INCIDENT_RULES_DEFAULTS["php_eol_versions"])
        self.assertEqual(A.incident_rules(), A.INCIDENT_RULES_DEFAULTS)


# --------------------------------------------------------------------------- #
#  bucket : « à traiter » (now) contre « à planifier » (plan)                   #
# --------------------------------------------------------------------------- #
class TestBucket(IncidentsBase):
    """Le classement d'une ligne — c'est lui qui décide de la pastille rouge.

    Trois types basculent selon le CONTEXTE et non selon leur nom : un `down`
    de moniteur en pause, une sauvegarde sans rien à cliquer, un certificat
    encore loin de son échéance.
    """

    def test_down_actif_est_a_traiter(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time())}}
        self.assertEqual(self.bucket("down"), "now")

    def test_down_de_moniteur_en_pause_est_a_planifier(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time()), "active": False}}
        inc = self.par_kind("down")[0]
        self.assertEqual((inc["bucket"], inc["severity"]), ("plan", "warning"))

    def test_php_fatal_est_a_traiter(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.poser_json(A.PHPERR_PATH, {"sites": [{"domain": "a.fr", "groups": [
            {"severity": "Fatal error", "message": "boom", "short": "a.php", "line": 3,
             "count": 1, "first": ts_local(time.time()), "last": ts_local(time.time())}]}]})
        self.assertEqual(self.bucket("php_fatal"), "now")

    def test_vuln_critique_corrigeable_est_a_traiter(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.poser_json(A.VULNS_FOUND_PATH, {"sites": [{"domain": "a.fr", "findings": [
            {"kind": "plugin", "component": "x", "version": "1.0", "severity": "critical",
             "update_to": "1.1", "cve": "CVE-1", "title": "XSS"}]}]})
        self.assertEqual(self.bucket("vuln_critical_fixable"), "now")

    def test_checksums_et_admin_inconnu_sont_a_traiter(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr", admins=[{"login": "pirate"}])]))
        self.poser_json(os.path.join(self.data, "admins_baseline.json"),
                        {"a.fr": {"logins": ["admin"]}})
        self.poser_json(A.CHECKSUMS_PATH, {"a.fr": {
            "ts": ts_local(time.time()), "ok": False,
            "output_tail": "File doesn't verify against checksum: wp-includes/load.php"}})
        self.assertEqual(self.bucket("checksums_modified"), "now")
        self.assertEqual(self.bucket("admin_unknown"), "now")

    def test_sauvegarde_datee_est_a_traiter(self):
        self.poser_fleet(self.serveur(sites=[site(
            "a.fr", updraft={"last_backup_ts": time.time() - 100 * HEURE})]))
        self.assertEqual(self.bucket("backup_late"), "now")

    def test_sauvegarde_jamais_faite_est_a_planifier(self):
        """Le site abandonné en retard depuis 285 jours : rien à cliquer."""
        self.poser_fleet(self.serveur(sites=[site("a.fr", updraft={"service": "sftp"})]))
        self.assertEqual(self.bucket("backup_late"), "plan")

    def test_sauvegarde_d_un_site_rest_est_a_planifier(self):
        # Sans SSH, le bouton « Sauvegarder » répondrait « action indisponible ».
        self.poser_fleet(self.serveur(sites=[site(
            "a.fr", via="rest", updraft={"last_backup_ts": time.time() - 100 * HEURE})]))
        self.assertEqual(self.bucket("backup_late"), "plan")

    def test_certificat_sous_sept_jours_est_a_traiter(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.certs = {"certs": [{"monitor": "a.fr", "days_left": 3, "valid_to": "2026-09-06"}]}
        self.assertEqual(self.bucket("cert_expiring"), "now")

    def test_certificat_au_dela_de_sept_jours_est_a_planifier(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.certs = {"certs": [{"monitor": "a.fr", "days_left": 15, "valid_to": "2026-09-18"}]}
        self.assertEqual(self.bucket("cert_expiring"), "plan")

    def test_php_eol_et_serveur_injoignable_sont_a_planifier(self):
        self.poser_fleet(
            self.serveur("vps1", [site("a.fr", php_version="7.4.33")]),
            self.serveur("legacy", [site("b.fr")], stale=True, error="injoignable",
                         last_attempt=ts_local(time.time() - 3 * HEURE)))
        self.assertEqual(self.bucket("php_eol"), "plan")
        self.assertEqual(self.bucket("server_stale"), "plan")

    def test_plan_kinds_deplace_un_type(self):
        self.poser_fleet(self.serveur(sites=[site(
            "a.fr", updraft={"last_backup_ts": time.time() - 100 * HEURE})]))
        self.assertEqual(self.bucket("backup_late"), "now")
        self.reglages(plan_kinds=["backup_late"])
        self.assertEqual(self.bucket("backup_late"), "plan")

    def test_plan_kinds_vide_ramene_les_chantiers_dans_la_file(self):
        self.poser_fleet(self.serveur("vps1", [site("a.fr", php_version="7.4.33")]))
        self.assertEqual(self.bucket("php_eol"), "plan")
        self.reglages(plan_kinds=[])
        self.assertEqual(self.bucket("php_eol"), "now")

    def test_plan_kinds_ne_touche_pas_au_contexte(self):
        """Retirer `server_stale` de la liste ne réhabilite pas un moniteur en pause."""
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time()), "active": False}}
        self.reglages(plan_kinds=[])
        self.assertEqual(self.bucket("down"), "plan")

    def test_la_pastille_ne_compte_que_les_now(self):
        self.poser_fleet(
            self.serveur("vps1", [site("a.fr", php_version="7.4.33"),
                                  site("b.fr", updraft={"service": "sftp"})]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time())}}
        c = self.snapshot()[0]["counts"]
        # 1 down (now, critique) · 1 php_eol + 1 backup sans sauvegarde (plan)
        self.assertEqual((c["now_critical"], c["now_warning"], c["plan"]), (1, 0, 2))
        self.assertEqual(c["now_critical"] + c["now_warning"], 1)
        self.assertEqual(A.sidebar_counts()["incidents"], c)


# --------------------------------------------------------------------------- #
#  empreinte d'un incident                                                     #
# --------------------------------------------------------------------------- #
class TestEmpreinte(IncidentsBase):

    def php_fatal(self, message="boom", ligne=3, count=1):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.poser_json(A.PHPERR_PATH, {"sites": [{"domain": "a.fr", "groups": [
            {"severity": "Fatal error", "message": message, "short": "a.php",
             "line": ligne, "count": count, "first": ts_local(time.time()),
             "last": ts_local(time.time())}]}]})
        return A.incident_fingerprint(self.par_kind("php_fatal")[0])

    def test_php_fatal_ignore_le_compteur(self):
        self.assertEqual(self.php_fatal(count=1), self.php_fatal(count=48))

    def test_php_fatal_suit_le_fichier_et_la_ligne(self):
        self.assertNotEqual(self.php_fatal(ligne=3), self.php_fatal(ligne=91))

    def test_php_fatal_normalise_les_nombres_du_message(self):
        # « id 12 » et « id 4211 » : le même défaut, deux occurrences.
        self.assertEqual(self.php_fatal(message="undefined index id 12"),
                         self.php_fatal(message="undefined index id 4211"))
        self.assertNotEqual(self.php_fatal(message="undefined index"),
                            self.php_fatal(message="undefined method"))

    def vuln(self, version="1.0"):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.poser_json(A.VULNS_FOUND_PATH, {"sites": [{"domain": "a.fr", "findings": [
            {"kind": "plugin", "component": "x", "version": version, "severity": "critical",
             "update_to": "9.9", "cve": "CVE-1", "title": "XSS"}]}]})
        return A.incident_fingerprint(self.par_kind("vuln_critical_fixable")[0])

    def test_vuln_suit_la_version_installee(self):
        self.assertEqual(self.vuln("1.0"), self.vuln("1.0"))
        self.assertNotEqual(self.vuln("1.0"), self.vuln("1.1"))

    def backup(self, ts):
        self.poser_fleet(self.serveur(sites=[site("a.fr", updraft={"last_backup_ts": ts}
                                                  if ts else {"service": "sftp"})]))
        return A.incident_fingerprint(self.par_kind("backup_late")[0])

    def test_backup_suit_la_derniere_sauvegarde(self):
        vieux = time.time() - 100 * HEURE
        self.assertEqual(self.backup(vieux), self.backup(vieux))
        self.assertNotEqual(self.backup(vieux), self.backup(time.time() - 60 * HEURE))
        # aucune sauvegarde connue : l'empreinte est stable, elle aussi
        self.assertEqual(self.backup(None), self.backup(None))

    def cert(self, valid_to):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.certs = {"certs": [{"monitor": "a.fr", "days_left": 3, "valid_to": valid_to}]}
        return A.incident_fingerprint(self.par_kind("cert_expiring")[0])

    def test_cert_suit_le_certificat_courant(self):
        self.assertEqual(self.cert("2026-09-06"), self.cert("2026-09-06"))
        self.assertNotEqual(self.cert("2026-09-06"), self.cert("2027-01-01"))

    def down(self, msg):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time()), "msg": msg}}
        return A.incident_fingerprint(self.par_kind("down")[0])

    def test_down_n_a_pas_d_empreinte_variable(self):
        """C'est l'état lui-même : le message du moniteur n'y entre pas."""
        self.assertEqual(self.down("timeout"), self.down("503 Service Unavailable"))

    def test_type_inconnu_retombe_sur_le_titre(self):
        a = A.incident_fingerprint({"kind": "inedit", "title": "T", "detail": "D"})
        self.assertEqual(a, A.incident_fingerprint({"kind": "inedit", "title": "T", "detail": "D"}))
        self.assertNotEqual(a, A.incident_fingerprint({"kind": "inedit", "title": "T",
                                                       "detail": "autre"}))

    def test_valeur_courte_et_stable(self):
        e = A.incident_fingerprint({"kind": "down"})
        self.assertRegex(e, r"^[0-9a-f]{16}$")
        # Ce qui n'est PAS un incident n'a pas d'empreinte : `incident_ack_state`
        # comparerait alors deux chaînes vides et masquerait n'importe quoi.
        self.assertEqual(A.incident_fingerprint(None), "")
        self.assertEqual(A.incident_fingerprint("down:a.fr:"), "")


# --------------------------------------------------------------------------- #
#  acquittement : veille, écart, retour de l'incident                          #
# --------------------------------------------------------------------------- #
class TestAcquittement(IncidentsBase):

    def poser_down(self, msg="503"):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time() - HEURE),
                                    "msg": msg}}
        return "down:a.fr:"

    def poser_vuln(self, version="1.0"):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.poser_json(A.VULNS_FOUND_PATH, {"sites": [{"domain": "a.fr", "findings": [
            {"kind": "plugin", "component": "x", "version": version, "severity": "critical",
             "update_to": "9.9", "cve": "CVE-1", "title": "XSS"}]}]})
        return "vuln_critical_fixable:a.fr:x"

    # ---- veille ---------------------------------------------------------- #
    def test_veille_active_exclut_l_incident(self):
        cid = self.poser_down()
        self.acquitter(cid, "snooze", jours=7, raison="client prévenu")
        p = self.snapshot()[0]
        self.assertEqual(p["incidents"], [])
        self.assertEqual(p["counts"]["acked"], 1)
        self.assertEqual(p["counts"]["now_critical"], 0)
        self.assertEqual([i["id"] for i in p["acked"]], [cid])
        vu = p["acked"][0]["acked"]
        self.assertEqual((vu["mode"], vu["by"], vu["reason"]),
                         ("snooze", "tommy", "client prévenu"))
        self.assertFalse(vu["stale_fingerprint"])
        self.assertGreater(vu["until"], time.time())

    def test_veille_expiree_fait_reapparaitre_l_incident(self):
        cid = self.poser_down()
        self.acquitter(cid, "snooze", jours=7)
        # l'échéance est repoussée dans le passé
        A.update_json(A.ACKS_PATH,
                      lambda cur: {cid: dict(cur[cid], until=time.time() - 60)}, {})
        self.vider_cache()
        p = self.snapshot()[0]
        self.assertEqual([i["id"] for i in p["incidents"]], [cid])
        # une veille échue ne dit plus rien : la ligne redevient ordinaire
        self.assertIsNone(p["incidents"][0]["acked"])
        self.assertEqual(p["counts"]["acked"], 0)

    def test_veille_sans_echeance_ne_masque_rien(self):
        """Entrée abîmée (`until` absent) : on montre plutôt que de masquer."""
        cid = self.poser_down()
        self.acquitter(cid, "snooze", jours=None)
        self.assertEqual([i["id"] for i in self.snapshot()[0]["incidents"]], [cid])

    # ---- écarté jusqu'à changement --------------------------------------- #
    def test_ecarte_empreinte_inchangee_exclut_l_incident(self):
        cid = self.poser_vuln("1.0")
        self.acquitter(cid, "ignore", raison="extension gelée")
        p = self.snapshot()[0]
        self.assertEqual(p["incidents"], [])
        self.assertEqual(p["counts"]["acked"], 1)
        self.assertFalse(p["acked"][0]["acked"]["stale_fingerprint"])

    def test_ecarte_empreinte_changee_fait_revenir_l_incident(self):
        cid = self.poser_vuln("1.0")
        self.acquitter(cid, "ignore", raison="extension gelée")
        self.poser_vuln("1.1")            # nouvelle version, toujours vulnérable
        self.vider_cache()
        p = self.snapshot()[0]
        self.assertEqual([i["id"] for i in p["incidents"]], [cid])
        vu = p["incidents"][0]["acked"]
        self.assertTrue(vu["stale_fingerprint"])
        self.assertEqual(vu["reason"], "extension gelée")
        self.assertEqual(p["counts"]["acked"], 0)
        self.assertEqual(p["counts"]["now_critical"], 1)

    def test_sauvegarde_faite_puis_re_retardee_revient(self):
        self.poser_fleet(self.serveur(sites=[site(
            "a.fr", updraft={"last_backup_ts": time.time() - 300 * HEURE})]))
        self.acquitter("backup_late:a.fr:", "ignore", raison="site abandonné")
        self.assertEqual(self.snapshot()[0]["incidents"], [])
        # une sauvegarde a fini par passer… puis le retard est revenu
        self.poser_fleet(self.serveur(sites=[site(
            "a.fr", updraft={"last_backup_ts": time.time() - 90 * HEURE})]))
        self.vider_cache()
        p = self.snapshot()[0]
        self.assertEqual(len(p["incidents"]), 1)
        self.assertTrue(p["incidents"][0]["acked"]["stale_fingerprint"])

    def test_acquittement_d_un_id_disparu_n_invente_pas_d_incident(self):
        self.poser_down()
        self.acquitter("down:fantome.fr:", "ignore")
        self.assertEqual(len(self.snapshot()[0]["incidents"]), 1)

    def test_mode_inconnu_ignore(self):
        cid = self.poser_down()
        A.incident_ack_write(cid, "n'importe quoi", None, "", "tommy", "")
        self.vider_cache()
        self.assertEqual([i["id"] for i in self.snapshot()[0]["incidents"]], [cid])

    def test_fichier_illisible_ne_masque_rien(self):
        cid = self.poser_down()
        with open(A.ACKS_PATH, "w") as fh:
            fh.write("{ pas du json")
        self.assertEqual([i["id"] for i in self.snapshot()[0]["incidents"]], [cid])

    def test_retrait_de_l_acquittement(self):
        cid = self.poser_down()
        self.acquitter(cid, "ignore")
        self.assertEqual(self.snapshot()[0]["incidents"], [])
        self.assertTrue(A.incident_ack_clear(cid))
        self.vider_cache()
        self.assertEqual([i["id"] for i in self.snapshot()[0]["incidents"]], [cid])
        self.assertFalse(A.incident_ack_clear(cid))   # deux fois : pas une erreur

    def test_le_fichier_est_en_0600(self):
        self.acquitter("down:a.fr:", "ignore", empreinte="x")
        self.assertEqual(os.stat(A.ACKS_PATH).st_mode & 0o777, 0o600)

    # ---- « vu à » et purge ----------------------------------------------- #
    def test_vu_a_est_rafraichi_quand_l_incident_existe_encore(self):
        cid = self.poser_down()
        self.acquitter(cid, "ignore", vu=time.time() - 10 * 86400)
        self.snapshot()
        vu = A.incident_acks()[cid]["last_seen"]
        self.assertGreater(vu, time.time() - 60)

    def test_vu_a_n_est_pas_reecrit_a_chaque_appel(self):
        cid = self.poser_down()
        self.acquitter(cid, "ignore")
        avant = A.incident_acks()[cid]["last_seen"]
        self.vider_cache()
        self.snapshot()
        self.assertEqual(A.incident_acks()[cid]["last_seen"], avant)

    def test_purge_des_entrees_sans_incident_depuis_90_jours(self):
        vieux, recent = time.time() - 100 * 86400, time.time() - 80 * 86400
        self.acquitter("down:parti.fr:", "ignore", empreinte="x", vu=vieux)
        self.acquitter("down:present.fr:", "ignore", empreinte="x", vu=recent)
        self.assertEqual(A.incident_acks_purge(), 1)
        self.assertEqual(sorted(A.incident_acks()), ["down:present.fr:"])

    def test_purge_conserve_un_acquittement_encore_vu(self):
        cid = self.poser_down()
        self.acquitter(cid, "ignore", vu=time.time() - 100 * 86400)
        self.snapshot()                   # l'incident existe : « vu à » repart à zéro
        self.assertEqual(A.incident_acks_purge(), 0)
        self.assertIn(cid, A.incident_acks())

    def test_purge_retire_les_entrees_abimees(self):
        A.save_json(A.ACKS_PATH, {"x": "pas un dictionnaire"})
        self.assertEqual(A.incident_acks_purge(), 1)
        self.assertEqual(A.incident_acks(), {})


# --------------------------------------------------------------------------- #
#  routes HTTP                                                                 #
# --------------------------------------------------------------------------- #
class RoutesBase(IncidentsBase):
    """Un vrai serveur sur 127.0.0.1, une session valide, deux raccourcis."""

    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), A.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cookie = "dash_session=" + A.make_token("tommy")

    def get(self, chemin, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", chemin, headers=({"Cookie": cookie} if cookie else {}))
            r = c.getresponse()
            corps = r.read()
            return r.status, (json.loads(corps) if corps else None)
        finally:
            c.close()


class TestRoutes(RoutesBase):

    def test_incidents_sans_cookie_401(self):
        st, corps = self.get("/api/incidents")
        self.assertEqual(st, 401)
        self.assertEqual(corps, {"error": "non authentifié"})

    def test_counts_sans_cookie_401(self):
        self.assertEqual(self.get("/api/mgmt/counts")[0], 401)

    def test_cookie_invalide_401(self):
        self.assertEqual(self.get("/api/incidents", "dash_session=faux")[0], 401)

    def test_forme_de_la_reponse(self):
        self.poser_fleet(self.serveur(sites=[site("elwave.fr")]))
        self.battements = {"elwave.fr": {"status": 0, "time": ts_utc(time.time() - HEURE),
                                         "msg": "502"}}
        st, corps = self.get("/api/incidents", self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(sorted(corps), ["counts", "errors", "generated_at", "incidents"])
        self.assertEqual(sorted(corps["counts"]),
                         ["acked", "critical", "now_critical", "now_warning", "plan", "warning"])
        self.assertEqual(len(corps["incidents"]), 1)
        self.assertEqual(sorted(corps["incidents"][0]),
                         ["acked", "action", "age_h", "bucket", "detail", "extra", "id",
                          "kind", "link", "server", "severity", "since", "site", "title"])
        # `extra` est un dictionnaire libre, dont les clés dépendent du kind :
        # ici un `down`, donc le message du moniteur.
        self.assertEqual(corps["incidents"][0]["extra"]["msg"], "502")

    def test_parc_vide_repond_une_liste_vide(self):
        st, corps = self.get("/api/incidents", self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(corps["incidents"], [])
        self.assertEqual(corps["counts"], {"critical": 0, "warning": 0, "now_critical": 0,
                                           "now_warning": 0, "plan": 0, "acked": 0})

    def test_incidents_recalcule_a_chaque_appel(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time())}}
        self.assertEqual(len(self.get("/api/incidents", self.cookie)[1]["incidents"]), 1)
        self.battements = {"a.fr": {"status": 1, "time": ts_utc(time.time())}}
        self.assertEqual(self.get("/api/incidents", self.cookie)[1]["incidents"], [])

    def test_counts_suit_la_forme_attendue(self):
        st, corps = self.get("/api/mgmt/counts", self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(sorted(corps), ["incidents", "parc", "securite"])
        self.assertEqual(sorted(corps["securite"]), ["admins_unknown", "vulns_fixable"])
        self.assertEqual(sorted(corps["parc"]), ["updates_sites"])

    def test_les_seuils_sortent_dans_les_reglages(self):
        st, corps = self.get("/api/mgmt/settings", self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(corps["settings"]["incident_rules"], A.INCIDENT_RULES_DEFAULTS)
        self.assertEqual(corps["defaults"]["incident_rules"], A.INCIDENT_RULES_DEFAULTS)

    def test_reponse_rapide_sur_les_fixtures(self):
        self.poser_fleet(self.serveur(sites=[site(f"s{i}.fr") for i in range(60)]))
        t0 = time.time()
        self.assertEqual(self.get("/api/incidents", self.cookie)[0], 200)
        self.assertLess(time.time() - t0, 0.5)


# --------------------------------------------------------------------------- #
#  routes d'acquittement                                                       #
# --------------------------------------------------------------------------- #
class TestRoutesAck(RoutesBase):
    """POST /api/incidents/ack et /unack : garde de session, validation, journal."""

    def post(self, chemin, corps, cookie=None, dash=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            entetes = {"Content-Type": "application/json"}
            if dash:
                entetes["X-Dash"] = "1"
            if cookie:
                entetes["Cookie"] = cookie
            c.request("POST", chemin, body=json.dumps(corps).encode(), headers=entetes)
            r = c.getresponse()
            brut = r.read()
            return r.status, (json.loads(brut) if brut else None)
        finally:
            c.close()

    def poser_down(self):
        self.poser_fleet(self.serveur(sites=[site("a.fr")]))
        self.battements = {"a.fr": {"status": 0, "time": ts_utc(time.time()), "msg": "503"}}
        return "down:a.fr:"

    def journal(self):
        with open(A.LOG) as fh:
            return [json.loads(l) for l in fh if l.strip()]

    # ---- gardes ---------------------------------------------------------- #
    def test_ack_sans_session_401(self):
        st, corps = self.post("/api/incidents/ack", {"id": "x", "mode": "ignore"})
        self.assertEqual(st, 401)
        self.assertEqual(corps, {"error": "non authentifié"})

    def test_ack_sans_entete_dash_403(self):
        st, _ = self.post("/api/incidents/ack", {"id": "x", "mode": "ignore"},
                          cookie=self.cookie, dash=False)
        self.assertEqual(st, 403)

    def test_unack_sans_session_401(self):
        self.assertEqual(self.post("/api/incidents/unack", {"id": "x"})[0], 401)

    # ---- validation ------------------------------------------------------ #
    def test_mode_invalide_refuse(self):
        cid = self.poser_down()
        st, corps = self.post("/api/incidents/ack", {"id": cid, "mode": "oubli"},
                              cookie=self.cookie)
        self.assertEqual(st, 400)
        self.assertIn("mode", corps["error"])

    def test_identifiant_vide_refuse(self):
        self.assertEqual(self.post("/api/incidents/ack", {"id": "", "mode": "ignore"},
                                   cookie=self.cookie)[0], 400)

    def test_jours_hors_bornes_refuses(self):
        cid = self.poser_down()
        for jours in (0, 366, -3, "sept"):
            st, corps = self.post("/api/incidents/ack",
                                  {"id": cid, "mode": "snooze", "days": jours},
                                  cookie=self.cookie)
            self.assertEqual(st, 400, jours)
            self.assertIn("days", corps["error"])

    def test_snooze_sans_jours_refuse(self):
        cid = self.poser_down()
        self.assertEqual(self.post("/api/incidents/ack", {"id": cid, "mode": "snooze"},
                                   cookie=self.cookie)[0], 400)

    def test_raison_trop_longue_refusee(self):
        cid = self.poser_down()
        st, corps = self.post("/api/incidents/ack",
                              {"id": cid, "mode": "ignore", "reason": "x" * 301},
                              cookie=self.cookie)
        self.assertEqual(st, 400)
        self.assertIn("300", corps["error"])
        self.assertEqual(A.incident_acks(), {})

    def test_incident_inconnu_404(self):
        self.poser_down()
        st, corps = self.post("/api/incidents/ack",
                              {"id": "down:fantome.fr:", "mode": "ignore"},
                              cookie=self.cookie)
        self.assertEqual(st, 404)
        self.assertIn("inconnu", corps["error"])
        self.assertEqual(A.incident_acks(), {})

    # ---- effet ----------------------------------------------------------- #
    def test_veille_de_sept_jours_retire_la_ligne_de_la_file(self):
        cid = self.poser_down()
        st, corps = self.post("/api/incidents/ack",
                              {"id": cid, "mode": "snooze", "days": 7,
                               "reason": "  intervention   programmée "},
                              cookie=self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(corps["acked"]["mode"], "snooze")
        self.assertEqual(corps["acked"]["reason"], "intervention programmée")
        self.assertEqual(corps["acked"]["by"], "tommy")
        p = self.get("/api/incidents", self.cookie)[1]
        self.assertEqual(p["incidents"], [])
        self.assertEqual(p["counts"]["acked"], 1)
        self.assertNotIn("acked", p)      # la liste ne sort que sur demande

    def test_include_acked_rend_la_liste_des_acquittes(self):
        cid = self.poser_down()
        self.post("/api/incidents/ack", {"id": cid, "mode": "ignore", "reason": "connu"},
                  cookie=self.cookie)
        p = self.get("/api/incidents?include=acked", self.cookie)[1]
        self.assertEqual(p["incidents"], [])
        self.assertEqual([i["id"] for i in p["acked"]], [cid])
        self.assertEqual(p["acked"][0]["acked"]["reason"], "connu")

    def test_unack_ramene_l_incident(self):
        cid = self.poser_down()
        self.post("/api/incidents/ack", {"id": cid, "mode": "ignore"}, cookie=self.cookie)
        self.assertEqual(self.get("/api/incidents", self.cookie)[1]["incidents"], [])
        st, corps = self.post("/api/incidents/unack", {"id": cid}, cookie=self.cookie)
        self.assertEqual((st, corps["removed"]), (200, True))
        self.assertEqual(len(self.get("/api/incidents", self.cookie)[1]["incidents"]), 1)

    def test_unack_deux_fois_reste_un_succes(self):
        cid = self.poser_down()
        self.post("/api/incidents/ack", {"id": cid, "mode": "ignore"}, cookie=self.cookie)
        self.post("/api/incidents/unack", {"id": cid}, cookie=self.cookie)
        st, corps = self.post("/api/incidents/unack", {"id": cid}, cookie=self.cookie)
        self.assertEqual((st, corps["removed"]), (200, False))

    def test_la_pastille_suit_immediatement(self):
        cid = self.poser_down()
        self.assertEqual(self.get("/api/mgmt/counts", self.cookie)[1]["incidents"]["now_critical"], 1)
        self.post("/api/incidents/ack", {"id": cid, "mode": "ignore"}, cookie=self.cookie)
        # sans purge du cache, la pastille aurait gardé 1 pendant 30 s
        self.assertEqual(self.get("/api/mgmt/counts", self.cookie)[1]["incidents"]["now_critical"], 0)

    # ---- journalisation --------------------------------------------------- #
    def test_acquittement_journalise(self):
        cid = self.poser_down()
        self.post("/api/incidents/ack",
                  {"id": cid, "mode": "snooze", "days": 30, "reason": "migration prévue"},
                  cookie=self.cookie)
        e = self.journal()[-1]
        self.assertEqual(e["action"], "incident_ack")
        self.assertEqual(e["arg"], cid)
        self.assertEqual(e["domain"], "a.fr")
        self.assertEqual(e["server"], "vps1")
        self.assertIn("veille 30 j", e["output_tail"])
        self.assertIn("migration prévue", e["output_tail"])

    def test_ecart_journalise_son_mode(self):
        cid = self.poser_down()
        self.post("/api/incidents/ack", {"id": cid, "mode": "ignore"}, cookie=self.cookie)
        self.assertIn("écarté jusqu'à changement", self.journal()[-1]["output_tail"])

    def test_rappel_journalise(self):
        cid = self.poser_down()
        self.post("/api/incidents/ack", {"id": cid, "mode": "ignore"}, cookie=self.cookie)
        self.post("/api/incidents/unack", {"id": cid}, cookie=self.cookie)
        e = self.journal()[-1]
        self.assertEqual((e["action"], e["arg"]), ("incident_unack", cid))
        self.assertIn("réactivé", e["output_tail"])

    def test_refus_ne_journalise_rien(self):
        self.poser_down()
        self.post("/api/incidents/ack", {"id": "down:fantome.fr:", "mode": "ignore"},
                  cookie=self.cookie)
        self.assertFalse(os.path.exists(A.LOG))


if __name__ == "__main__":
    unittest.main()
