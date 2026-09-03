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
                       "CHECKSUMS_PATH", "SETTINGS_PATH", "SESSION_SECRET_PATH", "LOG")}
        A.BASE = self.root
        A.DATA = self.data
        A.FLEET_PATH = os.path.join(self.data, "fleet.json")
        A.PHPERR_PATH = os.path.join(self.data, "php_errors.json")
        A.VULNS_FOUND_PATH = os.path.join(self.data, "vulns_found.json")
        A.CHECKSUMS_PATH = os.path.join(self.data, "checksums.json")
        A.SETTINGS_PATH = os.path.join(self.data, "settings.json")
        A.SESSION_SECRET_PATH = os.path.join(self.data, ".session_secret")
        A.LOG = os.path.join(self.data, "actions.log")
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
        lignes = ["\t".join((nom, str(hb.get("status", 1)), hb.get("time", ""),
                             hb.get("msg", ""))) for nom, hb in self.battements.items()]
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
        self.assertEqual(payload["counts"], {"critical": 2, "warning": 2})
        self.assertEqual(len(payload["incidents"]),
                         payload["counts"]["critical"] + payload["counts"]["warning"])
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
        self.assertEqual(payload["counts"], {"critical": 2, "warning": 2})

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
        self.assertEqual(compteurs["incidents"], {"critical": 2, "warning": 0})
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
#  routes HTTP                                                                 #
# --------------------------------------------------------------------------- #
class TestRoutes(IncidentsBase):

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
        self.assertEqual(sorted(corps["counts"]), ["critical", "warning"])
        self.assertEqual(len(corps["incidents"]), 1)
        self.assertEqual(sorted(corps["incidents"][0]),
                         ["action", "age_h", "detail", "id", "kind", "link",
                          "server", "severity", "since", "site", "title"])

    def test_parc_vide_repond_une_liste_vide(self):
        st, corps = self.get("/api/incidents", self.cookie)
        self.assertEqual(st, 200)
        self.assertEqual(corps["incidents"], [])
        self.assertEqual(corps["counts"], {"critical": 0, "warning": 0})

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


if __name__ == "__main__":
    unittest.main()
