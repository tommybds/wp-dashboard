"""Mises à jour de nuit faites par le dashboard (maj_nuit.py) : choix de ce qui
est mis à jour, garde-fous, versions refusées, incidents et route du mode."""
import json
import os
import sys
import time
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import actions_server as A          # noqa: E402
import maj_nuit                     # noqa: E402
from tests.test_incidents import IncidentsBase, RoutesBase, site   # noqa: E402


def site_maj(**kw):
    s = site("auto.fr", vizproof={"connected": True, "has_cli": True},
             plugins_updates_list=[{"name": "elementor", "from": "3.30.0", "to": "3.30.1"},
                                   {"name": "wordfence", "from": "8.0.0", "to": "8.0.1"}],
             themes_list=[{"name": "astra", "update": "available", "update_version": "4.15.0"},
                          {"name": "astra-child", "update": "none", "update_version": ""}])
    s.update(kw)
    return s


class TestChoix(IncidentsBase):

    def test_extensions_et_themes_en_attente(self):
        p, t, e = maj_nuit.a_mettre_a_jour(site_maj(), {})
        self.assertEqual(p, ["elementor", "wordfence"])
        self.assertEqual(t, ["astra"])
        self.assertEqual(e, [])

    def test_version_refusee_ecartee_mais_pas_la_suivante(self):
        p, _t, e = maj_nuit.a_mettre_a_jour(site_maj(), {"elementor": "3.30.1", "wordfence": "7.9.9"})
        self.assertEqual(p, ["wordfence"])          # refus sur une AUTRE version : on retente
        self.assertEqual(e, ["elementor 3.30.1"])

    def test_theme_refuse(self):
        _p, t, e = maj_nuit.a_mettre_a_jour(site_maj(), {"theme:astra": "4.15.0"})
        self.assertEqual(t, [])
        self.assertEqual(e, ["astra 4.15.0"])

    def test_gel_respecte(self):
        with mock.patch.object(A, "_frozen_lists", return_value=(["wordfence"], ["astra"])):
            p, t, _e = maj_nuit.a_mettre_a_jour(site_maj(), {})
        self.assertEqual((p, t), (["elementor"], []))


class TestTraiter(IncidentsBase):

    def test_rien_en_attente_rien_a_faire(self):
        s = site_maj(plugins_updates_list=[], themes_list=[])
        with mock.patch.object(A, "safe_update_run") as run:
            self.assertIsNone(maj_nuit.traiter("vps1", s, {"rollback": True}, {}, False))
        run.assert_not_called()

    def test_ecart_non_regle_bloque_sans_toucher_au_site(self):
        with mock.patch.object(maj_nuit, "ecart_ouvert", return_value=[("Accueil", ["mobile"], None)]), \
                mock.patch.object(A, "safe_update_run") as run:
            r = maj_nuit.traiter("vps1", site_maj(), {"rollback": True}, {}, False)
        run.assert_not_called()
        self.assertEqual(r["verdict"], "bloqué")
        self.assertIn("Accueil", r["cause"])

    def test_chaine_controlee_avec_le_reglage_du_site(self):
        def faux(*a, **kw):
            A.SAFE.update({"verdict": "réussi", "steps": [
                {"label": "Contrôle visuel VizProof", "ok": True, "detail": "ok",
                 "report": {"report_url": "https://v/r"}}]})
        with mock.patch.object(maj_nuit, "ecart_ouvert", return_value=[]), \
                mock.patch.object(A, "safe_update_run", side_effect=faux) as run:
            r = maj_nuit.traiter("vps1", site_maj(), {"rollback": False}, {}, False)
        kw = run.call_args.kwargs
        self.assertEqual(kw["slugs"], ["elementor", "wordfence"])
        self.assertEqual(kw["themes"], ["astra"])
        self.assertFalse(kw["viz_rollback"])
        self.assertFalse(kw["with_core"])            # le cœur reste à WordPress
        self.assertEqual(r["verdict"], "réussi")
        self.assertEqual(r["report_url"], "https://v/r")
        self.assertEqual(r["visees"], {"elementor": "3.30.1", "wordfence": "8.0.1",
                                       "theme:astra": "4.15.0"})

    def test_sans_extension_la_chaine_ne_prend_pas_tout(self):
        """slugs=[] voudrait dire « toutes » : un site qui n'a qu'un thème à jour
        doit passer with_plugins=False."""
        s = site_maj(plugins_updates_list=[])
        with mock.patch.object(maj_nuit, "ecart_ouvert", return_value=[]), \
                mock.patch.object(A, "safe_update_run") as run:
            A.SAFE.update({"verdict": "réussi", "steps": []})
            maj_nuit.traiter("vps1", s, {}, {}, False)
        self.assertFalse(run.call_args.kwargs["with_plugins"])


class TestRefus(IncidentsBase):

    def lancer(self, verdict, refus_avant=None):
        A.save_json(maj_nuit.PATH, {"refus": refus_avant or {}})
        s = site_maj()
        r = {"domain": "auto.fr", "server": "vps1", "ts": time.time(), "items": ["elementor"],
             "verdict": verdict, "visees": {"elementor": "3.30.1"}}
        with mock.patch.object(A, "auto_mode_load", return_value={"auto.fr": {"rollback": True}}), \
                mock.patch.object(A, "visible_sites", return_value=[("vps1", s)]), \
                mock.patch.object(A, "attendre_envois"), \
                mock.patch.object(maj_nuit, "traiter", return_value=r), \
                mock.patch("builtins.print"):
            maj_nuit.main()
        return A.load_json(maj_nuit.PATH, {})

    def setUp(self):
        super().setUp()
        self._p = maj_nuit.PATH
        maj_nuit.PATH = os.path.join(self.data, "maj_nuit.json")
        self.addCleanup(setattr, maj_nuit, "PATH", self._p)

    def test_annulation_retient_la_version(self):
        d = self.lancer("annulé (retour arrière)")
        self.assertEqual(d["refus"], {"auto.fr": {"elementor": "3.30.1"}})
        self.assertEqual(d["sites"]["auto.fr"]["verdict"], "annulé (retour arrière)")

    def test_refus_oublie_quand_une_nouvelle_version_sort(self):
        d = self.lancer("réussi", {"auto.fr": {"wordfence": "8.0.0", "elementor": "3.30.1"}})
        # wordfence propose 8.0.1 : le refus de 8.0.0 tombe ; elementor 3.30.1 reste.
        self.assertEqual(d["refus"], {"auto.fr": {"elementor": "3.30.1"}})


class TestIncidents(IncidentsBase):

    def poser(self, verdict, **kw):
        self.poser_fleet(self.serveur(sites=[site("auto.fr")]))
        r = {"domain": "auto.fr", "server": "vps1", "ts": time.time() - 3600,
             "items": ["elementor"], "verdict": verdict}
        r.update(kw)
        A.save_json(A.MAJ_NUIT_PATH, {"sites": {"auto.fr": r}})

    def test_retour_arriere(self):
        self.poser("annulé (retour arrière)", cause="Contrôle visuel VizProof : échec")
        inc = self.par_kind("auto_rollback")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "warning")
        self.assertIn("ne seront pas retentées", inc[0]["detail"])

    def test_echec_est_critique(self):
        self.poser("ÉCHEC — intervention requise")
        self.assertEqual(self.par_kind("auto_rollback")[0]["severity"], "critical")

    def test_bloque_a_planifier(self):
        self.poser("bloqué", cause="écart VizProof non réglé (Accueil)")
        inc = self.par_kind("auto_update_blocked")
        self.assertEqual(inc[0]["bucket"], "plan")

    def test_ecart_conserve(self):
        self.poser("réussie avec anomalies visuelles")
        self.assertEqual(len(self.par_kind("viz_auto_update")), 1)

    def test_reussi_rien(self):
        self.poser("réussi")
        self.assertEqual([k for k in self.kinds() if "auto" in k], [])

    def test_bilan_perime_ignore(self):
        self.poser("annulé (retour arrière)", ts=time.time() - 40 * 3600)
        self.assertEqual(self.par_kind("auto_rollback"), [])


class TestRouteMode(RoutesBase):

    def post(self, corps):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("POST", "/api/mgmt/auto_mode", body=json.dumps(corps).encode(),
                      headers={"Content-Type": "application/json", "X-Dash": "1", "Cookie": self.cookie})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"null")
        finally:
            c.close()

    def setUp(self):
        super().setUp()
        p = mock.patch.object(A, "find_site", return_value=({"name": "vps1"}, {"domain": "auto.fr"}))
        p.start()
        self.addCleanup(p.stop)

    def test_activer_puis_regler_le_retour_puis_desactiver(self):
        st, j = self.post({"server": "vps1", "domain": "auto.fr", "auto": True, "rollback": False})
        self.assertEqual(st, 200)
        self.assertEqual(j["modes"]["auto.fr"]["rollback"], False)
        st, j = self.post({"server": "vps1", "domain": "auto.fr", "rollback": True})
        self.assertEqual(j["modes"]["auto.fr"]["rollback"], True)
        st, j = self.post({"server": "vps1", "domain": "auto.fr", "auto": False})
        self.assertNotIn("auto.fr", j["modes"])

    def test_retour_seul_sur_un_site_hors_mode_refuse(self):
        st, _j = self.post({"server": "vps1", "domain": "auto.fr", "rollback": True})
        self.assertEqual(st, 409)


if __name__ == "__main__":
    unittest.main()
