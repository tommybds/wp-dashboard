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


class TestVizNuitApresDashboard(IncidentsBase):
    """viz_nuit ne repasse pas sur ce que le dashboard a fait, mais contrôle le
    reste — une mise à jour forcée par WordPress.org passe outre le réglage."""

    def examiner(self, majs, deja):
        import viz_nuit
        with mock.patch.object(A, "find_site", return_value=({"name": "vps1"}, {"domain": "auto.fr"})), \
                mock.patch.object(viz_nuit, "maj_journalisees", return_value=majs), \
                mock.patch.object(viz_nuit, "evenements", return_value=[]), \
                mock.patch.object(viz_nuit, "lire_rapport", return_value=None):
            return viz_nuit.examiner("vps1", site("auto.fr"), time.time(), rattraper=False, deja=deja)

    def test_composants_du_dashboard_ignores(self):
        self.assertIsNone(self.examiner([("elementor", "plugin", time.time(), "3.30.0")], {"elementor"}))

    def test_mise_a_jour_forcee_controlee(self):
        r = self.examiner([("elementor", "plugin", time.time(), "3.30.0"),
                           ("ninja-forms", "plugin", time.time(), "3.6.10")], {"elementor"})
        self.assertEqual(r["non_couvertes"], ["ninja-forms"])


class TestTemoinEtEchecs(IncidentsBase):

    RAPPORT = {"totals": {"fail": 2, "warn": 0, "ok": 1}, "items": [
        {"page": "Accueil", "status": "fail", "cause": "pixel"},
        {"page": "Contact", "status": "fail", "cause": "pixel+a11y"},
        {"page": "Dojo", "status": "warn"}]}

    def test_pages_instables(self):
        sem, pix = A.pages_instables(self.RAPPORT)
        self.assertEqual(sem, ["Contact (a11y)"])
        self.assertEqual(pix, {"Accueil"})

    def test_echec_de_pixels_seul_sur_page_instable_ne_bloque_pas(self):
        self.assertEqual(A.totaux_bloquants(self.RAPPORT, {"Accueil"})["fail"], 1)
        # l'accessibilité compte toujours, même sur une page instable en pixels
        self.assertEqual(A.totaux_bloquants(self.RAPPORT, {"Accueil", "Contact"})["fail"], 1)
        self.assertEqual(A.totaux_bloquants(self.RAPPORT, set())["fail"], 2)

    def test_maj_par_extension(self):
        sortie = ("Warning: Aucune archive de mise à jour disponible.\n"
                  "name\told_version\tnew_version\tstatus\n"
                  "modern-events-calendar\t6.8.10\t7.36.4\tError\n"
                  "wp-rocket\t3.19\t3.20\tUpdated\n"
                  "Error: Only updated 1 of 2 plugins.\n")
        self.assertEqual(A.maj_par_extension(sortie, ["modern-events-calendar", "wp-rocket"]),
                         (["wp-rocket"], ["modern-events-calendar"]))
        self.assertEqual(A.maj_par_extension("Error: boom", ["x"]), (None, None))

    def test_natives_recoupees_et_signalees(self):
        s = site_maj(plugins_auto_update=6, themes_auto_update=0)
        with mock.patch.object(A, "run_action", return_value=(0, "ok")) as run, \
                mock.patch.object(A, "alert") as alerte:
            self.assertEqual(maj_nuit.recouper_natives("vps1", s, False), 6)
        self.assertEqual([c.args[2] for c in run.call_args_list], ["autoupdate_off", "themes_autoupdate_off"])
        alerte.assert_called_once()
        with mock.patch.object(A, "run_action") as run:
            self.assertEqual(maj_nuit.recouper_natives("vps1", site_maj(plugins_auto_update=0), False), 0)
        run.assert_not_called()

    def test_incidents_page_instable_et_echec(self):
        self.poser_fleet(self.serveur(sites=[site("auto.fr")]))
        A.save_json(A.MAJ_NUIT_PATH, {"sites": {"auto.fr": {
            "domain": "auto.fr", "server": "vps1", "ts": time.time(), "items": ["wp-rocket"],
            "verdict": "réussi", "echecs": {"modern-events-calendar": "7.36.4"}}}})
        inc = self.par_kind("auto_update_noop")
        self.assertEqual(inc[0]["extra"]["item"], "modern-events-calendar")
        A.save_json(A.MAJ_NUIT_PATH, {"sites": {"auto.fr": {
            "domain": "auto.fr", "server": "vps1", "ts": time.time(), "items": ["x"],
            "verdict": "page instable", "cause": "Scan témoin : Accueil (a11y)"}}})
        self.vider_cache()
        self.assertEqual(self.par_kind("auto_update_blocked")[0]["bucket"], "plan")

    def test_refus_limite_aux_echecs(self):
        self._p = maj_nuit.PATH
        maj_nuit.PATH = os.path.join(self.data, "maj_nuit.json")
        self.addCleanup(setattr, maj_nuit, "PATH", self._p)
        r = {"domain": "auto.fr", "server": "vps1", "ts": time.time(), "items": ["elementor"],
             "verdict": "réussi", "visees": {"elementor": "3.30.1"}, "echecs": {"wordfence": "8.0.1"}}
        with mock.patch.object(A, "auto_mode_load", return_value={"auto.fr": {}}), \
                mock.patch.object(A, "visible_sites", return_value=[("vps1", site_maj())]), \
                mock.patch.object(A, "attendre_envois"), \
                mock.patch.object(maj_nuit, "traiter", return_value=r), \
                mock.patch("builtins.print"):
            maj_nuit.main()
        self.assertEqual(A.load_json(maj_nuit.PATH, {})["refus"], {"auto.fr": {"wordfence": "8.0.1"}})


class TestChecksSemantiques(RoutesBase):
    """Poids des méta SEO et de l'arbre d'accessibilité (plugin ≥ 1.3.17)."""

    def post(self, chemin, corps):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("POST", chemin, body=json.dumps(corps).encode(),
                      headers={"Content-Type": "application/json", "X-Dash": "1", "Cookie": self.cookie})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"null")
        finally:
            c.close()

    def test_niveaux_ecrits_sur_le_site(self):
        with mock.patch.object(A, "viz_cible", return_value=({"name": "vps1"}, {"domain": "auto.fr"})), \
                mock.patch.object(A, "remote_bash",
                                  return_value=(0, '{"ok":true,"changed":true,"checks":{"seo":"fail","a11y":"off"}}')) as rb:
            st, j = self.post("/api/actions/viz_checks", {"server": "vps1", "domain": "auto.fr",
                                                          "seo": "fail", "a11y": "off"})
        self.assertEqual((st, j["checks"]), (200, {"seo": "fail", "a11y": "off"}))
        self.assertIn("vizproof checks --seo=fail --a11y=off", rb.call_args.args[2])

    def test_plugin_trop_ancien(self):
        with mock.patch.object(A, "viz_cible", return_value=({"name": "vps1"}, {"domain": "auto.fr"})), \
                mock.patch.object(A, "remote_bash", return_value=(1, "Error: 'checks' is not a registered subcommand")):
            st, j = self.post("/api/actions/viz_checks", {"server": "vps1", "domain": "auto.fr",
                                                          "seo": "fail", "a11y": "fail"})
        self.assertEqual((st, j["rc"]), (200, A.VIZ_OLD_RC))
        self.assertIn("1.3.17", j["error"])

    def test_niveau_invalide_refuse(self):
        st, _j = self.post("/api/actions/viz_checks", {"server": "vps1", "domain": "auto.fr",
                                                       "seo": "rm -rf", "a11y": "fail"})
        self.assertEqual(st, 400)
        st, _j = self.post("/api/mgmt/settings", {"settings": {"viz_check_seo": "nimporte"}})
        self.assertEqual(st, 400)


class TestCollecteChecks(unittest.TestCase):

    def test_niveaux_lus_ou_absents(self):
        import collect
        self.assertEqual(collect.niveaux_checks({"seo": "fail", "a11y": "warn"}), {"seo": "fail", "a11y": "warn"})
        self.assertIsNone(collect.niveaux_checks(None))
        self.assertIsNone(collect.niveaux_checks({"seo": "boom", "a11y": "warn"}))


class TestElementMasque(unittest.TestCase):

    def test_masque_absent_est_un_fait_pas_du_bruit(self):
        sem, pix = A.pages_instables({"items": [{"page": "Accueil", "status": "fail", "cause": "masque"}]})
        self.assertEqual(sem, ["Accueil (masque)"])
        self.assertEqual(pix, set())

    def test_rapport_recopie_les_elements_absents(self):
        it = A.viz_report_item({"page": "Accueil", "status": "fail", "cause": "masque",
                                "masked_missing": ["Flux Instagram", ""]})
        self.assertEqual(it["masked_missing"], ["Flux Instagram"])


class TestAnomaliesSignificatives(unittest.TestCase):

    def test_rapport_propre_ou_sans_cause(self):
        self.assertEqual(A.ecarts_significatifs({"items": [{"page": "A", "status": "ok"}]}), [])
        self.assertEqual(A.ecarts_significatifs({"items": [{"page": "A", "status": "warn"}]}), [])

    def test_pixels_d_une_page_instable_ignores_mais_pas_le_seo(self):
        rap = {"items": [{"page": "Accueil", "status": "fail", "cause": "pixel"},
                         {"page": "Accueil", "status": "warn", "cause": "pixel+seo"}]}
        self.assertEqual(len(A.ecarts_significatifs(rap, {"Accueil"})), 1)
        self.assertEqual(len(A.ecarts_significatifs(rap, set())), 2)

    def test_pixels_sous_le_seuil_toleres(self):
        """WARN de pixels seuls = sous le seuil du site : toléré, sans alerte."""
        rap = {"items": [{"page": "Accueil", "status": "warn", "cause": "pixel", "diff_percent": 0.02}]}
        self.assertEqual(A.ecarts_significatifs(rap), [])
        rap["items"][0]["cause"] = "a11y"
        self.assertEqual(len(A.ecarts_significatifs(rap)), 1)


class TestBruitGabarit(unittest.TestCase):

    def test_gabarit_de_theme_appele_directement(self):
        import phperrors
        self.assertEqual(phperrors.famille_bruit({
            "message": "Uncaught Error: Call to undefined function get_header()",
            "file": "/var/www/vhosts/la-kage.fr/httpdocs/wp-content/themes/Divi/index.php"}), "acces_direct")
        # une fonction « pluggable » appelée trop tôt par une extension reste un vrai bug
        self.assertEqual(phperrors.famille_bruit({
            "message": "Uncaught Error: Call to undefined function wp_get_current_user()",
            "file": "/var/www/x/wp-content/plugins/foo/foo.php"}), "")


class TestCollecteModeAuto(IncidentsBase):

    def test_sites_en_automatique_marques(self):
        import collect
        A.save_json(A.AUTO_MODE_PATH, {"auto.fr": {"rollback": True}})
        fleet = {"servers": [{"name": "vps1", "sites": [{"domain": "auto.fr"}, {"domain": "manuel.fr"}]}]}
        with mock.patch.object(collect, "DATA", self.data):
            collect.annotate_auto_mode(fleet)
        self.assertEqual([s["auto_mode"] for s in fleet["servers"][0]["sites"]], [True, False])


class TestContenusEtRetour(IncidentsBase):

    def test_texte_contenus_gabarits_d_abord(self):
        import viz_nuit
        cs = [{"type": "post", "titre": "Article", "quand": "06/10 15:20", "qui": "T"},
              {"type": "wp_template_part", "titre": "Pied de page", "quand": "06/10 15:34", "qui": "Tiphaine Doria"}]
        self.assertTrue(viz_nuit.texte_contenus(cs).startswith("Pied de page (partie de modèle, Tiphaine Doria, 06/10 15:34)"))

    def test_rien_retabli_n_est_pas_une_annulation(self):
        self.poser_fleet(self.serveur(sites=[site("tip.fr")]))
        A.save_json(A.VIZ_NUIT_PATH, {"sites": {"tip.fr": {
            "site": "tip.fr", "domain": "tip.fr", "server": "vps1",
            "at": datetime_iso(time.time() - 3600), "items": ["wordpress-core"],
            "ecarts": [{"page": "Accueil", "formats": ["desktop"], "http": None}],
            "retour": {"retablis": [], "impossibles": [{"slug": "wordpress-core", "raison": "le cœur ne se rétablit pas"}]},
            "contenus_modifies": [{"type": "wp_template_part", "titre": "Pied de page", "quand": "06/10 15:34", "qui": "Tiphaine"}]}}})
        self.assertEqual(self.par_kind("auto_rollback"), [])
        inc = self.par_kind("viz_auto_update")[0]
        self.assertIn("retour impossible", inc["detail"].replace("le cœur ne se rétablit pas", "retour impossible"))
        self.assertIn("Pied de page", inc["detail"])

    def test_page_de_maintenance_wpt_pas_a_verifier(self):
        import digest
        out = digest.maintenance_wpt([{"kind": "plugin_add", "severity": "warn", "detail": "+ extension maintenance.php"},
                                      {"kind": "plugin_add", "severity": "warn", "detail": "+ extension inconnu 1.0"}])
        self.assertEqual([c["severity"] for c in out], ["info", "warn"])


def datetime_iso(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
