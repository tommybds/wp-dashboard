#!/usr/bin/env python3
"""Chasse aux portes dérobées (scan.py) — règles, référence, agrégation.

Ces tests existent parce que la première version du scan, lancée sur un site
parfaitement sain, a produit 186 signalements dont ZÉRO vrai. Chaque cas
ci-dessous fige un faux positif réellement observé sur le parc, pour qu'il ne
revienne pas :

  * Wordfence parle d'`auto_prepend_file` dans son PHP (39 fois) ;
  * mpdf enchaîne deux `chr()` pour dessiner des glyphes ;
  * guzzle et markbaker embarquent des `include 'phar://'` de construction ;
  * WordPress dépose un `index.php` vide dans chaque dossier de médias ;
  * un `dev.site.fr` à côté de `httpdocs` est une installation, pas un atelier ;
  * `wp-config.php` hors docroot est une bonne pratique WordOps, pas un intrus.

Et le point qui décide de tout : sans référence, la liste est illisible ; avec
elle, seul ce qui S'AJOUTE compte.

    python3 -m unittest tests.test_scan -v
"""
import os
import unittest
import urllib.error
from unittest import mock

import dashlib
import scan


class Regles(unittest.TestCase):
    """Ce que chaque motif doit attraper — et surtout ne pas attraper."""

    def test_eval_sur_chaine_decodee(self):
        self.assertEqual(scan.attribuer("/a.php", 'eval(base64_decode($x));'), "eval_decode")

    def test_eval_sur_entree_http(self):
        self.assertEqual(scan.attribuer("/a.php", 'eval($_POST["c"]);'), "eval_input")

    def test_commande_systeme_sur_entree_http(self):
        self.assertEqual(scan.attribuer("/a.php", 'system($_GET["cmd"]);'), "shell_input")

    def test_flux_compresse(self):
        self.assertEqual(scan.attribuer("/a.php", "@include_once 'compress.zlib://k.gz';"),
                         "stream_include")

    def test_phar_de_construction_ignore(self):
        """guzzle/phar-stub.php et markbaker/buildPhar.php : cinq faux positifs
        sur un seul site, aucun vrai. phar:// est sorti de la règle."""
        self.assertIsNone(scan.attribuer("/vendor/buildPhar.php", "include 'phar://f.php';"))

    def test_cle_derivee_du_domaine(self):
        self.assertEqual(
            scan.attribuer("/a.php", 'hash("sha256", "finaxys.com|1785057287", true)'),
            "domain_key")

    def test_commentaire_ignore(self):
        """« // wp_set_auth_cookie() sends the new browser cookie… » — sept
        signalements sur un site, tous des lignes de commentaire."""
        self.assertIsNone(scan.attribuer("/a.php", "  // wp_set_auth_cookie() explique ceci"))
        self.assertEqual(scan.attribuer("/a.php", "  wp_set_auth_cookie($id);"), "auth_cookie")

    def test_auto_prepend_seulement_en_configuration(self):
        """Wordfence en parle 39 fois dans son PHP ; seul le .user.ini règle
        vraiment quelque chose."""
        self.assertIsNone(scan.attribuer("/wordfence-waf.php", "auto_prepend_file = x"))
        self.assertEqual(scan.attribuer("/.user.ini", "auto_prepend_file = x"), "auto_prepend")

    def test_handler_php_seulement_en_configuration(self):
        self.assertIsNone(scan.attribuer("/lib/wfConfig.php", "AddHandler php-script"))
        self.assertEqual(scan.attribuer("/uploads/.htaccess", "AddHandler php-script"),
                         "htaccess_php")

    def test_chr_enchaines_seuil(self):
        """Deux chr() enchaînés, c'est mpdf. Quatre, c'est quelqu'un qui épelle
        un nom de fonction pour qu'il n'apparaisse pas."""
        self.assertIsNone(scan.attribuer("/mpdf.php", "chr(60).chr(62)"))
        self.assertEqual(scan.attribuer("/a.php", "chr(101).chr(118).chr(97).chr(108)"),
                         "chr_chain")

    def test_base64_seuil_reel_applique_ici(self):
        """Le serveur cherche un motif court (l'automate de grep explose sur une
        répétition bornée à 1500 : 65 s pour 400 fichiers) ; le vrai seuil est
        appliqué au retour."""
        self.assertIsNone(scan.attribuer("/a.php", '"' + "QUJD" * 40 + '"'))
        self.assertEqual(scan.attribuer("/a.php", '"' + "QUJD" * 400 + '"'), "long_b64")

    def test_la_plus_grave_gagne(self):
        """Une ligne qui vérifie deux règles ne doit produire qu'un signalement."""
        self.assertEqual(scan.attribuer("/a.php", 'eval(base64_decode($_GET["x"]));'),
                         "eval_decode")

    def test_motif_distant_borne(self):
        script = scan.build_script(["/var/www/a"], ["/var/www/a/htdocs"])
        self.assertNotIn("{1500,}", script)
        self.assertIn("{120}", script)


class Chemins(unittest.TestCase):
    def test_fichier_de_configuration(self):
        self.assertTrue(scan.est_config("/x/.user.ini"))
        self.assertTrue(scan.est_config("/x/.htaccess"))
        self.assertFalse(scan.est_config("/x/index.php"))

    def test_garde_muette_des_medias(self):
        """WordPress et la plupart des extensions déposent un index.php vide
        dans chaque dossier d'uploads : quarante sur un seul site."""
        meta = {"/u/index.php": {"size": "0"}, "/u/shell.php": {"size": "4200"}}
        self.assertTrue(scan.garde_muette({"rule": "php_in_uploads", "path": "/u/index.php"}, meta))
        self.assertFalse(scan.garde_muette({"rule": "php_in_uploads", "path": "/u/shell.php"}, meta))

    def test_garde_muette_ne_touche_pas_les_autres_regles(self):
        meta = {"/u/index.php": {"size": "0"}}
        self.assertFalse(scan.garde_muette({"rule": "eval_input", "path": "/u/index.php"}, meta))

    def test_wp_config_hors_docroot_ecarte(self):
        """Disposition WordOps standard : le fichier est DEHORS exprès."""
        script = scan.build_script(["/var/www/a"], ["/var/www/a/htdocs"])
        self.assertIn("grep -v '/wp-config\\.php$'", script)

    def test_installation_reelle_reconnue_par_wp_load(self):
        """Le discriminant du faux dossier du cœur : wp-load.php. Sans lui,
        dev.site.fr, staging et les dossiers de quarantaine passaient tous pour
        des ateliers — 22 « critiques » dont aucun vrai."""
        script = scan.build_script(["/var/www/a"], ["/var/www/a/htdocs"])
        self.assertIn("-name wp-load.php", script)
        self.assertIn("fake_core_dir", script)


class Racines(unittest.TestCase):
    """Le voisinage du docroot : indispensable (le kit finaxys y vivait), mais
    seulement quand il appartient à un seul site."""

    def test_voisinage_propre_retenu(self):
        r = scan.racines(["/var/www/vhosts/a.fr/httpdocs"], ["/var/www/vhosts/a.fr/httpdocs"])
        self.assertEqual(r, ["/var/www/vhosts/a.fr"])

    def test_parent_tres_partage_refuse(self):
        """Un parent qui abrite beaucoup de sites : y remonter reviendrait à
        scanner le serveur entier une fois par site."""
        # Six docroots enfants directs du même dossier : c'est ce dossier qui
        # abrite tout le monde, et il ne doit pas devenir une racine.
        tous = [f"/srv/sites/{n}" for n in "abcdef"]
        self.assertEqual(scan.racines(["/srv/sites/a"], tous), ["/srv/sites/a"])

    def test_vhost_a_plusieurs_docroots_garde_son_voisinage(self):
        """sumotori.fr porte httpdocs, dev et alizes-locations : c'est dans leur
        dossier commun que vivaient le kit et la quarantaine."""
        tous = ["/var/www/vhosts/s.fr/httpdocs", "/var/www/vhosts/s.fr/dev",
                "/var/www/vhosts/s.fr/alizes"]
        self.assertEqual(scan.racines(tous, tous), ["/var/www/vhosts/s.fr"])

    def test_dossier_systeme_jamais_racine(self):
        """/var/www/html → /var/www hébergerait tout le serveur."""
        self.assertEqual(scan.racines(["/var/www/html"], ["/var/www/html"]), ["/var/www/html"])

    def test_dedoublonnage_par_inclusion(self):
        r = scan.racines(["/var/www/vhosts/a.fr/httpdocs", "/var/www/vhosts/a.fr/dev"],
                         ["/var/www/vhosts/a.fr/httpdocs", "/var/www/vhosts/a.fr/dev"])
        self.assertEqual(r, ["/var/www/vhosts/a.fr"])


class Reference(unittest.TestCase):
    """La référence est ce qui rend le scan exploitable."""

    def setUp(self):
        self.t = [
            {"rule": "auth_cookie", "path": "/s/a.php", "line": 3, "excerpt": "x",
             "sev": "high", "domain": "a.fr"},
            {"rule": "eval_input", "path": "/s/b.php", "line": 9, "excerpt": "y",
             "sev": "critical", "domain": "a.fr"},
        ]
        self.ref = {"a.fr": {dashlib.scan_fingerprint("a.fr", "auth_cookie", "/s/a.php"): {}}}

    def test_connu_contre_nouveau(self):
        s = scan.agrege([dict(x) for x in self.t], {"a.fr": "/s"}, self.ref)[0]
        self.assertEqual((s["total"], s["new"]), (2, 1))
        self.assertEqual([(f["rule"], f["new"]) for f in s["findings"]],
                         [("eval_input", True), ("auth_cookie", False)])

    def test_pire_gravite_porte_sur_le_nouveau(self):
        """Avec une référence, un vendor connu ne doit pas laisser un site
        « critique » pour toujours."""
        connu = {"a.fr": {dashlib.scan_fingerprint("a.fr", r["rule"], r["path"]): {}
                          for r in self.t}}
        s = scan.agrege([dict(x) for x in self.t], {"a.fr": "/s"}, connu)[0]
        self.assertEqual(s["new"], 0)
        self.assertEqual(s["worst"], "")

    def test_sans_reference_tout_est_nouveau(self):
        s = scan.agrege([dict(x) for x in self.t], {"a.fr": "/s"}, {})[0]
        self.assertEqual(s["new"], 2)
        self.assertFalse(s["has_baseline"])

    def test_empreinte_ignore_le_numero_de_ligne(self):
        """Sinon un fichier légitime qui se décale d'une ligne redevient
        « nouveau » à chaque mise à jour, et la référence ne tient pas."""
        self.assertEqual(dashlib.scan_fingerprint("a.fr", "r", "/p"),
                         dashlib.scan_fingerprint("a.fr", "r", "/p"))
        self.assertNotEqual(dashlib.scan_fingerprint("a.fr", "r", "/p"),
                            dashlib.scan_fingerprint("b.fr", "r", "/p"))

    def test_reference_partielle_par_site(self):
        """Accepter un site ne doit pas accepter les cinquante-sept autres."""
        found = {"sites": [{"domain": "a.fr", "findings": [{"rule": "r", "path": "/p"}]},
                           {"domain": "b.fr", "findings": [{"rule": "r", "path": "/q"}]}]}
        ref = dashlib.scan_baseline_from(found, sites={"a.fr"})
        self.assertEqual(list(ref), ["a.fr"])

    def test_plafond_par_regle_et_reste_annonce(self):
        beaucoup = [{"rule": "long_b64", "path": f"/s/f{i}.php", "line": 1, "excerpt": "",
                     "sev": "low", "domain": "a.fr"} for i in range(scan.MAX_PER_RULE + 7)]
        s = scan.agrege(beaucoup, {"a.fr": "/s"}, {})[0]
        self.assertEqual(s["shown"], scan.MAX_PER_RULE)
        self.assertEqual(s["hidden"], 7)
        self.assertEqual(s["total"], scan.MAX_PER_RULE + 7)


class LectureDuFluxDistant(unittest.TestCase):
    """Le dépouillement de la sortie du script distant, sans SSH."""

    SORTIE = "\n".join([
        "@@HIT@@/var/www/a.fr/htdocs/wp-content/plugins/x/s.php:12:eval(base64_decode($x));",
        "@@HIT@@/var/www/a.fr/htdocs/wp-content/plugins/x/s.php:13:// eval(base64_decode()) doc",
        "@@PATH@@fake_core_dir|/var/www/a.fr/atelier/wp-includes",
        "@@META@@/var/www/a.fr/htdocs/wp-content/plugins/x/s.php|1757000000|1234|www-data",
        "@@ILLISIBLE@@/var/www/b.fr",
        "@@TRONQUE@@912 correspondances, 500 remontées",
        "@@STAT@@19402",
        "@@FIN@@",
    ])

    def _scan(self, sortie):
        with mock.patch.object(scan.A, "run_remote_script", return_value=(0, sortie)):
            return scan.scan_serveur({"name": "s1"},
                                     [{"domain": "a.fr", "path": "/var/www/a.fr/htdocs"}],
                                     ["/var/www/a.fr/htdocs"])

    def test_depouillement_complet(self):
        trv, err, ill, trc, vus = self._scan(self.SORTIE)
        self.assertIsNone(err)
        self.assertEqual(vus, 19402)
        self.assertEqual(ill, ["/var/www/b.fr"])
        self.assertEqual(len(trc), 1)
        # La ligne de commentaire ne compte pas : deux @@HIT@@, un signalement.
        regles = sorted(t["rule"] for t in trv)
        self.assertEqual(regles, ["eval_decode", "fake_core_dir"])

    def test_metadonnees_et_rattachement(self):
        trv, *_ = self._scan(self.SORTIE)
        hit = [t for t in trv if t["rule"] == "eval_decode"][0]
        self.assertEqual(hit["domain"], "a.fr")
        self.assertTrue(hit["inside"])
        self.assertEqual(hit["owner"], "www-data")
        self.assertEqual(hit["sev"], "critical")

    def test_voisinage_rattache_au_site(self):
        """Le kit finaxys vivait à côté du docroot : sans ce rattachement, il
        n'apparaîtrait sous aucun site."""
        trv, *_ = self._scan(self.SORTIE)
        faux = [t for t in trv if t["rule"] == "fake_core_dir"][0]
        self.assertEqual(faux["domain"], "a.fr")
        self.assertFalse(faux["inside"])

    def test_sortie_tronquee_refusee(self):
        """Sans @@FIN@@, la sortie est partielle : la présenter comme un
        résultat ferait lire « rien trouvé » là où on n'a pas fini de regarder."""
        trv, err, *_ = self._scan("@@HIT@@/a.php:1:eval($_GET[1]);")
        self.assertEqual(trv, [])
        self.assertIn("interrompu", err)


class Raccourci(unittest.TestCase):
    def test_chemin_relatif_au_docroot(self):
        self.assertEqual(
            scan.raccourcir("/var/www/a/htdocs/wp-content/plugins/x/y.php", "/var/www/a/htdocs"),
            "wp-content/plugins/x/y.php")

    def test_hors_docroot_garde_le_repere(self):
        self.assertEqual(scan.raccourcir("/var/www/a/atelier/wp-content/z.php", "/var/www/a/htdocs"),
                         "wp-content/z.php")


if __name__ == "__main__":
    unittest.main()


class ControlesAgent(unittest.TestCase):
    """Ce que seul WordPress voit, remonté par l'agent (route /scan, 1.6.0+)."""

    REPONSE = {"findings": [
        {"rule": "wp_cron_ghost", "target": "sys_maint", "detail": "crochet sans code"},
        {"rule": "wp_option_code", "target": "_wp_pbn_c", "detail": "36 Ko de PHP"},
        {"rule": "inconnue", "target": "x", "detail": "règle non reconnue"},
    ]}

    def setUp(self):
        self.entries = [{"url": "https://a.fr", "domain": "a.fr"}]
        self.secrets = {"a.fr": "s3cret"}

    def _charge(self, chemin, defaut):
        return self.entries if chemin.endswith("rest_sites.json") else self.secrets

    def test_trouvailles_normalisees(self):
        with mock.patch.object(scan.A, "load_json", side_effect=self._charge), \
             mock.patch.object(scan.collect, "agent_get", return_value=self.REPONSE):
            trv, err = scan.scan_agents()
        self.assertEqual(err, {})
        # La règle inconnue est écartée : un agent plus récent que le dashboard
        # ne doit pas injecter des signalements que l'écran ne sait pas décrire.
        self.assertEqual([t["rule"] for t in trv], ["wp_cron_ghost", "wp_option_code"])
        self.assertEqual(trv[0]["path"], "sys_maint")
        self.assertEqual(trv[0]["sev"], "high")
        self.assertEqual(trv[0]["domain"], "a.fr")

    def test_agent_trop_ancien_nest_pas_une_panne(self):
        """404 = version, pas incident. Sinon la même ligne rouge s'afficherait
        indéfiniment sur un site parfaitement sain."""
        erreur = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with mock.patch.object(scan.A, "load_json", side_effect=self._charge), \
             mock.patch.object(scan.collect, "agent_get", side_effect=erreur):
            trv, err = scan.scan_agents()
        self.assertEqual(trv, [])
        self.assertIn("antérieur à la 1.6.0", err["a.fr"])

    def test_site_non_appaire_ignore(self):
        with mock.patch.object(scan.A, "load_json", side_effect=lambda c, d: self.entries if c.endswith("rest_sites.json") else {}), \
             mock.patch.object(scan.collect, "agent_get") as appel:
            trv, err = scan.scan_agents()
        appel.assert_not_called()
        self.assertEqual((trv, err), ([], {}))

    def test_regles_agent_toutes_decrites(self):
        """Une règle sans `label` ni `why` produit une ligne que personne ne sait
        traiter : l'écran affiche le pourquoi, il doit exister."""
        for rid, r in scan.AGENT_RULES.items():
            self.assertTrue(r.get("label"), rid)
            self.assertTrue(r.get("why"), rid)
            self.assertIn(r["sev"], scan.SEV_RANK, rid)
            self.assertIn(rid, scan.ALL_RULES)
