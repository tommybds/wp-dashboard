#!/usr/bin/env python3
"""Tests de la règle « identifiants uniques » de tools/check_front.py.

C'est la règle qui rattrape le bug d'écrasement silencieux : deux écrans qui
déclarent le même id, `getElementById` rendant le premier du document. Elle
n'est vérifiée par rien d'autre, et son point délicat est la tolérance envers
index.html — il ne faut surtout pas qu'elle masque une vraie collision.

    python3 -m unittest tests.test_check_front -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))

import check_front  # noqa: E402


def faux_front(racine, fichiers):
    """Écrit un mini public/ : {chemin relatif -> contenu}."""
    for rel, contenu in fichiers.items():
        p = Path(racine) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenu, encoding="utf-8")
    return Path(racine)


class TestIdsDupliques(unittest.TestCase):
    def test_front_sain(self):
        with tempfile.TemporaryDirectory() as d:
            r = faux_front(d, {
                "public/screens/a.js": "h('div', { id: 'a-body' })",
                "public/screens/b.js": "h('div', { id: 'b-body' })",
                "public/index.html": '<div id="nav"></div>',
            })
            self.assertEqual(check_front.ids_dupliques(r), {})

    def test_deux_ecrans_meme_id(self):
        """Le cas exact du bug : Incidents et Réglages avec « inc-body »."""
        with tempfile.TemporaryDirectory() as d:
            r = faux_front(d, {
                "public/screens/incidents.js": "h('div', { id: 'inc-body' })",
                "public/screens/reglages.js": "h('div', { id: 'inc-body' })",
                "public/index.html": "<div></div>",
            })
            self.assertEqual(
                check_front.ids_dupliques(r),
                {"inc-body": ["public/screens/incidents.js",
                              "public/screens/reglages.js"]})

    def test_un_ecran_et_la_coque(self):
        """Un écran qui vise un id de index.html est normal, pas un doublon."""
        with tempfile.TemporaryDirectory() as d:
            r = faux_front(d, {
                "public/screens/a.js": "h('div', { id: 'nav' })",
                "public/index.html": '<div id="nav"></div>',
            })
            dbl = check_front.ids_dupliques(r)
            self.assertEqual(sorted(dbl["nav"]),
                             ["public/index.html", "public/screens/a.js"])


class TestCheckIdsUniques(unittest.TestCase):
    """`check_ids_uniques` filtre le résultat brut ; c'est là qu'était le trou."""

    def lancer(self, fichiers):
        with tempfile.TemporaryDirectory() as d:
            r = faux_front(d, fichiers)
            ancien = check_front.ROOT
            check_front.ROOT = r
            try:
                pbs = []
                check_front.check_ids_uniques(pbs)
                return pbs
            finally:
                check_front.ROOT = ancien

    def test_coque_seule_toleree(self):
        self.assertEqual(self.lancer({
            "public/screens/a.js": "h('div', { id: 'nav' })",
            "public/index.html": '<div id="nav"></div>',
        }), [])

    def test_deux_modules_signales(self):
        pbs = self.lancer({
            "public/screens/incidents.js": "h('div', { id: 'inc-body' })",
            "public/screens/reglages.js": "h('div', { id: 'inc-body' })",
            "public/index.html": "<div></div>",
        })
        self.assertEqual(len(pbs), 1)
        self.assertIn("inc-body", pbs[0])
        self.assertIn("incidents.js", pbs[0])
        self.assertIn("reglages.js", pbs[0])

    def test_deux_modules_signales_meme_si_la_coque_declare_aussi(self):
        """Le trou corrigé : index.html ne doit pas absoudre deux modules."""
        pbs = self.lancer({
            "public/screens/a.js": "h('div', { id: 'nav' })",
            "public/components/b.js": "h('div', { id: 'nav' })",
            "public/index.html": '<div id="nav"></div>',
        })
        self.assertEqual(len(pbs), 1)
        self.assertIn("nav", pbs[0])
        self.assertIn("public/screens/a.js", pbs[0])
        self.assertIn("public/components/b.js", pbs[0])
        self.assertNotIn("index.html", pbs[0])

    def test_ecran_et_composant(self):
        pbs = self.lancer({
            "public/screens/a.js": "h('div', { id: 'x-body' })",
            "public/components/c.js": "h('div', { id: 'x-body' })",
        })
        self.assertEqual(len(pbs), 1)


if __name__ == "__main__":
    unittest.main()
