#!/usr/bin/env python3
"""Code mort du front : exports jamais importés, classes CSS jamais posées.

Sans build, rien ne signale une fonction qu'on a cessé d'appeler ou une règle
CSS dont l'écran a disparu : le fichier reste, il est servi, et la prochaine
personne le lit comme s'il comptait. Ces deux contrôles-là sont mécaniques.

  a. un nom exporté par un module et importé par aucun autre ;
  b. une classe CSS écrite dans css/ et absente du HTML comme du JS.

Le (b) demande une soupape : le front compose des noms de classe
(`'chip ' + niveau`, `'v-' + couleur`). Ces familles sont déclarées dans
CLASSES_COMPOSEES, avec la raison — une entrée ajoutée là doit dire POURQUOI le
nom ne peut pas être trouvé littéralement.

Usage : python3 tools/check_dead.py [-v]
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"

FICHIERS_JS = sorted(
    list(PUBLIC.glob("*.js")) + list(PUBLIC.glob("lib/*.js"))
    + list(PUBLIC.glob("components/*.js")) + list(PUBLIC.glob("screens/*.js"))
)
FICHIERS_HTML = [PUBLIC / "index.html", PUBLIC / "login.html"]
FICHIERS_CSS = sorted(PUBLIC.glob("css/*.css"))

# `app.js` est le point d'entrée : il n'est importé par personne, ce qu'il
# exporte est donc légitimement « jamais importé »… mais alors il ne devrait
# rien exporter du tout. On le traite comme les autres, exprès.
ENTREES = set()

# Classes dont le nom est COMPOSÉ à l'exécution : introuvables littéralement.
# Chaque entrée dit pourquoi.
CLASSES_COMPOSEES = {
    "ok": "niveau d'état concaténé : `'chip ' + niveau`",
    "warn": "niveau d'état concaténé",
    "err": "niveau d'état concaténé",
    "mut": "niveau d'état concaténé",
    "acc": "niveau d'état concaténé (chip d'accent)",
    "v-ok": "compteur du Parc : `'cnt v-' + couleur`",
    "v-warn": "compteur du Parc",
    "v-err": "compteur du Parc",
    "up": "pastille Kuma : `'dot ' + etat`",
    "down": "pastille Kuma",
    "pending": "pastille Kuma",
    "ic-ok": "icône colorée par l'état",
    "ic-warn": "icône colorée par l'état",
    "ic-err": "icône colorée par l'état",
    "deb-g": "posée par initDebordement() : `classList.toggle('deb-g', …)`",
    "deb-d": "posée par initDebordement()",
    "sheet": "seconde classe de la feuille basse : `'modal sheet'`",
    "primary": "variante de bouton concaténée : `'btn ' + kind`",
    "danger": "variante de bouton concaténée",
    "sm": "taille de bouton concaténée : `'btn ' + size`",
    "icon": "forme de bouton concaténée",
    "start": "alignement du menu : `'menu-p' + (align === 'start' ? ' start' : '')`",
    "active": "état de navigation/onglet : `classList.toggle('active', …)`",
    "sel": "état de sélection : `classList.toggle('sel', …)`",
    "open": "état d'ouverture : `classList.add('open')`",
    "drag": "feuille en cours de glissement",
    "selmode": "mode sélection de la liste de cartes",
    "wait": "barre de progression indéterminée : `classList.toggle('wait', …)`",
    "indet": "barre de progression indéterminée",
    "clic": "ligne de notification cliquable : `'ntf' + … + ' clic'`",
    "attention": "entrée de menu qui modifie le site",
    "is-busy": "bouton en cours (components/button.js)",
    "row-frozen": "ligne d'extension gelée",
    "up": "pastille Kuma en ligne",
    "flash": "ligne mise en évidence à l'arrivée",
    "num": "classe utilitaire posée aussi par `class=\"num\"` dans un gabarit",
}


# ------------------------------------------------------------------- exports
def sans_commentaires(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", src)


def exports_de(src: str) -> set:
    noms = set()
    noms |= set(re.findall(r"export\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)", src))
    noms |= set(re.findall(r"export\s+(?:const|let|var|class)\s+([A-Za-z0-9_$]+)", src))
    for bloc in re.findall(r"export\s*\{([^}]*)\}", src):
        for part in bloc.split(","):
            part = part.strip()
            if part:
                noms.add(part.split(" as ")[-1].strip())
    return noms


def imports_globaux() -> set:
    vus = set()
    for f in FICHIERS_JS:
        src = sans_commentaires(f.read_text(encoding="utf-8"))
        for bloc, _ in re.findall(r"import\s*\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]", src):
            for part in bloc.split(","):
                part = part.strip()
                if part:
                    vus.add(part.split(" as ")[0].strip())
    return vus


def check_exports(pbs, verbose):
    importes = imports_globaux()
    n = 0
    for f in FICHIERS_JS:
        src = sans_commentaires(f.read_text(encoding="utf-8"))
        for nom in sorted(exports_de(src)):
            n += 1
            if nom in importes or f.name in ENTREES:
                continue
            pbs.append(f"(a) export jamais importé : {nom} ({f.relative_to(ROOT)})")
    if verbose:
        print(f"  (a) {n} noms exportés, croisés avec {len(importes)} noms importés")


# ----------------------------------------------------------------------- CSS
# Toute classe d'un sélecteur, y compris dans `.a.b` et `.a > .b`.
CLASSE = re.compile(r"\.(-?[_a-zA-Z][\w-]*)")


def classes_declarees() -> dict:
    """classe → fichier:ligne de sa première déclaration."""
    out = {}
    for f in FICHIERS_CSS:
        src = f.read_text(encoding="utf-8")
        src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
        for i, ligne in enumerate(src.split("\n"), 1):
            # Seule la partie SÉLECTEUR compte : `.x{…}` et non `background:.5`.
            sel = ligne.split("{")[0]
            if "{" not in ligne and ":" in ligne and not ligne.strip().startswith("."):
                continue
            for mo in CLASSE.finditer(sel):
                out.setdefault(mo.group(1), f"{f.relative_to(ROOT)}:{i}")
    return out


def check_css(pbs, verbose):
    declarees = classes_declarees()
    corpus = "\n".join(f.read_text(encoding="utf-8") for f in FICHIERS_JS + FICHIERS_HTML)
    inutiles = 0
    for cls, ou in sorted(declarees.items()):
        if cls in CLASSES_COMPOSEES:
            continue
        # Le nom doit apparaître comme MOT quelque part dans le front.
        if re.search(r"(?<![\w-])" + re.escape(cls) + r"(?![\w-])", corpus):
            continue
        inutiles += 1
        pbs.append(f"(b) classe CSS jamais posée : .{cls} ({ou})")
    if verbose:
        print(f"  (b) {len(declarees)} classes déclarées, "
              f"{len(CLASSES_COMPOSEES)} composées à l'exécution")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    pbs = []
    print("Contrôles de code mort :")
    check_exports(pbs, a.verbose)
    check_css(pbs, a.verbose)
    if pbs:
        print()
        for p in pbs:
            print("ÉCHEC :", p, file=sys.stderr)
        print(f"\n{len(pbs)} problème(s).", file=sys.stderr)
        return 1
    print("\nAucun export orphelin, aucune classe CSS orpheline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
