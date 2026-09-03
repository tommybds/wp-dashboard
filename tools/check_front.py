#!/usr/bin/env python3
"""Contrôles automatiques du front (phase 1 de la refonte).

Ils tiennent en une commande et échouent bruyamment :

  a. tout `api('/api/…')` du front correspond à une route d'actions_server.py
  b. tout `data-act="…"` correspond à une clé de ACTIONS (ou à une action
     supplémentaire explicitement autorisée)
  c. tout `getElementById('x')` vise un identifiant présent dans index.html
     ou créé par un gabarit du front
  d. plus aucun emoji dans le front
  e. plus aucun `style="…"` en ligne, hors la liste de cas justifiés
  f. chaque nom importé d'un module y est bien exporté, et chaque module
     référencé existe

Usage : python3 tools/check_front.py [-v]
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
SERVER = ROOT / "actions_server.py"

# Routes servies par nginx à Uptime Kuma, pas par actions_server.py.
ROUTES_PROXY = {"/api/status-page/", "/api/status-page/heartbeat/"}
# Fichier statique produit par le collecteur.
FICHIERS_STATIQUES = {"fleet.json"}
# Actions groupées qui ne sont pas des commandes wp-cli de ACTIONS.
ACTIONS_EXTRA = {"rescan", "dash_connect", "dash_disconnect"}

# Cas de `style="…"` explicitement tolérés : aucun pour l'instant. Toute
# entrée ajoutée ici doit dire POURQUOI la valeur ne peut pas être un jeton.
STYLE_JUSTIFIE = {
    # exemple de forme attendue :
    # ("public/screens/x.js", "largeur calculée à partir d'une donnée"),
}

# Plages Unicode des emoji (pictogrammes, symboles divers, sélecteur de
# variante) + les quelques glyphes typographiques qui servaient d'icônes.
EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF"      # pictogrammes, émoticônes, symboles
    "☀-➿"               # symboles divers et dingbats
    "⬀-⯿"               # flèches et formes
    "️︎"                # sélecteurs de variante
    "‍"                      # liant de séquence emoji
    "↻↺↩↪"    # flèches circulaires détournées en icône
    "◆▲▼●◉"  # losange, triangles, disques
    "⬤⏳⌛"          # gros disque, sabliers
    "＋⊕⊖⊘"    # plus pleine chasse, cercles barrés
    "✓✔✗✘"    # coches et croix
    "✕✖"                # croix détournées en bouton de fermeture
    # « × » (U+00D7) reste un signe de multiplication légitime (« 42 × 3 jeux ») :
    # il n'est pas listé ici.
    "⚠⛔⛨"          # avertissement
    "⬆⬇⬅➡"    # flèches pleines
    "⤓⤒⤉"          # flèches à barre
    "≡☰"                # barres de menu
    "⚭⚮"                # anneaux
    "⚙"                      # engrenage
    "⏻-⏾"               # boutons d'alimentation
    "]"
)

# `×` (U+00D7) reste légitime dans un texte (« 3 × 20 ») : on ne l'interdit que
# comme contenu d'un bouton. Le bandeau d'erreur JS l'utilise comme croix de
# fermeture, faute de pouvoir dépendre du sprite — c'est le seul emploi toléré.
EXCEPTIONS_GLYPHE = [
    (re.compile(r"x\.textContent='×';"), "croix du bandeau d'erreur JS (avant tout module)"),
]

FICHIERS_JS = sorted(
    list(PUBLIC.glob("*.js")) + list(PUBLIC.glob("lib/*.js"))
    + list(PUBLIC.glob("components/*.js")) + list(PUBLIC.glob("screens/*.js"))
)
FICHIERS_HTML = [PUBLIC / "index.html", PUBLIC / "login.html"]


def sans_commentaires(src: str) -> str:
    """Retire les commentaires /* */ et // (approximation suffisante ici)."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", src)


def routes_backend() -> set:
    s = SERVER.read_text(encoding="utf-8")
    return set(re.findall(r"[\"'](/api/[A-Za-z0-9_/.\-]+)[\"']", s))


def actions_backend() -> set:
    s = SERVER.read_text(encoding="utf-8")
    m = re.search(r"\nACTIONS\s*=\s*\{(.*?)\n\}", s, re.S)
    if not m:
        raise SystemExit("ACTIONS introuvable dans actions_server.py")
    return set(re.findall(r'"([a-z0-9_]+)"\s*:', m.group(1))) | ACTIONS_EXTRA


def check_routes(pbs, verbose):
    connues = routes_backend()
    vues = set()
    for f in FICHIERS_JS:
        src = f.read_text(encoding="utf-8")
        for m in re.finditer(r"""api\(\s*['"`]([^'"`]+)""", src):
            vues.add((m.group(1), f))
    for url, f in sorted(vues, key=lambda x: x[0]):
        base = url.split("?")[0]
        if base in FICHIERS_STATIQUES or url.split("?")[0] in FICHIERS_STATIQUES:
            continue
        if any(url.startswith(p) for p in ROUTES_PROXY):
            continue
        if base not in connues:
            pbs.append(f"(a) route inconnue du backend : {base} (dans {f.relative_to(ROOT)})")
    if verbose:
        print(f"  (a) {len(vues)} appels d'API distincts, {len(connues)} routes déclarées côté serveur")


def check_actions(pbs, verbose):
    connues = actions_backend()
    vues = set()
    for f in FICHIERS_JS + FICHIERS_HTML:
        src = f.read_text(encoding="utf-8")
        vues |= set(re.findall(r'data-act="([a-z0-9_]+)"', src))
        # Actions posées dynamiquement dans un corps de requête, ou déclarées
        # dans une table d'entrées de menu / de barre groupée. Le motif exige
        # un « _ » (ou le cas particulier `rescan`) pour ne pas confondre avec
        # une clé `action:` d'un tout autre objet (table d'icônes, journal…).
        vues |= set(re.findall(r"""action:\s*['"]([a-z0-9]+(?:_[a-z0-9]+)+|rescan)['"]""", src))
        # `data-act` posé sur un nœud construit par h() : `el.dataset.act = '…'`.
        vues |= set(re.findall(r"""dataset\.act\s*=\s*['"]([a-z0-9_]+)['"]""", src))
    for a in sorted(vues):
        if a not in connues:
            pbs.append(f"(b) action absente de ACTIONS : {a}")
    if verbose:
        print(f"  (b) {len(vues)} actions référencées, toutes dans ACTIONS ({len(connues)})")


def check_ids(pbs, verbose):
    ids = set()
    for f in FICHIERS_HTML:
        ids |= set(re.findall(r'\sid="([A-Za-z0-9_\-]+)"', f.read_text(encoding="utf-8")))
    for f in FICHIERS_JS:                       # identifiants créés par les gabarits
        src = f.read_text(encoding="utf-8")
        ids |= set(re.findall(r'id="([A-Za-z0-9_\-]+)"', src))
        ids |= set(re.findall(r"""\.id\s*=\s*['"]([A-Za-z0-9_\-]+)['"]""", src))
        ids |= set(re.findall(r"""id:\s*['"]([A-Za-z0-9_\-]+)['"]""", src))
        # `zoneMessage('x')` (lib/dom.js) construit un <span id="x"> : c'est une
        # déclaration d'identifiant comme une autre.
        ids |= set(re.findall(r"""zoneMessage\(\s*['"]([A-Za-z0-9_\-]+)['"]""", src))
    manquants = set()
    for f in FICHIERS_JS:
        src = f.read_text(encoding="utf-8")
        # `\)` en fin de motif : on ignore les identifiants construits par
        # concaténation (`getElementById('cnt-' + nom)`), qui sont vérifiés par
        # l'existence des éléments côté HTML, pas par ce contrôle.
        for m in re.finditer(r"""getElementById\(\s*['"]([A-Za-z0-9_\-]+)['"]\s*\)""", src):
            if m.group(1) not in ids:
                manquants.add((m.group(1), f.relative_to(ROOT)))
    for nom, f in sorted(manquants):
        pbs.append(f"(c) getElementById('{nom}') sans identifiant correspondant ({f})")
    if verbose:
        print(f"  (c) {len(ids)} identifiants connus")


def check_emoji(pbs, verbose):
    n = 0
    for f in FICHIERS_JS + FICHIERS_HTML + sorted(PUBLIC.glob("css/*.css")):
        for i, ligne in enumerate(f.read_text(encoding="utf-8").split("\n"), 1):
            for m in EMOJI.finditer(ligne):
                if any(rx.search(ligne) for rx, _ in EXCEPTIONS_GLYPHE):
                    continue
                n += 1
                pbs.append(f"(d) glyphe {m.group(0)!r} (U+{ord(m.group(0)):04X}) "
                           f"dans {f.relative_to(ROOT)}:{i}")
    if verbose and not n:
        print("  (d) aucun emoji dans le front")


def check_styles(pbs, verbose):
    n = 0
    justifies = {f for f, _ in STYLE_JUSTIFIE}
    for f in FICHIERS_JS + FICHIERS_HTML:
        rel = str(f.relative_to(ROOT))
        for i, ligne in enumerate(f.read_text(encoding="utf-8").split("\n"), 1):
            if 'style="' in ligne and rel not in justifies:
                n += 1
                pbs.append(f"(e) style en ligne dans {rel}:{i} — la valeur doit venir d'un jeton")
    if verbose and not n:
        print("  (e) aucun style en ligne")


def check_imports(pbs, verbose):
    """Chaque nom importé est-il réellement exporté par le module visé ?"""
    exports = {}
    for f in FICHIERS_JS:
        src = sans_commentaires(f.read_text(encoding="utf-8"))
        noms = set()
        noms |= set(re.findall(r"export\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)", src))
        noms |= set(re.findall(r"export\s+(?:const|let|var|class)\s+([A-Za-z0-9_$]+)", src))
        for bloc in re.findall(r"export\s*\{([^}]*)\}", src):
            for part in bloc.split(","):
                part = part.strip()
                if not part:
                    continue
                noms.add(part.split(" as ")[-1].strip())
        exports[f.resolve()] = noms
    nb = 0
    for f in FICHIERS_JS:
        src = sans_commentaires(f.read_text(encoding="utf-8"))
        for bloc, cible in re.findall(r"import\s*\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]", src):
            chemin = (f.parent / cible).resolve()
            if not chemin.exists():
                pbs.append(f"(f) module introuvable : {cible} (importé par {f.relative_to(ROOT)})")
                continue
            for part in bloc.split(","):
                part = part.strip()
                if not part:
                    continue
                nom = part.split(" as ")[0].strip()
                nb += 1
                if nom not in exports.get(chemin, set()):
                    pbs.append(f"(f) {f.relative_to(ROOT)} importe « {nom} » "
                               f"que {cible} n'exporte pas")
    if verbose:
        print(f"  (f) {nb} noms importés vérifiés sur {len(FICHIERS_JS)} modules")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    pbs = []
    print("Contrôles du front :")
    check_routes(pbs, a.verbose)
    check_actions(pbs, a.verbose)
    check_ids(pbs, a.verbose)
    check_emoji(pbs, a.verbose)
    check_styles(pbs, a.verbose)
    check_imports(pbs, a.verbose)
    if pbs:
        print()
        for p in pbs:
            print("ÉCHEC :", p, file=sys.stderr)
        print(f"\n{len(pbs)} problème(s).", file=sys.stderr)
        return 1
    print("\nTout est cohérent : routes, actions, identifiants, icônes, styles, imports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
