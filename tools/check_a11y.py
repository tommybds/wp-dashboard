#!/usr/bin/env python3
"""Contrôles d'accessibilité statiques du front (phase 5 de la refonte).

Ils ne remplacent pas un essai au clavier et au lecteur d'écran : ils attrapent
les cinq fautes qui reviennent, et qui ne se voient pas à l'œil parce que
l'interface *a l'air* correcte.

  a. bouton sans nom accessible — une icône seule, sans `aria-label`, sans
     `title` et sans texte : elle est annoncée « bouton », point.
  b. image ou SVG sans étiquette ni `aria-hidden` — le lecteur d'écran énonce
     alors un nom de fichier, ou rien.
  c. champ de saisie sans étiquette — ni `aria-label`, ni `id` (donc pas de
     `<label for>` possible), ni `<label>` parent.
  d. `tabindex` positif — il réordonne la tabulation de TOUTE la page, et
     personne ne maintient cet ordre bien longtemps.
  e. `role="button"` sans gestion clavier — un <div> cliquable qu'Entrée
     n'active pas.

Le front est construit avec `h(tag, attrs, …enfants)` : le contrôle analyse
donc ces appels, avec leur imbrication, plutôt que du HTML. Un petit analyseur
(masque des littéraux, puis parenthèses équilibrées) suffit — et il vaut mieux
qu'une expression régulière, qui se trompe dès qu'un attribut contient une
parenthèse.

Usage : python3 tools/check_a11y.py [-v]
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

# Balises dont on vérifie le nom accessible / l'étiquette.
SAISIES = {"input", "select", "textarea"}

# Un `<input type=…>` de ces types n'a pas d'étiquette à porter.
TYPES_SANS_ETIQUETTE = {"hidden", "submit", "reset", "button"}


# --------------------------------------------------------------- analyseur JS
def masque_code(src: str) -> bytearray:
    """1 là où l'on est dans du CODE, 0 dans un littéral ou un commentaire.

    Les chaînes du front contiennent des accolades, des parenthèses et des
    apostrophes : sans ce masque, l'équilibrage des parenthèses part en vrille
    dès le premier `'/[&<>"\\']/g'`.
    """
    m = bytearray(b"\x01" * len(src))
    i, n = 0, len(src)
    etat = None          # None | "'" | '"' | '`' | '//' | '/*' | 're'
    prev = ""            # dernier caractère de code significatif
    classe_regex = False
    while i < n:
        c = src[i]
        if etat is None:
            if c == "'" or c == '"' or c == "`":
                etat = c
                m[i] = 0
            elif c == "/" and i + 1 < n and src[i + 1] == "/":
                etat = "//"
                m[i] = m[i + 1] = 0
                i += 1
            elif c == "/" and i + 1 < n and src[i + 1] == "*":
                etat = "/*"
                m[i] = m[i + 1] = 0
                i += 1
            elif c == "/" and (prev == "" or prev in "(,=:[!&|?{};+-*%~^<>\n"):
                etat = "re"
                classe_regex = False
                m[i] = 0
            elif not c.isspace():
                prev = c
        elif etat in ("'", '"', "`"):
            m[i] = 0
            if c == "\\":
                if i + 1 < n:
                    m[i + 1] = 0
                i += 1
            elif c == etat:
                etat = None
                prev = c
        elif etat == "//":
            m[i] = 0
            if c == "\n":
                etat = None
        elif etat == "/*":
            m[i] = 0
            if c == "*" and i + 1 < n and src[i + 1] == "/":
                m[i + 1] = 0
                i += 1
                etat = None
        elif etat == "re":
            m[i] = 0
            if c == "\\":
                if i + 1 < n:
                    m[i + 1] = 0
                i += 1
            elif c == "[":
                classe_regex = True
            elif c == "]":
                classe_regex = False
            elif c == "/" and not classe_regex:
                etat = None
                prev = c
        i += 1
    return m


def _fin_parenthese(src, m, ouvre):
    """Index de la parenthèse fermante correspondant à `ouvre` (ou None)."""
    d, i, n = 0, ouvre, len(src)
    while i < n:
        if m[i]:
            if src[i] == "(":
                d += 1
            elif src[i] == ")":
                d -= 1
                if d == 0:
                    return i
        i += 1
    return None


def _fin_accolade(src, m, ouvre):
    d, i, n = 0, ouvre, len(src)
    while i < n:
        if m[i]:
            if src[i] == "{":
                d += 1
            elif src[i] == "}":
                d -= 1
                if d == 0:
                    return i
        i += 1
    return None


APPEL = re.compile(r"\bh\(\s*['\"]([a-zA-Z0-9]+)['\"]")


class Noeud:
    __slots__ = ("tag", "debut", "fin", "attrs", "enfants", "ligne", "parents")

    def __init__(self, tag, debut, fin, attrs, enfants, ligne):
        self.tag = tag
        self.debut = debut
        self.fin = fin
        self.attrs = attrs
        self.enfants = enfants
        self.ligne = ligne
        self.parents = []


def analyser(src: str):
    """Tous les appels `h('tag', …)` du fichier, avec leur imbrication."""
    m = masque_code(src)
    noeuds = []
    for mo in APPEL.finditer(src):
        if not m[mo.start()]:
            continue                     # `h('div'` cité dans un commentaire
        ouvre = src.index("(", mo.start())
        fin = _fin_parenthese(src, m, ouvre)
        if fin is None:
            continue
        # Les attributs : la première accolade après la virgule qui suit le tag.
        attrs, apres = "", mo.end()
        j = mo.end()
        while j < fin and (not m[j] or src[j].isspace()):
            j += 1
        if j < fin and src[j] == ",":
            j += 1
            while j < fin and (not m[j] or src[j].isspace()):
                j += 1
            if j < fin and src[j] == "{":
                f = _fin_accolade(src, m, j)
                if f is not None and f < fin:
                    attrs, apres = src[j:f + 1], f + 1
        noeuds.append(Noeud(mo.group(1), mo.start(), fin, attrs,
                            src[apres:fin], src.count("\n", 0, mo.start()) + 1))
    # Imbrication : un appel contenu dans un autre en est l'enfant.
    for a in noeuds:
        a.parents = [b.tag for b in noeuds if b is not a and b.debut < a.debut and a.fin < b.fin]
    return noeuds, m


def enfants_directs_texte(noeud, src, m):
    """Le nœud reçoit-il une chaîne littérale comme enfant DIRECT ?

    `h('button', {…}, iconEl('x'), 'Actions')` en a une ; `h('button', {…},
    iconEl('x'))` n'en a pas — la chaîne 'x' appartient à l'appel imbriqué.
    """
    debut = noeud.fin - len(noeud.enfants)
    d = 0
    for i in range(debut, noeud.fin):
        if m[i]:
            if src[i] in "([{":
                d += 1
            elif src[i] in ")]}":
                d -= 1
        elif d == 0 and src[i] in "'\"`":
            # Le masque met à 0 les délimiteurs ET le contenu : un délimiteur
            # au niveau 0 est donc bien une chaîne enfant directe.
            return True
    return False


def a_attr(attrs, *noms):
    """L'attribut est-il présent ? `{id: x}` comme `{id}` (forme abrégée)."""
    for nom in noms:
        q = re.escape(nom)
        if re.search(r"""(^|[{,\s])['"]?""" + q + r"""['"]?\s*:""", attrs):
            return True
        if re.search(r"(^|[{,\s])" + q + r"\s*[,}]", attrs):
            return True
    return False


def enfant_variable(noeud, src, m):
    """Le nœud reçoit-il une VARIABLE comme enfant direct ?

    `h('button', {…}, iconEl(ic), label)` porte son nom dans `label` : rien ne
    le dit au contrôle statique, mais un bouton dont tous les enfants sont des
    appels (une icône, rien d'autre) est, lui, forcément muet.
    """
    debut = noeud.fin - len(noeud.enfants)
    d, i = 0, debut
    while i < noeud.fin:
        if m[i]:
            c = src[i]
            if c in "([{":
                d += 1
            elif c in ")]}":
                d -= 1
            elif d == 0 and (c.isalpha() or c == "_" or c == "$"):
                j = i
                while j < noeud.fin and (src[j].isalnum() or src[j] in "_$."):
                    j += 1
                mot = src[i:j]
                k = j
                while k < noeud.fin and src[k].isspace():
                    k += 1
                appel = k < noeud.fin and src[k] == "("
                if not appel and mot not in ("null", "false", "true", "undefined"):
                    return True
                i = j - 1
        i += 1
    return False


# ------------------------------------------------------------------ contrôles
def check_js(pbs, verbose):
    n_btn = n_saisie = 0
    for f in FICHIERS_JS:
        src = f.read_text(encoding="utf-8")
        rel = f.relative_to(ROOT)
        noeuds, m = analyser(src)
        for nd in noeuds:
            # (a) bouton sans nom accessible
            if nd.tag in ("button", "a") and nd.tag == "button":
                n_btn += 1
                nomme = (a_attr(nd.attrs, "text", "aria-label", "title")
                         or "text:" in nd.enfants or "label:" in nd.enfants
                         or enfants_directs_texte(nd, src, m)
                         or enfant_variable(nd, src, m))
                if not nomme:
                    pbs.append(f"(a) bouton sans nom accessible : {rel}:{nd.ligne} "
                               f"— ajoutez `text`, `aria-label` ou un libellé")
            # (c) champ de saisie sans étiquette
            if nd.tag in SAISIES:
                t = re.search(r"""type:\s*['"]([a-z]+)['"]""", nd.attrs)
                if t and t.group(1) in TYPES_SANS_ETIQUETTE:
                    continue
                n_saisie += 1
                if not (a_attr(nd.attrs, "aria-label", "aria-labelledby", "id", "title")
                        or "label" in nd.parents):
                    pbs.append(f"(c) champ sans étiquette : <{nd.tag}> {rel}:{nd.ligne} "
                               f"— `aria-label`, un `id` reçu par un <label for>, "
                               f"ou un <label> parent")
            # (e) role="button" sans gestion clavier
            if re.search(r"""role:\s*['"]button['"]""", nd.attrs):
                # Le gestionnaire est souvent posé APRÈS la construction
                # (`c.onkeydown = …`) : on regarde les lignes qui suivent (fenêtre large,
                suite = src[nd.fin:nd.fin + 1500]
                clavier = ("onkeydown" in nd.attrs or "onkeydown" in suite
                           or "activeAuClavier" in suite
                           or a_attr(nd.attrs, "data-tip"))
                if not clavier and nd.tag != "button":
                    pbs.append(f"(e) role=\"button\" sans gestion clavier : "
                               f"<{nd.tag}> {rel}:{nd.ligne}")
        # (d) tabindex positif
        for i, ligne in enumerate(src.split("\n"), 1):
            for mo in re.finditer(r"""tabindex['"]?\s*[:=]\s*['"]?(-?\d+)""", ligne, re.I):
                if int(mo.group(1)) > 0:
                    pbs.append(f"(d) tabindex positif ({mo.group(1)}) : {rel}:{i}")
    if verbose:
        print(f"  (a) {n_btn} boutons construits par h() vérifiés")
        print(f"  (c) {n_saisie} champs de saisie vérifiés")


BALISE = re.compile(r"<(button|svg|img|input|select|textarea)\b([^>]*)>", re.I | re.S)


def zones_label(src):
    """Plages couvertes par un <label>…</label> : un champ à l'intérieur est
    étiqueté par lui, sans avoir besoin d'un `for`."""
    zones = []
    for mo in re.finditer(r"<label\b", src, re.I):
        fin = src.find("</label>", mo.end())
        if fin > 0:
            zones.append((mo.start(), fin))
    return zones


def check_html(pbs, verbose):
    n = 0
    for f in FICHIERS_HTML:
        src = f.read_text(encoding="utf-8")
        rel = f.relative_to(ROOT)
        labels = zones_label(src)
        for mo in BALISE.finditer(src):
            tag, attrs = mo.group(1).lower(), mo.group(2)
            ligne = src.count("\n", 0, mo.start()) + 1
            n += 1
            etiquete = re.search(r'\baria-label(ledby)?\s*=', attrs) or re.search(r'\btitle\s*=', attrs)
            if tag == "button":
                # Le contenu du bouton compte comme nom : on prend le texte
                # jusqu'à </button>, balises retirées.
                fin = src.find("</button>", mo.end())
                interne = re.sub(r"<[^>]*>", "", src[mo.end():fin]) if fin > 0 else ""
                if not etiquete and not interne.strip():
                    pbs.append(f"(a) bouton sans nom accessible : {rel}:{ligne}")
            elif tag in ("svg", "img"):
                if tag == "img" and not re.search(r"\balt\s*=", attrs):
                    pbs.append(f"(b) <img> sans `alt` : {rel}:{ligne}")
                if tag == "svg" and not etiquete and 'aria-hidden' not in attrs:
                    pbs.append(f"(b) <svg> sans étiquette ni `aria-hidden` : {rel}:{ligne}")
            elif tag in SAISIES:
                t = re.search(r"""type\s*=\s*["']?([a-z]+)""", attrs, re.I)
                if t and t.group(1).lower() in TYPES_SANS_ETIQUETTE:
                    continue
                idm = re.search(r"""\bid\s*=\s*["']([^"']+)""", attrs)
                pour = idm and re.search(r'for\s*=\s*["\']' + re.escape(idm.group(1)), src)
                dans = any(a < mo.start() < b for a, b in labels)
                if not etiquete and not pour and not dans:
                    pbs.append(f"(c) champ sans étiquette : <{tag}> {rel}:{ligne}")
        for i, ligne in enumerate(src.split("\n"), 1):
            for mo in re.finditer(r"""tabindex\s*=\s*["']?(-?\d+)""", ligne, re.I):
                if int(mo.group(1)) > 0:
                    pbs.append(f"(d) tabindex positif ({mo.group(1)}) : {rel}:{i}")
            if re.search(r'role\s*=\s*["\']button', ligne, re.I):
                pbs.append(f"(e) role=\"button\" en HTML : {rel}:{i} — utilisez <button>")
    if verbose:
        print(f"  (b) {n} balises interactives vérifiées dans les deux pages HTML")


def check_icones(pbs, verbose):
    """`icon()` / `iconEl()` sans `label` sont décoratifs (aria-hidden) : c'est
    voulu. Ce qui ne l'est pas, c'est un bouton dont l'icône est le SEUL
    contenu ET dont l'icône porte un `label` différent du bouton — deux noms
    pour une même chose. On se contente ici de vérifier que le sprite n'est
    jamais inséré sans passer par ces deux fonctions."""
    n = 0
    for f in FICHIERS_JS:
        src = f.read_text(encoding="utf-8")
        for i, ligne in enumerate(src.split("\n"), 1):
            if "<use href=" in ligne and "icons.js" not in str(f):
                n += 1
                pbs.append(f"(b) sprite inséré à la main : {f.relative_to(ROOT)}:{i} "
                           f"— passez par icon()/iconEl(), qui posent aria-hidden ou aria-label")
    if verbose and not n:
        print("  (b) aucune insertion de sprite hors lib/icons.js")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    pbs = []
    print("Contrôles d'accessibilité :")
    check_js(pbs, a.verbose)
    check_html(pbs, a.verbose)
    check_icones(pbs, a.verbose)
    if pbs:
        print()
        for p in pbs:
            print("ÉCHEC :", p, file=sys.stderr)
        print(f"\n{len(pbs)} problème(s).", file=sys.stderr)
        return 1
    print("\nNoms accessibles, étiquettes, ordre de tabulation et gestion clavier : OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
