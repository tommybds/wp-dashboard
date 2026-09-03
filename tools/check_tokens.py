#!/usr/bin/env python3
"""Contraste WCAG des jetons de couleur, dans les deux thèmes.

Lit public/css/tokens.css, reconstitue la palette claire et la palette sombre,
et vérifie les seuils du §3 du plan de refonte :

  * texte courant (--ink) sur les fonds        ≥ 7:1
  * texte secondaire (--ink-2, --muted)        ≥ 4.5:1
  * chips (--ok/--warn/--err/--accent-ink)     ≥ 4.5:1 sur leur fond
  * texte sur aplat d'accent                   ≥ 4.5:1

Vérifie en plus que le bloc « sombre suivi du système » et le bloc « sombre
forcé » déclarent EXACTEMENT les mêmes valeurs : sans cela, le bouton de thème
donnerait un rendu différent de la préférence système.

Sortie : un tableau, code de retour 1 si un seuil n'est pas tenu.
"""
import re
import sys
from pathlib import Path

TOKENS = Path(__file__).resolve().parent.parent / "public" / "css" / "tokens.css"

# (avant-plan, fond, seuil, description)
PAIRS = [
    ("ink", "page", 7.0, "texte courant sur la page"),
    ("ink", "surface", 7.0, "texte courant sur une surface"),
    ("ink-2", "page", 4.5, "texte appuyé sur la page"),
    ("ink-2", "surface", 4.5, "texte appuyé sur une surface"),
    ("muted", "page", 4.5, "texte secondaire sur la page"),
    ("muted", "surface", 4.5, "texte secondaire sur une surface"),
    ("muted", "surface-2", 4.5, "texte secondaire sur surface secondaire"),
    ("muted", "neutral-bg", 4.5, "chip « inconnu »"),
    ("muted", "code-bg", 4.5, "code et sorties wp-cli"),
    ("accent", "surface", 4.5, "lien / action sur une surface"),
    ("accent", "page", 4.5, "lien / action sur la page"),
    ("accent-ink", "accent-bg", 4.5, "chip d'accent"),
    ("on-accent", "accent", 4.5, "texte sur bouton principal"),
    ("ok", "ok-bg", 4.5, "chip « à jour »"),
    ("warn", "warn-bg", 4.5, "chip « attention »"),
    ("err", "err-bg", 4.5, "chip « critique »"),
    ("ok", "surface", 4.5, "texte d'état ok sur surface"),
    ("warn", "surface", 4.5, "texte d'état attention sur surface"),
    ("err", "surface", 4.5, "texte d'état critique sur surface"),
]

HEX = re.compile(r"^#([0-9A-Fa-f]{6})$")


def _channel(v: float) -> float:
    v /= 255.0
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def luminance(hexcolor: str) -> float:
    h = hexcolor.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def block(css: str, selector: str) -> dict:
    """Déclarations `--nom:#rrggbb` d'un bloc, repéré par son sélecteur exact."""
    # Le sélecteur apparaît AUSSI dans le commentaire d'en-tête : on n'accepte
    # que l'occurrence réellement suivie d'une accolade ouvrante.
    m = re.search(re.escape(selector.rstrip("{")) + r"\s*\{", css)
    if not m:
        raise SystemExit(f"bloc introuvable dans tokens.css : {selector}")
    start = m.end()
    depth, j = 1, start
    while depth and j < len(css):
        if css[j] == "{":
            depth += 1
        elif css[j] == "}":
            depth -= 1
        j += 1
    body = css[start:j - 1]
    out = {}
    for name, value in re.findall(r"--([a-z0-9-]+)\s*:\s*([^;]+);", body):
        value = value.strip()
        if HEX.match(value):
            out[name] = value
    return out


def main() -> int:
    css = TOKENS.read_text(encoding="utf-8")
    light = block(css, ":root{")
    dark_auto = block(css, ':root:not([data-theme="light"])')
    dark_forced = block(css, ':root[data-theme="dark"]')

    problems = []

    if dark_auto != dark_forced:
        diff = sorted(set(dark_auto) ^ set(dark_forced)) or [
            k for k in dark_auto if dark_auto[k] != dark_forced.get(k)
        ]
        problems.append(
            "les deux blocs sombres divergent (le bouton de thème ne rendrait "
            "pas comme la préférence système) : " + ", ".join(diff)
        )

    dark = dict(light)
    dark.update(dark_auto)

    for theme_name, palette in (("clair", light), ("sombre", dark)):
        print(f"\n== thème {theme_name}")
        for fg, bg, mini, label in PAIRS:
            if fg not in palette or bg not in palette:
                problems.append(f"[{theme_name}] jeton absent : --{fg} ou --{bg}")
                continue
            ratio = contrast(palette[fg], palette[bg])
            ok = ratio + 1e-9 >= mini
            flag = "ok  " if ok else "ÉCHEC"
            print(f"  {flag} {ratio:5.2f} (≥ {mini})  --{fg} sur --{bg:12s} {label}")
            if not ok:
                problems.append(
                    f"[{theme_name}] --{fg} sur --{bg} : {ratio:.2f} < {mini} ({label})"
                )

    print()
    if problems:
        for p in problems:
            print("ÉCHEC :", p, file=sys.stderr)
        return 1
    print("Tous les seuils de contraste sont tenus dans les deux thèmes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
