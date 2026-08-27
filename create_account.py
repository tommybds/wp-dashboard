#!/usr/bin/env python3
"""Crée ou remplace le compte d'accès au dashboard (data/auth.json).

Usage :
    python3 create_account.py                 # demande login + mot de passe
    python3 create_account.py <login>         # demande seulement le mot de passe

Le mot de passe n'est jamais stocké en clair : seul un dérivé PBKDF2-HMAC-SHA256
(200 000 itérations, sel aléatoire) est écrit. Il n'y a qu'un seul compte.
"""
import os, sys, json, hashlib, getpass

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
AUTH_PATH = os.path.join(DATA, "auth.json")
ITERS = 200000


def main():
    user = sys.argv[1] if len(sys.argv) > 1 else input("Login : ").strip()
    if not user:
        raise SystemExit("login vide.")
    pw = getpass.getpass("Mot de passe : ")
    if len(pw) < 8:
        raise SystemExit("mot de passe trop court (8 caractères minimum).")
    if pw != getpass.getpass("Confirmer : "):
        raise SystemExit("les deux saisies diffèrent.")
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERS)
    os.makedirs(DATA, exist_ok=True)
    with open(AUTH_PATH, "w") as fh:
        json.dump({"user": user, "salt": salt.hex(), "hash": dk.hex(), "iters": ITERS}, fh)
    os.chmod(AUTH_PATH, 0o600)
    print(f"Compte « {user} » enregistré dans {AUTH_PATH}.")


if __name__ == "__main__":
    main()
