#!/usr/bin/env bash
# Déploiement du front, à lancer DEPUIS LE MAC.
#
#   tools/deploy.sh --dry-run     estampille la version, ne copie rien
#   tools/deploy.sh               estampille + scp de public/ vers le VPS
#   tools/deploy.sh --nginx       + `systemctl reload nginx` (uniquement si la
#                                   configuration du vhost a changé)
#
# Ce que fait l'estampillage :
#   * public/version.js          → export const V = "AAAA-MM-JJ-hhmm"
#   * index.html et login.html   → tous les `?v=…` (CSS, app.js, table d'imports)
#   * la table d'imports         → régénérée à partir des fichiers réellement
#                                  présents, pour qu'un module ajouté soit
#                                  versionné sans qu'on ait à y penser
#
# Les polices ne portent PAS de `?v=` : leur URL doit être identique à celle
# du @font-face, sinon le navigateur télécharge deux fois. Une police qui
# change change de nom de fichier.
#
# Le backend (actions_server.py) n'est pas concerné : `git pull` +
# `systemctl restart wp-dashboard-api` comme avant.
set -euo pipefail

CIBLE="${WPDASH_CIBLE:-root@46.62.165.112}"
DEST="${WPDASH_DEST:-/opt/wp-dashboard/public/}"
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC="$RACINE/public"

DRY=0
NGINX=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --nginx)   NGINX=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "argument inconnu : $arg" >&2; exit 2 ;;
  esac
done

V="$(date +%Y-%m-%d-%H%M)"

echo "== contrôles"
python3 "$RACINE/tools/check_tokens.py" > /dev/null
python3 "$RACINE/tools/check_front.py"  > /dev/null
python3 "$RACINE/tools/check_a11y.py"   > /dev/null
python3 "$RACINE/tools/check_dead.py"   > /dev/null
for f in $(find "$PUBLIC" -name '*.js' | sort); do
  # `node --check <fichier>` ne vérifie PAS un module ES (il le détecte et rend
  # la main) : il faut le lui passer sur l'entrée standard en mode module.
  node --input-type=module --check < "$f" || { echo "syntaxe : $f" >&2; exit 1; }
done
echo "   jetons, accessibilité, code mort, front et syntaxe : OK"

echo "== estampillage v=$V"
python3 - "$PUBLIC" "$V" <<'PY'
import json, pathlib, re, sys

public, V = pathlib.Path(sys.argv[1]), sys.argv[2]

(public / "version.js").write_text(
    "/* Version du front, posée par tools/deploy.sh. Elle sert de suffixe `?v=`\n"
    "   à la table d'imports et aux feuilles de style : nginx peut alors mettre\n"
    "   en cache css/, lib/, components/, screens/ pendant un an, index.html\n"
    "   restant en no-store. */\n"
    f'export const V = "{V}";\n', encoding="utf-8")

# Table d'imports : un module = une entrée, construite depuis le disque.
modules = ["./version.js"]
for dossier in ("lib", "components", "screens"):
    modules += sorted(f"./{dossier}/{p.name}" for p in (public / dossier).glob("*.js"))
carte = json.dumps({"imports": {m: f"{m}?v={V}" for m in modules}},
                   ensure_ascii=False, indent=2)

index = public / "index.html"
s = index.read_text(encoding="utf-8")
s = re.sub(r'(<script type="importmap">)\n.*?\n(</script>)',
           lambda m: m.group(1) + "\n" + carte + "\n" + m.group(2), s, flags=re.S)
index.write_text(s, encoding="utf-8")

# Tous les `?v=…` des deux pages (CSS, app.js) — sauf les polices, dont l'URL
# doit rester identique à celle du @font-face.
for page in (index, public / "login.html"):
    s = page.read_text(encoding="utf-8")
    s = re.sub(r'(href="fonts/[^"]+?)\?v=[^"]*"', r'\1"', s)
    s = re.sub(r'\?v=[0-9A-Za-z._-]+', f'?v={V}', s)
    page.write_text(s, encoding="utf-8")

print(f"   version.js, table d'imports ({len(modules)} modules) et suffixes : OK")
PY

if [ "$DRY" = "1" ]; then
  echo "== --dry-run : rien n'est copié"
  exit 0
fi

echo "== copie vers $CIBLE:$DEST"
# `--delete` volontairement absent : le VPS peut porter des fichiers hors dépôt
# (favicon personnalisé, fleet.json produit par le collecteur — qui vit dans
# data/ mais est servi depuis public/ par un lien).
rsync -av --exclude='.DS_Store' --exclude='index.html.orig' \
      "$PUBLIC"/ "$CIBLE:$DEST"

if [ "$NGINX" = "1" ]; then
  echo "== rechargement de nginx"
  ssh "$CIBLE" 'nginx -t && systemctl reload nginx'
else
  echo "   nginx non rechargé (passer --nginx si le vhost a changé)"
fi

echo "== déployé en v=$V"
