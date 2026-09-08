#!/usr/bin/env python3
"""Chasse aux portes dérobées du parc — scan STRUCTUREL, pas de signatures.

Leçon du sweep du 2026-08-22, et c'est la raison d'être de ce fichier :
rechercher les IOC exacts d'un incident connu (le nom de fichier, la clé) n'a
rien trouvé ailleurs sur le parc. Ce sont les STRUCTURES qui ont tout sorti —
une extension qui se retire de `all_plugins`, un `wp_set_auth_cookie` hors
plugin d'authentification, un `include 'compress.zlib://'`. Ce script cherche
donc des formes, jamais des noms.

Il regarde aussi À CÔTÉ du docroot. Le kit le plus abouti rencontré sur le parc
(serveur finaxys) vivait dans un faux `wp-content/` et un faux `wp-includes/`
posés en voisins de `htdocs/` : invisible depuis WordPress, invisible d'un scan
borné au docroot. Le voisinage n'est retenu que s'il n'héberge qu'un seul site
du parc — sinon `/var/www/html` ferait remonter à `/var/www` et on scannerait
le serveur entier une fois par site.

Aucune écriture sur les sites : `find` et `grep`, sous nice/ionice, avec des
plafonds explicites. Ce qui dépasse un plafond est DIT (`truncated`), jamais
escamoté : « rien trouvé » ne doit jamais pouvoir vouloir dire « pas regardé ».
Même règle pour un dossier illisible au compte utilisé (`unreadable`), cas
courant depuis que le dashboard peut tourner sans root.

Ce que ce scan ne voit pas, par construction : ce qui n'est pas un fichier. La
charge de sisma-androgyne vivait dans l'option `_wp_pbn_c`, le spam d'elwave
dans un contenu Elementor, la porte de ffhbi dans un événement wp-cron sans
fichier. Rien de tout cela ne laisse de trace ici — c'est le rôle de l'agent
WordPress, qui voit la base et le cron mais pas le voisinage du docroot.

Usage :
    python3 scan.py                  # tout le parc → data/scan_found.json
    python3 scan.py --only vps-usf   # un seul serveur
    python3 scan.py --print          # avec le détail à l'écran
    python3 scan.py --baseline       # accepte le résultat courant comme référence

La référence (data/scan_baseline.json) est ce qui rend le tout exploitable :
sans elle, un site sain sort ~190 signalements légitimes ; avec elle, il n'en
sort plus aucun, et ce qui apparaît la nuit suivante se voit. Elle ne se pose
jamais toute seule — accepter en bloc ce qu'on n'a pas regardé reviendrait à
blanchir une porte dérobée déjà installée.
"""
import os, sys, re, datetime, collections
import concurrent.futures

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from dashlib import DATA_DIR as DATA          # noqa: E402
from dashlib import save_json as _save_json   # noqa: E402
from dashlib import scan_fingerprint, scan_baseline_from  # noqa: E402
import actions_server as A                    # noqa: E402

OUT_PATH = os.path.join(DATA, "scan_found.json")
BASELINE_PATH = os.path.join(DATA, "scan_baseline.json")
FLEET_PATH = os.path.join(DATA, "fleet.json")

MAX_FILES = 400000    # fichiers examinés par serveur (le mutualisé en porte 216 000)
MAX_HITS = 4000       # correspondances remontées par serveur (41 sites sur le mutualisé)
MAX_PER_RULE = 40     # correspondances remontées par règle et par site
MAX_SIZE_MB = 3       # au-delà, un .php n'est plus du code mais une donnée
TIMEOUT = 1500        # le mutualisé porte ~41 sites : la passe est longue
MAX_VOISINS = 4       # docroots sous un même parent au-delà desquels on ne remonte pas

# Dossiers dont le PARENT ne doit jamais devenir une racine de scan : ils
# hébergent tout le monde, y remonter reviendrait à scanner le serveur entier.
PARENTS_INTERDITS = {"/", "/var", "/var/www", "/var/www/vhosts", "/var/www/html",
                     "/home", "/srv", "/opt", "/usr", "/usr/share", "/data"}

# ---------------------------------------------------------------------------
# Les règles. `re` sert deux fois : transmise à grep -Ei sur le serveur (elle
# fait le tri, seules les lignes utiles voyagent), puis rejouée ici pour savoir
# LAQUELLE a mordu — grep -f ne le dit pas.
#
# `sev` suit le vocabulaire du reste du dashboard (critical/high/medium/low).
# `why` est ce qui s'affiche : une règle qu'on ne sait pas interpréter produit
# un signalement qu'on n'ose ni traiter ni fermer.
# ---------------------------------------------------------------------------
RULES = [
    {"id": "eval_decode", "sev": "critical",
     "label": "eval() sur une chaîne décodée",
     "re": r"\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|hex2bin|pack)\s*\(",
     "why": "Le code réellement exécuté n'est pas lisible dans le fichier. "
            "Aucune extension légitime n'a besoin de se cacher d'une relecture."},
    {"id": "eval_input", "sev": "critical",
     "label": "eval() sur une entrée HTTP",
     "re": r"\b(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
     "why": "Le visiteur choisit le code exécuté : c'est la définition d'un webshell."},
    {"id": "shell_input", "sev": "critical",
     "label": "commande système sur une entrée HTTP",
     "re": r"\b(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*[\"']?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)",
     "why": "Exécution de commandes du serveur pilotée depuis l'extérieur."},
    {"id": "stream_include", "sev": "critical",
     "label": "include d'un flux compressé ou d'une archive",
     "re": r"\b(include|require)(_once)?\s*[^;\n]{0,80}(compress\.(zlib|bzip2)|data)://",
     "why": "Le PHP n'est jamais en clair sur le disque — mécanique exacte du kit "
            "wp-compat-cache trouvé sur le serveur finaxys le 22/08."},
    {"id": "domain_key", "sev": "critical",
     "label": "clé de déchiffrement dérivée du domaine",
     "re": r"hash\s*\(\s*[\"']sha256[\"']\s*,\s*[\"'][^\"']{3,60}\|[0-9]{6,}",
     "why": "La charge ne se déchiffre que sur l'hôte visé : kit généré pour ce site, "
            "impossible à analyser ailleurs. Vu tel quel sur finaxys."},
    {"id": "hide_plugin", "sev": "high",
     "label": "extension qui se retire de la liste des extensions",
     "re": r"add_filter\s*\(\s*[\"']all_plugins[\"']",
     "why": "Une extension qui se masque de l'écran Extensions. Quelques outils de "
            "marque blanche le font légitimement : à confirmer, pas à ignorer."},
    {"id": "auth_cookie", "sev": "high",
     "label": "ouverture de session sans mot de passe",
     "re": r"\bwp_set_auth_cookie\s*\(",
     "why": "Connecte un compte sans authentification. Légitime dans un plugin de "
            "connexion (wp-cli-login-server), à examiner partout ailleurs."},
    {"id": "auto_prepend", "sev": "high",
     "label": "code injecté avant chaque page (auto_prepend_file)",
     "re": r"auto_prepend_file",
     "conf_only": True,
     "why": "Charge exécutée avant TOUT script PHP du site, sans être appelée par "
            "WordPress. C'est ce qui restait sur la-kage après la première passe."},
    {"id": "self_write_php", "sev": "medium",
     "label": "script qui réécrit un fichier PHP",
     "re": r"\bfile_put_contents\s*\(\s*[^,;\n]{0,80}\.php[\"']",
     "why": "Mécanique de persistance : le fichier « revient » après chaque nettoyage. "
            "C'est ainsi que l'option _wp_pbn_c réécrivait functions.php sur sisma-androgyne."},
    {"id": "fake_author", "sev": "medium",
     "label": "en-tête d'extension usurpant WordPress",
     "re": r"^[^A-Za-z0-9]{0,4}(Author|Plugin URI)\s*:\s*(WordPress\s*$|https?://wordpress\.org/plugins/\s*$)",
     "why": "Une extension du dépôt officiel ne s'annonce jamais ainsi : en-tête "
            "recopié pour se fondre dans la liste."},
    {"id": "chr_chain", "sev": "low",
     "label": "chaîne construite caractère par caractère",
     "re": r"(chr\s*\(\s*[0-9]{1,3}\s*\)\s*\.\s*){3,}chr\s*\(",
     "why": "Obfuscation : le nom de fonction ou d'URL n'apparaît nulle part en clair."},
    {"id": "htaccess_php", "sev": "high",
     "label": ".htaccess qui autorise du PHP là où il ne devrait pas y en avoir",
     "re": r"^\s*(AddType|AddHandler|SetHandler)[^\n]*php",
     "conf_only": True,
     "why": "Rend exécutable un dossier de dépôt (uploads, cache) : la moitié du travail "
            "d'un webshell est faite."},
    {"id": "htaccess_indexes", "sev": "low",
     "label": ".htaccess ouvrant l'index du dossier",
     "re": r"^\s*Options\s+\+Indexes",
     "conf_only": True,
     "why": "Accompagnait chaque faux dossier du kit finaxys — l'attaquant veut lister "
            "ses propres fichiers depuis un navigateur."},
    {"id": "long_b64", "sev": "low",
     "label": "bloc encodé de plus de 1500 caractères",
     "re": r"[\"'][A-Za-z0-9+/]{1500,}={0,2}[\"']",
     # grep construit un automate déterministe : une répétition bornée à 1500
     # le fait exploser (mesuré : 65 s pour 400 fichiers, contre moins d'une
     # seconde ici). Le serveur cherche donc un motif court et bon marché, et
     # c'est le dashboard qui applique le vrai seuil en rejouant `re`.
     "re_grep": r"[\"'][A-Za-z0-9+/]{120}",
     "why": "Une charge stockée en base64. Des extensions légitimes embarquent ainsi "
            "des polices ou des images : à regarder, pas à conclure."},
]
RULES_BY_ID = {r["id"]: r for r in RULES}

# Règles de CHEMIN — elles ne se cherchent pas dans le contenu mais dans
# l'emplacement, et sont donc évaluées par `find` sur le serveur.
PATH_RULES = {
    "php_in_uploads": {"sev": "high", "label": "script PHP dans le dossier des médias",
                       "why": "wp-content/uploads reçoit des fichiers déposés par des "
                              "visiteurs ou des comptes peu privilégiés : aucun .php n'y "
                              "a sa place."},
    "fake_core_dir": {"sev": "critical", "label": "faux dossier du cœur hors du site",
                      "why": "Un wp-content/ ou wp-includes/ posé À CÔTÉ du docroot n'est "
                             "pas une installation WordPress : c'est un atelier. Exactement "
                             "ce qui a été trouvé sur le serveur finaxys."},
    "php_outside": {"sev": "medium", "label": "script PHP hors du site, dans son voisinage",
                    "why": "Du PHP dans le dossier parent du docroot ne sert pas le site. "
                           "Parfois un outil d'administration légitime, parfois le reste "
                           "d'un kit."},
    "cjk_padding": {"sev": "medium", "label": "idéogrammes en remplissage dans du PHP",
                    "why": "Le kit finaxys était bourré de poésie chinoise classique pour "
                           "déjouer l'analyse de signature et d'entropie. Une extension "
                           "réellement sinophone met ses traductions dans des .po, pas "
                           "au milieu de son code."},
}
ALL_RULES = dict(
    {r["id"]: {"sev": r["sev"], "label": r["label"], "why": r["why"]} for r in RULES},
    **PATH_RULES)

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def save_json_atomic(path, obj, mode=0o600):
    """0600 : ce fichier nomme des chemins de webshells présumés, avec extraits."""
    _save_json(path, obj, mode=mode, indent=None, fsync=True)


def racines(sites, tous_docroots):
    """Docroots d'un serveur + leur voisinage → racines de scan dédoublonnées.

    Le voisinage (dossier parent) n'est retenu que s'il est PROPRE au site :
    sur le mutualisé, /var/www/vhosts/elwave.fr/ n'abrite qu'elwave et mérite
    d'être vu en entier ; /var/www, qui abrite tout le monde, ne le mérite pas.
    """
    docroots = sorted({s for s in sites if s and s.startswith("/")})
    parents = collections.Counter(os.path.dirname(d.rstrip("/")) for d in tous_docroots)
    out = []
    for d in docroots:
        p = os.path.dirname(d.rstrip("/"))
        # Un dossier système, ou un parent qui abrite un grand nombre de sites,
        # reste hors du scan : on garde le docroot seul. Le seuil n'est pas à 1
        # — un vhost Plesk porte couramment deux ou trois docroots (sumotori.fr
        # en a trois : httpdocs, dev, alizes-locations), et c'est justement dans
        # leur dossier commun qu'un kit peut se poser sans être servi par aucun.
        # Le dédoublonnage par inclusion, plus bas, évite de scanner deux fois.
        out.append(d if (p in PARENTS_INTERDITS or parents[p] > MAX_VOISINS
                         or p.count("/") < 2) else p)
    # Dédoublonnage par inclusion : si /a est retenu, /a/htdocs n'ajoute rien.
    final = []
    for r in sorted(set(out)):
        if not any(r == k or r.startswith(k.rstrip("/") + "/") for k in final):
            final.append(r)
    return final


def build_script(roots, docroots):
    """Le script distant. Trois étapes, dans cet ordre pour ne rien lire deux fois :

      1. `find` établit la liste des fichiers à examiner (et applique au passage
         les règles de CHEMIN, qui ne coûtent rien puisqu'on parcourt déjà) ;
      2. un seul `grep` passe tous les motifs sur cette liste ;
      3. `stat` ne s'exécute que sur les fichiers signalés — la date de dernière
         modification est la première chose qu'on regarde devant une trouvaille.
    """
    motifs = "\n".join(r.get("re_grep") or r["re"] for r in RULES)
    liste_roots = "\n".join(roots)
    liste_docs = "\n".join(d.rstrip("/") for d in docroots)
    script = r"""#!/bin/bash
# Priorité minimale : ce scan ne doit jamais peser sur les sites qu'il examine.
command -v ionice >/dev/null 2>&1 && ionice -c3 -p $$ >/dev/null 2>&1
renice 19 -p $$ >/dev/null 2>&1

TMP=$(mktemp -d /tmp/.wpdash-scan.XXXXXX) || exit 91
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
find /tmp -maxdepth 1 -name '.wpdash-scan.*' -mmin +720 -exec rm -rf {} + 2>/dev/null

cat > "$TMP/motifs" <<'@@MOTIFS@@'
__MOTIFS__
@@MOTIFS@@
cat > "$TMP/roots" <<'@@ROOTS@@'
__ROOTS__
@@ROOTS@@
cat > "$TMP/docroots" <<'@@DOCS@@'
__DOCS__
@@DOCS@@

# 1. La liste des fichiers. -size borne le coût : au-delà de quelques Mo, un
#    .php n'est plus du code mais une donnée, et grep y perdrait son temps.
: > "$TMP/files"
while IFS= read -r R; do
  [ -n "$R" ] || continue
  if [ ! -d "$R" ]; then printf '@@ABSENT@@%s\n' "$R"; continue; fi
  if [ ! -r "$R" ] || [ ! -x "$R" ]; then printf '@@ILLISIBLE@@%s\n' "$R"; continue; fi
  find "$R" -type d \( -name node_modules -o -name .git -o -name .svn \) -prune -o \
       -type f -size -__MAXMB__M \
       \( -name '*.php' -o -name '*.phtml' -o -name '*.php[57]' -o -name '.htaccess' -o -name '.user.ini' \) \
       -print 2>/dev/null >> "$TMP/files"
done < "$TMP/roots"

TOTAL=$(wc -l < "$TMP/files" 2>/dev/null || echo 0)
if [ "$TOTAL" -gt __MAXFILES__ ]; then
  printf '@@TRONQUE@@%s fichiers trouvés, %s examinés\n' "$TOTAL" __MAXFILES__
  head -n __MAXFILES__ "$TMP/files" > "$TMP/f2" && mv "$TMP/f2" "$TMP/files"
fi

# 2. Les règles de chemin, sur la liste déjà établie — aucun parcours de plus.
: > "$TMP/paths"
grep -E '/wp-content/uploads/.*\.(php|phtml|php[57])$' "$TMP/files" 2>/dev/null \
  | head -n 200 | sed 's|^|php_in_uploads\||' >> "$TMP/paths"

#    Les installations WordPress RÉELLES du voisinage : un dossier qui contient
#    wp-load.php. C'est LE discriminant. Un dev.site.fr, un staging, un dossier
#    de quarantaine sont des installations complètes et n'ont rien à faire dans
#    un signalement ; le kit du serveur finaxys, lui, n'avait que les NOMS
#    wp-content/ et wp-includes/, sans une seule ligne du cœur.
cp "$TMP/docroots" "$TMP/installs"
while IFS= read -r R; do
  [ -d "$R" ] || continue
  find "$R" -maxdepth 4 -type f -name wp-load.php 2>/dev/null
done < "$TMP/roots" | sed 's|/wp-load\.php$||' >> "$TMP/installs"
sort -u "$TMP/installs" -o "$TMP/installs"

#    Hors installation : un .php qui n'appartient à AUCUNE installation connue.
if [ -s "$TMP/installs" ]; then
  # wp-config.php HORS docroot n'est pas une anomalie mais une bonne pratique
  # (disposition WordOps standard) : l'écarter, sinon la règle crie sur chaque
  # site correctement rangé.
  grep -vF -f "$TMP/installs" "$TMP/files" 2>/dev/null \
    | grep -E '\.(php|phtml|php[57])$' | grep -v '/wp-config\.php$' | head -n 200 \
    | sed 's|^|php_outside\||' >> "$TMP/paths"
fi

#    Un wp-content/ ou wp-includes/ dont le dossier parent n'est PAS une
#    installation : les noms du cœur sans le cœur, c'est un atelier.
while IFS= read -r R; do
  [ -d "$R" ] || continue
  find "$R" -maxdepth 3 -type d \( -name wp-content -o -name wp-includes -o -name wp-admin \) 2>/dev/null
done < "$TMP/roots" | while IFS= read -r D; do
  grep -qxF "${D%/*}" "$TMP/installs" || printf 'fake_core_dir|%s\n' "$D"
done | head -n 50 >> "$TMP/paths"
sed 's|^|@@PATH@@|' "$TMP/paths"

# 3. Le contenu. -I écarte le binaire, -a serait un piège : un webshell collé
#    derrière une image passe pour binaire et n'a de toute façon pas d'extension
#    .php ici. Le plafond de sortie est appliqué APRÈS grep, jamais avant.
: > "$TMP/hits"
xargs -a "$TMP/files" -d '\n' -r -n 400 \
  grep -HnIEi -f "$TMP/motifs" -- 2>/dev/null >> "$TMP/hits"
NH=$(wc -l < "$TMP/hits" 2>/dev/null || echo 0)
if [ "$NH" -gt __MAXHITS__ ]; then
  printf '@@TRONQUE@@%s correspondances, %s remontées\n' "$NH" __MAXHITS__
  head -n __MAXHITS__ "$TMP/hits" > "$TMP/h2" && mv "$TMP/h2" "$TMP/hits"
fi
sed 's|^|@@HIT@@|' "$TMP/hits" | cut -c1-500

# 4. Idéogrammes : seconde passe, uniquement sur les fichiers DÉJÀ signalés.
#    Chercher du CJK sur tout le parc coûterait cher et sortirait surtout des
#    extensions sinophones parfaitement légitimes.
cut -d: -f1 "$TMP/hits" 2>/dev/null | sort -u > "$TMP/cands"
if [ -s "$TMP/cands" ]; then
  xargs -a "$TMP/cands" -d '\n' -r -n 100 \
    grep -lP '[\x{4e00}-\x{9fff}]{6,}' -- 2>/dev/null \
    | head -n 50 | sed 's|^|cjk_padding\||' | tee -a "$TMP/paths" \
    | sed 's|^|@@PATH@@|'
fi

# 5. Dates et tailles des seuls fichiers signalés : « mtime maquillé en 2025 »
#    se lit d'un coup d'œil, et c'est souvent ce qui tranche.
{ cut -d: -f1 "$TMP/hits" 2>/dev/null; cut -d'|' -f2- "$TMP/paths" 2>/dev/null; } \
  | sort -u > "$TMP/meta"
if [ -s "$TMP/meta" ]; then
  xargs -a "$TMP/meta" -d '\n' -r stat -c '@@META@@%n|%Y|%s|%U' -- 2>/dev/null | head -n 600
fi

printf '@@STAT@@%s\n' "$TOTAL"
echo "@@FIN@@"
"""
    return (script.replace("__MOTIFS__", motifs)
                  .replace("__ROOTS__", liste_roots)
                  .replace("__DOCS__", liste_docs)
                  .replace("__MAXMB__", str(MAX_SIZE_MB))
                  .replace("__MAXFILES__", str(MAX_FILES))
                  .replace("__MAXHITS__", str(MAX_HITS)))


RE_HIT = re.compile(r"^(?P<f>.+?):(?P<n>\d+):(?P<t>.*)$")
COMPILED = [(r["id"], re.compile(r["re"], re.I | re.M)) for r in RULES]
CONF_ONLY = {r["id"] for r in RULES if r.get("conf_only")}
CONF_NAMES = (".htaccess", ".user.ini")


def est_config(path):
    """Un fichier de CONFIGURATION, par opposition à du code PHP.

    `auto_prepend_file` ou `AddHandler php` dans un .php ne configure rien : au
    mieux c'est une chaîne (Wordfence en parle 39 fois), au pire du bruit qui
    enterre le vrai signalement dans un .user.ini.
    """
    base = os.path.basename(path or "")
    return base in CONF_NAMES or base.endswith((".ini", ".conf", ".htaccess"))


RE_COMMENTAIRE = re.compile(r"^\s*(//|#|\*|/\*)")


def attribuer(path, texte):
    """Quelle règle a mordu sur cette ligne ? grep -f ne le dit pas, on rejoue.

    Une même ligne peut vérifier deux règles (un `eval(base64_decode(` posé sur
    une entrée HTTP) : la plus grave l'emporte, sans quoi le même fichier
    apparaîtrait deux fois pour un seul défaut.
    """
    # Une ligne de COMMENTAIRE n'exécute rien. Sur un seul site, sept
    # signalements venaient de « // wp_set_auth_cookie() sends the new… » :
    # du bruit qui use la confiance dans les autres.
    if RE_COMMENTAIRE.match(texte or ""):
        return None
    conf = est_config(path)
    trouves = [rid for rid, rx in COMPILED
               if (conf or rid not in CONF_ONLY) and rx.search(texte)]
    if not trouves:
        return None
    return max(trouves, key=lambda rid: SEV_RANK.get(RULES_BY_ID[rid]["sev"], 0))


def _run_remote(server, script, timeout=TIMEOUT):
    """Sortie ENTIÈRE : le plafond par défaut de run_remote_script (6000
    caractères) couperait la liste des trouvailles au milieu — et le marqueur
    @@FIN@@ survivrait à la coupe, donnant l'illusion d'un scan complet."""
    return A.run_remote_script(server, script, timeout=timeout, max_out=None)


def site_de(path, par_docroot, par_voisinage):
    """Le site auquel rattacher un chemin. D'abord le docroot (cas courant),
    ensuite le voisinage — c'est là que vivait le kit finaxys, et le rattacher
    au site voisin est précisément ce qui le rend visible."""
    for d, dom in par_docroot:
        if path.startswith(d + "/"):
            return dom, True
    for v, dom in par_voisinage:
        if path.startswith(v + "/"):
            return dom, False
    return None, False


def scan_serveur(srv, sites_du_serveur, tous_docroots):
    """Un serveur → (trouvailles, erreur, illisibles, tronqués, fichiers_vus)."""
    docroots = [s["path"] for s in sites_du_serveur if s.get("path")]
    roots = racines(docroots, tous_docroots)
    if not roots:
        return [], None, [], [], 0

    rc, out = _run_remote(srv, build_script(roots, docroots))
    if "@@FIN@@" not in (out or ""):
        # Sans le marqueur, la sortie est partielle (délai, coupure SSH) : le
        # dire, plutôt que de présenter une liste incomplète comme un résultat.
        return [], (f"scan interrompu (rc={rc}) : " + (out or "")[-200:].strip()), [], [], 0

    par_docroot = sorted(((s["path"].rstrip("/"), s["domain"])
                          for s in sites_du_serveur if s.get("path")),
                         key=lambda x: -len(x[0]))
    par_voisinage = sorted(((os.path.dirname(s["path"].rstrip("/")), s["domain"])
                            for s in sites_du_serveur if s.get("path")),
                           key=lambda x: -len(x[0]))

    trouvailles, illisibles, tronques, vus = [], [], [], 0
    meta = {}
    for ligne in (out or "").splitlines():
        if ligne.startswith("@@META@@"):
            bout = ligne[8:].split("|")
            if len(bout) >= 4:
                meta[bout[0]] = {"mtime": bout[1], "size": bout[2], "owner": bout[3]}
            continue
        if ligne.startswith("@@ILLISIBLE@@"):
            illisibles.append(ligne[13:]); continue
        if ligne.startswith("@@ABSENT@@"):
            illisibles.append(ligne[10:] + " (absent)"); continue
        if ligne.startswith("@@TRONQUE@@"):
            tronques.append(ligne[11:]); continue
        if ligne.startswith("@@STAT@@"):
            try: vus = int(ligne[8:].strip())
            except ValueError: pass
            continue
        if ligne.startswith("@@PATH@@"):
            rid, _, chemin = ligne[8:].partition("|")
            if rid in PATH_RULES and chemin:
                trouvailles.append({"rule": rid, "path": chemin, "line": 0, "excerpt": ""})
            continue
        if ligne.startswith("@@HIT@@"):
            m = RE_HIT.match(ligne[7:])
            if not m:
                continue
            rid = attribuer(m.group("f"), m.group("t"))
            if rid:
                trouvailles.append({"rule": rid, "path": m.group("f"),
                                    "line": int(m.group("n")),
                                    "excerpt": m.group("t").strip()[:200]})

    trouvailles = [t for t in trouvailles if not garde_muette(t, meta)]
    for t in trouvailles:
        t.update(meta.get(t["path"], {}))
        dom, dedans = site_de(t["path"], par_docroot, par_voisinage)
        t["domain"] = dom
        t["inside"] = dedans
        t["sev"] = ALL_RULES[t["rule"]]["sev"]
    return trouvailles, None, illisibles, tronques, vus


# « Silence is golden » : WordPress et la plupart des extensions déposent un
# index.php vide dans chaque dossier de médias pour empêcher l'indexation. Sur
# un seul site, quarante de ces gardes remplissaient la règle php_in_uploads —
# et enterraient le jour où un vrai .php y apparaîtrait.
GARDE_MAX_OCTETS = 60


def garde_muette(t, meta):
    """Ce signalement n'est-il que le garde vide d'un dossier de médias ?"""
    if t.get("rule") != "php_in_uploads" or os.path.basename(t["path"]) != "index.php":
        return False
    try:
        return int((meta.get(t["path"]) or {}).get("size", 10**9)) <= GARDE_MAX_OCTETS
    except (TypeError, ValueError):
        return False


def raccourcir(chemin, docroot):
    """wp-content/plugins/x/y.php — le chemin complet n'apprend rien de plus."""
    if docroot and chemin.startswith(docroot.rstrip("/") + "/"):
        return chemin[len(docroot.rstrip("/")) + 1:]
    i = chemin.find("/wp-content/")
    return chemin[i + 1:] if i >= 0 else chemin


def agrege(trouvailles, chemins_sites, reference=None):
    """Trouvailles → un bloc par site, trié par gravité puis par nombre.

    Le plafond MAX_PER_RULE est par RÈGLE et par site : un site qui déclenche
    300 fois `long_b64` ne doit pas chasser de l'écran le seul `eval_decode`
    d'un autre site.

    `reference` (data/scan_baseline.json) marque ce qui était DÉJÀ là : c'est
    elle qui rend le résultat lisible. Sans référence, un site sain sort ~190
    signalements parfaitement légitimes ; avec elle, il n'en sort plus aucun, et
    le moindre fichier nouveau saute aux yeux.
    """
    reference = reference or {}
    par_site = collections.defaultdict(lambda: collections.defaultdict(list))
    for t in trouvailles:
        par_site[t.get("domain") or ""][t["rule"]].append(t)
    sites = []
    for dom, par_regle in par_site.items():
        connus = reference.get(dom) or {}
        items, coupes = [], 0
        for rid, lst in par_regle.items():
            lst.sort(key=lambda x: (x["path"], x["line"]))
            coupes += max(0, len(lst) - MAX_PER_RULE)
            for t in lst[:MAX_PER_RULE]:
                fp = scan_fingerprint(dom, t["rule"], t["path"])
                items.append(dict(t, fp=fp, new=fp not in connus,
                                  short=raccourcir(t["path"], chemins_sites.get(dom, ""))))
        # Le NOUVEAU d'abord, quelle que soit sa gravité : un `long_b64`
        # apparu cette nuit mérite plus d'attention qu'un `auth_cookie` connu
        # depuis six mois.
        items.sort(key=lambda t: (not t["new"], -SEV_RANK.get(t["sev"], 0), t["rule"], t["short"]))
        nouveaux = [t for t in items if t["new"]]
        # « Pire gravité » se lit sur ce qui est NOUVEAU quand une référence
        # existe : sinon un site sous surveillance depuis des mois resterait
        # éternellement « critique » à cause d'un vendor connu.
        pires = [t["sev"] for t in (nouveaux if connus else items)]
        sites.append({
            "domain": dom, "total": sum(len(v) for v in par_regle.values()),
            "new": len(nouveaux), "has_baseline": bool(connus),
            "shown": len(items), "hidden": coupes,
            "worst": max(pires, key=lambda s: SEV_RANK.get(s, 0)) if pires else "",
            "rules": sorted({t["rule"] for t in items}),
            "findings": items,
        })
    sites.sort(key=lambda s: (-s["new"], -SEV_RANK.get(s["worst"], 0), -s["total"]))
    return sites


def main():
    args = sys.argv[1:]
    seulement = None
    if "--only" in args:
        try:
            seulement = args[args.index("--only") + 1]
        except IndexError:
            pass

    fleet = A.load_json(FLEET_PATH, {"servers": []})
    servers = {s["name"]: s for s in A.servers_list()}
    par_serveur = collections.defaultdict(list)
    chemins_sites, tous_docroots = {}, []
    for srv in fleet.get("servers", []):
        nom = srv.get("name")
        if nom not in servers or (seulement and nom != seulement):
            continue
        for site in srv.get("sites", []):
            if not A.site_visible(site) or not site.get("path"):
                continue
            par_serveur[nom].append({"domain": site.get("domain"), "path": site["path"]})
            chemins_sites[site.get("domain")] = site["path"]
            tous_docroots.append(site["path"])

    resultats, erreurs, illisibles, tronques = [], {}, {}, {}
    vus_total = 0

    def un_serveur(nom):
        """Ne lève jamais : un serveur lent ou coupé ne doit pas emporter la
        passe entière — même règle que collect.ssh_collect et phperrors."""
        try:
            return nom, scan_serveur(servers[nom], par_serveur[nom], tous_docroots)
        except Exception as e:
            return nom, ([], f"{type(e).__name__}: {e}"[:300], [], [], 0)

    if par_serveur:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(6, len(par_serveur))) as pool:
            for nom, (trv, err, ill, trc, vus) in pool.map(un_serveur, list(par_serveur)):
                if err:
                    erreurs[nom] = err
                if ill:
                    illisibles[nom] = ill
                if trc:
                    tronques[nom] = trc
                vus_total += vus
                for t in trv:
                    t["server"] = nom
                resultats.extend(trv)

    reference = A.load_json(BASELINE_PATH, {}).get("sites") or {}
    sites = agrege(resultats, chemins_sites, reference)
    comptes = collections.Counter(t["sev"] for s in sites for t in s["findings"] if t["new"])
    res = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "files_scanned": vus_total,
        "sites_flagged": len([s for s in sites if s["domain"]]),
        "total": len(resultats),
        "new_total": sum(s["new"] for s in sites),
        "sites_without_baseline": [s["domain"] for s in sites
                                   if s["domain"] and not s["has_baseline"]],
        # `counts` ne compte QUE le nouveau : c'est ce chiffre qui s'affiche en
        # tête d'écran, et il doit valoir zéro sur un parc sous surveillance.
        "counts": {k: comptes.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "servers_failed": erreurs,
        # Un dossier illisible ou un plafond atteint change le sens de « rien
        # trouvé » : l'interface doit pouvoir le dire au lieu de rassurer à tort.
        "unreadable": illisibles,
        "truncated": tronques,
        # Le dictionnaire des règles voyage avec le résultat : l'écran affiche
        # le « pourquoi » sans en garder une seconde copie qui divergerait.
        "rules": ALL_RULES,
        "sites": sites,
    }
    if seulement:
        # Passe partielle : ne pas écraser le résultat des autres serveurs.
        ancien = A.load_json(OUT_PATH, {})
        gardes = [s for s in (ancien.get("sites") or [])
                  if s.get("domain") not in {x["domain"] for x in sites}
                  and not any(f.get("server") == seulement for f in (s.get("findings") or []))]
        res["sites"] = sorted(sites + gardes,
                              key=lambda s: (-SEV_RANK.get(s.get("worst"), 0), -s.get("total", 0)))
        res["partial_server"] = seulement
    save_json_atomic(OUT_PATH, res)
    if "--baseline" in args:
        # La référence n'est PAS posée automatiquement : accepter en bloc ce
        # qu'on n'a pas regardé reviendrait à blanchir une porte dérobée déjà
        # en place. C'est un geste explicite, ici ou depuis l'écran Sécurité.
        ref = scan_baseline_from(res)
        save_json_atomic(BASELINE_PATH, {"generated_at": res["generated_at"], "sites": ref})
        print(f"référence posée : {sum(len(v) for v in ref.values())} signalement(s) "
              f"connus sur {len(ref)} site(s)")
        return
    print(f"{res['new_total']} NOUVEAU(X) sur {res['total']} signalement(s), "
          f"{res['sites_flagged']} site(s), {vus_total} fichier(s) examinés"
          + (f" | serveurs en échec : {list(erreurs)}" if erreurs else "")
          + (f" | analyse partielle : {list(tronques)}" if tronques else "")
          + (f" | dossiers illisibles : {list(illisibles)}" if illisibles else ""))
    if "--print" in args:
        for s in sites[:20]:
            print(f"\n  {s['domain'] or '(hors site)'} — {s['new']} nouveau(x) "
                  f"sur {s['total']}, pire : {s['worst'] or 'rien'}"
                  + ("" if s["has_baseline"] else "  [SANS RÉFÉRENCE]"))
            for t in [x for x in s["findings"] if x["new"]][:8] or s["findings"][:4]:
                print(f"    {'NEW ' if t['new'] else '    '}[{t['sev']:8}] {t['rule']:16} {t['short']}"
                      + (f":{t['line']}" if t["line"] else ""))
                if t["excerpt"]:
                    print(f"                                 {t['excerpt'][:90]}")


if __name__ == "__main__":
    main()
