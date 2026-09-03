# Dashboard parc WordPress

Un tableau de bord auto-hébergé pour superviser et maintenir un parc de sites
WordPress.

- **Inventaire** de chaque site : cœur, extensions, thèmes, PHP, comptes
  administrateurs, réglages de sauvegarde UpdraftPlus.
- **Disponibilité en direct** via **Uptime Kuma**, certificats TLS compris.
- **Mises à jour sûres** : archivage des fichiers et de la base, mise à jour,
  contrôle de santé, puis **retour arrière automatique** si le site casse.
- **Rétablissement d'une version** : depuis l'archive locale (extensions
  premium comprises) ou depuis n'importe quelle version publiée sur
  wordpress.org.
- **Veille de vulnérabilités** : l'inventaire est croisé **en local** avec une
  base publique ouverte — aucune donnée du parc n'est transmise.
- **Erreurs PHP** relevées dans les journaux que les serveurs écrivent déjà,
  sans rien installer sur les sites.
- **Historique** : tendance du parc et journal des changements d'état, avec
  bilan quotidien sur Telegram.

Aucune dépendance Python hors bibliothèque standard. Le dashboard parle à vos
sites de deux façons : en **SSH** (wp-cli), ou via un **agent** léger installé
sur les sites sans accès SSH.

> ⚠️ **Ce dépôt ne contient aucune donnée de parc.** La configuration propre à
> votre déploiement (`config.json`), l'inventaire des serveurs (`servers.json`)
> et tout le dossier `data/` (secrets, mots de passe d'application, inventaire)
> sont exclus par `.gitignore`. Ne les committez jamais.

---

## Sommaire

- [Architecture](#architecture)
- [Frontend](#frontend)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Rattacher des sites](#rattacher-des-sites)
- [L'agent compagnon](#lagent-compagnon)
- [Sécurité](#sécurité)
- [Exploitation](#exploitation)
- [Réglages](#réglages)
- [VizProof](#vizproof)
- [Licence](#licence)

---

## Architecture

Trois composants, tous dans `/opt/wp-dashboard/` :

| Composant | Fichier | Rôle |
|---|---|---|
| **Collecteur** | `collect.py` | Interroge chaque serveur en SSH (wp-cli) et les sites sans SSH via l'agent, produit `data/fleet.json`. Lancé par cron toutes les 30 min. |
| **API** | `actions_server.py` | Service HTTP local (127.0.0.1:8090) : authentification, actions de maintenance sur liste blanche, endpoints de l'interface. Exposé en HTTPS par nginx. |
| **Interface** | `public/` | Application monopage en modules ES, servie telle quelle par nginx — **aucun build**. Voir [Frontend](#frontend). |

Et les tâches périodiques, toutes lancées par cron :

| Fichier | Rôle | Cadence (`deploy/wp-dashboard.cron`) |
|---|---|---|
| `collect.py` | Inventaire du parc. | toutes les 30 min |
| `vulns.py` | Croise l'inventaire avec la base de vulnérabilités publique. Le croisement est **local** : on demande « quelles failles pour l'extension X ? », jamais « voici mes sites ». | 1×/jour, à 6 h |
| `phperrors.py` | Lit les journaux d'erreur PHP des serveurs (PHP-FPM sur Plesk, nginx sur les VPS) et regroupe les occurrences par fichier et ligne. Aucun site modifié. | toutes les 2 h |
| `digest.py` | Bilan quotidien des changements, envoyé sur Telegram s'il y en a. | 1×/jour, à 8 h |
| `rotate.py` | Rotation des journaux à **rétention différenciée** : courte pour le tout-venant, longue pour ce qui a valeur de preuve (création d'administrateur, échec d'action…). | 1×/semaine, dimanche 4 h 30 |

À côté :

- **Uptime Kuma** (conteneur Docker) fournit l'état de disponibilité. Le
  dashboard lit sa base SQLite en lecture (`docker exec … sqlite3`) pour relier
  chaque site à son moniteur, et proxifie sa status page.
- **`dashboard_config.py`** lit `config.json` : c'est le seul endroit où vivent
  les valeurs propres à une installation.
- **`dashlib.py`** regroupe les briques communes à tous les scripts ci-dessus
  (lecture/écriture JSON atomique, quotage shell, identité et visibilité d'un
  site, expressions de validation partagées) : une seule copie, pas six.
- **[L'agent compagnon](#lagent-compagnon)** (`agent/sumotori-dash-agent/`) est
  le plugin WordPress installé sur les sites sans SSH.

```
                    ┌────────────── nginx (HTTPS, auth_request) ──────────────┐
   navigateur ──────┤  /            → public/ (HTML, CSS, modules ES, polices) │
                    │  /api/actions,mgmt,sec,site,auth → 127.0.0.1:8090 (API)  │
                    │  /api/         → 127.0.0.1:3001 (Uptime Kuma, statut)     │
                    └──────────────────────────────────────────────────────────┘
   cron ── collect.py ──SSH (wp-cli)──▶ serveurs du parc
                      └──HTTPS signé HMAC──▶ sites sans SSH (agent)
```

---

## Frontend

Le front est un ensemble de fichiers servis tels quels : **le code déployé est
le code écrit**. Pas de bundler, pas de transpilation, aucune dépendance npm —
les navigateurs chargent des modules ES nativement, nginx sert des fichiers.

### Arborescence

```
public/
  index.html            coque : barre latérale, en-tête d'écran, gabarits des écrans,
                        table d'imports, un seul <script type="module" src="app.js?v=…">
  login.html            page de connexion, autonome (ni module, ni sprite, ni API)
  app.js                démarrage, routeur par fragment, abonnement au store
  version.js            export const V = "AAAA-MM-JJ-hhmm" — posé par tools/deploy.sh
  icons.svg             sprite Lucide (34 icônes), injecté une fois par lib/icons.js
  css/
    tokens.css          couleur (2 thèmes), typo, espace, rayons, @font-face
    base.css            remise à zéro, typographie, focus, utilitaires
    components.css      bouton, chip, tableau, modale, tiroir, notification, bulle
    screens.css         coque et mises en page propres aux écrans
  lib/
    api.js              fetch, session, X-Dash, redirection sur 401
    state.js            store (flotte, statut Kuma, sélection, filtres, réglages)
                        + abonnements + cache court par chargeur
    poll.js             sondage borné : s'arrête sur erreurs, sur `until`, à la demande
    dom.js              h(), esc(), mount(), delegate()
    format.js           dates relatives, durées, URL, cadences UpdraftPlus, bruit PHP
    icons.js            icon() / iconEl() + injection du sprite
  components/
    button.js  chip.js  confirm.js  job.js  shell.js  table.js  tip.js  toast.js
  screens/
    parc.js  incidents.js  securite.js  changements → historique.js
    gestion.js  reglages.js
  fonts/                Archivo, IBM Plex Sans, IBM Plex Mono (woff2, latin + latin-ext)
```

### Versions et cache : la table d'imports

nginx garde `no-store` sur l'API et sur `index.html`, mais met `css/`, `lib/`,
`components/`, `screens/` et `fonts/` en cache **un an** (voir
`deploy/nginx-static-cache.conf`). Ce qui invalide le cache, c'est le suffixe
`?v=<horodatage>`.

Le piège : `<script type="module" src="app.js?v=…">` ne versionne **que**
app.js. Les `import '../lib/api.js'` qu'il déclenche, eux, partent sans
suffixe — et resteraient en cache après un déploiement. D'où la **table
d'imports** déclarée dans `index.html` :

```html
<script type="importmap">
{"imports":{
  "./lib/api.js":"./lib/api.js?v=2026-09-12-1430",
  …
}}
</script>
```

Une entrée par module. `tools/deploy.sh` la régénère à partir des fichiers
réellement présents : **ajouter un module ne demande rien de plus**. Les
polices, elles, ne portent pas de `?v=` — leur URL doit être identique à celle
du `@font-face`, sinon le navigateur télécharge deux fois.

### Jetons

`css/tokens.css` est la seule source de vérité pour la couleur, la
typographie, l'espace et les rayons. Une valeur brute ailleurs est un bug :
`tools/check_front.py` refuse tout `style="…"` en ligne.

- **Couleur** — neutres froids, deux fonds (`--page`, `--surface`), un accent
  unique (`--accent`, réservé à l'action principale et au focus) et une gamme
  d'état indépendante de l'accent (`--ok`, `--warn`, `--err`, `--muted`).
- **Thème** — motif à trois états : `:root` porte le thème clair complet,
  `@media (prefers-color-scheme: dark)` guardé par
  `:root:not([data-theme="light"])` porte le sombre suivi du système, et
  `:root[data-theme="dark"]` porte le sombre forcé. Le bouton de la barre
  latérale écrit `localStorage.dashTheme` et pose (ou retire) `data-theme`.
- **Typographie** — 12 / 13 / 14 / 16 / 20 / 26 px. Interface à 14, textes
  explicatifs à 16, chiffres en `tabular-nums`.
- **Espace** — 4 / 8 / 12 / 16 / 24 / 32 / 48. **Rayons** — 4 px pour les
  contrôles, 6 px pour les surfaces, pilule pour les chips.
- **Élévation par bordure**, pas par ombre : la seule ombre est celle des
  couches flottantes (modale, tiroir, notification).

`tools/check_tokens.py` calcule les contrastes dans les **deux** thèmes et
échoue si un seuil n'est pas tenu : encre ≥ 7:1, texte secondaire ≥ 4.5:1,
chips ≥ 4.5:1 sur leur fond. À lancer après toute modification de `tokens.css`.

### Polices

Trois familles servies **localement** depuis `public/fonts/` — une console
d'administration n'appelle pas un CDN tiers à chaque chargement. Archivo pour
les titres et la navigation, IBM Plex Sans pour l'interface, IBM Plex Mono pour
les versions, chemins, identifiants et sorties wp-cli. `font-display: swap` et
un repli système déclaré dans `--f-body` / `--f-display` / `--f-mono`.

Dix fichiers woff2 (latin + latin-ext), **198 Ko au total**, dont ~75 Ko
seulement pour le premier affichage (les deux faces latines). Licence SIL OFL
1.1, voir [Licence](#licence).

### Icônes

Un sprite unique, `public/icons.svg` (34 icônes Lucide, trait 1,5 px, 7 Ko).
`lib/icons.js` l'injecte une fois dans le document — `<use href="#i-…">` ne
fonctionne de façon fiable qu'en référence **interne**, pas vers un autre
fichier. `app.js` attend cette injection avant le premier rendu.

```js
import { icon, iconEl } from './lib/icons.js';
icon('refresh-cw')                       // chaîne HTML, pour les gabarits
icon('x', { label: 'Fermer' })           // icône seule : aria-label obligatoire
iconEl('shield-check', { size: 20 })     // nœud DOM, pour les composants
```

Sans `label`, l'icône est décorative (`aria-hidden`) : le texte voisin porte le
sens. **Aucune icône seule dans une colonne de tableau.** Plus aucun emoji dans
l'interface — `tools/check_front.py` le vérifie.

### Ajouter un écran

1. Créer `public/screens/<nom>.js` — il exporte au moins une fonction de
   chargement/rendu, et importe ce dont il a besoin de `lib/` et `components/`.
2. Ajouter son gabarit dans `index.html` : `<div class="page" id="page-<nom>">`.
3. Dans `app.js`, ajouter une entrée à `DESTINATIONS`
   (`{route, page, titre, legacy?}`), l'importer, et l'appeler dans `showDest`.
4. Ajouter le lien dans la barre latérale d'`index.html`
   (`<a class="nav-i" href="#<route>" data-dest="<route>">`) avec son icône —
   et l'icône au sprite si elle manque (voir l'entête de `tools/preview.py`
   pour régénérer).
5. Lancer `python3 tools/check_front.py` : il vérifie que les routes d'API
   existent, que les identifiants visés existent, et que les imports résolvent.

Rien à déclarer ailleurs : `tools/deploy.sh` découvre le nouveau module et
l'ajoute à la table d'imports.

### Vérifier sans toucher à la production

```bash
python3 tools/preview.py                  # page bouchonnée, 20 sites, port 8787
python3 tools/preview.py --scenario gros  # 200 sites
python3 tools/preview.py --scenario vide  # aucun site
python3 tools/preview.py --scenario stale # un serveur injoignable
python3 tools/preview.py --scenario joblent   # collecte en cours
python3 tools/preview.py --scenario anomalie  # anomalie visuelle VizProof
```

`window.fetch` y est remplacé par des fixtures : aucune requête ne sort. Les
vraies réponses déposées dans `scratchpad/fixture/<route>.json` (le `/` du
chemin devenant `_`) sont utilisées en priorité.

Contrôles automatiques, à passer avant chaque déploiement :

```bash
python3 tools/check_tokens.py                     # contrastes, deux thèmes
python3 tools/check_front.py -v                   # routes, actions, ids, icônes, styles, imports
for f in $(find public -name '*.js'); do node --input-type=module --check < "$f" || echo "$f"; done
```

`node --check <fichier>` seul **ne vérifie pas** un module ES : Node le détecte
comme tel et rend la main sans erreur. Il faut le lui passer sur l'entrée
standard avec `--input-type=module`.

### Déployer

```bash
tools/deploy.sh --dry-run     # estampille la version, ne copie rien
tools/deploy.sh               # estampille + rsync de public/ vers le VPS
tools/deploy.sh --nginx       # + reload nginx (seulement si le vhost a changé)
```

Le script lance d'abord les trois contrôles ci-dessus, écrit `version.js`,
régénère la table d'imports et les `?v=`, puis copie. La règle de cache nginx
est dans `deploy/nginx-static-cache.conf`, à inclure une fois dans le bloc
`server{}` du vhost.

---

## Prérequis

- Un serveur Linux (testé sur Ubuntu 24.04) avec **Python 3.8+** (stdlib seule).
- **nginx** en frontal + un certificat TLS (Let's Encrypt/certbot).
- **Uptime Kuma** en conteneur Docker (image `louislam/uptime-kuma`), joignable
  en local sur le port 3001. Le dashboard est conçu autour de Kuma pour l'état
  de disponibilité : c'est une dépendance de fait.
- Accès aux sites à superviser, au choix par site :
  - **SSH** avec `wp-cli` installé sur le serveur cible (fonctions complètes) ;
  - **ou l'agent** installé sur le site (inventaire + évènements, lecture seule).
- Le service tourne en **root** (lecture des clés SSH du parc, `docker exec`
  vers Kuma). Voir [Sécurité](#sécurité).

---

## Installation

```bash
# 1. Récupérer le code
sudo git clone https://github.com/<vous>/wp-dashboard.git /opt/wp-dashboard
cd /opt/wp-dashboard

# 2. Configurer (voir la section Configuration)
sudo cp config.example.json config.json
sudo cp servers.example.json servers.json
sudo $EDITOR config.json servers.json
sudo chmod 600 config.json servers.json

# 3. Clé SSH dédiée au dashboard, déployée sur les serveurs du parc
sudo ssh-keygen -t ed25519 -f /root/.ssh/id_dashboard -N ""
# → ajoutez la clé publique dans ~/.ssh/authorized_keys de chaque serveur

# 4. Service applicatif
sudo cp deploy/wp-dashboard-api.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wp-dashboard-api

# 5. Collecte + bilan quotidien
sudo cp deploy/wp-dashboard.cron /etc/cron.d/wp-dashboard

# 6. nginx : zone de limitation + format de log + vhost
#    Ajoutez dans le http{} de /etc/nginx/nginx.conf :
#      limit_req_zone $binary_remote_addr zone=dashlogin:10m rate=5r/s;
sudo cp deploy/nginx-log-sansargs.conf /etc/nginx/conf.d/
sudo cp deploy/nginx-dashboard.conf /etc/nginx/sites-available/dashboard
sudo ln -s /etc/nginx/sites-available/dashboard /etc/nginx/sites-enabled/
sudo $EDITOR /etc/nginx/sites-available/dashboard   # remplacez dashboard.example.com
sudo certbot --nginx -d dashboard.example.com
sudo nginx -t && sudo systemctl reload nginx

# 7. Créer le compte d'accès au dashboard (login + mot de passe)
cd /opt/wp-dashboard && sudo python3 create_account.py
```

> Le compte est unique, stocké haché (PBKDF2) dans `data/auth.json`. Pour le
> changer plus tard, relancez `create_account.py`. Le premier lancement du
> service crée `data/` automatiquement.

Première collecte manuelle pour peupler l'inventaire :

```bash
cd /opt/wp-dashboard && sudo python3 collect.py
```

---

## Configuration

### `config.json`

Copie de `config.example.json`. Toutes les valeurs propres à votre déploiement :

| Clé | Rôle | Défaut |
|---|---|---|
| `dashboard_url` | URL publique du dashboard (sert d'endpoint d'ingestion des agents et de retour d'autorisation WordPress). | `https://dashboard.example.com` |
| `ssh_key` | Clé SSH par défaut pour joindre les serveurs (surchargeable par serveur). | `/root/.ssh/id_dashboard` |
| `kuma_container` | Nom du conteneur Docker Uptime Kuma. | `uptime-kuma` |
| `kuma_db` | Chemin de la base SQLite **dans** le conteneur. | `/app/data/kuma.db` |
| `kuma_slug` | Slug de la status page Kuma listant vos moniteurs (**à renseigner**). | `""` |
| `kuma_status_url` | URL JSON de cette status page ; le slug y est ajouté automatiquement s'il finit par `/`. | `http://127.0.0.1:3001/api/status-page/` |
| `bot_admin_login` | Login du compte admin créé lors de la liaison « en un clic ». | `dashboard_agent` |
| `bot_admin_email` | Base d'adresse e-mail de ce compte. | `admin@example.com` |
| `vuln_skip_slugs` | Slugs d'extensions à exclure de la veille de vulnérabilités : mu-plugins maison, extensions internes, tout ce qui n'existe pas sur wordpress.org. Les drop-ins WordPress (`object-cache.php`…) sont déjà ignorés. | `[]` |

Créez une **status page privée** dans Uptime Kuma qui regroupe les moniteurs de
votre parc, et reportez son slug dans `kuma_slug`.

### `servers.json`

Copie de `servers.example.json`. Un objet par serveur SSH :

| Champ | Obligatoire | Rôle |
|---|---|---|
| `name` | oui | Identifiant court (`[a-z0-9-]`). |
| `host` | oui | Hôte ou IP. |
| `port` | oui | Port SSH. |
| `patterns` | oui | Globs des docroots à scanner (ex. `/var/www/vhosts/*/httpdocs`). Le collecteur découvre les WordPress via `wp-load.php`. |
| `user` | non | Utilisateur SSH (défaut `root`). |
| `no_su` | non | `true` sur un mutualisé : wp-cli tourne directement sous l'utilisateur SSH, sans `su`. |
| `key` | non | Clé SSH spécifique à ce serveur (sinon `config.json > ssh_key`). |
| `parallel` | non | Sites collectés simultanément sur ce serveur (défaut 4). |
| `priority` | non | Entier, défaut **2**. Départage les doublons : quand le même domaine est trouvé sur deux serveurs (migration en cours, ancienne copie…), le moniteur Kuma est rattaché au serveur de plus forte priorité. Mettez `3` sur le serveur de production et `1` sur l'ancien. |

Les `patterns` (et les docroots ajoutés depuis l'interface) doivent être des
chemins absolus de la forme `^/[A-Za-z0-9_./*@-]+$`, sans `..` : tout motif hors
de cette forme est **rejeté et signalé** dans le journal de collecte plutôt que
transmis au shell distant.

Les sites sans aucun SSH ne vont pas ici : ils s'ajoutent depuis l'interface
(**Gestion → Ajouter un site**) et sont interrogés via l'agent.

---

## Rattacher des sites

Deux méthodes, combinables :

**En SSH (fonctions complètes).** Déclarez le serveur dans `servers.json`. Le
collecteur inventorie tous ses WordPress et vous pouvez lancer les actions de
maintenance (mises à jour cœur/extensions/thèmes, sauvegarde UpdraftPlus, vider
les caches, `wp core verify-checksums`, auto-mises à jour).

**Via l'agent (sites sans SSH).** Depuis **Gestion → Ajouter un site**, saisissez
l'URL : le dashboard sonde l'API REST, vous guide pour installer l'agent et
génère un **code d'appairage** à usage unique. L'inventaire est alors identique
au mode SSH ; seules les **actions** d'écriture sont indisponibles (l'agent est
en lecture seule) — vous gagnez en revanche les **évènements en temps réel**
(nouvel administrateur, activation d'extension, mise à jour terminée).

Installer l'agent sur un site **déjà** en SSH est purement additif : la collecte
reste SSH et vous ajoutez les évènements temps réel.

---

## L'agent compagnon

`agent/sumotori-dash-agent/` est un plugin WordPress autonome (multisite
compatible) : il signale les évènements d'administration signés en HMAC et répond
aux requêtes d'inventaire signées. Il n'embarque **aucune adresse de service** :
l'URL du dashboard est saisie à l'appairage.

- **Installation** : depuis l'interface (ZIP + code), ou `wp dash-agent pair
  --url=<dashboard> --code=XXXXXX`.
- Le dashboard peut le servir en ZIP à la volée (aucune publication requise).
- Détail des données échangées : voir `agent/sumotori-dash-agent/readme.txt`,
  section « External services ».

---

## Sécurité

- **Le service tourne en root** pour lire les clés SSH du parc et exécuter
  `docker exec` vers Kuma. Isolez le serveur en conséquence ; l'API n'écoute que
  sur `127.0.0.1`, seul nginx l'expose.
- **Authentification** : session par cookie signé (HMAC), mot de passe haché
  PBKDF2 dans `data/auth.json`, protection anti-force-brute (échecs → `fail2ban`
  possible via `data/auth_fail.log`).
- **Actions sur liste blanche** : seules les commandes du dictionnaire `ACTIONS`
  sont exécutables ; les cibles (serveur, domaine) sont validées par expression
  régulière.
- **wp-cli en lecture** tourne sous l'utilisateur du site (jamais root sauf
  docroot root) avec `--skip-plugins --skip-themes` (n'exécute pas le code des
  extensions potentiellement compromises).
- **Compte admin dédié** : la liaison « en un clic » crée un administrateur
  dédié (login `bot_admin_login`) plutôt que d'utiliser un compte personnel —
  gain d'attribution et de révocabilité. Sa création est journalisée **et**
  alertée. Il est supprimé quand on retire le site.
- **Mots de passe d'application WordPress** : le retour d'autorisation contient
  le mot de passe en paramètre d'URL ; le vhost le journalise donc **sans** la
  chaîne de requête (`log_format sansargs`). Ne modifiez pas ce point.
- **Permissions de `data/`** : tout ce que produisent les tâches périodiques est
  écrit en **0600** (inventaire, journaux d'évènements et de changements,
  vulnérabilités, erreurs PHP) — ces fichiers citent des logins et des adresses
  e-mail d'administrateurs. Seule la copie servie par nginx,
  `public/fleet.json`, est en 0644. Les écritures sont **atomiques** (fichier
  temporaire puis `os.replace`) : l'API et le navigateur ne lisent jamais un
  JSON à moitié écrit.
- **Ne committez jamais** `config.json`, `servers.json`, `data/`,
  `public/fleet.json` ni vos clés — tout est déjà dans `.gitignore`. Vérifiez
  avec `git status` avant le premier `push`.

---

## Exploitation

### Les destinations

La barre latérale porte cinq destinations. L'adresse est partageable :
`#parc`, `#incidents`, `#securite/<section>`, `#changements/<section>`,
`#gestion/<section>`. Les anciens fragments (`#dash`, `#sec/…`, `#hist/…`,
`#mgmt/…`) redirigent automatiquement — les liens déjà partagés continuent de
tomber au bon endroit.

| Destination | Contenu |
|---|---|
| **Parc** | La liste des sites : état, versions, mises à jour en attente, sauvegardes. Filtres, vues enregistrées, export CSV, actions groupées, fiche site. |
| **Incidents** | Écran de la phase 3 : sites down, erreurs PHP fatales, serveurs injoignables, checksums en anomalie, certificats proches de l'expiration. Le compteur de la barre latérale (sites injoignables) est déjà juste. |
| **Sécurité** | Vulnérabilités, erreurs PHP, comptes administrateurs, recherche transversale d'extension, PHP obsolète, certificats, extensions à risque, intégrité du cœur. |
| **Changements** | Tendance du parc (courbes) et journal des changements d'état. |
| **Gestion** | Ajout d'un site par URL, sites supervisés non gérés, serveurs, clés SSH, moniteurs Kuma, docroots. |

En bas de la barre : **Réglages** (aussi accessible par `#reglages`),
**Journal** des actions, bascule de **thème** (auto / clair / sombre) et
déconnexion. Sous 1000 px la barre se replie en icônes, sous 720 px elle
s'ouvre par le bouton menu.

### Mettre à jour un site

Le bouton **MAJ sûre** de la fiche site enchaîne : contrôle avant → sauvegarde
UpdraftPlus → **archivage des fichiers et dump de la base** → mise à jour →
contrôles (page servie, poids non effondré, WordPress fonctionnel, et scan
visuel VizProof si la commande est disponible) → **retour arrière automatique**
si quelque chose casse.

Deux garde-fous : la base n'est **jamais** restaurée automatiquement — elle
contient ce qui a été écrit pendant l'opération, la commande exacte est donnée
pour en faire une décision — et une extension **gelée** n'est jamais mise à
jour, quel que soit le chemin emprunté.

Les boutons de mise à jour **sans filet** (« Cœur seul », « Extensions seules »,
le bouton **MAJ** de chaque extension) ne font ni archive ni retour arrière, mais
sur un site relié à VizProof ils passent depuis peu par un **déroulé suivi** —
baseline, mise à jour, verdict visuel, inventaire — au lieu d'une simple
commande : voir [Contrôle visuel après une mise à jour
unitaire](#contrôle-visuel-après-une-mise-à-jour-unitaire).

`POST /api/actions/safe_update {"dry_run": true}` simule sans rien écrire.
Le corps accepte aussi `"viz_rollback": true|false` pour surcharger, **le temps
d'une exécution**, le réglage décrit à la section VizProof ci-dessous.

### La barre de notifications

Toute action lancée depuis l'interface s'inscrit dans une **barre de
notifications** en haut à droite (sous l'en-tête, au-dessus de tout le reste) :
mise à jour unitaire, re-scan d'une ligne, installation ou connexion VizProof,
MAJ sûre, action groupée, collecte, vérification des checksums.

- **Progression déterminée** quand le serveur en fournit une (collecte : serveurs
  relevés ; groupé : tâches faites/total ; MAJ sûre : étapes franchies),
  **indéterminée** sinon (une action unitaire ne sait pas où elle en est).
- À la fin, la ligne devient un **verdict** : vert et effacé après 8 s ; **orange**
  (anomalie visuelle, lot partiellement réussi) ou **rouge** conservés jusqu'au ✕.
  Un clic ouvre le tiroir du site concerné, ou la modale de l'action groupée.
- Elle **survit** à la fermeture du tiroir, de la modale groupée et au changement
  d'onglet : c'est tout son intérêt. Elle ne remplace ni la console du tiroir ni
  la modale groupée, elle les résume.

Corollaire : fermer la modale d'une action groupée n'arrête plus son suivi — le
job continuait déjà côté serveur, il reste maintenant visible.

### Incidents

La **file « à traiter »** rassemble en une seule liste ce qui est cassé ou périmé
*maintenant*, toutes sources confondues. Elle est calculée côté serveur pour que
l'écran Incidents et les **pastilles de la barre latérale** ne puissent pas dire
deux choses différentes.

```bash
curl -s ... /api/incidents   # → {"generated_at","counts":{"critical","warning"},"incidents":[…],"errors":[…]}
curl -s ... /api/mgmt/counts # → {"incidents":{…},"securite":{…},"parc":{…}}
```

Chaque incident a la même forme :

```json
{"id": "vuln_critical_fixable:ffhbi.fr:ml-slider", "severity": "critical",
 "kind": "vuln_critical_fixable", "site": "ffhbi.fr", "server": "vps1",
 "title": "ml-slider 3.100.1 · critical corrigeable",
 "detail": "Stored XSS (CVE-2026-1) — correctif en 3.100.2",
 "since": "2026-09-02T18:05:00", "age_h": 14.6,
 "action": {"label": "MAJ ml-slider → 3.100.2", "act": "plugin_update", "arg": "ml-slider"},
 "link": {"tab": "securite", "sub": "vulns"}}
```

`id` vaut `kind:cible:arg` — la cible est la clé du site (clé Kuma ou domaine),
ou le **nom du serveur** pour les incidents qui portent sur un serveur. Il est
**stable** d'un appel à l'autre : c'est lui qui dédoublonne (un domaine présent
sur deux serveurs ne produit qu'une ligne). `action` est `null` quand il n'y a
rien à lancer — notamment sur un **site REST**, où aucune commande wp-cli n'est
disponible : l'incident reste, le bouton disparaît. `since` vaut `null` (et
`age_h` 0) quand la source ne date pas son constat.

| `kind` | Gravité | Déclenchement | Action proposée |
|---|---|---|---|
| `down` | critique | Dernier battement Kuma en `status 0`, sur un site visible. `since` = heure du battement | `rescan` |
| `php_fatal` | critique | `Fatal error` / `Parse error` dans la fenêtre courante de `data/php_errors.json` | — |
| `vuln_critical_fixable` | critique | Vulnérabilité `critical` **avec** `update_to` renseigné ; une entrée par (site, composant) | `plugin_update` / `core_update` |
| `checksums_modified` | critique | Dernier `wp core verify-checksums` en échec (`data/checksums.json`) | — |
| `admin_unknown` | critique | Administrateur absent de `data/admins_baseline.json`. Un site **sans référence** est ignoré | — |
| `server_stale` | avertissement | Serveur `stale` dans `fleet.json` (injoignable à la dernière collecte) | — |
| `backup_late` | avertissement | Sauvegarde UpdraftPlus plus vieille que le seuil, ou jamais faite. Un site **sans UpdraftPlus** est ignoré | `updraft_backup` |
| `cert_expiring` | avert. / critique | Jours restants sous le seuil (critique sous le second seuil, ou déjà expiré) | — |
| `php_eol` | avertissement | Version PHP hors support : **une entrée par serveur et par version**, sites regroupés dans le détail | — |

Tri : **critique avant avertissement**, puis `age_h` décroissant — le plus ancien
d'abord. Chaque source est lue isolément : celle qui échoue laisse une ligne dans
`errors` (`{"source": "kuma", "error": "…"}`) sans empêcher les autres de
remonter. Une source jamais lancée (fichier absent) n'est **pas** une erreur.

La route ne fait **aucun appel réseau ni ssh** : elle relit les fichiers de
`data/` et interroge la base SQLite de Kuma (`docker exec`, comme
`/api/sec/certs`). `/api/incidents` recalcule à chaque appel ;
`/api/mgmt/counts` sert le **même** agrégat, mis en cache **30 s**.

Les seuils vivent dans `data/settings.json`, sous la clé `incident_rules` :

| Seuil | Défaut | Effet |
|---|---|---|
| `backup_max_age_h` | `48` | Âge au-delà duquel une sauvegarde UpdraftPlus est « en retard » |
| `cert_warn_days` | `21` | Jours restants sous lesquels un certificat est signalé |
| `cert_critical_days` | `7` | …et sous lesquels il devient **critique** |
| `vuln_high_is_incident` | `false` | Compter aussi les vulnérabilités `high` corrigeables comme des incidents critiques |
| `php_eol_versions` | `["7.0","7.1","7.2","7.3","7.4","8.0"]` | Versions PHP majeure.mineure considérées hors support |

```bash
curl -s ... -d '{"settings":{"incident_rules":{"backup_max_age_h":24}}}' ... /api/mgmt/settings
```

Une écriture **partielle** conserve les autres seuils, les clés inconnues sont
ignorées et une valeur d'un autre type est ramenée au type attendu — mêmes règles
qu'au premier niveau des [Réglages](#réglages).

### Réglages

**Réglages ⚙** regroupe la cadence de collecte, les clés SSH, les alertes
Telegram, le jeton VizProof et deux réglages de comportement, stockés dans
`data/settings.json` (fichier **0600**) :

| Réglage | Défaut | Effet |
|---|---|---|
| **Retour arrière automatique sur anomalie visuelle** (`viz_anomaly_rollback`) | décoché | Pendant une **MAJ sûre**, une anomalie VizProof (rc 2) annule la mise à jour au lieu de la conserver. Voir [VizProof](#vizproof). |
| **Contrôle visuel VizProof après chaque mise à jour** (`viz_scan_after_update`) | **coché** | Après une mise à jour lancée depuis le tiroir (cœur, extensions, thèmes), le dashboard récupère **en arrière-plan** le verdict visuel des sites reliés : il **attend le scan que le plugin lance lui-même** et ne scanne qu'en repli. Il **informe seulement**. Voir [Contrôle visuel après une mise à jour unitaire](#contrôle-visuel-après-une-mise-à-jour-unitaire). |
| **Baseline VizProof avant chaque mise à jour unitaire** (`viz_baseline_before_update`) | **coché** | Sur un site relié, la mise à jour lancée depuis le tiroir passe par un **job suivi** : baseline → mise à jour → verdict visuel → inventaire. Sans baseline, le verdict d'après compare au dernier état connu de VizProof. Voir [Baseline avant, verdict après](#baseline-avant-verdict-après--le-job-viz_update). |
| **Exiger la baseline** (`viz_baseline_required`) | décoché | Décoché : une baseline ratée est un **avertissement**, la mise à jour se fait quand même. Coché : la mise à jour est **annulée** tant qu'aucun témoin d'avant n'a pu être pris. |
| **Seuils de la file d'incidents** (`incident_rules`) | voir le tableau | Sous-dictionnaire : âge maximal d'une sauvegarde, seuils de certificat, prise en compte des vulnérabilités `high`, versions PHP hors support. Voir [Incidents](#incidents). |

Ils se lisent et s'écrivent aussi en direct ; les clés inconnues sont ignorées et
une valeur d'un autre type est ramenée au type attendu :

```bash
curl -s ... /api/mgmt/settings                                    # → {"settings": {...}, "defaults": {...}}
curl -s ... -d '{"settings":{"viz_scan_after_update":false}}' ... /api/mgmt/settings
```

`GET /api/mgmt/settings` ne renvoie **jamais** le jeton VizProof : il ressort en
`vizproof_token_set` et `vizproof_token_tail`.

### VizProof

**VizProof Timeline** est une extension publique qui photographie le rendu des
pages d'un site et signale les **régressions visuelles**. Le dashboard s'en sert
comme contrôle de fin de parcours dans la MAJ sûre, et affiche l'état de chaque
site dans la colonne **Vizproof** du tableau.

#### Les cinq états de la colonne

| État | Affichage | Ce qu'il faut faire |
|---|---|---|
| Extension absente | `＋ installer` | Le bouton installe et active l'extension. |
| Installée, sans CLI | `v1.0.3 · à mettre à jour` | La commande `wp vizproof` n'existe qu'à partir de la 1.3 : mettre l'extension à jour (bouton de MAJ habituel), puis connecter. |
| Installée mais désactivée | `v1.3.6 · inactif` | À activer depuis wp-admin. |
| CLI présente, non reliée | `v1.3.6 · non connecté` + **Connecter** | Voir ci-dessous. |
| Reliée | `v1.3.6 · N pages` (vert) | Rien. La pastille du dernier scan suit. |

Un site sans inventaire d'extensions affiche `—`. Le tiroir reprend le même état
en une phrase, avec les mêmes boutons, un lien **ouvrir dans wp-admin** et, pour
un site relié, la ligne **Dernier scan** : date relative, verdict (aucune
anomalie / N anomalies / échec) et lien vers le rapport.

> Avant, un plugin installé mais jamais relié était **indiscernable d'un plugin
> absent** : `wp vizproof status` sort en 1 dans ce cas, et la collecte jetait
> tout ce qui n'était pas rc 0. Le collecteur accepte désormais ce rc 1 **quand
> la sortie contient un JSON portant la clé `configured`** — le seul signe qui
> distingue « le site répond mais n'est pas configuré » de « la commande
> n'existe pas ». La fiche `vizproof` d'un site porte donc `has_cli`,
> `configured`, `has_credentials`, `connected` et `site_id`, en plus de
> `version`, `pages` et `last_run`.

#### Le token de compte (Réglages ⚙ → VizProof)

Le token se crée dans **VizProof → Réglages → API** (format `vrt_…`) et
s'enregistre **une fois pour tout le parc** dans **Réglages ⚙ → VizProof**. Il
sert à deux choses : retrouver ou créer le site VizProof d'après l'URL du
WordPress, puis relier le plugin.

- il vit dans `data/settings.json` (fichier **0600**), sous la clé
  `vizproof_token` ; `vizproof_api_base` (défaut `https://vizproof.com`, https
  obligatoire, mêmes gardes anti-SSRF que le reste du dashboard) l'accompagne ;
- `GET /api/mgmt/settings` **ne le renvoie jamais** : comme le jeton Telegram des
  alertes, il ressort en `vizproof_token_set` (booléen) et `vizproof_token_tail`
  (4 derniers caractères). Il n'apparaît pas davantage dans `data/actions.log` ;
- à l'écriture, un champ **vide ou absent conserve** la valeur enregistrée ;
  l'effacement est un geste explicite (bouton **Effacer**, confirmation) :
  `{"settings":{"vizproof_token":""},"vizproof_token_clear":true}` ;
- le bouton **Tester** appelle `POST /api/mgmt/vizproof/test`, qui fait un
  `GET {base}/api/sites?limit=1` avec le token stocké et rend
  `{ok, total, error}` — l'interface affiche « N sites accessibles ».

```bash
curl -s ... -d '{"settings":{"vizproof_token":"vrt_…"}}' .../api/mgmt/settings
curl -s ... -d '{}' .../api/mgmt/vizproof/test        # → {"ok":true,"total":12,"error":null}
```

#### Résolution du site VizProof par l'URL

`viz_resolve_site(domain, siteurl, token, base)` prend l'**hôte** du `siteurl`
(repli sur le domaine), en minuscule et sans `www.`, puis parcourt
`GET /api/sites?limit=100&page=N` (réponse paginée `{data, total, …}`, 500 sites
au plus) en comparant l'hôte — avec et sans `www.` — à chaque entrée de
`domains` (chaîne JSON d'une liste, nulle tant qu'aucune page n'a été ajoutée ;
une valeur illisible est ignorée, pas fatale). Le résultat est
`{site_id, name, created, matched_domain, ambiguous, host}` :

- **une correspondance** → le site existant, `created:false` ;
- **plusieurs** → la première, avec `ambiguous:true` (l'interface le signale) ;
- **aucune** → `POST /api/sites {"name": "<hôte>"}` puis `created:true`. Ce qui
  est créé côté VizProof, c'est **un site portant l'hôte pour nom** — sans page,
  donc avec `domains` à `null` jusqu'à la première page ajoutée.

Tous les appels passent par `_open_no_redirect` (timeout 20 s, lecture bornée,
`Authorization: Bearer`) : **aucune redirection n'est suivie**, un 30x devient
une erreur — sinon l'en-tête d'autorisation repartirait vers l'hôte suivant.

`POST /api/actions/viz_resolve {server, domain}` expose la même chose et sert à
l'**aperçu** de la modale (« Site VizProof : Elwave — existant, domaine
www.elwave.fr »). Il n'écrit **rien** côté WordPress ; sans token enregistré il
rend `{"ok":false,"error":"aucun token VizProof dans les Réglages"}`.

#### Connecter un site

Le bouton **Connecter** (colonne ou tiroir) ouvre une modale. Avec un token
enregistré, c'est un clic : l'identifiant est **facultatif** (vide = résolution
par URL), le champ jeton est replié derrière « utiliser un autre token », et un
aperçu s'affiche à l'ouverture. Sans token enregistré, la modale reste celle
d'avant — **identifiant de site** (`[A-Za-z0-9_-]`, 80 caractères au plus) et, au
choix, le **jeton** de compte ou un **code de connexion** à usage unique — avec
un lien vers les Réglages. Les options repliées permettent de viser une autre
base API et de choisir la portée (`site` ou `selected_pages`).

`POST /api/actions/viz_connect {server, domain, site_id?, token?, code?,
api_base?, scope?}` : `site_id` absent → résolu par URL ; `token` absent → celui
des Réglages (le corps peut toujours en fournir un ponctuel, qui prime pour
wp-cli). La réponse ajoute `site_id`, `site_created` et `site_name` à
`{ok, rc, output, error}`. Un échec de résolution rend **rc 95** sans toucher au
site.

Depuis la **barre d'actions groupées**, « Connecter VizProof… » ouvre la même
modale avec une ligne par site coché : la colonne identifiant reste, pré-remplie
« par URL » (vide = résolution automatique), et un seul clic « Connecter N
sites » enchaîne les appels avec, en face de chaque ligne, le site VizProof
retenu, `créé`/`existant` et le rc. Les sites non éligibles (sans SSH, sans CLI,
extension absente) sont écartés de la liste.

- Un site géré **sans SSH** ne peut pas être connecté d'ici (l'agent est en
  lecture seule) : seul le lien wp-admin est proposé.
- Sur une extension antérieure à 1.3.6, wp-cli répond « `connect` is not a
  registered subcommand » ; le dashboard le traduit en **rc 99** et en un message
  clair plutôt qu'en échec opaque.
- **Le jeton ne passe jamais par la ligne de commande distante** (il est transmis
  sur l'entrée standard de `wp vizproof connect --token-stdin`, via un document
  ici — rien n'est écrit sur le disque du site) et il est masqué dans
  `data/actions.log` comme dans la réponse HTTP. Sur un mutualisé, un argument de
  commande est lisible par tous les comptes du serveur (`ps aux`) : c'est la
  raison de ce détour. C'est aussi pourquoi `viz_connect` n'est **pas** dans le
  dictionnaire `ACTIONS` : il n'est pas atteignable par `/api/actions/run`, qui
  journalise son argument. Le journal porte l'`arg` = `site_id` et le témoin
  `site_created`, jamais le token.

`POST /api/actions/viz_disconnect {server, domain}` fait l'inverse (bouton
**Dissocier** du tiroir) ; l'extension reste installée.

#### Anomalie visuelle pendant une MAJ sûre

Quand VizProof détecte des anomalies après une mise à jour (`rc 2`), deux
conduites sont possibles. Le réglage **« Retour arrière automatique sur anomalie
visuelle »** (Réglages ⚙, stocké dans `data/settings.json`) les départage :

- **décoché — défaut** : la mise à jour est **conservée**, l'étape est marquée
  *attention* avec le lien du rapport si le scan en fournit un, et le verdict
  devient **« réussie avec anomalies visuelles »** — affiché en orange, pas en
  vert. Une alerte part si la règle `viz_anomaly` est active ;
- **coché** : retour arrière automatique, comme pour un site cassé.

Le défaut est volontairement prudent côté « avertir » : un rendu qui change n'est
pas forcément un rendu cassé (bandeau de cookies, carrousel, publicité), et
annuler systématiquement coûtait plus de mises à jour perdues qu'il n'évitait de
régressions. La case est reprise, **pré-remplie**, dans la modale de confirmation
de chaque MAJ sûre : on décide donc au coup par coup sans toucher au réglage. Un
scan qui échoue **techniquement** (tout rc autre que 0 ou 2) reste bloquant dans
les deux cas.

Le réglage se lit et s'écrit aussi en direct (voir [Réglages](#réglages)).

#### Contrôle visuel après une mise à jour unitaire

Le bouton **MAJ** du tiroir passe par `/api/actions/run`, qui ne faisait
**aucun** contrôle visuel : seules la MAJ sûre et l'action groupée « vérifiée
visuellement » en faisaient un. Avec le réglage **« Contrôle visuel VizProof
après chaque mise à jour »** (actif par défaut), les actions `plugin_update`,
`plugins_update_all`, `plugins_update_except`, `core_update` et
`themes_update_all` donnent désormais un **verdict visuel** quand :

1. le réglage est actif, **et**
2. la mise à jour a réussi (rc 0), **et**
3. le site est **relié** (`vizproof.configured`/`connected` de l'inventaire ; à
   défaut, une sonde `wp vizproof status --format=json` sur le site), **et**
4. la commande `wp vizproof` existe (`viz_available`).

##### C'est le plugin qui scanne — le dashboard attend son verdict

`vizproof-timeline` (≥ 1.3.6) enregistre ses hooks `upgrader_pre_install` /
`upgrader_process_complete` **globalement**, donc aussi sous WP-CLI. Quand son
option de site `enable_update_scan_by_default` est vraie — **son défaut** — un
`wp plugin update` lancé par le dashboard **met déjà un scan en file** côté
vizproof.com. Vérifié sur elwave.fr : après une MAJ déclenchée depuis le
dashboard, `wp vizproof status --format=json` porte un `last_run.at` à
l'horodatage exact de cette mise à jour. Enchaîner notre propre
`wp vizproof scan --wait` revenait donc à **photographier deux fois** toutes les
pages suivies.

Le dashboard **attend le scan du plugin** :

1. l'instant `t0` est pris **avant** de lancer la mise à jour, et l'identifiant
   `vizproof.last_run.id` connu de `fleet.json` sert de repère ;
2. la mise à jour faite, un thread interroge `wp vizproof status --format=json`
   **toutes les 10 s pendant au plus 90 s**, jusqu'à voir un `last_run` dont
   l'`id` **diffère** du précédent **et** dont l'`at` est ≥ `t0 − 60 s` (les 60 s
   absorbent l'écart d'horloge entre le dashboard et le serveur du site) ;
3. **run trouvé** → on le suit jusqu'à son état final (`completed` / `failed`),
   10 s à la fois, **5 min au total** ; le verdict porte `source: "plugin"`,
   `rc` 2 si `anomalies > 0` et 0 sinon, plus `anomalies_count`, `run_id` et le
   `report_url` du run ;
4. **aucun run après 90 s** → on lit `wp option get vizproof_timeline_options
   --format=json` :
   - `enable_update_scan_by_default` **faux ou illisible** → c'est **nous** qui
     scannons (`wp vizproof scan --wait --format=json`, `source: "dashboard"`),
     comme avant ;
   - **vrai** → le plugin aurait dû scanner et ne l'a pas fait (site sans page
     suivie, non éligible…) : on renvoie `ran: false`,
     `reason: "le plugin n'a lancé aucun scan"` **sans rien lancer** — un scan
     tardif ne serait qu'un doublon de plus.

**La baseline d'avant, elle, ne vient pas du plugin** : son option
`pre_update_baseline_on_auto_updates` est **fausse par défaut**. Elle est prise
par la **MAJ sûre**, par l'action groupée **« vérification visuelle »**
(`viz_baseline` puis `viz_scan`), et depuis peu par le job décrit juste après —
sans quoi le verdict comparerait au dernier état connu de VizProof et non à
l'état d'avant cette mise à jour.

##### Baseline avant, verdict après : le job `viz_update`

Un verdict visuel ne vaut que par ce à quoi il se compare. Sans baseline prise
juste avant, VizProof compare au **dernier état connu** — qui peut dater de la
veille et mêler d'autres changements (une actualité publiée, une bannière
saisonnière) à ceux de la mise à jour. La **MAJ sûre** prenait déjà sa baseline ;
la mise à jour unitaire le fait désormais aussi.

Comme baseline + mise à jour + attente du verdict dépassent largement les **340 s**
que nginx laisse à `/api/actions/run`, la route ne fait plus la mise à jour dans
sa réponse : elle **démarre un job** et rend la main. C'est le cas quand :

1. l'action est une des cinq mises à jour, **et**
2. le site est relié d'après `fleet.json` — `vizproof.has_cli` **et**
   `vizproof.configured` (volontairement plus strict que le contrôle visuel
   seul : on ne démarre pas un job de plusieurs minutes sur un « peut-être »),
   **et**
3. `viz_baseline_before_update` **ou** `viz_scan_after_update` est actif.

Tous les autres cas — site non relié, réglages éteints, action hors périmètre —
**gardent la réponse synchrone** d'avant (`ok`, `rc`, `output`, `error`, et le
bloc `viz` en tâche de fond).

```jsonc
// POST /api/actions/run — réponse immédiate, la mise à jour n'a pas commencé
{"ok": true, "job": "viz_update", "domain": "elwave.fr", "server": "vps1",
 "action": "plugin_update", "arg": "akismet",
 "steps": [{"key": "baseline", "label": "Baseline VizProof", "status": "attente", "detail": "", "ts": ""},
           {"key": "update",   "label": "Mise à jour",       "status": "attente", "detail": "", "ts": ""},
           {"key": "viz",      "label": "Contrôle visuel",   "status": "attente", "detail": "", "ts": ""},
           {"key": "rescan",   "label": "Inventaire à jour", "status": "attente", "detail": "", "ts": ""}]}
```

Le job enchaîne :

| étape | ce qu'elle fait |
| --- | --- |
| `baseline` | `wp vizproof baseline --wait --format=json` (300 s), journalisé sous la source `pre-update`. Absente si `viz_baseline_before_update` est décoché. |
| `update` | exactement la mise à jour qu'aurait faite la route, journalisée comme avant ; `t0` est pris juste avant. |
| `viz` | le verdict visuel décrit plus haut : attente du scan du plugin, repli sur le nôtre. Absente si `viz_scan_after_update` est décoché ; en `warn` sans rien lancer si la mise à jour a échoué. |
| `rescan` | inventaire rafraîchi, pour que le tiroir montre le dernier scan. |

Chaque étape porte un `status` : `attente`, `en cours`, `ok`, `warn`, `erreur`.

- **Baseline en échec** : étape en `warn`, **la mise à jour continue** — VizProof
  est un filet, pas une condition. Avec `viz_baseline_required` coché, l'étape
  passe en `erreur` et **la mise à jour n'est pas lancée**.
- **Anomalies visuelles** : étape `viz` en `warn`, jamais en `erreur` — la mise à
  jour est passée, c'est le rendu qui a changé. L'alerte `viz_anomaly` part comme
  ailleurs.
- **Un seul job par site**, et **jamais en même temps qu'une MAJ sûre** sur ce
  site : les deux touchent le même WordPress. Les deux routes se réservent sous
  le **même verrou** et répondent **409** avec le motif.

```bash
curl -s ... '/api/actions/viz_update_status?domain=elwave.fr'
# → {"running":false,"domain":"elwave.fr","server":"vps1","action":"plugin_update",
#    "arg":"akismet","started":"…","finished":"…",
#    "steps":[{"key":"baseline","label":"Baseline VizProof","status":"ok","detail":"baseline capturée","ts":"14:47:12"}, …],
#    "result":{"rc":0,"output":"…","viz":{"source":"plugin","anomalies_count":0, …},"duration_s":128.4}}
```

Un domaine sans job répond un job **vide** (`running: false`, `steps: []`) plutôt
qu'une erreur. Comme `viz_last`, c'est une **mémoire de processus** bornée, vidée
au redémarrage du service : l'historique reste dans `actions.log`.

Côté interface, la console du tiroir affiche les étapes **en direct**, du même
rendu que la MAJ sûre, et la barre de notifications passe en progression
déterminée (« baseline VizProof… », « mise à jour… », « le plugin VizProof
scanne… », puis le verdict). Les boutons de mise à jour du site sont désactivés
pendant le job ; le tiroir peut être fermé et rouvert — à la réouverture, un job
en cours est **ré-affiché et re-suivi**.

##### Quand la réponse reste synchrone

Hors des conditions du job ci-dessus (site non relié, réglages éteints), la route
fait la mise à jour elle-même — et là encore **elle n'attend pas le verdict**.
`/api/actions/run` tient la connexion pendant toute l'action et nginx la coupe à
**340 s** (`proxy_read_timeout`, `deploy/nginx-dashboard.conf`) : attendre le
scan dans la réponse ferait perdre, sur un gros site, non seulement le scan mais
le **résultat d'une mise à jour déjà appliquée**. La route répond dès la mise à
jour terminée, l'attente part dans un thread, et le verdict se récupère ensuite.

La réponse conserve son contrat (`ok`, `rc`, `output`, `error`) et gagne un bloc
`viz` :

```jsonc
// contrôle lancé : le verdict viendra
{"ok": true, "rc": 0, "output": "…", "error": null,
 "viz": {"ran": true, "pending": true, "phase": "attente du scan du plugin",
         "message": "contrôle visuel VizProof en cours…"}}
// contrôle impossible : on dit pourquoi
{"viz": {"ran": false, "reason": "non relié" | "CLI absente" | "désactivé"
                                 | "mise à jour en échec"
                                 | "le plugin n'a lancé aucun scan"}}
```

```bash
curl -s ... '/api/actions/viz_last?domain=elwave.fr'
# → {"viz":{"ran":true,"pending":false,"source":"plugin","run_id":"r_42","rc":2,
#           "anomalies":true,"anomalies_count":3,"phase":null,
#           "report_url":"https://vizproof.com/r/42",
#           "message":"anomalies visuelles détectées (3)"}}
```

`GET /api/actions/viz_last?domain=` renvoie donc, en plus de l'ancien contrat :

| champ | valeur |
| --- | --- |
| `source` | `plugin` (scan du plugin) \| `dashboard` (repli) \| `null` |
| `run_id` | identifiant du run VizProof, quand il est connu |
| `anomalies_count` | nombre d'anomalies (0 si aucune ou inconnu) |
| `phase` | pendant l'attente : `attente du scan du plugin`, `scan en cours`, `scan dashboard` ; `null` une fois le verdict rendu |

- `rc 2` = **anomalies visuelles** : `viz.anomalies` passe à `true` et l'alerte
  Telegram `viz_anomaly` part, quel que soit l'auteur du scan.
- `rc null` avec `ran: true` = le run du plugin n'était **pas terminé** au bout
  de 5 min : ce n'est ni un « ok » ni un échec, et rien n'est journalisé.
- **Aucun retour arrière ici** : le bouton unitaire n'archive rien avant de
  mettre à jour, il n'y a donc rien à annuler — on informe, on n'annule pas.
- Le verdict est journalisé dans `data/actions.log` sous l'action
  **`viz_verdict`** (source `auto-after-update`, `arg` = `run_id`, `rc` 0/2,
  sortie = résumé) : sans cette entrée, un scan lancé par le plugin ne laisserait
  **aucune trace** dans l'historique du site, puisqu'il ne passe pas par nous. Le
  scan de repli reste en plus journalisé comme `viz_scan`. Un `rescan` suit dans
  tous les cas, pour que la ligne « Dernier scan » du tiroir soit à jour.
- `GET /api/actions/viz_last?domain=` est une **mémoire de processus** (bornée,
  vidée au redémarrage du service) : l'historique, lui, est dans `actions.log`.

Côté interface : la console du tiroir ajoute « Contrôle visuel VizProof : le
plugin VizProof scanne… », remplacée au fil des phases puis par le verdict —
« aucune anomalie *(scan du plugin)* », « anomalies détectées (3) *(scan
dashboard)* » — avec le lien du rapport ; la
[barre de notifications](#la-barre-de-notifications) suit les mêmes étapes, en
**orange** s'il y a des anomalies.

### Tâches périodiques

Toutes dans `deploy/wp-dashboard.cron`. Chaque script s'exécute aussi à la main :

```bash
python3 vulns.py --fetch --scan     # veille de vulnérabilités
python3 phperrors.py --print        # erreurs PHP (--hours 72 pour élargir)
python3 digest.py --dry-run         # bilan Telegram, sans envoyer
python3 rotate.py --dry-run         # rotation des journaux, à blanc
```

Le bilan Telegram exige un bot configuré dans **Réglages** (jeton + chat_id) ;
sans cela il ne fait rien.

### Quand un serveur ne répond plus

Si un serveur est injoignable au moment de la collecte (SSH en timeout, machine
en maintenance), son entrée **conserve les sites de la collecte précédente**,
marqués `"stale": true`, avec `"error"` et `"last_attempt"`. Sans cela ses sites
disparaissaient du dashboard, la courbe de tendance plongeait à zéro et le
journal des changements perdait le fil. Les données affichées sont donc celles
de la dernière collecte réussie : c'est le drapeau `stale` qui fait foi sur leur
fraîcheur. `data/collect_history.jsonl` note le nombre de serveurs dans cet état
(`stale_servers`).

De même, `data/php_errors.json` porte un champ `truncated` — `{serveur:
[{file, reason}]}` — quand un journal a dépassé le plafond de 20 000 lignes
retenues : l'analyse de ce fichier est alors partielle et l'interface peut le
signaler.

### Divers

- **Mise à jour du code** : `git pull` puis `systemctl restart wp-dashboard-api`.
- **Journaux** : `journalctl -u wp-dashboard-api` pour l'API,
  `/var/log/wp-dashboard.log` pour les tâches cron.
- **Compression** : pensez à activer `gzip_types` dans `nginx.conf`. Sans elle,
  seul le HTML est compressé et l'inventaire JSON part en clair — sur un parc
  d'une quarantaine de sites, c'est 234 Ko contre 22 Ko à chaque chargement.

---

## Licence

Ressources tierces embarquées dans `public/` :

| Ressource | Fichiers | Licence |
| --- | --- | --- |
| **Archivo** (titres) | `public/fonts/archivo-*.woff2` | SIL Open Font License 1.1 |
| **IBM Plex Sans** (interface) | `public/fonts/plex-sans-*.woff2` | SIL Open Font License 1.1 |
| **IBM Plex Mono** (données, code) | `public/fonts/plex-mono-*.woff2` | SIL Open Font License 1.1 |
| **Lucide** (34 icônes, sprite) | `public/icons.svg` | ISC |

L'OFL et l'ISC autorisent toutes deux la redistribution avec le logiciel, y
compris commerciale ; l'OFL interdit seulement la vente des polices seules.

À définir par le mainteneur. L'agent compagnon est publié sous **GPLv2+**
(exigence de l'écosystème WordPress) ; la même licence pour l'ensemble est le
choix le plus simple. Ajoutez un fichier `LICENSE` en conséquence.
