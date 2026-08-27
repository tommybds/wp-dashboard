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
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Rattacher des sites](#rattacher-des-sites)
- [L'agent compagnon](#lagent-compagnon)
- [Sécurité](#sécurité)
- [Exploitation](#exploitation)
- [Licence](#licence)

---

## Architecture

Trois composants, tous dans `/opt/wp-dashboard/` :

| Composant | Fichier | Rôle |
|---|---|---|
| **Collecteur** | `collect.py` | Interroge chaque serveur en SSH (wp-cli) et les sites sans SSH via l'agent, produit `data/fleet.json`. Lancé par cron toutes les 30 min. |
| **API** | `actions_server.py` | Service HTTP local (127.0.0.1:8090) : authentification, actions de maintenance sur liste blanche, endpoints de l'interface. Exposé en HTTPS par nginx. |
| **Interface** | `public/index.html` | Application monopage (aucun build) servie par nginx. |

Et les tâches périodiques, toutes lancées par cron :

| Fichier | Rôle | Cadence |
|---|---|---|
| `vulns.py` | Croise l'inventaire avec la base de vulnérabilités publique. Le croisement est **local** : on demande « quelles failles pour l'extension X ? », jamais « voici mes sites ». | 6 h |
| `phperrors.py` | Lit les journaux d'erreur PHP des serveurs (PHP-FPM sur Plesk, nginx sur les VPS) et regroupe les occurrences par fichier et ligne. Aucun site modifié. | 2 h |
| `digest.py` | Bilan quotidien des changements, envoyé sur Telegram s'il y en a. | 8 h |
| `rotate.py` | Rotation des journaux à **rétention différenciée** : courte pour le tout-venant, longue pour ce qui a valeur de preuve (création d'administrateur, échec d'action…). | hebdo |

À côté :

- **Uptime Kuma** (conteneur Docker) fournit l'état de disponibilité. Le
  dashboard lit sa base SQLite en lecture (`docker exec … sqlite3`) pour relier
  chaque site à son moniteur, et proxifie sa status page.
- **`dashboard_config.py`** lit `config.json` : c'est le seul endroit où vivent
  les valeurs propres à une installation.
- **[L'agent compagnon](#lagent-compagnon)** (`agent/sumotori-dash-agent/`) est
  le plugin WordPress installé sur les sites sans SSH.

```
                    ┌────────────── nginx (HTTPS, auth_request) ──────────────┐
   navigateur ──────┤  /            → public/index.html                        │
                    │  /api/actions,mgmt,sec,site,auth → 127.0.0.1:8090 (API)  │
                    │  /api/         → 127.0.0.1:3001 (Uptime Kuma, statut)     │
                    └──────────────────────────────────────────────────────────┘
   cron ── collect.py ──SSH (wp-cli)──▶ serveurs du parc
                      └──HTTPS signé HMAC──▶ sites sans SSH (agent)
```

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
- **Ne committez jamais** `config.json`, `servers.json`, `data/`,
  `public/fleet.json` ni vos clés — tout est déjà dans `.gitignore`. Vérifiez
  avec `git status` avant le premier `push`.

---

## Exploitation

### Les onglets

| Onglet | Contenu |
|---|---|
| **Tableau de bord** | La liste des sites : état, versions, mises à jour en attente, sauvegardes. Filtres, vues enregistrées, export CSV, actions groupées. |
| **Gestion** | Ajout d'un site par URL, sites supervisés non gérés, serveurs, clés SSH, moniteurs Kuma. |
| **Sécurité** | Vulnérabilités, erreurs PHP, comptes administrateurs, recherche transversale d'extension, PHP obsolète, certificats, extensions à risque, intégrité du cœur. |
| **Historique** | Tendance du parc (courbes) et journal des changements d'état. |

### Mettre à jour un site

Le bouton **🛡 MAJ sûre** du tiroir enchaîne : contrôle avant → sauvegarde
UpdraftPlus → **archivage des fichiers et dump de la base** → mise à jour →
contrôles (page servie, poids non effondré, WordPress fonctionnel, et scan
visuel VizProof si la commande est disponible) → **retour arrière automatique**
si quelque chose casse.

Deux garde-fous : la base n'est **jamais** restaurée automatiquement — elle
contient ce qui a été écrit pendant l'opération, la commande exacte est donnée
pour en faire une décision — et une extension **gelée** n'est jamais mise à
jour, quel que soit le chemin emprunté.

`POST /api/actions/safe_update {"dry_run": true}` simule sans rien écrire.

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

### Divers

- **Mise à jour du code** : `git pull` puis `systemctl restart wp-dashboard-api`.
- **Journaux** : `journalctl -u wp-dashboard-api` pour l'API,
  `/var/log/wp-dashboard.log` pour les tâches cron.
- **Compression** : pensez à activer `gzip_types` dans `nginx.conf`. Sans elle,
  seul le HTML est compressé et l'inventaire JSON part en clair — sur un parc
  d'une quarantaine de sites, c'est 234 Ko contre 22 Ko à chaque chargement.

---

## Licence

À définir par le mainteneur. L'agent compagnon est publié sous **GPLv2+**
(exigence de l'écosystème WordPress) ; la même licence pour l'ensemble est le
choix le plus simple. Ajoutez un fichier `LICENSE` en conséquence.
