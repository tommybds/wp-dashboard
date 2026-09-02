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
- [VizProof](#vizproof)
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
Le corps accepte aussi `"viz_rollback": true|false` pour surcharger, **le temps
d'une exécution**, le réglage décrit à la section VizProof ci-dessous.

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
en une phrase, avec les mêmes boutons et un lien **ouvrir dans wp-admin**.

> Avant, un plugin installé mais jamais relié était **indiscernable d'un plugin
> absent** : `wp vizproof status` sort en 1 dans ce cas, et la collecte jetait
> tout ce qui n'était pas rc 0. Le collecteur accepte désormais ce rc 1 **quand
> la sortie contient un JSON portant la clé `configured`** — le seul signe qui
> distingue « le site répond mais n'est pas configuré » de « la commande
> n'existe pas ». La fiche `vizproof` d'un site porte donc `has_cli`,
> `configured`, `has_credentials`, `connected` et `site_id`, en plus de
> `version`, `pages` et `last_run`.

#### Connecter un site

Le bouton **Connecter** (colonne ou tiroir) ouvre une modale : un **identifiant
de site** (`[A-Za-z0-9_-]`, 80 caractères au plus) et, au choix, le **jeton** du
compte VizProof ou un **code de connexion** à usage unique. Le jeton se crée dans
**VizProof → Réglages → API**. Les options repliées permettent de viser une autre
base API (https obligatoire, mêmes gardes anti-SSRF que le reste du dashboard) et
de choisir la portée (`site` ou `selected_pages`).

Depuis la **barre d'actions groupées**, « Connecter VizProof… » ouvre la même
modale avec une ligne par site coché : l'identifiant est propre à chaque site,
mais le jeton de compte vaut pour tous, et les appels s'enchaînent avec leur
résultat en face de chaque ligne. Les sites non éligibles (sans SSH, sans CLI,
extension absente) sont écartés de la liste.

- Un site géré **sans SSH** ne peut pas être connecté d'ici (l'agent est en
  lecture seule) : seul le lien wp-admin est proposé.
- Sur une extension antérieure à 1.3.6, wp-cli répond « `connect` is not a
  registered subcommand » ; le dashboard le traduit en **rc 99** et en un message
  clair plutôt qu'en échec opaque.
- **Le jeton n'est jamais enregistré** côté dashboard, ne passe **jamais** par la
  ligne de commande distante (il est transmis sur l'entrée standard de
  `wp vizproof connect --token-stdin`, via un document ici — rien n'est écrit sur
  le disque du site) et il est masqué dans `data/actions.log` comme dans la
  réponse HTTP. Sur un mutualisé, un argument de commande est lisible par tous
  les comptes du serveur (`ps aux`) : c'est la raison de ce détour. C'est aussi
  pourquoi `viz_connect` n'est **pas** dans le dictionnaire `ACTIONS` : il n'est
  pas atteignable par `/api/actions/run`, qui journalise son argument.

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

Le réglage se lit et s'écrit aussi en direct :

```bash
curl -s ... /api/mgmt/settings                                  # → {"settings": {...}, "defaults": {...}}
curl -s ... -d '{"settings":{"viz_anomaly_rollback":true}}' ... # les clés inconnues sont ignorées
```

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

À définir par le mainteneur. L'agent compagnon est publié sous **GPLv2+**
(exigence de l'écosystème WordPress) ; la même licence pour l'ensemble est le
choix le plus simple. Ajoutez un fichier `LICENSE` en conséquence.
