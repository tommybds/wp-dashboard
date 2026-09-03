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

La refonte de septembre 2026 s'est faite en cinq phases (plan complet :
[`docs/refonte-plan.html`](docs/refonte-plan.html)). Ce qui suit décrit
l'**état d'arrivée**, pas le chemin : il n'y a plus ni tiroir, ni sous-onglet,
ni modale de réglages.

### Les six écrans

| Écran | Fragment | Ce qu'il porte |
|---|---|---|
| **Parc** | `#parc` | File « à traiter », compteurs cliquables, liste des sites (tableau au bureau, cartes au mobile), actions groupées. |
| **Incidents** | `#incidents` | La file complète de `GET /api/incidents`, groupée par gravité, avec action en ligne. |
| **Sécurité** | `#securite[/<ancre>]` | Une page, huit sections repérées par un sommaire d'ancres. |
| **Changements** | `#changements[/<ancre>]` | Chronologie unifiée, puis la tendance du parc. |
| **Gestion** | `#gestion[/<ancre>]` | Serveurs, installs, sites sans SSH, moniteurs, docroots, non gérés. |
| **Réglages** | `#reglages[/<ancre>]` | Huit sections, chacune avec son bouton d'enregistrement. |
| **Page site** | `#site/<clé>[/<onglet>]` | Tout sur un site, en cinq onglets, et les actions dessus. |

Une **destination** est une page entière ; un **onglet** n'existe que sur la
page site (un seul volet à la fois sur un même objet) ; partout ailleurs, un
sous-slug d'URL désigne une **ancre** dans la page. Les anciens fragments
(`#dash`, `#sec/…`, `#hist/…`, `#mgmt/…`) redirigent.

Passer d'une ancre à l'autre **n'est pas une navigation** : la destination est
déjà à l'écran, `app.js` défile jusqu'à la section et `replaceState` le fragment,
sans rien remonter — un remontage remplacerait le champ en cours de saisie. Le
chip actif suit la **section visible**, et la re-visée qui rattrape les sections
qui se remplissent n'existe qu'au **premier rendu** d'une destination : elle
s'arrête dès que quelqu'un d'autre a défilé, ou après 3 s.

### Arborescence

```
public/
  index.html            coque : barre latérale, barre d'onglets basse (mobile),
                        en-tête d'écran, modales partagées, table d'imports,
                        un seul <script type="module" src="app.js?v=…">.
                        Aucun écran n'y a de gabarit : tous sont construits
                        par leur module avec h()
  login.html            page de connexion, autonome (ni module, ni sprite, ni API)
  app.js                démarrage, routeur par fragment, abonnement au store
  version.js            export const V = "AAAA-MM-JJ-hhmm" — posé par tools/deploy.sh
  icons.svg             sprite Lucide (35 icônes), injecté une fois par lib/icons.js
  css/
    tokens.css          couleur (2 thèmes), typo, espace, rayons, @font-face
    base.css            remise à zéro, typographie, focus, reduced-motion, utilitaires
    components.css      bouton, chip, tableau, menu, modale, feuille basse,
                        notification, bulle, palette de recherche
    screens.css         coque, barre d'onglets basse, mises en page des écrans,
                        et TOUTE l'adaptation mobile (un seul bloc, sous 720 px)
  lib/
    api.js              fetch, session, X-Dash, redirection sur 401
    dom.js              h(), esc(), mount(), zoneMessage(), occupe()
    format.js           dates relatives et courtes, durées, URL, cadences
                        UpdraftPlus, détail d'un évènement d'agent, bruit PHP
    icons.js            icon() / iconEl() + injection du sprite
    poll.js             sondage borné : s'arrête sur erreurs, sur `until`, à la demande
    state.js            store (flotte, statut Kuma, sélection, filtres, réglages)
                        + abonnements + cache court par chargeur
  components/
    actions-menu.js  add-site.js  button.js  chip.js  confirm.js  incident.js
    job.js  log.js  rollback.js  search.js  sheet.js  shell.js  table.js
    tip.js  toast.js  viz.js  wpauth.js
      incident.js  la ligne d'incident dépliable : message entier, pile
                   d'appels, « que faire », copier — un seul objet pour les
                   trois écrans qui montrent des incidents
      confirm.js   modales génériques, ordre des couches, Échap, piège de focus
      sheet.js     feuille basse : la couche de choix du mobile
      shell.js     barres de navigation, compteurs, thème, collecte
      table.js     tri, densité, colonnes masquables, ombres de débordement
  screens/
    parc.js  site.js  incidents.js  securite.js  historique.js
    gestion.js  reglages.js          (historique.js = écran « Changements »)
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
  `:root[data-theme="dark"]` porte le sombre forcé. Le bouton de thème écrit
  `localStorage.dashTheme` et pose (ou retire) `data-theme`.
- **Typographie** — 12 / 13 / 14 / 16 / 20 / 26 px. Interface à 14, textes
  explicatifs à 16, chiffres en `tabular-nums`.
- **Espace** — 4 / 8 / 12 / 16 / 24 / 32 / 48. **Rayons** — 4 px pour les
  contrôles, 6 px pour les surfaces, pilule pour les chips.
- **Élévation par bordure**, pas par ombre : la seule ombre est celle des
  couches flottantes (menu, modale, feuille, notification).

`tools/check_tokens.py` calcule les contrastes dans les **deux** thèmes et
échoue si un seuil n'est pas tenu : encre ≥ 7:1, texte secondaire ≥ 4.5:1,
chips ≥ 4.5:1 sur leur fond. À lancer après toute modification de `tokens.css`.

### Composants

| Composant | Ce qu'il fait |
|---|---|
| `chip.js` | Chip d'état : point + libellé, **quatre** niveaux (`ok`, `warn`, `err`, `mut`) et un seul vocabulaire dans toute l'application. |
| `incident.js` | La ligne d'incident **dépliable**, partagée par la file « à traiter » (Parc et page site), l'écran Incidents et les groupes d'erreurs PHP de Sécurité. Repliée elle tient sur une ligne ; ouverte elle donne le message **entier**, le fichier fautif (`wp-content/plugins/<slug>` mis en évidence), la fenêtre d'apparition, la **pile d'appels** défilante, un bouton **Copier** et une phrase « Que faire » par type. Le pli est un vrai `<button>` (`aria-expanded` + `aria-controls`) : Entrée et Espace marchent sans être simulés, et le résumé garde ses liens, qui n'auraient rien à faire dans un bouton. |
| `button.js` | États d'un bouton : chargement (`setBusy`/`setIdle`, qui préservent l'icône) et confirmation à deux clics. |
| `table.js` | Tri par colonne avec `aria-sort`, densité, colonnes masquables mémorisées, et les **ombres de débordement** horizontal. |
| `actions-menu.js` | Menu groupé par intention. Un groupe peut s'ouvrir sur des **lignes d'état** non cliquables (`{etat:true}`) et ne montrer ensuite que les entrées qui ont un sens dans cet état. Au bureau c'est un panneau `role="menu"` ; sous 720 px, **la même liste s'ouvre en feuille basse**. |
| `sheet.js` | La feuille basse : `role="dialog"`, glisser pour fermer, boutons pleine largeur. |
| `confirm.js` | Les modales génériques, l'**ordre des couches** (Échap ferme la plus haute) et le **piège de focus**, valable pour toutes. |
| `search.js` | Palette ⌘K / Ctrl+K : sites, extensions, administrateurs, actions. |
| `toast.js` | Barre de notifications : elle survit au changement d'écran et résume ce qui tourne. |
| `job.js` | Suivi d'une exécution groupée (modale + progression + notification). |
| `shell.js` | Barre latérale, barre d'onglets basse, compteurs, thème, collecte. |
| `viz.js` · `rollback.js` · `add-site.js` · `wpauth.js` · `log.js` · `tip.js` | VizProof, rétablissement de version, assistant d'ajout, autorisation WordPress, journal des actions, infobulles. |

### Mobile

« Bureau d'abord, mobile correct » : sous 720 px on doit pouvoir consulter
l'état, ouvrir un incident, lancer un re-scan ou une MAJ sûre — **sans zoom ni
défilement horizontal**. Toute l'adaptation vit dans un seul bloc
`@media(max-width:720px)` de `screens.css`, plus un appoint sous 380 px.

- La barre latérale disparaît au profit d'une **barre d'onglets basse** (Parc,
  Incidents, Sécurité, Plus), avec ses pastilles et `aria-current`.
  `safe-area-inset-bottom` est respecté. « Plus » ouvre une feuille :
  Changements, Gestion, Réglages, Journal, Thème, Déconnexion.
- La liste des sites devient une **liste de cartes** — même objet de ligne que
  le tableau (`objetLigne()` dans `screens/parc.js`), donc les deux ne peuvent
  pas diverger. La case à cocher n'apparaît qu'en **mode sélection** (bouton
  « Sélection », ou appui long sur une carte).
- Les menus flottants et la barre d'actions groupées deviennent des
  **feuilles** qui montent du bas ; les confirmations aussi, avec un bouton de
  validation pleine largeur.
- Sommaires d'ancres et onglets défilent horizontalement, avec un **fondu de
  débordement** posé par `initDebordement()` uniquement quand il y a de quoi
  défiler.
- Les tableaux larges restent dans leur `overflow-x:auto` (même fondu) ; le
  tableau des extensions de la page site, lui, s'empile en label/valeur.
- Toute cible tactile fait au moins 44 px.

### Accessibilité

- **Clavier** : ordre logique, `Tab` n'atteint rien de caché, `Échap` ferme la
  couche la plus haute (bulle → menu → modale ou feuille), le focus est piégé
  dans les modales, la feuille et la palette, et revient toujours à l'élément
  qui a ouvert la couche.
- **Rôles et noms** : boutons-icônes avec `aria-label`, `<th scope="col">`
  (posé par `h()`, une fois pour tous les tableaux), `aria-sort` sur les
  colonnes triables, `role="tablist"/"tab"/"tabpanel"` sur la page site,
  `role="menu"` pour le menu d'actions, `role="status"` sur les messages de
  résultat (`zoneMessage()`), `aria-live` sur la barre de notifications et
  `aria-busy` pendant les chargements (`occupe()`).
- **Contrastes** : vérifiés par script dans les deux thèmes, couples
  texte-sur-chip et texte secondaire sur surface compris.
- **Mouvement** : `prefers-reduced-motion` coupe toutes les animations —
  aucune n'est porteuse d'information.

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

Un sprite unique, `public/icons.svg` (35 icônes Lucide, trait 1,5 px, 7 Ko).
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
2. Ajouter son volet dans `index.html` : `<div class="page" id="page-<nom>">`
   (vide : l'écran le remplit avec `h()`).
3. Dans `app.js`, ajouter une entrée à `DESTINATIONS`
   (`{route, page, titre, legacy?}`), l'importer, et l'appeler dans `showDest`.
4. Ajouter le lien dans la barre latérale d'`index.html`
   (`<a class="nav-i" href="#<route>" data-dest="<route>">`) — et, si la
   destination doit rester atteignable au mobile, soit un `.tab-i` de la barre
   d'onglets basse, soit une entrée de la feuille « Plus »
   (`ouvrirPlus()` dans `components/shell.js`).
5. Lancer les contrôles ci-dessous.

Rien à déclarer ailleurs : `tools/deploy.sh` découvre le nouveau module et
l'ajoute à la table d'imports.

### Ajouter un composant

Un fichier dans `public/components/`, qui **ne connaît aucun écran**. Quand un
composant a besoin d'un écran (rafraîchir Sécurité après un job, ouvrir la page
d'un site depuis une notification), l'écran s'**enregistre** auprès de lui
(`setSecRefresh`, `setOuvreurs`, `registerModalCloser`) plutôt que d'être
importé : c'est ce qui évite les cycles d'import, et ils arrivent vite.

Son CSS va dans `components.css` s'il ne dépend d'aucun écran, dans
`screens.css` sinon. Un export jamais importé est refusé par
`tools/check_dead.py` : une fonction utilisée seulement chez elle n'est pas
exportée.

### Ajouter une icône

Le sprite est un fichier statique. Pour en ajouter une, copier le `<symbol
id="i-<nom>" viewBox="0 0 24 24">…</symbol>` de l'icône Lucide dans
`public/icons.svg` (en retirant `width`/`height`/`stroke` : `.ic` les porte),
puis l'utiliser par `icon('<nom>')`. `tools/check_front.py` vérifie qu'aucune
icône référencée ne manque du sprite.

### Vérifier sans toucher à la production

```bash
python3 tools/preview.py                  # page bouchonnée, 20 sites, port 8787
python3 tools/preview.py --scenario gros  # 200 sites
python3 tools/preview.py --scenario vide  # aucun site
python3 tools/preview.py --scenario stale # un serveur injoignable
python3 tools/preview.py --scenario joblent   # collecte et MAJ en cours
python3 tools/preview.py --scenario anomalie  # anomalie visuelle VizProof
```

`window.fetch` y est remplacé par des fixtures : aucune requête ne sort. Les
vraies réponses déposées dans `scratchpad/fixture/<route>.json` (le `/` du
chemin devenant `_`) sont utilisées en priorité.

Les routes d'**écriture** et les routes de Gestion / Réglages ne répondent pas
un `{"ok":true}` figé : le serveur bouchonné tient un état (serveurs, docroots,
overrides, moniteurs, sites REST, clés, réglages, alertes) et **rejoue la
validation du backend**, refus HTTP 400 compris — c'est ce qui permet de vérifier
que l'erreur d'un serveur s'affiche bien sur le bon champ du formulaire.

Contrôles automatiques, tous lancés par `tools/deploy.sh` avant chaque copie :

```bash
python3 tools/check_tokens.py                     # contrastes, deux thèmes
python3 tools/check_front.py -v                   # routes, actions, ids, icônes, styles, imports
python3 tools/check_a11y.py -v                    # noms accessibles, étiquettes, tabindex, clavier
python3 tools/check_dead.py -v                    # exports et classes CSS orphelins
for f in $(find public -name '*.js'); do node --input-type=module --check < "$f" || echo "$f"; done
```

`node --check <fichier>` seul **ne vérifie pas** un module ES : Node le détecte
comme tel et rend la main sans erreur. Il faut le lui passer sur l'entrée
standard avec `--input-type=module`.

Les captures de référence (six écrans + page site, deux thèmes, 1440 et 390 px)
vivent dans [`docs/captures/`](docs/captures/) et se régénèrent depuis la page
bouchonnée — c'est le seul usage de npm du projet, et il est hors production :

```bash
npm i --no-save playwright                       # une fois — hors dépôt (.gitignore)
npx playwright install chromium-headless-shell   # une fois
python3 tools/preview.py &                       # page bouchonnée sur le port 8787
node tools/captures.mjs                          # → docs/captures/*.png
```

### Déployer

```bash
tools/deploy.sh --dry-run     # contrôles + estampille la version, ne copie rien
tools/deploy.sh               # + rsync de public/ vers le VPS
tools/deploy.sh --nginx       # + reload nginx (seulement si le vhost a changé)
```

Le script lance d'abord les contrôles ci-dessus, écrit `version.js`, régénère
la table d'imports et les `?v=`, puis copie. La règle de cache nginx est dans
`deploy/nginx-static-cache.conf`, à inclure une fois dans le bloc `server{}` du
vhost.

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

La barre latérale porte cinq destinations, plus **Réglages** en pied de barre
(au mobile, la barre d'onglets basse et sa feuille « Plus » les portent toutes).
L'adresse est partageable : `#parc`, `#incidents`, `#securite/<section>`,
`#changements/<section>`, `#gestion/<section>`, `#reglages/<section>`. Les
anciens fragments (`#dash`, `#sec/…`, `#hist/…`, `#mgmt/…`) redirigent
automatiquement — les liens déjà partagés continuent de tomber au bon endroit.

**Aucune destination n'a de sous-onglet** : `<section>` désigne toujours une
**ancre**, `#securite/vulnerabilites` ouvre la page et défile jusqu'à la
section. Les deux familles de noms tombent juste — les anciens
slugs (`vulnerabilites`, `erreurs-php`, `administrateurs`, `recherche-plugin`,
`php-obsolete`, `certificats`, `plugins-a-risque`, `integrite-core`, `tendance`,
`changements`, et pour Gestion `serveurs`, `installs`, `mode-rest`, `moniteurs`,
`docroots`, `sites-non-geres`) et ceux que le backend pose dans le champ `link`
des incidents (`vulns`, `phperrors`, `admins`, `php`, `certs`, `checksums`).

| Destination | Contenu |
|---|---|
| **Parc** | La liste des sites : état, versions, mises à jour en attente, sauvegardes. Filtres, vues enregistrées, export CSV, actions groupées ; au mobile, une liste de cartes et une feuille d’actions. Une ligne mène à la **page site**. |
| **Incidents** | La file « à traiter » complète (`GET /api/incidents`), groupée par gravité : sites down, erreurs PHP fatales, vulnérabilités critiques corrigeables, checksums en anomalie, administrateurs inconnus, serveurs injoignables, sauvegardes en retard, certificats, PHP en fin de support. Filtres gravité / type / recherche, action en ligne (même confirmation que la page site) ou lien vers la section concernée ; une source en échec s'affiche en « source incomplète ». |
| **Sécurité** | **Une seule page à ancres**, ouverte par un sommaire chiffré : vulnérabilités (vue par site ou par extension, action groupée), comptes administrateurs et référence, erreurs PHP, extensions à risque, PHP obsolète regroupé par version, certificats, intégrité du cœur, recherche transversale d'extension. |
| **Changements** | Une **chronologie** groupée par jour qui fusionne les changements d'état détectés par la collecte (`/api/mgmt/changes`) et les actions lancées depuis le dashboard (`/api/actions/log`), filtrable par site, type, gravité et texte — puis la **tendance du parc** (quatre courbes) en bas de page. |
| **Gestion** | **Une seule page à ancres** : serveurs (en formulaires), installs découverts, sites sans SSH et assistant d'ajout par URL, moniteurs Kuma, docroots supplémentaires, sites supervisés non gérés. |
| **Réglages** | **Une seule page à ancres** : cadence de collecte, alertes Telegram, VizProof, contrôle visuel, règles d'incidents, clés SSH, apparence, session. |

En bas de la barre : **Réglages** (`#reglages`), **Journal** des actions (une
modale, volontairement : on la consulte en passant depuis n'importe quel écran),
bascule de **thème** (auto / clair / sombre) et déconnexion.

Sous 1000 px la barre se replie en icônes. Sous **720 px** elle disparaît au
profit d'une **barre d'onglets basse** — Parc, Incidents, Sécurité, et un bouton
« Plus » qui ouvre une feuille avec Changements, Gestion, Réglages, Journal,
Thème et la déconnexion. Voir [Mobile](#mobile).

### Gestion

La page répond à « comment le parc est-il branché ? », dans l'ordre du
branchement.

| Section | Ce qu'on y fait |
|---|---|
| **Serveurs** (`#gestion/serveurs`) | Le tableau de `servers.json` : hôte, port, utilisateur, clé, priorité, parallélisme, motifs de docroot, nombre d'installs relevées et état du dernier relevé. **Ajouter** / **Modifier** ouvrent un **formulaire**, un champ par attribut, avec son aide. La validation reproduit `validate_server()` à la saisie, et un refus du serveur (HTTP 400) s'affiche **sur le champ concerné** — le message backend nomme le serveur et l'attribut. **Tester la connexion** ouvre une session SSH avec la clé choisie (sur un serveur déjà enregistré). **éditer le JSON** reste disponible en repli, pour une clé que le formulaire ne connaît pas. |
| **Installs découverts** (`#gestion/installs`) | Tous les WordPress trouvés en SSH, filtrables par serveur, par visibilité et par « sans moniteur ». Par ligne : moniteur Kuma (ou **créer moniteur**, avec choix du client et du type de contrôle), **visibilité** (auto / toujours afficher / masquer), **alias** de moniteur, **Dashboard** (connecter ou dissocier l'agent), **WordPress** (identifiants d'application : Autoriser / Révoquer). |
| **Sites sans SSH** (`#gestion/mode-rest`) | L'assistant **« Ajouter un site par URL »** en trois étapes : analyse de l'URL (`discover`), choix de la méthode (SSH ou appairage), puis ZIP de l'agent + code d'appairage à usage unique avec son compte à rebours et l'adresse du dashboard à recopier. En dessous, la liste des sites pilotés par l'agent, avec leurs identifiants WordPress et le retrait (qui propose de supprimer, ou non, le compte dédié créé sur le site). |
| **Moniteurs Kuma** (`#gestion/moniteurs`) | Pause, réactivation, suppression. Chaque modification redémarre Kuma (~15 s sans monitoring). |
| **Docroots** (`#gestion/docroots`) | Chemins scannés en plus des motifs du serveur. Même règle de validation que les motifs, appliquée à la saisie et côté serveur. |
| **Non gérés** (`#gestion/sites-non-geres`) | Sites vus par le monitoring mais absents du parc : **Ajouter par URL** ouvre l'assistant, URL pré-remplie. |

### Mettre à jour un site

Le bouton **MAJ sûre** de la page site enchaîne : contrôle avant → sauvegarde
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
  Un clic ouvre la page du site concerné, ou la modale de l'action groupée.
- Elle **survit** au changement d'écran, à la fermeture de la modale groupée et
  au changement d'onglet : c'est tout son intérêt. Elle ne remplace ni la console
  de la page site ni la modale groupée, elle les résume.

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
 "link": {"tab": "securite", "sub": "vulns"},
 "extra": {"cve": ["CVE-2026-1"], "slug": "ml-slider", "from": "3.100.1", "to": "3.100.2"}}
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

#### `extra` : ce que la ligne ne peut pas dire

`title` et `detail` tiennent sur **une ligne de liste** ; tout ce qui ne tient
pas là va dans `extra`, que l'interface affiche quand on **déplie** l'incident
(chevron sur la ligne, écran Incidents comme page site). C'est un **dictionnaire
libre**, sans schéma commun : ses clés dépendent du `kind`, et un front qui n'en
connaît pas une l'ignore. Il est toujours présent, éventuellement vide.

| `kind` | Clés de `extra` |
|---|---|
| `php_fatal` | `trace` (liste de cadres, 12 au plus), `trace_truncated`, `sample_ts` (occurrence qui a fourni la pile), `count`, `first`, `last`, `file` (chemin raccourci), `line` |
| `vuln_critical_fixable` | `cve` (liste — une extension cumule souvent plusieurs CVE graves), `slug`, `from`, `to` |
| `backup_late` | `last_backup` (ISO, `""` si jamais), `age_h` (`null` si jamais), `service` |
| `cert_expiring` | `days_left`, `expires` |
| `down` | `msg` (message du moniteur Kuma), `since` |
| `server_stale` | `error`, `last_attempt` |
| `php_eol` | `version`, `sites` (**tous** les sites, là où `detail` s'arrête à 12) |
| `checksums_modified` | `files` (chemins relevés dans la sortie wp-cli, 20 au plus) |
| `admin_unknown` | `login`, `email`, `registered` |

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

**Réglages** est une **page** (`#reglages`), plus une modale, découpée en huit
sections qui ont chacune leur bouton d'enregistrement et leur message de
résultat :

| Section | Contenu |
|---|---|
| **Collecte** (`#reglages/collecte`) | Cadence du cron (`/api/mgmt/schedule`), cron actuel affiché, et un raccourci vers la collecte manuelle. |
| **Alertes Telegram** (`#reglages/alertes`) | Interrupteur général, jeton du bot, `chat_id`, quatre déclencheurs booléens et trois seuils, plus **Envoyer un test** (qui utilise la configuration **enregistrée**). |
| **VizProof** (`#reglages/vizproof`) | Jeton de compte, base de l'API, **Tester**, **Effacer**. |
| **Contrôle visuel** (`#reglages/controle-visuel`) | Les quatre cases décrites ci-dessous, enregistrées à la volée. |
| **Règles d'incidents** (`#reglages/incidents`) | `incident_rules` en champs typés : âge maximal d'une sauvegarde, seuils de certificat (avertissement / critique), vulnérabilités `high` comptées ou non, versions PHP en fin de support. |
| **Clés SSH** (`#reglages/cles-ssh`) | Liste (nom, type, empreinte, clé publique dépliable), génération d'une clé dédiée, affectation par serveur avec **Tester** avant **Assigner**, et l'assignation à tous les serveurs. |
| **Apparence** (`#reglages/apparence`) | Thème (auto / clair / sombre) et densité des tableaux. Préférences **de ce navigateur** : elles ne partent pas au serveur. |
| **Session** (`#reglages/session`) | Utilisateur connecté, adresse du dashboard, déconnexion. |

Les **secrets** (jeton Telegram, jeton VizProof) ne sont **jamais réinjectés**
dans un champ : l'API n'en renvoie qu'un témoin et les quatre derniers
caractères, un champ laissé vide veut dire « inchangé », et effacer est un geste
explicite.

Les réglages de comportement sont stockés dans `data/settings.json` (fichier
**0600**) :

| Réglage | Défaut | Effet |
|---|---|---|
| **Retour arrière automatique sur anomalie visuelle** (`viz_anomaly_rollback`) | décoché | Pendant une **MAJ sûre**, une anomalie VizProof (rc 2) annule la mise à jour au lieu de la conserver. Voir [VizProof](#vizproof). |
| **Contrôle visuel VizProof après chaque mise à jour** (`viz_scan_after_update`) | **coché** | Après une mise à jour lancée depuis la page site (cœur, extensions, thèmes), le dashboard récupère **en arrière-plan** le verdict visuel des sites reliés : il **attend le scan que le plugin lance lui-même** et ne scanne qu'en repli. Il **informe seulement**. Voir [Contrôle visuel après une mise à jour unitaire](#contrôle-visuel-après-une-mise-à-jour-unitaire). |
| **Baseline VizProof avant chaque mise à jour unitaire** (`viz_baseline_before_update`) | **coché** | Sur un site relié, la mise à jour lancée depuis la page site passe par un **job suivi** : baseline → mise à jour → verdict visuel → inventaire. Sans baseline, le verdict d'après compare au dernier état connu de VizProof. Voir [Baseline avant, verdict après](#baseline-avant-verdict-après--le-job-viz_update). |
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

Un site sans inventaire d'extensions affiche `—`. La page site reprend le même état
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

Le bouton **Connecter** (colonne ou page site) ouvre une modale. Avec un token
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
**Dissocier** de la page site) ; l'extension reste installée.

#### Choisir les pages surveillées

Une fois le site relié, la question suivante est **quelles pages photographier**.
La modale de connexion y enchaîne d'elle-même, et le bloc VizProof d'un site relié
y revient par **Pages surveillées…** — même étape, deux entrées.

```
GET  /api/actions/viz_pages?server=&domain=
POST /api/actions/viz_pages {server, domain, ids:[…], scope}
→ {ok, rc, source, scope, limit, selected:[ids], critical:[ids],
   pages:[{id, title, url, type, selected, critical}], message}
```

`type` vaut `page`, `front` (l'accueil est une page statique) ou `home` (l'accueil
est le flux d'articles). **`home` porte l'identifiant 0 et n'est pas sélectionnable** :
il n'y a pas de page à capturer, le plugin refuse `--ids=0`, et la seule façon de
surveiller cet accueil-là est la portée `site`. La route refuse donc l'identifiant 0
hors portée `site`, où elle le retire simplement de l'envoi.

Validation, avant tout ssh : identifiants entiers positifs, dédoublonnés,
**20 au plus** (`array_slice($ids, 0, 20)` côté plugin — l'interface l'affiche),
`scope` ∈ `site` | `selected_pages`, et au moins une page en `selected_pages`.
L'écriture est journalisée sous l'action **`viz_pages`** dans `actions.log`
(`arg` = `<portée>:<ids>`), et un re-scan suit l'enregistrement pour que la
colonne du Parc affiche tout de suite le nouveau décompte.

> **Repli pour le plugin 1.3.7.** La sous-commande `pages` n'existe qu'à partir de
> la 1.3.8 ; en dessous, wp-cli répond « `'pages' is not a registered subcommand` ».
> Le serveur bascule alors sur `wp post list --post_type=page --post_status=publish`
> + `wp option get page_on_front` pour lire, et sur deux
> `wp option patch update vizproof_timeline_options …` pour écrire —
> `selected_wordpress_page_ids` (des identifiants **WordPress**) et `scan_scope`,
> rien d'autre dans l'option. **Attention** : `selected_page_ids`, lui, contient des
> identifiants de pages **VizProof** et ne sert qu'à l'écran réseau multisite ; y
> écrire des identifiants WordPress casse les captures.
> Limites du repli, dites à l'utilisateur dans la modale : **aucune validation par
> l'extension** (une page dépubliée entre la lecture et l'écriture passe quand même),
> pas de notion de page critique, et l'accueil « flux d'articles » n'est reconnu
> qu'à `page_on_front = 0`. La réponse porte `source: "repli-1.3.7"`.

Un site géré **sans SSH** répond `rc 97` : l'interface renvoie alors vers
`…/wp-admin/admin.php?page=vizproof-timeline`.

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

Le bouton **MAJ** de la page site passe par `/api/actions/run`, qui ne faisait
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
| `rescan` | inventaire rafraîchi, pour que la page site montre le dernier scan. |

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

Côté interface, la console de la page site affiche les étapes **en direct**, du même
rendu que la MAJ sûre, et la barre de notifications passe en progression
déterminée (« baseline VizProof… », « mise à jour… », « le plugin VizProof
scanne… », puis le verdict). Les boutons de mise à jour du site sont désactivés
pendant le job ; la page site peut être quittée et rouverte — au retour, un job
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
  tous les cas, pour que la ligne « Dernier scan » de la page site soit à jour.
- `GET /api/actions/viz_last?domain=` est une **mémoire de processus** (bornée,
  vidée au redémarrage du service) : l'historique, lui, est dans `actions.log`.

Côté interface : la console de la page site ajoute « Contrôle visuel VizProof : le
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

#### La pile d'appels des exceptions non capturées

Un `Uncaught Error: …` seul ne dit pas d'où il vient : le fichier fautif est
souvent un fichier du **cœur**, appelé par une extension qu'il faut retrouver
dans la pile. `phperrors.py` la capture donc, et le groupe porte trois champs de
plus :

| Champ du groupe | Contenu |
|---|---|
| `trace` | Les cadres, nettoyés, **12 au plus** — `#0 …`, `#1 …`, et la ligne `thrown in …`. L'en-tête `Stack trace:` n'en fait pas partie |
| `trace_truncated` | Vrai dès qu'un cadre a été **coupé par le journal** : FPM tronque chaque ligne autour de 200 caractères et la termine par `..."`. L'interface le dit, plutôt que de laisser lire une pile incomplète comme si elle était entière |
| `sample_ts` | Horodatage de l'occurrence qui a fourni la pile — la **plus récente** du groupe. Les 17 occurrences d'un même défaut ont la même pile : la recopier 17 fois n'apprendrait rien |

Deux formes de journal, deux lectures : sur **Plesk/FPM**, chaque cadre arrive
sur sa propre ligne, derrière le même bruit `[pool <domaine>] child N said into
stderr:` — la pile est rattachée à l'occurrence en cours **du même domaine**, ce
qui la garde correcte quand deux sites d'un mutualisé plantent en même temps. Sur
**nginx**, le message arrive d'un bloc et la pile se découpe sur les `#N`.

Ces lignes-là ne portent pas `PHP message` : le filtre côté serveur les laisse
passer explicitement, sans quoi la trace se perdait avant d'arriver au dashboard.

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
| **Lucide** (35 icônes, sprite) | `public/icons.svg` | ISC |

L'OFL et l'ISC autorisent toutes deux la redistribution avec le logiciel, y
compris commerciale ; l'OFL interdit seulement la vente des polices seules.

À définir par le mainteneur. L'agent compagnon est publié sous **GPLv2+**
(exigence de l'écosystème WordPress) ; la même licence pour l'ensemble est le
choix le plus simple. Ajoutez un fichier `LICENSE` en conséquence.
