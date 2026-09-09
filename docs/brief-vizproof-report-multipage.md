# Brief 2 — `wp vizproof report` ne rend qu'une page sur N

*Suite du brief `brief-vizproof-seo-cli.md`, même dépôt `~/Dev/PERSO/VRT-FINAL`.*

## Le constat, mesuré

Site `lesgeiq-pdl.fr`, 3 pages surveillées. Un scan lancé à 14:54 a produit
**trois runs distincts**, un par page, deux captures chacun :

```
cmtu7ycqe01s   2026-09-09T14:54   Évènements       → 2 snapshots
cmtu7ycn901s   2026-09-09T14:54   Candidats…       → 2 snapshots
cmtu7yck601s   2026-09-09T14:54   Page d'accueil   → 2 snapshots
```

`wp vizproof report` (sans argument) rend le **dernier run**. Son `summary` dit
donc `pages_scanned: 1` alors que le site en surveille 3, et son tableau ne
contient que les deux lignes d'une seule page.

Pour un consommateur externe, le résultat est trompeur : il affiche « 1 page
scannée » sous un en-tête qui annonce « 3 pages surveillées », sans aucun moyen
de savoir que les deux autres existent ailleurs. C'est exactement la question
qui a été posée : « j'ai 3 pages enregistrées mais je n'en vois qu'une ».

## Ce qui est demandé

Une des deux, au choix — la première est préférable.

### Option A (préférée) : agréger le scan

`wp vizproof report` rend le dernier **scan** et non le dernier **run** :
les items des N runs issus du même déclenchement sont concaténés, et le
`summary` porte les totaux du lot.

```json
{
  "run_id": "cmtu7ycqe01s",
  "run_ids": ["cmtu7yck601s", "cmtu7ycn901s", "cmtu7ycqe01s"],
  "summary": { "pages_scanned": 3, "pages_changed": 1, "top_page": "Page d'accueil" },
  "totals":  { "fail": 0, "warn": 2, "ok": 4, "other": 0 },
  "total_items": 6,
  "items": [ … les 6 lignes, page + viewport … ]
}
```

Le regroupement se fait sur ce qui identifie un déclenchement : `triggerMeta`,
`runSource`/`triggerSource`, ou à défaut une fenêtre de quelques secondes sur
`createdAt` pour un même `siteId`. Vous savez lequel est fiable, pas moi.

### Option B (repli) : dire qu'il y a des frères

Si l'agrégation est trop lourde, il suffit que le rapport porte de quoi aller
chercher les autres :

```json
{ "run_id": "cmtu7ycqe01s",
  "scan_run_ids": ["cmtu7yck601s", "cmtu7ycn901s", "cmtu7ycqe01s"],
  "scan_pages_total": 3 }
```

Le consommateur appelle alors `wp vizproof report --run=<id>` pour chacun —
la commande accepte déjà un identifiant de run. Trois appels wp-cli au lieu
d'un, mais au moins l'information est complète et rien n'est deviné.

## Garde-fous

1. **Rétrocompatibilité.** Les six clés d'item (`page`, `url`, `viewport`,
   `status`, `diff_percent`, `label`) et les deux ajoutées en 1.3.10 (`cause`,
   `seo_changes`) gardent leur nom et leur sens. `run_id` continue de désigner
   **un** run.
2. **Plafond.** 20 pages × 2 écrans = 40 items : au-delà de ce que rend déjà
   `has_more` / `total_items`, appliquer la même troncature qu'aujourd'hui.
3. **Le cas d'une seule page ne change pas** : `run_ids` d'un seul élément, ou
   absent — pas de tableau à un élément qui obligerait à traiter deux formes.

## Un second point, plus petit

Toujours sur `lesgeiq-pdl.fr`, le run `cmtu7tl3f01kq1slajjjhbcn3` est rendu avec
`is_baseline: true` **et** `totals: {fail: 0, warn: 2, ok: 0}` — deux lignes en
avertissement sur un run annoncé comme référence.

Les deux à la fois sont contradictoires pour un lecteur : soit c'est une
baseline et il n'y a rien à comparer, soit c'est un scan comparé qu'on a promu
en référence. Le dashboard s'accommode désormais des deux lectures (il affiche
les lignes quand il y en a, quel que soit le drapeau), mais il vaudrait mieux
que le sens soit tranché à la source — par exemple `is_baseline` réservé aux
runs sans comparaison, et un `promoted_as_baseline` distinct pour un scan promu.

## Comment vérifier

- Un scan de 3 pages doit rendre `pages_scanned: 3` et 6 items (option A), ou
  `scan_run_ids` de longueur 3 (option B).
- Un scan d'une seule page rend exactement ce qu'il rend aujourd'hui.
- Une baseline reste sans `cause` ni `seo_changes`, comme convenu en 1.3.10.
