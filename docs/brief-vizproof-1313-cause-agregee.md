# Brief 3 — la 1.3.13 : `cause` et `seo_changes` disparaissent du rapport agrégé

*Dépôt `~/Dev/PERSO/VRT-FINAL`. Fait suite aux briefs 1 (cause/seo_changes,
livrés en 1.3.10) et 2 (agrégation multi-runs, livrée en 1.3.11/1.3.12).*

## Le constat, mesuré

Site `lesgeiq-pdl.fr`, extension **1.3.12**, 3 pages surveillées. Scan de
comparaison — pas une baseline :

```
run cmtub3btn000w1smg1wwuxnhd
is_baseline: False   promoted_as_baseline: None
summary: {pages_scanned: 3, pages_changed: 3, top_page: "Page d'accueil"}
totals:  {fail: 0, warn: 4, ok: 2, other: 0}
items:   6
```

Les six items ne portent que les **six clés d'origine** :

```
clés d'un item : diff_percent, label, page, status, url, viewport
```

Sur les quatre items `warn` : `cause` absente, `seo_changes` absente.

Or le contrat de la 1.3.10 dit : « `cause` … **présente uniquement sur les items
`warn` et `fail`** ». Quatre items `warn` devraient donc porter au minimum
`cause: "pixel"`.

## L'hypothèse

`cause` et `seo_changes` sont produites sur le chemin d'un **run unique**. La
concaténation introduite pour le rapport agrégé reconstruit vraisemblablement
les items à partir des données de run — page, url, viewport, status,
diff_percent, label — sans recopier les deux clés calculées.

À vérifier là où le lot est assemblé, dans `class-vizproof-timeline-cli-service.php`
(la normalisation d'item est `normalize_report_item`, l. ~1835 avant les
modifications de la 1.3.11).

## Ce qui est demandé

Que le rapport agrégé porte, pour chaque item, exactement ce que porterait le
rapport de son run pris seul. Rien de plus, rien de moins.

```json
{ "page": "Page d'accueil", "url": "https://lesgeiq-pdl.fr/", "viewport": "mobile",
  "status": "warn", "diff_percent": 0.23, "label": "À vérifier",
  "cause": "pixel" }
```

et, quand un champ SEO a changé sur cette page :

```json
{ "…": "…", "cause": "pixel+seo",
  "seo_changes": [ { "field": "title", "before": "…", "after": "…" } ] }
```

Les règles du brief 1 restent inchangées : combinaison jointe par `+` dans
l'ordre `pixel+seo+a11y`, clés absentes (jamais vides) quand il n'y a rien à
dire, absentes aussi sur une baseline.

## Comment vérifier

Trois cas, sur un site à plusieurs pages :

1. **Scan multi-pages, pixels seulement** → chaque item `warn`/`fail` porte
   `cause: "pixel"`, aucun `seo_changes`.
2. **Scan multi-pages, un `title` modifié sur une seule page** → cette page
   porte `cause` contenant `seo` et un `seo_changes` d'un élément ; les autres
   pages gardent `cause: "pixel"` ou rien si elles sont `ok`.
3. **Non-régression du run unique** : un site à une seule page doit rendre
   exactement ce qu'il rend en 1.3.12 — c'est ce chemin-là qui fonctionne
   aujourd'hui, il ne doit pas bouger.

Un `diff -u` entre la sortie d'un run seul et celle du même run dans un lot
agrégé est probablement le test le plus rapide à écrire.

## Ce que ça débloque, côté parc

Le dashboard affiche déjà, sous le résumé de chaque rapport, trois verdicts par
nature — `visuel`, `SEO`, `structure` — en vert, orange ou rouge. Le gris
« SEO : non mesuré » est ce qu'il affiche quand aucun item ne porte `cause` :
c'est exactement l'état actuel de tes deux sites, et c'est volontairement gris
plutôt que vert, pour ne pas laisser croire que le référencement a été vérifié.

Dès que les deux clés reviennent dans le rapport agrégé :

- les badges passent au vert ou à l'orange selon la réalité ;
- la ligne concernée affiche `title : ancien → nouveau` sous elle ;
- `structure : modifiée` s'allume aussi, sans autre changement — le dashboard
  lit déjà `a11y` dans `cause`.

Rien à faire côté dashboard : le code est en place et attend la donnée.

## Hors périmètre, et volumineux

Le **contenu textuel** des pages n'est capturé nulle part : ni `innerText`, ni
HTML du corps, ni compte de mots, ni empreinte. Le seul HTML persisté est
l'`outerHTML` des sélecteurs critiques déclarés à la main. Un contrôle « le
contenu a-t-il changé ? » demande donc une capture nouvelle, un champ nouveau
en base et un diff nouveau — c'est un chantier à part entière, pas une 1.3.13.

## Résolution, le 9 septembre 2026 : pas de 1.3.13

Vérifié sur la chaîne complète du plugin : la 1.3.12 rend `cause` et
`seo_changes` sur chaque item du rapport agrégé, à l'identique du run seul, et
`promoted_as_baseline` et `run_ids` au sommet. La perte était dans le dashboard,
dans `actions_server.py` : `viz_report_item` ne recopiait que six clés, et
`viz_report_payload` ne recopiait ni `promoted_as_baseline` ni `run_ids`, d'où
le `promoted_as_baseline: None` du constat.

Les quatre clés sont recopiées, bornées, et absentes quand elles sont vides.
`viz.js` les lisait déjà : les badges et la ligne `title : ancien → nouveau`
s'allument sans autre changement. Le test rejoue l'échantillon 1.3.10 de
`tools/preview.py` à travers `viz_report_payload`.
