# Brief — faire remonter le SEO dans `wp vizproof report`

*Pour une session de travail sur le dépôt `~/Dev/PERSO/VRT-FINAL` (VizProof).*

## Le problème, en une phrase

VizProof **compare déjà** sept champs SEO d'un run à l'autre et requalifie un
item `ok` en `warn` quand l'un d'eux change — mais la commande CLI
`wp vizproof report`, seule porte d'entrée des intégrations tierces, jette
cette information. Un consommateur externe reçoit « à vérifier » sans pouvoir
savoir si c'est un déplacement de pixels ou une balise `title` réécrite.

## Ce qui existe déjà (à ne pas refaire)

| Étape | Fichier | État |
|---|---|---|
| Extraction des champs SEO | `packages/server/src/services/captureInsights.ts` → `extractSeoMetadata` | ✅ |
| Comparaison baseline ↔ run | `packages/server/src/services/snapshotSemanticDiff.ts` → `SEO_FIELDS` (7 champs) | ✅ |
| Assemblage du résumé | `packages/server/src/services/diffChangeSummary.ts` → `buildDiffChangeSummary` | ✅ |
| Exposition API | `packages/server/src/routes/runs.ts` → `changeSummary` | ✅ |
| Transport dans le plugin | `wordpress-plugin/.../class-vizproof-timeline-diff-preview-service.php` (l. ~141-216) : porte déjà `seoChanged`, `changedSeoFields`, `seoFieldChanges` | ✅ |
| Affichage wp-admin | `assets/admin/runtime.js` (l. ~1242) : badge `SEO` / `SEO + STRUCTURE` | ✅ |
| **Sortie CLI** | `includes/class-vizproof-timeline-cli-service.php` → `normalize_report_item` (l. ~1835-1859) | ❌ **le trou** |

Les sept champs comparés : `title`, `description`, `canonical`, `robots`,
`h1Count`, `ogTitle`, `ogDescription`.

## Le changement demandé

`normalize_report_item` réduit aujourd'hui chaque item à :

```
page, url, viewport, status, diff_percent, label
```

Un commentaire du code assume ce choix : « Nothing from the raw diff (image
URLs, SEO before/after, run internals) is carried over ». L'intention était
bonne — ne pas déverser le diff brut — mais elle a emporté le seul signal qui
explique un `warn` à 0,00 % d'écart.

**Ajouter deux clés, et rien d'autre :**

```json
{
  "page": "Page d'accueil",
  "url": "https://exemple.fr/",
  "viewport": "mobile",
  "status": "warn",
  "diff_percent": 0.0,
  "label": "À vérifier",
  "cause": "seo",
  "seo_changes": [
    { "field": "title",
      "before": "GEIQ Pays de la Loire — alternance",
      "after":  "GEIQ Pays de la Loire" }
  ]
}
```

- `cause` : `"pixel"` | `"seo"` | `"pixel+seo"` | `"a11y"`. C'est ce qui manque
  le plus : il répond à « pourquoi cette ligne est-elle orange ? » sans imposer
  de lire le reste.
- `seo_changes` : uniquement les champs ayant changé, avec `before`/`after`
  **déjà tronqués à 90 caractères** en amont (`snapshotSemanticDiff.ts` le fait).
  Absent quand rien n'a changé — pas de tableau vide.

## Garde-fous

1. **Rétrocompatibilité stricte.** Les six clés actuelles gardent leur nom, leur
   type et leur sémantique. Des intégrations existantes lisent `diff_percent` et
   `status` ; elles doivent continuer de fonctionner sans modification.
2. **Aucune donnée nouvelle collectée.** Tout ce qui est demandé existe déjà en
   base (`Snapshot.domMeta.seo`) et transite déjà par `changeSummary`. Il ne
   s'agit que d'arrêter de le jeter au dernier maillon.
3. **Pas d'URL d'image, pas d'interne de run.** L'intention du commentaire
   d'origine reste valable : on ajoute une explication, pas le diff brut.
4. **Plafond.** Sept champs au maximum par item, par construction. Inutile de
   borner davantage.
5. **`is_baseline`.** Une baseline n'a rien à comparer : `cause` et
   `seo_changes` doivent être absents, pas vides.

## Comment vérifier

- Un run où **seul** le `title` change doit produire `status: "warn"`,
  `diff_percent: 0`, `cause: "seo"`, et un `seo_changes` d'un élément.
- Un run où **seuls** les pixels bougent doit produire `cause: "pixel"` et
  **aucune** clé `seo_changes`.
- Une baseline doit produire ni l'une ni l'autre.
- `wp vizproof report --format=json` doit rester lisible par un consommateur
  qui ignore les deux nouvelles clés.

## Pourquoi ça compte, côté dashboard de parc

Le dashboard WordPress (`~/Dev/wp-dashboard`) affiche ce rapport dans l'onglet
VizProof de chaque site, après chaque mise à jour sous contrôle visuel. Il
montre aujourd'hui « à vérifier · 0,08 % » sans pouvoir dire si la balise title
a sauté. Dès que `cause` et `seo_changes` existent, il affichera
« title : *ancien* → *nouveau* » sur la ligne concernée — c'est une trentaine
de lignes de son côté, et rien à collecter de plus.

## Hors périmètre (constaté, pas demandé)

Ces signaux sont **capturés à chaque snapshot et stockés**, mais jamais
comparés ni affichés. À traiter séparément, si un jour :

- `advancedSeo` — images sans `alt`, `hreflang`, nombre de JSON-LD, liens
  internes/externes, `lang`, viewport ;
- `labMetrics` — LCP, CLS, INP, TTFB ;
- `lighthouseLike` — scores heuristiques maison (ce n'est pas Lighthouse) ;
- `runtimeIssues` — erreurs console, 4xx/5xx pendant le rendu.

Et ce qui n'est capturé nulle part : le texte de la page, les H2–H6 (seul le
*nombre* de H1 est vu), le texte des `alt`, le contenu des données structurées,
les liens cassés.
