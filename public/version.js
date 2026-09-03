/* Version du front, posée par tools/deploy.sh. Elle sert de suffixe `?v=`
   à la table d'imports et aux feuilles de style : nginx peut alors mettre
   en cache css/, lib/, components/, screens/ pendant un an, index.html
   restant en no-store. */
export const V = "2026-09-03-1838";
