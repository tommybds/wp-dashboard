/* Écran Incidents — construit en phase 3.

   La destination existe dès la phase 1 pour que la barre latérale soit
   complète et que son compteur (sites injoignables) soit déjà juste ; l'écran
   lui-même dira ce qu'il agrégera : sites down (Kuma), erreurs PHP fatales,
   serveurs injoignables, checksums modifiés, certificats à moins de 21 jours.

   Rien n'est chargé ici : aucune requête tant que l'écran n'existe pas. */

import { h, mount } from '../lib/dom.js';
import { iconEl } from '../lib/icons.js';
import { store, allSites, st } from '../lib/state.js';

export function renderIncidents() {
  const down = store.fleet ? allSites().filter(s => st(s) === 0).length : 0;
  const stale = (store.fleet?.servers || []).filter(x => x && x.stale).length;
  mount('page-incidents',
    h('div', { class: 'empty' },
      iconEl('construction', { size: 20 }),
      h('h2', { text: 'Incidents — en construction' }),
      h('p', {
        text: "Cet écran regroupera ce qui est cassé maintenant : sites injoignables, "
          + "erreurs PHP fatales, serveurs muets, intégrité du cœur en anomalie et "
          + "certificats proches de l'expiration. Il arrive en phase 3.",
      }),
      h('p', { class: 'muted small' },
        `En attendant : ${down} site${down > 1 ? 's' : ''} injoignable${down > 1 ? 's' : ''}`,
        ` · ${stale} serveur${stale > 1 ? 's' : ''} muet${stale > 1 ? 's' : ''}`,
        ' — le détail est dans Parc (filtre « down ») et dans Sécurité.'),
    ));
}
