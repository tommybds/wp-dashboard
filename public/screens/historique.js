/* Écran Changements — tendance du parc (courbes) et journal des changements
   d'état détectés à chaque collecte. Repris tel quel ; la phase 3 fusionnera
   les deux dans une chronologie filtrable. */

import { api } from '../lib/api.js';
import { esc as H } from '../lib/dom.js';
import { relTime, absTime, debounce } from '../lib/format.js';
import { cacheFrais, cacheVider } from '../lib/state.js';

/* ---- onglet Historique : tendance du parc ---- */
/* Courbe SVG simple : pas de bibliothèque, les données tiennent en 60 points. */
/* Courbe SVG : pas de bibliotheque, 60 points suffisent.
   `vector-effect:non-scaling-stroke` est indispensable — sans lui le trait
   s'ecrase quand le SVG est etire en largeur (preserveAspectRatio="none").
   Le point final n'est PAS un <circle> : l'etirement le deformerait en
   ellipse, car vector-effect ne corrige que l'epaisseur du trait, pas la
   geometrie. C'est donc un segment de longueur nulle a bout rond, qui reste
   parfaitement circulaire quelle que soit la largeur. */
/* Courbe SVG : pas de bibliotheque, 60 points suffisent.
   Deux contraintes liees a `preserveAspectRatio="none"` (etirement en largeur) :
   - le trait s'ecraserait sans `vector-effect="non-scaling-stroke"` ;
   - toute FORME ou TEXTE place dans le SVG serait deforme. Le point final est
     donc un segment a bout rond, et les ordonnees sont en HTML a cote. */
function sparkline(points, couleur, h=90){
  if(points.length<2) return '<div class="muted small">pas assez de relevés</div>';
  const w=400, pad=6;
  const mn=Math.min(...points), mx=Math.max(...points), amp=(mx-mn)||1;
  const x=i=>pad+i*(w-2*pad)/(points.length-1);
  const y=v=>h-pad-((v-mn)/amp)*(h-2*pad);
  const d=points.map((v,i)=>`${i?'L':'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
  const aire=`${d}L${x(points.length-1).toFixed(1)},${h-pad}L${x(0).toFixed(1)},${h-pad}Z`;
  const der=points[points.length-1], mid=(mn+mx)/2;
  const ligne=(v,tirets)=>`<line x1="0" y1="${y(v).toFixed(1)}" x2="${w}" y2="${y(v).toFixed(1)}"
      stroke="var(--line)" stroke-width="1" ${tirets?'stroke-dasharray="3 4"':''}
      vector-effect="non-scaling-stroke"/>`;
  const svg=`<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="spark" role="img"
      aria-label="évolution de ${mn} à ${mx}">
    ${ligne(mn,false)}${ligne(mid,true)}${ligne(mx,true)}
    <path d="${aire}" fill="${couleur}" opacity=".13"/>
    <path d="${d}" fill="none" stroke="${couleur}" stroke-width="2" stroke-linejoin="round"
      stroke-linecap="round" vector-effect="non-scaling-stroke"/>
    <path d="M${x(points.length-1).toFixed(1)},${y(der).toFixed(1)}L${x(points.length-1).toFixed(1)},${y(der).toFixed(1)}"
      stroke="${couleur}" stroke-width="7" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
  </svg>`;
  // Graduations en HTML : alignees sur les lignes de reference grace au meme
  // rembourrage vertical que le SVG (pad), qui est ici a l'echelle 1:1.
  // Ce sont des décomptes : une graduation à « 182,5 extensions » n'a pas de sens.
  const entiers=Number.isInteger(mn)&&Number.isInteger(mx);
  const fmt=v=>entiers?Math.round(v):(Number.isInteger(v)?v:v.toFixed(1));
  const axe=`<div class="yaxis">
    <span>${fmt(mx)}</span><span>${fmt(mid)}</span><span>${fmt(mn)}</span></div>`;
  return `<div class="chartbody">${axe}${svg}</div>`;
}

function deltaPill(cur, ref, inverse){
  if(ref===null||ref===undefined) return '';
  const d=cur-ref;
  if(!d) return '<span class="pill mut">stable</span>';
  // `inverse` : pour une dette, une baisse est une bonne nouvelle.
  const bon=inverse?d<0:d>0;
  return `<span class="pill ${bon?'ok':'warn'}">${d>0?'+':''}${H(d)}</span>`;
}
async function loadHist(force){
  if(cacheFrais('hist',force)) return;
  let hist=[];
  try{ hist=(await api('/api/actions/collect_history')).history||[]; }
  catch(e){ cacheVider('hist'); document.getElementById('hist-charts').innerHTML='historique indisponible'; return; }
  if(!hist.length){ document.getElementById('hist-charts').innerHTML='<span class="muted">aucun relevé.</span>'; return; }
  const der=hist[hist.length-1];
  // référence ≈ 24 h plus tôt : la collecte tourne toutes les 30 min
  const ref=hist[Math.max(0,hist.length-49)];
  // Couleurs prises dans les jetons du thème : les valeurs en dur (#b45309…)
  // étaient réglées pour le thème clair et illisibles en sombre.
  const M=[
    {k:'plugin_updates', lbl:'MAJ extensions', c:'var(--warn)',   inv:true},
    {k:'core_updates',   lbl:'MAJ cœur',       c:'var(--accent)', inv:true},
    {k:'errors',         lbl:'Sites en erreur',c:'var(--err)',    inv:true},
    {k:'sites',          lbl:'Installations',  c:'var(--ok)',     inv:false},
  ];
  document.getElementById('hist-sum').innerHTML=
    `<span class="pill mut">${H(hist.length)} relevés · depuis le ${H((hist[0].ts||'').slice(0,10))}</span>`;
  document.getElementById('hist-tiles').innerHTML=M.map(m=>
    `<div class="dstat"><div class="lbl">${H(m.lbl)}</div>
      <div class="val">${H(der[m.k]??'?')}</div>
      <div class="sub">${deltaPill(der[m.k]??0, ref[m.k], m.inv)} sur 24 h</div></div>`).join('');
  // Grille : sur un large ecran, quatre courbes pleine largeur donnent des
  // rapports hauteur/largeur absurdes. Deux colonnes au-dela de 900 px.
  document.getElementById('hist-charts').innerHTML='<div class="histgrid">'+M.map(m=>{
    const pts=hist.map(x=>x[m.k]??0);
    const mn=Math.min(...pts), mx=Math.max(...pts);
    return `<div class="chart">
      <div class="charttop"><b>${H(m.lbl)}</b>
        <span class="muted small">actuel : <b>${H(pts[pts.length-1])}</b></span></div>
      ${sparkline(pts, m.c)}
      <div class="chartaxis"><span>${H((hist[0].ts||'').slice(5,16))}</span>
        <span>${H((der.ts||'').slice(5,16))}</span></div></div>`;
  }).join('')+'</div>';
  // La section « Changements » vit dans cet onglet depuis qu'elle a quitté
  // Sécurité : son chargement doit suivre, sinon elle reste sur « chargement… ».
  try{ const ch=await api('/api/mgmt/changes?limit=800'); CHANGES=ch.changes||[];
    const su=ch.summary||{}; const sum=document.getElementById('chg-sum');
    if(su.day_total){ sum.innerHTML=`<span class="pill ${su.day_warn?'err':'mut'}">${H(su.day_total)} sur 24 h · ${H(su.day_sites)} site${su.day_sites>1?'s':''}${su.day_warn?` · ${H(su.day_warn)} à surveiller`:''}</span>`; }
    else sum.innerHTML='<span class="pill ok">rien sur 24 h</span>';
    renderChanges();
  }catch(e){ cacheVider('hist'); document.getElementById('chg-body').textContent='erreur de chargement : '+e; }
}

let CHANGES=[];
function renderChanges(){
  const q=(document.getElementById('chg-q').value||'').toLowerCase().trim();
  const warnOnly=document.getElementById('chg-warn').checked;
  const body=document.getElementById('chg-body'), cnt=document.getElementById('chg-count');
  let rows=CHANGES;
  if(warnOnly) rows=rows.filter(c=>c.severity==='warn');
  if(q) rows=rows.filter(c=>(c.domain+' '+c.label+' '+c.detail).toLowerCase().includes(q));
  cnt.textContent=rows.length?`${rows.length} affiché${rows.length>1?'s':''}`:'';
  if(!CHANGES.length){ body.innerHTML='<span class="pill ok">aucun changement enregistré</span> — l\'historique se remplit à chaque collecte (2 collectes minimum pour comparer).'; return; }
  if(!rows.length){ body.innerHTML='<span class="muted">aucun changement ne correspond au filtre.</span>'; return; }
  body.innerHTML=rows.map(c=>{
    const warn=c.severity==='warn';
    return `<div class="logline"><span class="pill ${warn?'err':'mut'}">${H(c.label)}</span> <b>${H(c.domain)}</b> <span class="muted">${H(c.detail)}</span> <span class="muted small fr" title="${H(absTime(c.ts))}">${H(relTime(c.ts))}</span></div>`;
  }).join('');
}

document.getElementById('chg-q').addEventListener('input',debounce(renderChanges,200));
document.getElementById('chg-warn').addEventListener('change',renderChanges);

export { loadHist, renderChanges };

