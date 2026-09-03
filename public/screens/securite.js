/* Écran Sécurité — vulnérabilités connues, erreurs PHP, comptes
   administrateurs, recherche transversale d'extension, PHP obsolète,
   certificats, extensions à risque, intégrité du cœur.
   Repris tel quel : la phase 3 fusionnera ces huit sections en une page. */

import { api } from '../lib/api.js';
import { esc as H, activeAuClavier } from '../lib/dom.js';
import { relTime, absTime, safeUrl, debounce } from '../lib/format.js';
import { icon } from '../lib/icons.js';
import { poll } from '../lib/poll.js';
import { store, allSites, siteByName, kName, cacheFrais, cacheVider } from '../lib/state.js';
import { askConfirm, askInfo } from '../components/confirm.js';
import { setBusy, setIdle } from '../components/button.js';
import { demarrerJob } from '../components/job.js';
import { setCounter } from '../components/shell.js';
import { chip } from '../components/chip.js';

/* ===== SÉCURITÉ ===== */
const RISKY=["wp-file-manager","file-manager-advanced","filester","duplicator","all-in-one-wp-migration","backup-migration","adminer","wp-phpmyadmin-extension","insert-php","php-everywhere","wp-file-upload"];
/* ---- vulnérabilités connues ---- */
let VULNS={sites:[]};
const SEVRANK={critical:4,high:3,medium:2,low:1,'':0};
const SEVLABEL={critical:'critique',high:'élevée',medium:'moyenne',low:'faible','':'non cotée'};
/* Gravité → un des quatre niveaux du langage d'état, rendu par le composant
   chip : même forme et mêmes mots que partout ailleurs. */
function sevPill(s){ const c=s==='critical'||s==='high'?'err':s==='medium'?'warn':'mut';
  return chip(SEVLABEL[s]||s||'?',c); }
/* Regroupement par extension : 222 CVE brutes deviennent ~54 lignes lisibles.
   Une meme extension cumule souvent 20 CVE — les lister une par une noie le
   signal, alors que la decision se prend au niveau de l'extension. */
function grouperParExtension(findings){
  const g=new Map();
  for(const v of findings){
    const cle=v.component+'@'+v.version;
    let e=g.get(cle);
    if(!e){ e={component:v.component,version:v.version,kind:v.kind,
               update_to:v.update_to||'',unfixed:false,worst:'',cves:[],n:0}; g.set(cle,e); }
    e.n++; e.cves.push(v);
    if(v.update_to) e.update_to=v.update_to;
    if(v.unfixed) e.unfixed=true;
    if((SEVRANK[v.severity]||0)>(SEVRANK[e.worst]||0)) e.worst=v.severity;
  }
  return [...g.values()].sort((a,b)=>(SEVRANK[b.worst]||0)-(SEVRANK[a.worst]||0)||b.n-a.n);
}
let VLNOPEN=new Set(), VEXTOPEN=new Set();

/* Vue inverse : une extension, tous les sites ou elle est vulnerable.
   `wordpress-seo` est vulnerable sur 5 sites : une seule action groupee les
   couvre tous, la vue par site obligeait a ouvrir les 5 fiches. */
function grouperParParc(sites){
  const g=new Map();
  for(const s of sites){
    for(const v of s.findings){
      let e=g.get(v.component);
      if(!e){ e={component:v.component, kind:v.kind, sites:new Map(), worst:'', n:0}; g.set(v.component,e); }
      e.n++;
      if((SEVRANK[v.severity]||0)>(SEVRANK[e.worst]||0)) e.worst=v.severity;
      let d=e.sites.get(s.domain);
      if(!d){ d={domain:s.domain, server:s.server, via:s.via, version:v.version,
                 update_to:v.update_to||'', n:0, worst:''}; e.sites.set(s.domain,d); }
      d.n++;
      if(v.update_to) d.update_to=v.update_to;
      if((SEVRANK[v.severity]||0)>(SEVRANK[d.worst]||0)) d.worst=v.severity;
    }
  }
  return [...g.values()].map(e=>({...e, sites:[...e.sites.values()]}))
    .sort((a,b)=>b.sites.length-a.sites.length
                 ||(SEVRANK[b.worst]||0)-(SEVRANK[a.worst]||0)||b.n-a.n);
}
function renderVulnsParExtension(sitesFiltres){
  const body=document.getElementById('vln-body'), cnt=document.getElementById('vln-count');
  const grp=grouperParParc(sitesFiltres);
  if(!grp.length){ body.innerHTML='<span class="muted">aucune vulnérabilité ne correspond au filtre.</span>';
    cnt.textContent=''; return; }
  const multi=grp.filter(e=>e.sites.length>1).length;
  cnt.textContent=`${grp.length} extension${grp.length>1?'s':''}`
    +(multi?` · ${multi} sur plusieurs sites`:'');
  body.innerHTML=grp.map(e=>{
    const ouvert=VEXTOPEN.has(e.component);
    const majables=e.sites.filter(d=>d.update_to&&d.via!=='rest');
    const bouton=majables.length
      ? `<button class="btn sm primary vbulk" data-ext="${H(e.component)}"
           title="Lance « MAJ ${H(e.component)} » sur les ${majables.length} site(s) où une mise à jour existe">
           MAJ sur ${majables.length} site${majables.length>1?'s':''}</button>`
      : '<span class="pill mut">aucun correctif</span>';
    const lignes=e.sites.sort((a,b)=>(SEVRANK[b.worst]||0)-(SEVRANK[a.worst]||0)).map(d=>
      `<div class="vrow">${sevPill(d.worst)}<b>${H(d.domain)}</b>
        <span class="muted">${H(d.version)}</span>
        <span class="pill mut">${d.n} faille${d.n>1?'s':''}</span>
        ${d.update_to?`<span class="pill ok">MAJ ${H(d.update_to)}</span>`
                     :'<span class="pill err">aucun correctif</span>'}
        ${d.via==='rest'?'<span class="pill mut" title="site géré sans SSH : action distante indisponible">REST</span>':''}
      </div>`).join('');
    return `<div class="vsite${ouvert?' open':''}" data-vext="${H(e.component)}"
        tabindex="0" role="button" aria-expanded="${ouvert?'true':'false'}">
        <span class="tlchev">${icon('chevron-right',{size:14})}</span><b>${H(e.component)}</b>${sevPill(e.worst)}
        <span class="muted small">${e.sites.length} site${e.sites.length>1?'s':''} · ${e.n} faille${e.n>1?'s':''}</span>
        ${bouton}</div>
      <div class="vlist"${ouvert?'':' hidden'}>${lignes}</div>`;
  }).join('');
  body.querySelectorAll('.vsite').forEach(h=>{
    const bascule=()=>{ const c=h.dataset.vext, liste=h.nextElementSibling;
      if(VEXTOPEN.has(c)) VEXTOPEN.delete(c); else VEXTOPEN.add(c);
      liste.hidden=!VEXTOPEN.has(c); h.classList.toggle('open',VEXTOPEN.has(c));
      h.setAttribute('aria-expanded',VEXTOPEN.has(c)?'true':'false'); };
    h.onclick=ev=>{ if(ev.target.closest('.vbulk')) return;   // le bouton ne doit pas replier
      bascule(); };
    h.onkeydown=ev=>{ if(ev.target!==h) return; activeAuClavier(ev,bascule); };
  });
  body.querySelectorAll('.vbulk').forEach(b=>b.onclick=async ev=>{
    ev.stopPropagation();
    const ext=b.dataset.ext, e=grp.find(x=>x.component===ext);
    const cibles=e.sites.filter(d=>d.update_to&&d.via!=='rest');
    // Le rapport de vulnérabilités nomme les sites par leur clé Kuma (souvent un
    // ALIAS). `find_site()` côté serveur ne connaît que le vhost réel : sans
    // cette résolution, tout site aliasé échouait en « cible invalide ».
    const resolus=cibles.map(d=>{ const s=siteByName(d.domain,d.server);
      return {...d, cible:{server:(s&&s.srv)||d.server, domain:(s&&s.domain)||d.domain},
              alias:!!(s&&s.domain!==d.domain)}; });
    const ok=await askConfirm(
      `Sur <b>${resolus.length} site(s)</b> où une mise à jour existe :<br>`
      +resolus.map(d=>`${H(d.domain)}${d.alias?` <span class="muted small">(vhost ${H(d.cible.domain)})</span>`:''} <span class="muted">${H(d.version)} → ${H(d.update_to)}</span>`).join('<br>')
      +`<br><br>Les extensions <b>gelées</b> sur un site seront ignorées automatiquement.`,
      {titre:`Mettre à jour « ${ext} »`,ok:'Mettre à jour'});
    if(!ok) return;
    // Le cœur ne se met pas à jour avec `plugin_update` : action distincte, sans argument.
    const tasks=resolus.map(d=>e.kind==='core'
      ? {server:d.cible.server,domain:d.cible.domain,action:'core_update',arg:null}
      : {server:d.cible.server,domain:d.cible.domain,action:'plugin_update',arg:ext});
    let r; try{ r=await api('/api/actions/bulk',{tasks,mode:'continue',backup_first:true,viz_verify:false}); }
    catch(err){ r={error:String(err)}; }
    if(r&&r.job) demarrerJob(r.job,`Mise à jour de ${ext}`,
      resolus.length+' site'+(resolus.length>1?'s':''));
    else askInfo('Mise à jour groupée impossible',(r&&r.error)?H(r.error):'Le serveur n\'a pas renvoyé de tâche.');
  });
}
function renderVulns(){
  const q=(document.getElementById('vln-q').value||'').toLowerCase().trim();
  const minSev=SEVRANK[document.getElementById('vln-sev').value]||0;
  const fixOnly=document.getElementById('vln-fix').checked;
  const body=document.getElementById('vln-body'), cnt=document.getElementById('vln-count');
  if(VULNS.running){ body.innerHTML='<span class="pill mut">analyse en cours…</span> '+H(VULNS.run_message||''); return; }
  if(!(VULNS.sites||[]).length){
    body.innerHTML=VULNS.sites_scanned
      ? '<span class="pill ok">aucune vulnérabilité connue sur le parc</span>'
      : 'Analyse jamais lancée — cliquez sur « Relancer l\'analyse ».';
    cnt.textContent=''; return; }
  // Filtrage commun aux deux vues, pour qu'elles restent coherentes.
  const filtres=(VULNS.sites||[]).map(s=>{
    let f=s.findings.filter(v=>SEVRANK[v.severity]>=minSev);
    if(fixOnly) f=f.filter(v=>v.update_to);
    if(q) f=f.filter(v=>(s.domain+' '+v.component+' '+(v.cve||'')+' '+v.title).toLowerCase().includes(q));
    return {...s, findings:f};
  }).filter(s=>s.findings.length);
  if(document.getElementById('vln-vue').value==='ext'){
    renderVulnsParExtension(filtres);
    renderVulnsPhp();
    return;
  }
  let nSites=0, nGrp=0;
  const html=VULNS.sites.map(s=>{
    let f=s.findings.filter(v=>SEVRANK[v.severity]>=minSev);
    if(fixOnly) f=f.filter(v=>v.update_to);
    if(q) f=f.filter(v=>(s.domain+' '+v.component+' '+(v.cve||'')+' '+v.title).toLowerCase().includes(q));
    if(!f.length) return '';
    nSites++;
    const grp=grouperParExtension(f);
    nGrp+=grp.length;
    const corrigeables=grp.filter(e=>e.update_to).length;
    const ouvert=VLNOPEN.has(s.domain)||!!q;
    const entete=`<div class="vsite${ouvert?' open':''}" data-vsite="${H(s.domain)}"
      tabindex="0" role="button" aria-expanded="${ouvert?'true':'false'}">
      <span class="tlchev">${icon('chevron-right',{size:14})}</span><b>${H(s.domain)}</b>
      ${sevPill(s.worst)}
      <span class="muted small">${grp.length} extension${grp.length>1?'s':''} · ${f.length} faille${f.length>1?'s':''}</span>
      ${corrigeables?`<span class="pill ok">${corrigeables} corrigeable${corrigeables>1?'s':''}</span>`
                    :'<span class="pill mut">aucun correctif</span>'}</div>`;
    const rangs=grp.map(e=>{
      const fix=e.update_to?`<span class="pill ok">MAJ ${H(e.update_to)}</span>`
        :'<span class="pill err">aucun correctif</span>';
      // Cinq references suffisent a enqueter ; au-dela la liste noie la ligne,
      // alors que la decision se prend sur le nombre et l'existence d'un correctif.
      const refs=e.cves.filter(c=>c.cve);
      // safeUrl : `link` vient du flux public de vulnérabilités, pas de nous.
      const cves=refs.slice(0,5)
        .map(c=>{ const u=safeUrl(c.link);
          return u?`<a href="${H(u)}" target="_blank" rel="noopener noreferrer">${H(c.cve)}</a>`
                  :`<span class="muted">${H(c.cve)}</span>`; }).join(' ')
        +(refs.length>5?` <span class="muted">+${refs.length-5}</span>`:'');
      return `<div class="vrow">${sevPill(e.worst)}
        <b>${H(e.component)}</b> <span class="muted">${H(e.version)}</span>
        <span class="pill mut">${e.n} faille${e.n>1?'s':''}</span> ${fix}
        ${refs.length?`<div class="muted small vcves">${cves}</div>`:''}</div>`;
    }).join('');
    return entete+`<div class="vlist"${ouvert?'':' hidden'}>${rangs}</div>`;
  }).join('');
  cnt.textContent=nGrp?`${nSites} site${nSites>1?'s':''} · ${nGrp} extension${nGrp>1?'s':''}`:'';
  body.innerHTML=html||'<span class="muted">aucune vulnérabilité ne correspond au filtre.</span>';
  body.querySelectorAll('.vsite').forEach(h=>{
    const bascule=()=>{ const d=h.dataset.vsite, liste=h.nextElementSibling;
      if(VLNOPEN.has(d)) VLNOPEN.delete(d); else VLNOPEN.add(d);
      liste.hidden=!VLNOPEN.has(d); h.classList.toggle('open',VLNOPEN.has(d));
      h.setAttribute('aria-expanded',VLNOPEN.has(d)?'true':'false'); };
    h.onclick=bascule;
    h.onkeydown=ev=>{ if(ev.target!==h) return; activeAuClavier(ev,bascule); };
  });
  renderVulnsPhp();
}
function renderVulnsPhp(){
  const php=document.getElementById('vln-php');
  if(!php) return;
  php.innerHTML=(VULNS.php||[]).length ? VULNS.php.map(e=>{
    const eol=/^([0-7]\.|8\.0)/.test(e.version);
    return `<div class="vulnrow">${sevPill(e.worst)} <b>PHP ${H(e.version)}</b>
      ${eol?'<span class="pill err">fin de support</span>':''}
      <span class="muted">${H(e.count)} faille${e.count>1?'s':''} connue${e.count>1?'s':''}</span>
      <span class="muted small">— ${e.sites.length} site${e.sites.length>1?'s':''} : ${H(e.sites.slice(0,4).join(', '))}${e.sites.length>4?'…':''}</span></div>`;
  }).join('') : '<span class="muted">aucune version PHP avec faille connue.</span>';
}
async function loadVulns(force){
  if(cacheFrais('vulns',force)) return;
  try{
    VULNS=await api('/api/sec/vulns');
    // Le chiffre utile n'est pas « 222 failles » mais la repartition entre ce
    // qui se corrige d'un clic et ce qui demande une decision.
    let corrigeables=0, sansFix=0;
    (VULNS.sites||[]).forEach(x=>x.findings.forEach(v=>v.update_to?corrigeables++:sansFix++));
    VULNS._fix=corrigeables; VULNS._nofix=sansFix;
    const t=VULNS.totals||{}, sum=document.getElementById('vln-sum');
    if(VULNS.sites_affected){
      const bits=[];
      if(t.critical) bits.push(`${t.critical} critiques`);
      if(t.high) bits.push(`${t.high} élevées`);
      if(t.medium) bits.push(`${t.medium} moyennes`);
      sum.innerHTML=`<span class="pill ${t.critical?'err':t.high?'warn':'mut'}">${VULNS.sites_affected}/${VULNS.sites_scanned} sites — ${bits.join(', ')||'—'}</span>`
        +` <span class="pill ok">${corrigeables} corrigeables par une MAJ</span>`
        +` <span class="pill mut">${sansFix} sans correctif</span>`;
    } else sum.innerHTML=VULNS.sites_scanned?'<span class="pill ok">parc sain</span>':'';
    majCompteurSec();
    renderVulns();
  }catch(e){ cacheVider('vulns'); document.getElementById('vln-body').textContent='erreur de chargement : '+e; }
}
document.getElementById('vln-q').addEventListener('input',debounce(renderVulns,200));
document.getElementById('vln-sev').addEventListener('change',renderVulns);
document.getElementById('vln-fix').addEventListener('change',renderVulns);
document.getElementById('vln-vue').addEventListener('change',renderVulns);
document.getElementById('vln-run').onclick=async(e)=>{
  const b=e.currentTarget; setBusy(b,'analyse…');
  document.getElementById('vln-body').innerHTML='<span class="pill mut">analyse en cours…</span> <span class="muted">~2 min (≈320 extensions à vérifier)</span>';
  const fini=()=>{ setIdle(b,icon('refresh-cw')+" Relancer l'analyse"); };
  let lancement; try{ lancement=await api('/api/sec/vulns/run',{refresh:true}); }catch(err){ lancement={error:String(err)}; }
  if(lancement&&lancement.error&&!lancement.running){
    askInfo('Analyse impossible',H(lancement.error)); fini(); loadVulns(true); return; }
  poll('vulns',async()=>{
    const r=await api('/api/sec/vulns');
    if(r&&!r.running){ loadVulns(true); return {fini:true}; }
    return {fini:false};
  },{every:5000,maxErrors:5,until:r=>!!(r&&r.fini),onStop:fini});
};

/* ---- erreurs PHP ---- */
let PHERR={sites:[]};
const PHRANK={'Fatal error':4,'Parse error':4,'Warning':3,'Deprecated':2,'Notice':1,'Strict Standards':1};
function phePill(sev){ const r=PHRANK[sev]||0;
  return `<span class="pill ${r>=4?'err':r>=3?'warn':'mut'}">${H(sev||'?')}</span>`; }
/* « Aucune erreur » n'a pas le même sens si un journal a été tronqué ou si un
   serveur n'a pas répondu : l'absence de résultat doit alors se dire.
   `truncated` = {serveur: [{file, reason}]} ; `servers_failed` = {serveur: raison}. */
function phePartielle(){
  const tr=(PHERR.truncated&&typeof PHERR.truncated==='object')?PHERR.truncated:{};
  const ko=(PHERR.servers_failed&&typeof PHERR.servers_failed==='object')?PHERR.servers_failed:{};
  const srvTr=Object.keys(tr).filter(k=>Array.isArray(tr[k])&&tr[k].length);
  const srvKo=Object.keys(ko).filter(k=>ko[k]!==null&&ko[k]!==undefined&&ko[k]!=='');
  const nTr=srvTr.reduce((a,k)=>a+tr[k].length,0);
  if(!nTr&&!srvKo.length) return '';
  const bouts=[];
  if(nTr) bouts.push(`${nTr} ${nTr>1?'journaux':'journal'} tronqué${nTr>1?'s':''}`);
  if(srvKo.length) bouts.push(`${srvKo.length} serveur${srvKo.length>1?'s':''} en échec`);
  let li='';
  srvKo.forEach(k=>{ li+=`<li><b>${H(k)}</b> — serveur non lu : ${H(String(ko[k]))}</li>`; });
  srvTr.forEach(k=>tr[k].forEach(x=>{
    li+=`<li><b>${H(k)}</b> — <code>${H((x&&x.file)||'journal')}</code> : ${H((x&&x.reason)||'tronqué')}</li>`; }));
  return `<div class="warnbox small mt2">${icon('triangle-alert')} <b>Analyse partielle</b> — ${H(bouts.join(', '))}.
    Des erreurs peuvent manquer dans la liste ci-dessous.<ul>${li}</ul></div>`;
}
function renderPhe(){
  const q=(document.getElementById('phe-q').value||'').toLowerCase().trim();
  const minR=parseInt(document.getElementById('phe-sev').value||'0',10);
  const body=document.getElementById('phe-body'), cnt=document.getElementById('phe-count');
  if(PHERR.running){ body.innerHTML='<span class="pill mut">analyse en cours…</span> '+H(PHERR.run_message||''); return; }
  const partielle=phePartielle();
  if(!(PHERR.sites||[]).length){
    body.innerHTML=(PHERR.generated_at?'<span class="pill ok">aucune erreur PHP sur la fenêtre</span>':'Analyse jamais lancée — cliquez sur « Relancer l\'analyse ».')+partielle;
    cnt.textContent=''; return; }
  let n=0;
  const html=PHERR.sites.map(s=>{
    let g=(s.groups||[]).filter(x=>(PHRANK[x.severity]||0)>=minR);
    if(q) g=g.filter(x=>(s.domain+' '+x.message+' '+(x.short||x.file||'')).toLowerCase().includes(q));
    if(!g.length) return ''; n+=g.length;
    return `<div class="phe-group"><b>${H(s.domain)}</b>
      <span class="muted small">${H(s.total)} occurrence${s.total>1?'s':''}</span>`+
      g.map(x=>`<div class="logline">${phePill(x.severity)}
        <span class="pill mut">×${H(x.count)}</span> ${H(x.message)}
        ${x.short?`<div class="muted small phe-loc"><code>${H(x.short)}:${H(x.line)}</code>
          · dernière ${H(relTime(x.last))}</div>`:''}</div>`).join('')+`</div>`;
  }).join('');
  cnt.textContent=n?`${n} groupe${n>1?'s':''}`:'';
  body.innerHTML=partielle+(html||'<span class="muted">aucune erreur ne correspond au filtre.</span>');
}
async function loadPhe(force){
  if(cacheFrais('phe',force)) return;
  try{
    PHERR=await api('/api/sec/phperrors');
    const sum=document.getElementById('phe-sum');
    if(PHERR.sites_with_errors) sum.innerHTML=`<span class="pill ${PHERR.fatals?'err':'warn'}">${PHERR.sites_with_errors} site(s) · ${PHERR.total} occurrence(s)${PHERR.fatals?` · ${PHERR.fatals} fatale(s)`:''}</span>`;
    else sum.innerHTML=PHERR.generated_at?'<span class="pill ok">aucune erreur</span>':'';
    renderPhe();
  }catch(e){ cacheVider('phe'); document.getElementById('phe-body').textContent='erreur de chargement : '+e; }
}
document.getElementById('phe-q').addEventListener('input',debounce(renderPhe,200));
document.getElementById('phe-sev').addEventListener('change',renderPhe);
document.getElementById('phe-run').onclick=async(e)=>{
  const b=e.currentTarget, h=document.getElementById('phe-h').value;
  setBusy(b,'analyse…');
  document.getElementById('phe-body').innerHTML='<span class="pill mut">lecture des journaux…</span>';
  const fini=()=>{ setIdle(b,icon('refresh-cw')+" Relancer l'analyse"); };
  let lancement; try{ lancement=await api('/api/sec/phperrors/run',{hours:parseInt(h,10)}); }catch(err){ lancement={error:String(err)}; }
  if(lancement&&lancement.error&&!lancement.running){
    askInfo('Analyse impossible',H(lancement.error)); fini(); loadPhe(true); return; }
  poll('phe',async()=>{
    const r=await api('/api/sec/phperrors');
    if(r&&!r.running){ loadPhe(true); return {fini:true}; }
    return {fini:false};
  },{every:3000,maxErrors:5,until:r=>!!(r&&r.fini),onStop:fini});
};


async function loadSec(force){
  if(cacheFrais('sec',force)) return;
  const S=allSites();
  loadVulns(force);   // indépendant : ne bloque pas le reste du volet
  loadPhe(force);
  // La référence des admins n'est qu'une des huit sections : son échec ne doit
  // pas emporter les certificats, les plugins à risque et les checksums.
  let blErr='';
  try{ const bl=await api('/api/sec/baseline'); store.baseline=(bl&&bl.baseline)||{}; }
  catch(e){ store.baseline={}; blErr=String(e); cacheVider('sec'); }
  document.getElementById('admin-tb').innerHTML=(blErr
    ? `<tr><td colspan="3"><span class="pill err">référence indisponible</span> <span class="muted small">${H(blErr)}</span></td></tr>`
    : '')+S.filter(s=>s.admins!==null).map(s=>{ const base=store.baseline[s.domain]?.logins;
    const cells=(s.admins||[]).map(a=>{ const isNew=base&&!base.includes(a.login); return `<span class="tag ${isNew?'new-admin':''}" title="${H(a.email||'')} · inscrit ${H(a.registered||'')}">${isNew?icon('triangle-alert')+' ':''}${H(a.login)}</span>`; }).join(' ');
    return `<tr><td><b>${H(kName(s)||s.domain)}</b></td><td>${cells||'<span class="muted">—</span>'}${base?'':' <span class="muted small">(pas de référence)</span>'}</td><td><button class="btn sm" data-bl="${H(s.domain)}">Marquer comme vu</button></td></tr>`; }).join('');
  document.querySelectorAll('[data-bl]').forEach(b=>b.onclick=async()=>{ b.textContent='…'; await api('/api/sec/baseline',{domain:b.dataset.bl}); loadSec(true); });
  // PHP obsolète
  const old=S.filter(s=>s.php_version&&parseFloat(s.php_version)<8.1).sort((a,b)=>parseFloat(a.php_version)-parseFloat(b.php_version));
  document.getElementById('php-body').innerHTML=old.length?old.map(s=>`<span class="tag"><span class="pill ${parseFloat(s.php_version)<7.4?'err':'warn'}">${H(s.php_version)}</span> ${H(kName(s)||s.domain)}</span>`).join(' '):'<span class="pill ok">tout le parc en PHP ≥ 8.1</span>';
  // certificats SSL
  const ctb=document.getElementById('cert-tb'), cmsg=document.getElementById('cert-msg');
  try{ const c=await api('/api/sec/certs'); const certs=c.certs||[];
    ctb.innerHTML=certs.map(x=>{ const d=x.days, cc=d==null?'mut':d<7?'err':d<21?'warn':'ok';
      return `<tr><td><b>${H(x.monitor)}</b></td><td><span class="pill ${cc}">${d==null?'?':H(d)+' j'}</span></td><td class="sub">${H(x.valid_to||'')}</td></tr>`; }).join('');
    cmsg.textContent=certs.length?'':(c.error||'aucun certificat remonté.');
  }catch(e){ ctb.innerHTML=''; cmsg.textContent='erreur de chargement : '+e; }
  // plugins à risque
  const rhits=[]; S.forEach(s=>(s.plugins_list||[]).forEach(p=>{ if(RISKY.includes((p.name||'').toLowerCase())) rhits.push({s,p}); }));
  document.getElementById('risky-body').innerHTML=rhits.length?rhits.map(({s,p})=>
    `<div class="logline"><span class="pill ${p.status==='active'?'err':'warn'}">${H(p.status||'inactif')}</span> <b>${H(kName(s)||s.domain)}</b> <span class="muted">·</span> ${H(p.name)} <span class="muted small">${H(p.version||'')}</span></div>`).join('')
    :'<span class="pill ok">aucun plugin à risque détecté</span>';
  // checksums — derniers résultats connus + bouton unitaire
  let CKS={}; try{ const c=await api('/api/sec/checksums');
    // La route renvoie {"checksums": {...}} ; on accepte aussi la forme à plat.
    if(c&&typeof c==='object'&&!c.error) CKS=(c.checksums&&typeof c.checksums==='object')?c.checksums:c; }catch(e){ CKS={}; }
  document.getElementById('verify-tb').innerHTML=S.filter(s=>s.core_version).map(s=>{
    const ck=CKS[s.domain]; const last=(ck&&typeof ck==='object')
      ? `<span class="pill ${ck.ok?'ok':'err'}" title="${H(String(ck.output_tail??'').slice(-400))}">${ck.ok?'intègre':'anomalie'}</span> <span class="muted small" title="${H(absTime(ck.ts))}">${H(relTime(ck.ts))}</span>`
      : '<span class="muted small">jamais vérifié</span>';
    return `<tr><td><b>${H(kName(s)||s.domain)}</b> <span class="muted small">${H(s.core_version)}</span></td>
      <td><button class="btn sm" data-verify="${H(s.srv)}|${H(s.domain)}">Vérifier</button> <span data-vres="${H(s.domain)}">${last}</span></td></tr>`; }).join('');
  document.querySelectorAll('[data-verify]').forEach(b=>b.onclick=async()=>{ const [srv,dom]=b.dataset.verify.split('|'); setBusy(b);
    let j; try{ j=await api('/api/sec/verify',{server:srv,domain:dom}); }catch(e){ j={ok:false,output:String(e)}; }
    setIdle(b,'Vérifier');
    const cell=document.querySelector(`[data-vres="${CSS.escape(dom)}"]`); if(!cell) return;
    cell.innerHTML=(j&&j.ok)?'<span class="pill ok">intègre</span>':`<span class="pill err">anomalie</span> <span class="muted small">${H(((j&&(j.output||j.error))||'').slice(-120))}</span>`; }); }

document.getElementById('baseline-all').onclick=async()=>{
  if(!await askConfirm('Figer la liste actuelle des administrateurs de <b>tous les sites</b> comme référence ?<br><br>Tout compte ajouté ensuite sera signalé en rouge.',
      {titre:'Tout marquer comme vu',ok:'Marquer comme vu'})) return;
  await api('/api/sec/baseline',{}).catch(()=>{}); loadSec(true); };
document.getElementById('verify-all').onclick=async()=>{ const btn=document.getElementById('verify-all'), msg=document.getElementById('verify-msg');
  if(!await askConfirm('Lancer <code>wp core verify-checksums</code> sur tout le parc ?<br><br>L\'opération passe sur chaque site et peut durer plusieurs minutes.',
      {titre:'Intégrité du cœur',ok:'Lancer'})) return;
  btn.disabled=true; msg.innerHTML='<span class="muted">lancement…</span>';
  try{ const j=await api('/api/sec/checksums/run',{})||{};
    if(!j.job){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted">${H(j.error||'aucun job renvoyé')}</span>`; btn.disabled=false; return; }
    msg.innerHTML=''; demarrerJob(j.job,'Vérification des checksums','tout le parc');
  }catch(e){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted">${H(String(e))}</span>`; }
  btn.disabled=false; };
document.getElementById('plug-q').oninput=debounce(e=>{ const q=e.target.value.toLowerCase().trim(); const tb=document.getElementById('plug-tb'), res=document.getElementById('plug-res');
  if(!q){ tb.innerHTML=''; res.textContent=''; return; } const hits=[];
  allSites().forEach(s=>(s.plugins_list||[]).forEach(p=>{ if((p.name||'').toLowerCase().includes(q)) hits.push({s,p}); }));
  res.textContent=`${hits.length} occurrence(s) sur ${new Set(hits.map(h=>h.s.domain)).size} site(s)`;
  tb.innerHTML=hits.map(({s,p})=>`<tr><td><b>${H(kName(s)||s.domain)}</b></td><td>${H(p.name)}</td><td>${H(p.version||'')}</td><td><span class="pill ${p.status==='active'?'ok':'mut'}">${H(p.status||'')}</span></td></tr>`).join(''); },200);

/* Compteur « vulnérabilités élevées » de la barre latérale : élevées et
   critiques, c'est-à-dire ce qui demande une décision aujourd'hui. */
export function majCompteurSec(){
  const t=(VULNS&&VULNS.totals)||{};
  setCounter('securite',(t.critical||0)+(t.high||0),'warn');
}

export { loadSec, loadVulns, loadPhe, sevPill, SEVLABEL, SEVRANK, grouperParExtension };

