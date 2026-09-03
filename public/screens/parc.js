/* Écran Parc — le tableau de bord et le tiroir de fiche, repris tels quels de
   la version d'avant la refonte : mêmes requêtes, mêmes actions, mêmes gardes.
   Seuls changent l'habillage (jetons, icônes) et la provenance de l'état
   partagé (store au lieu de variables globales).

   La phase 2 remplacera le tiroir par une vraie page site (#site/<domaine>) ;
   jusque-là, ne rien réordonner ici. */

import { api } from '../lib/api.js';
import { esc as H, activeAuClavier } from '../lib/dom.js';
import { relTime, absTime, safeUrl, debounce, stripPhpNoise,
         udIntervalFr, udHorizon, udRulesFr, tsMs } from '../lib/format.js';
import { icon } from '../lib/icons.js';
import { poll, stopPoll } from '../lib/poll.js';
import { store, allSites, st, bkAge, attn, key, kName, loadFleet } from '../lib/state.js';
import { NOTIF } from '../components/toast.js';
import { askConfirm, askInfo, askText, askChoice, askOpen,
         registerModalCloser, registerDrawerCloser } from '../components/confirm.js';
import { demarrerJob } from '../components/job.js';
import { fermerTips } from '../components/tip.js';
import { bindSortable, setDensity } from '../components/table.js';
import { chip } from '../components/chip.js';
import { setBusy, setIdle } from '../components/button.js';
import { updMeta } from '../components/shell.js';
import { sevPill, SEVLABEL } from './securite.js';
import { loadWpCred } from './gestion.js';
import { ensureSettings } from './reglages.js';

/* Libellé et pictogramme d'une action unitaire, pour la barre de notifications. */
const ACT_LIB={core_update:'MAJ cœur',plugins_update_all:'MAJ extensions',
  plugins_update_except:'MAJ extensions',plugin_update:'MAJ',themes_update_all:'MAJ thèmes',
  updraft_backup:'Sauvegarde UpdraftPlus',cache_flush:'Vidage des caches',
  autoupdate_on:'Activation des auto-MAJ',autoupdate_off:'Désactivation des auto-MAJ',
  verify_checksums:'Intégrité du cœur',vizproof_install:'Installation VizProof',
  viz_baseline:'Baseline visuelle',viz_scan:'Scan visuel',viz_disconnect:'Dissociation VizProof',
  rescan:'Re-scan'};
const ACT_KIND={core_update:'maj',plugins_update_all:'maj',plugins_update_except:'maj',
  plugin_update:'maj',themes_update_all:'maj',updraft_backup:'backup',cache_flush:'cache',
  verify_checksums:'check',vizproof_install:'install',viz_baseline:'viz',viz_scan:'viz',
  viz_disconnect:'connect',rescan:'rescan'};
function actLib(act,arg){ return (ACT_LIB[act]||act)+(arg?' '+arg:''); }
function notifLabel(act,arg,s){ return actLib(act,arg)+' · '+((s&&(kName(s)||s.domain))||''); }


/* Serveur injoignable à la dernière collecte : les données du site sont celles
   de la collecte précédente. Une pastille sur la ligne, le détail dans la bulle. */
function staleBadge(s){ if(!s||!s._stale) return '';
  const tip='données du '+(s._srvAt||'dernière collecte réussie')+', serveur '+(s.srv||'')+' injoignable'
    +(s._srvErr?' : '+s._srvErr:'');
  return ' '+chip('ancien','warn',{tip}); }
/* colonne Serveur : les sites sans SSH sont inventoriés par l'agent via REST */
function srvCell(s){ return s.via==='rest'
  ? `<span class="pill mut" title="inventaire via l'agent, sans SSH${s.srv?' · '+H(s.srv):''}">REST</span>`
  : `<span class="pill mut">${H(s.srv)}</span>`; }

/* vizproof-timeline */
const VIZ='vizproof-timeline';
function vizOf(s){ return (s.plugins_list||[]).find(p=>p.name===VIZ)||null; }
function vizInfo(s){ const v=s&&s.vizproof; return (v&&typeof v==='object')?v:null; }
function vizConnected(s){ const v=vizInfo(s); return !!(v&&v.connected); }
function vizRun(s){ const v=vizInfo(s); const r=v&&v.last_run; return (r&&typeof r==='object')?r:null; }
function vizAnom(s){ const r=vizRun(s); if(!r) return false;
  return (Number(r.anomalies)>0)||/anomal/i.test(String(r.status??'')); }
/* `configured` est arrivé avec la 1.3.6 côté plugin ; sur un inventaire plus
   ancien, la connexion établie est la seule preuve disponible. */
function vizConfigured(s){ const v=vizInfo(s); if(!v) return false;
  return v.configured===undefined?!!v.connected:!!v.configured; }
/* La CLI `wp vizproof` n'existe qu'à partir de la 1.3 : en dessous, le plugin
   est bien là mais le dashboard ne peut rien en faire tant qu'il n'est pas à jour. */
function vizVerOld(ver){ const m=/^(\d+)\.(\d+)/.exec(String(ver||'')); if(!m) return true;
  const M=+m[1], n=+m[2]; return M<1||(M===1&&n<3); }
/* État d'un site vis-à-vis de VizProof, en un seul mot. Toute la colonne et le
   tiroir en découlent — un seul endroit à corriger si la règle change.
   'nodata' inventaire absent · 'absent' pas installé · 'inactif' plugin désactivé
   · 'nocli' installé mais trop ancien pour la CLI · 'nonconnecte' CLI présente,
   site pas relié · 'connecte' relié et sonde OK. */
function vizState(s){ const list=s.plugins_list||[], p=vizOf(s), v=vizInfo(s);
  if(!p&&!v) return list.length?'absent':'nodata';
  if(p&&p.status&&p.status!=='active') return 'inactif';
  // Aucun JSON de statut = aucune CLI exploitable (extension d'avant la 1.3, ou
  // commande absente). Dans les deux cas la réponse est « mettre à jour », pas
  // « installer » : c'est ce que l'ancienne colonne ne savait pas dire.
  const ver=(v&&v.version)||(p&&p.version)||'';
  if(!v||v.has_cli===false||(ver&&vizVerOld(ver))) return 'nocli';
  return (vizConfigured(s)&&v.connected)?'connecte':'nonconnecte'; }
function vizVersion(s){ const v=vizInfo(s), p=vizOf(s); return (v&&v.version)||(p&&p.version)||'?'; }
/* Le site est-il connectable depuis ici ? Il faut du SSH : l'agent REST est en lecture seule. */
function vizConnectable(s){ return s.via!=='rest'&&['nonconnecte','connecte'].includes(vizState(s)); }
function vizAdminUrl(s){ return safeUrl((s.siteurl||('https://'+s.domain)).replace(/\/+$/,'')
  +'/wp-admin/admin.php?page=vizproof-timeline'); }
/* tri : anomalies(-1) < absent(0) < inactif(.5) < sans CLI(.8) < non connecté(1)
   < connecté sans run(2) < connecté OK(3) < sans données(4) */
function vizVal(s){ const e=vizState(s);
  if(e==='nodata') return 4;
  if(e==='absent') return 0;
  if(e==='inactif') return .5;
  if(e==='nocli') return .8;
  if(e==='nonconnecte') return 1;
  if(vizAnom(s)) return -1;
  return vizRun(s)?3:2; }
/* Pastille du dernier scan, commune à la colonne et au tiroir. */
function vizRunBadge(s){ const r=vizRun(s); if(!r) return '';
  const bad=vizAnom(s), an=Number(r.anomalies)||0;
  const ttl=H('dernier scan : '+(r.at?absTime(r.at):'?')+' · '+(bad?((an||'?')+' anomalie(s) visuelle(s)'):'aucune anomalie'));
  const body=bad?`<span class="pill err">${icon('triangle-alert')} ${H(an||'anomalies')}</span>`:'<span class="dot up"></span>';
  const u=safeUrl(r.url);
  return ' '+(u?`<a class="vizrun" data-vizrun href="${H(u)}" target="_blank" rel="noopener noreferrer" title="${ttl}">${body}</a>`
               :`<span class="vizrun" title="${ttl}">${body}</span>`); }
function vizAdminLink(s,txt){ const u=vizAdminUrl(s); if(!u) return '';
  return ` <a class="small" data-vizrun href="${H(u)}" target="_blank" rel="noopener noreferrer">${H(txt||'ouvrir dans wp-admin')}</a>`; }
function vizCell(s){ const e=vizState(s), ver=H(vizVersion(s));
  if(e==='nodata') return '—';
  if(e==='absent') return `<button class="btn sm" data-vizinstall>${icon('plus')} installer</button>`;
  if(e==='inactif') return `<span class="pill mut" title="extension présente mais désactivée">v${ver} · inactif</span>`;
  if(e==='nocli') return `<span class="pill warn" title="cette version n'expose pas la commande wp vizproof — mettez l'extension à jour (bouton MAJ)">v${ver} · à mettre à jour</span>`;
  if(e==='nonconnecte') return `<span class="pill warn" title="extension installée mais pas encore reliée à VizProof">v${ver} · non connecté</span>`
    +(s.via==='rest'?'':' <button class="btn sm" data-vizconnect>Connecter</button>')
    +vizAdminLink(s);
  const n=Number((vizInfo(s)||{}).pages)||0;
  return `<span class="pill ok">v${ver} · ${n} page${n>1?'s':''}</span>`+vizRunBadge(s); }
/* Bloc VizProof du tiroir : le MÊME état que la colonne, dit en une phrase.
   Deux endroits qui déduisent l'état séparément finissent par se contredire :
   ils partagent donc vizState(). */
function vizDrawerBlock(s){ const e=vizState(s); if(e==='nodata') return '';
  const ver=H(vizVersion(s)), rest=s.via==='rest', n=Number((vizInfo(s)||{}).pages)||0;
  const sid=(vizInfo(s)||{}).site_id;
  let txt='', btns='';
  if(e==='absent'){ txt='Extension non installée sur ce site.';
    // Sans SSH, l'installation passe par l'autorisation WordPress : le bouton
    // est posé par wpCredActions() une fois les identifiants connus, pas ici.
    if(!rest) btns='<button class="btn sm" data-act="vizproof_install">Installer vizproof</button>'; }
  else if(e==='inactif'){ txt=`Extension présente en v${ver} mais <b>désactivée</b> — à activer depuis wp-admin.`; }
  else if(e==='nocli'){ txt=`Extension en v${ver} : cette version n'expose pas la commande <code>wp vizproof</code>.
    Mettez-la à jour (bouton de MAJ de l'extension) pour pouvoir la connecter d'ici.`; }
  else if(e==='nonconnecte'){ txt=`Extension en v${ver} installée, mais <b>pas encore reliée</b> à VizProof.`
      +(rest?' Ce site est géré sans SSH : la connexion se fait depuis wp-admin.':'');
    if(!rest) btns='<button class="btn primary sm" data-vizconnect>Connecter VizProof</button>'; }
  else { txt=`Reliée à VizProof · <b>${n} page${n>1?'s':''}</b> suivie${n>1?'s':''}`
      +(sid?` · identifiant <code>${H(sid)}</code>`:'')+'.';
    if(!rest) btns='<button class="btn sm" data-vizdisconnect>Dissocier</button>'; }
  return `<div class="agroup"><span class="glbl">VizProof</span>
    <p class="hint hint-tight">${txt}${vizAdminLink(s)}${e==='connecte'?vizRunBadge(s):''}</p>
    ${e==='connecte'?vizLastRunLine(s):''}
    ${btns?`<div class="actions">${btns}</div>`:''}</div>`; }
/* Dernier scan, en clair. La pastille seule ne disait ni QUAND ni COMBIEN :
   depuis que chaque mise à jour déclenche un scan, c'est l'information qu'on
   vient chercher dans le tiroir. */
function vizLastRunLine(s){ const r=vizRun(s);
  if(!r) return '<p class="hint hint-tight">Aucun scan visuel enregistré pour l’instant.</p>';
  const bad=vizAnom(s), an=Number(r.anomalies)||0, u=safeUrl(r.url);
  const stt=String(r.status||'').toLowerCase();
  const cls=bad?'warn':(/err|échec|echec|fail/.test(stt)?'err':'ok');
  const quoi=bad?((an||'?')+' anomalie'+(an>1?'s':''))
    :(/err|échec|echec|fail/.test(stt)?(r.status||'échec'):'aucune anomalie');
  return `<p class="hint hint-tight">Dernier scan
    <span title="${H(absTime(r.at))}">${H(relTime(r.at))}</span>
    <span class="pill ${cls}">${H(quoi)}</span>
    ${u?`<a class="small" data-vizrun href="${H(u)}" target="_blank" rel="noopener noreferrer">voir le rapport</a>`:''}</p>`; }
/* ---- contrôle visuel automatique après une MAJ unitaire (réponse `viz`) ----
   Le scan est le plus souvent lancé par le PLUGIN lui-même (il accroche
   `upgrader_process_complete`, y compris sous WP-CLI) : le dashboard attend ce
   verdict-là et ne scanne qu'en repli. D'où `phase` pendant l'attente et
   `source` dans le verdict — dire QUI a scanné évite de croire à un doublon. */
const VIZ_PHASES={'attente du scan du plugin':'le plugin VizProof scanne…',
  'scan en cours':'scan du plugin en cours…',
  'scan dashboard':'scan lancé par le dashboard…'};
function vizSource(v){ return v&&v.source==='plugin'?' (scan du plugin)'
  :v&&v.source==='dashboard'?' (scan dashboard)':''; }
function vizPhrase(v){
  if(!v||typeof v!=='object') return '';
  if(v.pending) return VIZ_PHASES[v.phase]||'contrôle en cours…';
  if(!v.ran) return 'non lancé ('+(v.reason||v.message||'?')+')';
  const n=Number(v.anomalies_count)||0;
  if(v.anomalies) return 'anomalies détectées'+(n?' ('+n+')':'')+vizSource(v);
  if(Number(v.rc)===0) return 'aucune anomalie'+vizSource(v);
  /* rc absent : le scan du plugin n'était pas terminé dans le délai d'attente —
     ni « ok » ni « échec », un verdict qui n'est pas venu. */
  if(v.rc==null) return (v.message||'verdict non parvenu')+vizSource(v);
  return 'échec ('+(v.message||('rc '+(v.rc??'?')))+')'+vizSource(v); }
/* → '' (neutre) | 'ok' | 'warn' | 'err'.
   « Non lancé » est NEUTRE, pas un avertissement : la grande majorité des sites
   n'est pas reliée à VizProof, tout mettre en orange reviendrait à ne plus rien
   signaler du tout. */
function vizEtat(v){
  if(!v) return '';
  if(v.pending) return 'warn';
  if(!v.ran) return '';
  if(v.anomalies||v.rc==null) return 'warn';
  return Number(v.rc)===0?'ok':'err'; }
function vizConsoleLigne(v){
  if(!v) return '';
  const u=safeUrl(v.report_url);
  // La ligne porte un marqueur : le verdict REMPLACE le « scan en cours… »
  // affiché à la réponse, au lieu de s'empiler dessous.
  return `<span data-vizline><b class="${vizEtat(v)}">Contrôle visuel VizProof : ${H(vizPhrase(v))}</b>`
    +(u?` <a href="${H(u)}" target="_blank" rel="noopener noreferrer">rapport</a>`:'')+'</span>'; }
function vizConsoleMaj(dom,v){
  const c=consoleDe(dom); if(!c) return;
  const l=c.querySelector('[data-vizline]');
  if(l) l.outerHTML=vizConsoleLigne(v); else c.innerHTML+='\n'+vizConsoleLigne(v); }
/* Le contrôle se joue côté serveur APRÈS la réponse (cf. README §VizProof) : on
   interroge /api/actions/viz_last jusqu'au verdict. Borné dans le temps —
   un `pending` qui ne retombe jamais ne doit pas sonder à vie. Les `phase`
   successives sont réaffichées au passage : attendre le scan du plugin dure
   jusqu'à 90 s, mieux vaut dire ce qu'on attend. */
function suivreVizLast(srv,dom,nid){
  let tours=0, vue=null;
  poll('vizlast:'+dom,async()=>{
    if(++tours>150) return {fini:true,perdu:true};       // ≈ 10 min
    const j=await api('/api/actions/viz_last?domain='+encodeURIComponent(dom));
    const v=(j&&j.viz)||null;
    if(!v||v.pending){
      if(v&&v.phase&&v.phase!==vue){ vue=v.phase;
        NOTIF.update(nid,{detail:'contrôle visuel : '+vizPhrase(v),progress:null});
        vizConsoleMaj(dom,v); }
      return {fini:false}; }
    NOTIF.done(nid,{ok:vizEtat(v)!=='err',warn:vizEtat(v)==='warn',
      message:'contrôle visuel : '+vizPhrase(v)});
    vizConsoleMaj(dom,v);
    loadFleet().catch(()=>{});
    return {fini:true};
  },{every:4000,maxErrors:5,until:r=>!!(r&&r.fini),
     // Abandon (erreurs réseau, délai dépassé) : la ligne ne doit pas rester
     // à tourner indéfiniment. `done` est sans effet si le verdict est déjà là.
     onStop:()=>NOTIF.done(nid,{ok:false,
       message:'contrôle visuel : suivi interrompu, voir l’historique du site'})}); }


/* cartes */
function cards(){ const S=allSites(); let up=0,down=0;
  S.forEach(s=>{ const v=st(s); if(v===1)up++; else if(v===0)down++; });
  const core=S.filter(s=>s.core_update).length, plug=S.reduce((a,s)=>a+(s.plugins_updates||0),0),
    bk=S.filter(s=>s.updraft&&(bkAge(s)===null||bkAge(s)>48)).length, err=S.filter(s=>Object.keys(s.errors||{}).length).length;
  const defs=[['','sites',S.length,''],['up','en ligne',up,'ok'],['down','down',down,down?'err':'ok'],
    ['core','MAJ core',core,core?'warn':'ok'],['plug','MAJ plugins',plug,plug?'warn':'ok'],
    ['bk','backups>48h',bk,bk?'warn':'ok'],['err','en erreur',err,err?'err':'ok']];
  document.getElementById('cards').innerHTML=defs.map(([k,l,v,c])=>
    `<div class="card ${c?'v-'+c:''} ${store.filt.card===k&&k?'sel':''}" data-card="${H(k)}" tabindex="0" role="button"
       aria-pressed="${store.filt.card===k&&k?'true':'false'}"><b>${H(v)}</b><small>${H(l)}</small></div>`).join('');
  document.querySelectorAll('#cards .card').forEach(c=>{
    const act=()=>{ store.filt.card=(store.filt.card===c.dataset.card)?'':c.dataset.card; render(); };
    c.onclick=act; c.onkeydown=e=>activeAuClavier(e,act); }); }


function rowVals(s){ const v=st(s), age=bkAge(s);
  return { status:v===undefined?2.5:v, domain:kName(s)||s.domain, server:s.srv, core:s.core_version||'',
    plugins:s.plugins_updates||0, themes:s.themes_updates||0, viz:vizVal(s), php:s.php_version||'', backup:age===null?(s.updraft?9e9:-1):age,
    err:Object.keys(s.errors||{}).length }; }

function filtered(){ let S=allSites(); const q=store.filt.q.toLowerCase();
  if(q) S=S.filter(s=>(s._q||'').includes(q));
  if(store.filt.srv) S=S.filter(s=>s.srv===store.filt.srv);
  if(store.filt.grp) S=S.filter(s=>s.kuma_group===store.filt.grp);
  if(store.filt.st) S=S.filter(s=>{ const v=st(s); return store.filt.st==='up'?v===1:store.filt.st==='down'?v===0:v===undefined; });
  if(store.filt.todo) S=S.filter(attn);
  const cm={core:s=>s.core_update,plug:s=>s.plugins_updates,bk:s=>s.updraft&&(bkAge(s)===null||bkAge(s)>48),err:s=>Object.keys(s.errors||{}).length,down:s=>st(s)===0,up:s=>st(s)===1};
  if(cm[store.filt.card]) S=S.filter(cm[store.filt.card]);
  S.sort((a,b)=>{ const va=rowVals(a)[store.sort.k],vb=rowVals(b)[store.sort.k]; return (typeof va==='string'?va.localeCompare(vb):va-vb)*store.sort.dir; });
  return S; }

function rowHTML(s){ const v=st(s), age=bkAge(s), dot=v===1?'up':v===0?'down':v===2?'pending':'';
  let core=H(s.core_version||'—'),cc='mut'; if(s.core_version){ cc=s.core_update?'warn':'ok'; if(s.core_update) core+=' → '+H(s.core_update); }
  let pl='—',plc='mut'; if(s.plugins_total!=null){ pl=`${s.plugins_active}/${s.plugins_total}`; if(s.plugins_updates){ pl+=` · ${s.plugins_updates} MAJ`; plc='warn'; } else { pl+=' · ok'; plc='ok'; } }
  let bk='—',bkc='mut'; if(s.updraft){ if(age===null){ bk='jamais ?'; bkc='warn'; } else { bk=age>=48?`il y a ${(age/24).toFixed(1)} j`:`il y a ${Math.round(age)} h`; bkc=age>=48?'warn':'ok'; } }
  const ne=Object.keys(s.errors||{}).length, label=kName(s)||s.domain, sub=H(s.blogname||'')+(label!==s.domain?` <span class="muted">· ${H(s.domain)}</span>`:'');
  return `<tr data-d="${H(s.domain)}" data-s="${H(s.srv)}" tabindex="0" role="button"
      aria-label="${H('Ouvrir la fiche de '+(label||s.domain))}">
    <td><input type="checkbox" class="rowchk" ${store.sel.has(key(s))?'checked':''} aria-label="${H('Sélectionner '+(label||s.domain))}"></td>
    <td><span class="dot ${dot}"></span></td>
    <td class="site"><b>${H(label)}</b><button class="rowscan" data-rowscan title="Re-scanner ce site maintenant" aria-label="Re-scanner ce site">${icon('refresh-cw',{size:14})}</button><div class="sub">${sub}</div></td>
    <td>${srvCell(s)}${staleBadge(s)}</td>
    <td><span class="pill ${cc}">${core}</span></td>
    <td><span class="pill ${plc}">${pl}</span></td>
    <td><span class="pill ${s.themes_updates?'warn':'mut'}">${s.themes_updates??'—'}</span></td>
    <td class="vizcell">${vizCell(s)}</td>
    <td class="sub">${H(s.php_version||'?')}</td>
    <td title="${s.updraft?H('fichiers : '+udIntervalFr(s.updraft.interval)+' × '+(s.updraft.retain||'?')+' jeux · BDD : '+udIntervalFr(s.updraft.interval_db)+' × '+(s.updraft.retain_db||'?')+' jeux'):''}"><span class="pill ${bkc}">${bk}</span></td>
    <td>${ne?`<span class="pill err">${ne}</span>`:''}</td></tr>`; }

function render(){ if(!store.fleet) return; cards(); updMeta();
  setDensity(store.filt.compact);
  const S=filtered(); let html='';
  if(store.filt.groupby){ const by={}; S.forEach(s=>{ (by[s.kuma_group||'— autres —']=by[s.kuma_group||'— autres —']||[]).push(s); });
    Object.keys(by).sort().forEach(g=>{ html+=`<tr class="grouprow"><td colspan="11">${H(g)} · ${by[g].length}</td></tr>`; by[g].forEach(s=>html+=rowHTML(s)); });
  } else html=S.map(rowHTML).join('');
  document.getElementById('tb').innerHTML=html;
  document.querySelectorAll('#tb tr[data-d]').forEach(tr=>{
    tr.querySelector('.rowchk').onclick=e=>{ e.stopPropagation(); const s=allSites().find(x=>x.srv===tr.dataset.s&&x.domain===tr.dataset.d);
      if(e.target.checked) store.sel.add(key(s)); else store.sel.delete(key(s)); bulkBar(); };
    const vb=tr.querySelector('[data-vizinstall]');
    if(vb) vb.onclick=e=>{ e.stopPropagation(); vizInstall(vb,tr.dataset.s,tr.dataset.d); };
    const vc=tr.querySelector('[data-vizconnect]');
    if(vc) vc.onclick=e=>{ e.stopPropagation();
      const s=allSites().find(x=>x.srv===tr.dataset.s&&x.domain===tr.dataset.d);
      if(s) openVizConnect([s]); };
    tr.querySelectorAll('[data-vizrun]').forEach(a=>a.onclick=e=>e.stopPropagation());
    const rs=tr.querySelector('[data-rowscan]');
    if(rs){ rs.dataset.key=tr.dataset.s+'|'+tr.dataset.d;
      rs.onclick=e=>{ e.stopPropagation(); rowRescan(rs,tr.dataset.s,tr.dataset.d); };
      rs.onkeydown=e=>e.stopPropagation(); }
    tr.onclick=()=>openDrawer(tr.dataset.s,tr.dataset.d);
    tr.onkeydown=e=>{ if(e.target!==tr) return;      // la case à cocher garde sa touche Espace
      activeAuClavier(e,()=>openDrawer(tr.dataset.s,tr.dataset.d)); }; });
  bulkBar(); }
/* Après un re-render, le nœud d'origine n'existe plus : on retrouve le bouton
   de la même ligne par sa clé serveur|domaine. */
function rowscanFor(k){ return document.querySelector(`#tb [data-rowscan][data-key="${CSS.escape(k)}"]`); }

/* Re-scan d'un seul site depuis sa ligne, sans ouvrir le tiroir.
   `loadFleet()` redessine le tableau et DÉTRUIT le bouton : le verdict était posé
   sur un nœud déjà remplacé, donc invisible. On re-cible par data-key après le
   rendu, et on laisse l'état 2,5 s. */
async function rowRescan(btn,srv,dom){
  if(btn.dataset.busy) return;
  const cle=srv+'|'+dom;
  btn.dataset.busy='1';
  btn.innerHTML=icon('loader-circle',{size:14,spin:true,label:'re-scan en cours'});
  const nid=NOTIF.start({id:'rescan:'+cle,label:'Re-scan · '+dom,kind:'rescan',
    site:{srv,domain:dom}});
  let ok=false, titre='erreur réseau';
  try{
    const j=await api('/api/actions/run',{server:srv,domain:dom,action:'rescan'});
    ok=!!(j&&j.ok);
    titre=ok?'site re-scanné':('échec : '+((j&&(j.output||j.error))||'').slice(0,120));
    if(ok) await loadFleet();
  }catch(e){ ok=false; titre='erreur réseau'; }
  NOTIF.done(nid,{ok,message:ok?'':titre});
  const b2=rowscanFor(cle)||btn;
  b2.dataset.busy='1';
  b2.innerHTML=icon(ok?'check':'x',{size:14,label:titre}); b2.title=titre;
  setTimeout(()=>{ const b3=rowscanFor(cle)||b2;
    b3.innerHTML=icon('refresh-cw',{size:14,label:'Re-scanner ce site'}); b3.title='Re-scanner ce site maintenant';
    delete b3.dataset.busy; delete b2.dataset.busy; },2500);
}

async function vizInstall(btn,srv,dom){
  if(!btn.dataset.confirm){ btn.dataset.confirm='1'; btn.dataset.label=btn.innerHTML; btn.textContent='Confirmer ?'; btn.classList.add('danger');
    setTimeout(()=>{ if(btn.dataset.confirm){ delete btn.dataset.confirm; btn.innerHTML=btn.dataset.label; btn.classList.remove('danger'); } },4000); return; }
  const cle=srv+'|'+dom;
  const td=btn.closest('td'); td.innerHTML='<div class="bar indet"><div></div></div>';
  const nid=NOTIF.start({id:'vizinstall:'+cle,label:'Installation VizProof · '+dom,
    kind:'install',site:{srv,domain:dom}});
  const echec=t=>{ // après loadFleet la cellule d'origine a disparu : on retrouve la ligne
    const tr=document.querySelector(`#tb tr[data-s="${CSS.escape(srv)}"][data-d="${CSS.escape(dom)}"]`);
    const c=(tr&&tr.querySelector('.vizcell'))||td;
    c.innerHTML=`<span class="pill err" title="${H(t)}">échec</span>`;
    NOTIF.done(nid,{ok:false,message:t}); };
  try{ const j=await api('/api/actions/run',{server:srv,domain:dom,action:'vizproof_install',arg:null});
    if(!j.ok){ echec((j.output||'rc '+j.rc).slice(-300)); return; }
    await api('/api/actions/run',{server:srv,domain:dom,action:'rescan',arg:null});
    await loadFleet();
    NOTIF.done(nid,{ok:true,message:'extension installée et activée'});
    const b=rowscanFor(cle);                      // repère visuel : l'installation a abouti
    if(b){ b.dataset.busy='1'; b.innerHTML=icon('check',{size:14,label:'vizproof-timeline installé'}); b.title='vizproof-timeline installé';
      setTimeout(()=>{ const b3=rowscanFor(cle); if(b3){ b3.innerHTML=icon('refresh-cw',{size:14,label:'Re-scanner ce site'});
        b3.title='Re-scanner ce site maintenant'; delete b3.dataset.busy; } },2500); }
  }catch(e){ echec(String(e)); } }

/* ---- connexion d'un site (ou d'un lot) à VizProof ----
   Depuis que le jeton de compte s'enregistre dans les Réglages, le cas courant
   est le clic unique : ni jeton à saisir, ni identifiant à trouver — le site
   VizProof est retrouvé (ou créé) d'après l'URL WordPress, côté serveur. Les
   champs restent là pour les cas particuliers : jeton ponctuel, code de
   connexion à usage unique, identifiant imposé. */
let VZSITES=[], VZTOK=false;
function vizSlug(d){ return String(d||'').toLowerCase().replace(/[^a-z0-9_-]+/g,'-')
  .replace(/^-+|-+$/g,'').slice(0,80); }
const VZ_ID_RE=/^[A-Za-z0-9_-]{1,80}$/;
function closeViz(){ document.getElementById('vizmodal').classList.remove('open'); }
document.getElementById('vz-cancel').onclick=closeViz;
document.getElementById('vizmodal').onclick=e=>{ if(e.target.id==='vizmodal') closeViz(); };
document.getElementById('vz-adv').onclick=()=>{ const b=document.getElementById('vz-advbox');
  b.hidden=!b.hidden; document.getElementById('vz-adv').textContent=b.hidden?'Options avancées':'Masquer les options'; };
document.getElementById('vz-mode').onchange=e=>{ const tok=e.target.value==='token';
  document.getElementById('vz-tokwrap').hidden=!tok;
  document.getElementById('vz-codewrap').hidden=tok; };
/* Le bloc « jeton / code » se replie derrière un lien dès qu'un jeton est
   enregistré : on ne montre un champ secret que si on en a vraiment besoin. */
document.getElementById('vz-othertok').onclick=()=>{
  const b=document.getElementById('vz-credbox'); b.hidden=false;
  document.getElementById('vz-othertok').hidden=true;
  const f=document.getElementById('vz-token'); if(f) f.focus(); };
document.getElementById('vz-setlink').onclick=()=>{ closeViz(); document.getElementById('setbtn').click(); };
function vzOtherTok(){ return !document.getElementById('vz-credbox').hidden; }
async function openVizConnect(sites){
  // Sont éligibles : accès SSH (l'agent REST est en lecture seule) et une CLI
  // vizproof réellement disponible sur le site — cf. vizConnectable().
  VZSITES=(sites||[]).filter(s=>s&&vizConnectable(s));
  if(!VZSITES.length){ askInfo('Connecter VizProof',
    "Aucun site éligible dans la sélection. Il faut un accès <b>SSH</b> et une extension VizProof assez récente "
    +"pour exposer <code>wp vizproof</code> (pastille « à mettre à jour » sinon)."); return; }
  const cfg=await ensureSettings();
  VZTOK=!!cfg.vizproof_token_set;
  document.getElementById('vz-intro').innerHTML=VZSITES.length>1
    ? `<b>${VZSITES.length}</b> site(s) à relier.`+(VZTOK
        ? ' Le jeton enregistré vaut pour tous ; laissez l’identifiant vide pour que chaque site soit retrouvé ou créé d’après son URL.'
        : " L'identifiant est propre à chaque site ; le jeton, lui, est celui de votre compte et vaut pour tous.")
    : `Relier <b>${H(kName(VZSITES[0])||VZSITES[0].domain)}</b> à VizProof.`;
  document.getElementById('vz-rows').innerHTML=VZSITES.map((s,i)=>{
    // Avec un jeton enregistré, le champ reste VIDE : « par URL » est le défaut.
    const cur=VZTOK?'':((vizInfo(s)||{}).site_id||vizSlug(s.domain));
    return `<div class="logline"><b>${H(kName(s)||s.domain)}</b>
      <span class="muted small">${H(s.srv)}</span>
      <input class="inp w-sm" data-vzid="${i}" aria-label="${H('identifiant VizProof de '+s.domain)}"
             autocomplete="off" spellcheck="false" value="${H(cur)}"
             placeholder="${VZTOK?'par URL':''}">
      <span class="small" data-vzres="${i}"></span></div>`; }).join('');
  document.getElementById('vz-idhint').hidden=!VZTOK;
  document.getElementById('vz-tokstored').hidden=!VZTOK;
  document.getElementById('vz-toktail').textContent='…'+(cfg.vizproof_token_tail||'');
  document.getElementById('vz-othertok').hidden=false;
  document.getElementById('vz-credbox').hidden=VZTOK;   // replié tant qu'un jeton suffit
  document.getElementById('vz-goset').hidden=VZTOK;
  document.getElementById('vz-out').innerHTML='';
  document.getElementById('vz-apercu').innerHTML='';
  document.getElementById('vz-token').value='';
  document.getElementById('vz-code').value='';
  const go=document.getElementById('vz-go');
  go.disabled=false;
  go.textContent=(VZTOK&&VZSITES.length>1)?`Connecter ${VZSITES.length} sites`:'Connecter';
  go.onclick=runVizConnect;
  const ap=document.getElementById('vz-preview');
  ap.hidden=!VZTOK; ap.disabled=false; ap.textContent='Aperçu'; ap.onclick=()=>runVizPreview();
  const an=document.getElementById('vz-cancel'); an.textContent='Annuler'; an.className='btn';
  document.getElementById('vizmodal').classList.add('open');
  const f=document.querySelector('#vz-rows input'); if(f) f.focus();
  // Aperçu automatique sur un site unique : on affiche AVANT de connecter quel
  // site VizProof recevra ce WordPress.
  if(VZTOK&&VZSITES.length===1) runVizPreview().catch(()=>{}); }

/* Aperçu : `viz_resolve` ne crée rien, ni côté WordPress ni côté VizProof.
   Il dit quel site existant sera relié, ou que la connexion en créera un. */
function vizApercuTexte(j){
  if(!j||j.ok===false) return `<span class="pill err">aperçu impossible</span> <span class="muted">${H(String((j&&j.error)||'échec'))}</span>`;
  const nom=H(j.name||j.host||'?');
  if(j.created) return `<span class="pill ok">Site VizProof : <b>${nom}</b></span> <span class="muted">créé pour <code>${H(j.host||'')}</code></span>`;
  if(j.would_create) return `<span class="pill warn">Aucun site VizProof pour <code>${H(j.host||'')}</code></span> <span class="muted">il sera créé à la connexion</span>`;
  return `<span class="pill ok">Site VizProof : <b>${nom}</b></span> <span class="muted">existant, domaine <code>${H(j.matched_domain||j.host||'')}</code></span>`
    +(j.ambiguous?' <span class="pill warn" title="plusieurs sites VizProof portent cet hôte : le premier est retenu">ambigu</span>':''); }
async function vizResolveOne(s){
  const corps={server:s.srv,domain:s.domain};
  const api_base=document.getElementById('vz-api').value.trim();
  if(api_base) corps.api_base=api_base;
  try{ return await api('/api/actions/viz_resolve',corps)||{}; }
  catch(e){ return {ok:false,error:String(e)}; } }
async function runVizPreview(){
  const zone=document.getElementById('vz-apercu'), ap=document.getElementById('vz-preview');
  ap.disabled=true; ap.textContent='…';
  if(VZSITES.length===1){
    zone.innerHTML='<span class="muted">aperçu…</span>';
    zone.innerHTML=vizApercuTexte(await vizResolveOne(VZSITES[0]));
  }else{
    zone.innerHTML='<span class="muted">aperçu des '+VZSITES.length+' sites…</span>';
    for(let i=0;i<VZSITES.length;i++){
      const res=document.querySelector(`#vz-rows [data-vzres="${i}"]`);
      if(res) res.innerHTML='<span class="pill mut">…</span>';
      const j=await vizResolveOne(VZSITES[i]);
      if(res) res.innerHTML=(j&&j.ok)
        ? `<span class="pill ${j.created?'warn':'ok'}" title="${H(j.site_id||'')}">${H(j.name||j.host||'?')} · ${j.created?'créé':'existant'}</span>`
        : `<span class="pill err" title="${H(String((j&&j.error)||''))}">aperçu échoué</span>`; }
    zone.innerHTML='<span class="muted">aperçu terminé — rien n’a été connecté.</span>'; }
  ap.disabled=false; ap.textContent='Aperçu'; }

async function runVizConnect(){
  const autre=vzOtherTok();
  const mode=document.getElementById('vz-mode').value;
  const token=autre?document.getElementById('vz-token').value.trim():'';
  const code=autre?document.getElementById('vz-code').value.trim():'';
  const api_base=document.getElementById('vz-api').value.trim();
  const scope=document.getElementById('vz-scope').value;
  const out=document.getElementById('vz-out');
  const ids=VZSITES.map((s,i)=>document.querySelector(`#vz-rows [data-vzid="${i}"]`).value.trim());
  // Vide = résolution par URL côté serveur ; sinon le jeu de caractères est fermé.
  const mauvais=ids.findIndex(v=>v!==''?!VZ_ID_RE.test(v):!VZTOK);
  if(mauvais>=0){ out.innerHTML=ids[mauvais]===''
      ? '<span class="pill err">identifiant requis</span> <span class="muted">enregistrez un jeton VizProof dans les Réglages pour le déduire de l’URL.</span>'
      : '<span class="pill err">identifiant invalide</span> <span class="muted">lettres, chiffres, « _ » et « - », 80 caractères au plus.</span>';
    document.querySelector(`#vz-rows [data-vzid="${mauvais}"]`).focus(); return; }
  if(autre&&mode==='token'&&!token){ out.innerHTML='<span class="pill err">jeton manquant</span>'; return; }
  if(autre&&mode==='code'&&!code){ out.innerHTML='<span class="pill err">code manquant</span>'; return; }
  const go=document.getElementById('vz-go'); const lbl=go.textContent;
  go.disabled=true; go.textContent='en cours…';
  out.innerHTML='';
  const seul=VZSITES.length===1;
  const nid=NOTIF.start({id:'vizconnect',kind:'connect',
    label:'Connexion VizProof'+(seul?' · '+(kName(VZSITES[0])||VZSITES[0].domain)
                                     :' · '+VZSITES.length+' sites'),
    progress:seul?null:0,
    site:seul?{srv:VZSITES[0].srv,domain:VZSITES[0].domain}:null});
  let nok=0;
  for(let i=0;i<VZSITES.length;i++){
    const s=VZSITES[i], res=document.querySelector(`#vz-rows [data-vzres="${i}"]`);
    if(!seul) NOTIF.update(nid,{progress:i/VZSITES.length,detail:s.domain});
    if(res) res.innerHTML='<span class="pill mut">…</span>';
    const corps={server:s.srv,domain:s.domain};
    if(ids[i]) corps.site_id=ids[i];
    if(autre){ if(mode==='token') corps.token=token; else corps.code=code; }
    if(api_base) corps.api_base=api_base;
    if(scope) corps.scope=scope;
    let j; try{ j=await api('/api/actions/viz_connect',corps)||{}; }
    catch(e){ j={ok:false,rc:'—',error:String(e)}; }
    if(j.ok) nok++;
    const det=stripPhpNoise(String(j.output||j.error||'')).slice(-200);
    const sid=j.site_id?` <span class="muted">${H(j.site_name||j.site_id)}${j.site_created?' · créé':' · existant'}</span>`:'';
    if(res) res.innerHTML=(j.ok?'<span class="pill ok">connecté</span>'
      :`<span class="pill err" title="${H(det)}">rc ${H(j.rc??'?')}</span>`)+sid;
    if(!j.ok) out.innerHTML+=`<div class="logline"><b>${H(s.domain)}</b> <code>${H(det||'échec')}</code></div>`; }
  // Le champ jeton n'est jamais réinjecté : il est vidé dès l'envoi.
  document.getElementById('vz-token').value='';
  document.getElementById('vz-code').value='';
  NOTIF.done(nid,{ok:nok===VZSITES.length,warn:!!nok&&nok<VZSITES.length,
    message:nok+'/'+VZSITES.length+' connecté'+(nok>1?'s':'')});
  out.innerHTML=`<div class="mt2"><span class="pill ${nok===VZSITES.length?'ok':nok?'warn':'err'}">${nok}/${VZSITES.length} connecté(s)</span></div>`+out.innerHTML;
  go.textContent=lbl; go.disabled=false;
  const an=document.getElementById('vz-cancel'); an.textContent='Fermer'; an.className='btn primary';
  if(nok) loadFleet().catch(()=>{}); }
async function vizDisconnect(btn,s){
  if(!await askConfirm(`Dissocier <b>${H(s.domain)}</b> de VizProof ?<br><br>Le suivi visuel s'arrête ; l'extension reste installée.`,
      {titre:'Dissocier VizProof',ok:'Dissocier',danger:true})) return;
  const lbl=btn.innerHTML; btn.disabled=true; btn.textContent='…';
  const nid=NOTIF.start({kind:'connect',label:'Dissociation VizProof · '+(kName(s)||s.domain),
    site:{srv:s.srv,domain:s.domain}});
  let j; try{ j=await api('/api/actions/viz_disconnect',{server:s.srv,domain:s.domain})||{}; }
  catch(e){ j={ok:false,error:String(e)}; }
  btn.disabled=false; btn.innerHTML=lbl;
  NOTIF.done(nid,{ok:!!j.ok,
    message:j.ok?'':stripPhpNoise(String(j.output||j.error||'')).slice(-160)});
  if(!j.ok){ askInfo('Dissociation impossible',H(stripPhpNoise(String(j.output||j.error||'')).slice(-300)||'échec')); return; }
  await loadFleet(); openDrawer(s.srv,s.domain); }

document.getElementById('q').oninput=debounce(e=>{ store.filt.q=e.target.value; render(); },200);
['fsrv','fgrp','fst'].forEach(id=>{ const map={fsrv:'srv',fgrp:'grp',fst:'st'};
  document.getElementById(id).onchange=e=>{ store.filt[map[id]]=e.target.value; render(); }; });
['ftodo','fgroupby','fcompact'].forEach(id=>{ const map={ftodo:'todo',fgroupby:'groupby',fcompact:'compact'};
  document.getElementById(id).onchange=e=>{ store.filt[map[id]]=e.target.checked; render(); }; });
/* En-têtes de tri : atteignables au clavier et annoncés (aria-sort).
   Le composant générique porte désormais le comportement. */
bindSortable('#tbl',{get:()=>store.sort,set:s=>{ store.sort=s; },onChange:render});
document.getElementById('selall').onclick=e=>{ filtered().forEach(s=>{ if(e.target.checked) store.sel.add(key(s)); else store.sel.delete(key(s)); }); render(); };

/* barre d'actions de masse */
function bulkBar(){ document.getElementById('bulk-n').textContent=store.sel.size+' sélectionné'+(store.sel.size>1?'s':'');
  document.getElementById('bulkbar').classList.toggle('open',store.sel.size>0); }
document.getElementById('bulk-clear').onclick=()=>{ store.sel.clear(); render(); };
document.getElementById('bulk-vizconnect').onclick=()=>openVizConnect(allSites().filter(s=>store.sel.has(key(s))));
document.getElementById('bulk-run').onclick=async()=>{
  const act=document.getElementById('bulk-act').value; let arg=null;
  // « MAJ plugins sauf… » retiré : le gel par extension (tiroir du site)
  // exclut désormais automatiquement, et de façon persistante.
  const sites=allSites().filter(s=>store.sel.has(key(s)));
  const libelle=document.getElementById('bulk-act').selectedOptions[0].text;
  if(!sites.length){ askInfo('Aucun site sélectionné','Sélectionnez au moins un site dans le tableau.'); return; }
  if(!await askConfirm(`Exécuter <b>${H(libelle)}</b> sur <b>${sites.length}</b> site(s) ?`,
      {titre:'Action groupée',ok:'Exécuter'})) return;
  const tasks=sites.map(s=>({server:s.srv,domain:s.domain,action:act,arg}));
  let r; try{ r=await api('/api/actions/bulk',{tasks,mode:document.getElementById('bulk-stop').checked?'stop':'continue',
    backup_first:document.getElementById('bulk-backup').checked,viz_verify:document.getElementById('bulk-viz').checked}); }
  catch(e){ r={error:String(e)}; }
  // Sans ce `else`, une réponse 400 du backend (action refusée, cible invalide)
  // ne produisait strictement rien à l'écran.
  if(r&&r.job) demarrerJob(r.job,'Exécution en masse',
    libelle+' · '+sites.length+' site'+(sites.length>1?'s':''));
  else askInfo('Action groupée impossible',(r&&r.error)?H(r.error):'Le serveur n\'a pas renvoyé de tâche.'); };

/* export CSV */
document.getElementById('csvbtn').onclick=()=>{ const S=filtered();
  const rows=[['site','serveur','client','wordpress','maj_core','plugins_actifs','plugins_total','maj_plugins','maj_themes','vizproof','php','backup_h','statut','erreurs']];
  S.forEach(s=>{ const v=st(s),age=bkAge(s); rows.push([kName(s)||s.domain,s.srv,s.kuma_group||'',s.core_version||'',s.core_update||'',s.plugins_active??'',s.plugins_total??'',s.plugins_updates??'',s.themes_updates??'',vizInfo(s)?.version||vizOf(s)?.version||'',s.php_version||'',age===null?'':Math.round(age),v===1?'up':v===0?'down':'?',Object.keys(s.errors||{}).join(';')]); });
  const csv=rows.map(r=>r.map(x=>`"${String(x).replace(/"/g,'""')}"`).join(',')).join('\n');
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download='parc-wordpress.csv'; a.click(); };

/* vues sauvegardées */
function loadViews(){ const v=JSON.parse(localStorage.dashViews||'{}'); const sel=document.getElementById('views');
  sel.innerHTML='<option value="">Vues…</option>'+Object.keys(v).map(n=>`<option>${H(n)}</option>`).join('')+'<option value="__del">Supprimer une vue…</option>'; }
document.getElementById('saveview').onclick=async()=>{ const n=await askText('Enregistrer la vue','Elle mémorise les filtres actuels.',''); if(!n) return; const v=JSON.parse(localStorage.dashViews||'{}');
  v[n]={FILT:{...store.filt,card:undefined},SORT:store.sort}; localStorage.dashViews=JSON.stringify(v); loadViews(); };
document.getElementById('views').onchange=e=>{ const v=JSON.parse(localStorage.dashViews||'{}');
  if(e.target.value==='__del'){
    (async()=>{ const noms=Object.keys(v);
      const n=await askChoice('Supprimer une vue','Choisissez la vue à supprimer.',
        noms.map(x=>({value:x,label:x})));
      if(n&&v[n]){ delete v[n]; localStorage.dashViews=JSON.stringify(v); }
      loadViews(); })();
    return; }
  const view=v[e.target.value]; if(!view) return; Object.assign(store.filt,view.FILT); store.sort=view.SORT||store.sort;
  document.getElementById('q').value=store.filt.q||''; document.getElementById('fsrv').value=store.filt.srv||''; document.getElementById('fgrp').value=store.filt.grp||'';
  document.getElementById('fst').value=store.filt.st||''; document.getElementById('ftodo').checked=!!store.filt.todo;
  document.getElementById('fgroupby').checked=!!store.filt.groupby; document.getElementById('fcompact').checked=!!store.filt.compact; render(); };

/* tiroir détail + actions unitaires */
/* Un seul compteur de séquence pour TOUS les chargeurs du tiroir : ouvrir A
   puis vite B affichait sinon les gels, les points de restauration ou les
   vulnérabilités de A dans la fiche de B (une seule requête sur six était
   protégée). Chaque chargeur capture DRAWERSEQ et jette son résultat s'il a
   été dépassé. */
let DRAWERSEQ=0, DRAWEROPENER=null;
function openDrawer(srv,dom){ const s=allSites().find(x=>x.srv===srv&&x.domain===dom); if(!s) return; store.cur=s;
  DRAWERSEQ++; stopPoll('safe');
  // Un tiroir rouvert depuis un tiroir déjà ouvert (clic sur une autre ligne,
  // re-rendu après action) prendrait sa croix de fermeture pour son ouvreur : à la fermeture, le
  // focus reviendrait DANS un tiroir devenu aria-hidden. On ne retient donc
  // qu'un ouvreur extérieur au tiroir.
  const ouvreur=document.activeElement;
  DRAWEROPENER=(ouvreur&&document.getElementById('drawer').contains(ouvreur))?DRAWEROPENER:ouvreur;
  const v=st(s); document.getElementById('ddot').className='dot '+(v===1?'up':v===0?'down':v===2?'pending':'');
  document.getElementById('dtitle').textContent=kName(s)||s.domain;
  const ud=s.updraft, age=bkAge(s);
  const ligneP=(p,maj)=>`<tr data-plug="${H(p.name)}"><td>${H(p.name)}</td>
      <td>${maj?`${H(p.version)} → <b>${H(p.to||'?')}</b>`:H(p.version)}
        ${p.status!=='active'?'<span class="pill mut">inactive</span>':''}</td>
      <td class="pcell">${maj?`<button class="btn sm" data-act="plugin_update" data-arg="${H(p.name)}">MAJ</button>`:''}
      <button class="btn sm pfreeze" data-slug="${H(p.name)}" title="Ne plus jamais mettre à jour cette extension sur ce site">Geler</button>
      <button class="btn sm prb" data-slug="${H(p.name)}" title="Revenir à une version antérieure">${icon('rotate-ccw')} Rétablir</button></td></tr>`;
  const tousP=(s.plugins_list||[]).filter(p=>p.name&&!/\.php$/.test(p.name));
  const plugRows=tousP.filter(p=>p.update==='available').map(p=>ligneP(p,true)).join('');
  const autresRows=tousP.filter(p=>p.update!=='available').map(p=>ligneP(p,false)).join('');
  const adm=(s.admins||[]).map(a=>`<span class="tag">${H(a.login)}</span>`).join(' ')||'<span class="muted">—</span>';
  const auto=(()=>{ const n=s.plugins_auto_update, t=s.plugins_total;
    if(n==null||t==null) return {c:'',v:'?',s:'auto-MAJ'};
    if(t===0) return {c:'',v:'—',s:'aucune ext.'};
    if(n===0) return {c:'warn',v:'0/'+t,s:'auto-MAJ off'};
    if(n>=t)  return {c:'ok',v:n+'/'+t,s:'auto-MAJ'};
    return {c:'warn',v:n+'/'+t,s:'auto-MAJ'}; })();
  const bk=(age===null)?{c:'warn',v:'jamais',s:'sauvegarde'}
    :(age>=48?{c:'warn',v:(age/24).toFixed(1)+' j',s:'sauvegarde'}:{c:'ok',v:Math.round(age)+' h',s:'sauvegarde'});
  const phpOld=s.php_version&&parseFloat(s.php_version)<8.1;
  document.getElementById('dbody').innerHTML=`
    <div class="dstats">
      <div class="dstat ${s.core_update?'warn':'ok'}"><div class="lbl">WordPress</div>
        <div class="val">${H(s.core_version||'?')}</div>
        <div class="sub">${s.core_update?'→ '+H(s.core_update):'à jour'}</div></div>
      <div class="dstat ${s.plugins_updates?'warn':'ok'}"><div class="lbl">Extensions</div>
        <div class="val">${s.plugins_updates||0}</div>
        <div class="sub">sur ${s.plugins_total??'?'} installées</div></div>
      <div class="dstat ${phpOld?'warn':''}"><div class="lbl">PHP</div>
        <div class="val">${H(s.php_version||'?')}</div>
        <div class="sub">${phpOld?'obsolète':'à jour'}</div></div>
      <div class="dstat ${bk.c}"><div class="lbl">Sauvegarde</div>
        <div class="val">${H(bk.v)}</div><div class="sub">${H(ud?(ud.service||'locale'):'aucune')}</div></div>
      <div class="dstat ${auto.c}"><div class="lbl">Auto-MAJ</div>
        <div class="val">${H(auto.v)}</div><div class="sub">extensions</div></div>
      <div class="dstat" id="dvuln"><div class="lbl">Vulnérab.</div>
        <div class="val muted">…</div><div class="sub">analyse…</div></div>
    </div>
    ${s._stale?`<div class="warnbox small mt2">${icon('triangle-alert')} <b>Serveur ${H(s.srv)} injoignable</b> à la dernière collecte —
      les chiffres ci-dessus datent du ${H(s._srvAt||'relevé précédent')} et peuvent avoir changé depuis.
      ${s._srvErr?`<div class="mt1"><code>${H(s._srvErr)}</code></div>`:''}</div>`:''}
    ${s.via==='rest'
      ? `<div class="agroup"><span class="glbl">Actions</span><div class="actions" id="rest-actions">
           <span id="rest-vizslot"></span>
           <button class="btn sm" data-act="rescan">${icon('refresh-cw')} Re-scan</button></div></div>
         <p class="hint hint-loose" id="rest-note">Site géré <b>sans SSH</b> : l'agent est en lecture seule, les actions
         distantes (mises à jour, sauvegarde, checksums, caches) ne sont pas disponibles ici. À faire depuis wp-admin,
         ou en rattachant le serveur en SSH depuis Gestion → Serveurs.</p>
         ${vizDrawerBlock(s)}`
      : `${(s.plugins_updates||s.core_update)?`<div class="agroup"><span class="glbl">Mettre à jour</span><div class="actions">
      <button class="btn primary sm" id="safeup" data-core="${s.core_update?1:0}" data-n="${s.plugins_updates||0}" title="Archive ce qui va changer (fichiers + base), met à jour, contrôle le site, et remet en arrière automatiquement si quelque chose casse">${icon('shield-check')} MAJ sûre${s.core_update?' — cœur'+(s.plugins_updates?' + '+s.plugins_updates+' ext.':''):' — '+s.plugins_updates+' ext.'}</button>
      ${s.core_update?'<button class="btn sm" data-act="core_update">Cœur seul (sans filet)</button>':''}
      ${s.plugins_updates?'<button class="btn sm" data-act="plugins_update_all">Extensions seules (sans filet)</button>':''}
      ${s.themes_updates?'<button class="btn sm" data-act="themes_update_all">Thèmes</button>':''}
      </div></div>`:''}
      <div class="agroup"><span class="glbl">Vérifier</span><div class="actions">
      <button class="btn sm" data-act="verify_checksums">Intégrité du cœur</button>
      ${vizConnected(s)?'<button class="btn sm" data-act="viz_scan">Scan visuel</button><button class="btn sm" data-act="viz_baseline">Capturer une baseline</button>':''}
      <button class="btn sm" data-act="rescan">${icon('refresh-cw')} Re-scan</button>
      </div></div>
      ${vizDrawerBlock(s)}
      <div class="agroup"><span class="glbl">Maintenance</span><div class="actions">
      <button class="btn sm" data-act="cache_flush">Vider les caches</button>
      ${(s.plugins_total&&(s.plugins_auto_update??0)<s.plugins_total)
        ?`<button class="btn sm" data-act="autoupdate_on">Activer les auto-MAJ (${s.plugins_total})</button>`
        :(s.plugins_total?'<button class="btn sm" data-act="autoupdate_off">Désactiver les auto-MAJ</button>':'')}
      ${ud&&s.via!=='rest'?'<button class="btn sm" data-act="updraft_backup">Lancer une sauvegarde</button>':''}
      </div></div>`}
    ${plugRows?`<div class="dsec"><h3>Extensions à mettre à jour (${s.plugins_updates})</h3><table class="ptable"><tbody>${plugRows}</tbody></table></div>`:''}
    ${autresRows?`<div class="dsec"><h3>Toutes les extensions
        <button class="btn sm fr" id="pall-toggle">Afficher (${tousP.filter(p=>p.update!=='available').length} à jour)</button></h3>
      <p class="hint" id="pall-hint">Repliée par défaut. <span class="info" data-tip="Utile pour retablir une version anterieure d'une extension deja a jour.">?</span></p>
      <table class="ptable" id="pall-tbl" hidden><tbody>${autresRows}</tbody></table></div>`:''}
    <div class="dsec" hidden id="drbsec"><h3>Revenir en arrière</h3>
      <p class="hint">Archives laissées par les mises à jour sûres. <span class="info" data-tip="Cliquez une pastille pour remettre l'extension dans sa version d'avant, a l'identique — y compris pour les extensions premium. Le bouton Retablir de chaque extension permet en plus de choisir une version publiee sur wordpress.org. Dans les deux cas seuls les fichiers sont remplaces : la base n'est pas touchee.">?</span></p>
      <div id="drblist" class="small"></div></div>
    <div class="dsec" hidden id="dfrozensec"><h3>Extensions gelées</h3>
      <p class="hint">Jamais mises à jour par le dashboard. <span class="info" data-tip="Ni par un bouton, ni par une action groupee, ni par la MAJ sure. Utile quand une version casse le site, ou quand un client doit valider avant.">?</span></p>
      <div id="dfrozenlist" class="small"></div></div>
    <div class="dsec" hidden id="dvulnsec"><h3>Vulnérabilités connues <span id="dvulnsum" class="small"></span></h3>
      <div id="dvulnlist" class="small"></div></div>
    <div class="dsec"><h3>Fiche</h3>
    <div class="kv">
      <span class="k">Nom</span><span>${H(s.blogname||'—')}</span>
      <span class="k">URL</span><span>${(u=>u?`<a target="_blank" rel="noopener noreferrer" href="${H(u)}">${H(s.siteurl||u)}</a>`
        :`<span class="muted">${H(s.siteurl||'—')}</span>`)(safeUrl(s.siteurl||'https://'+s.domain))}</span>
      <span class="k">Serveur</span><span>${srvCell(s)}${s.via==='rest'&&s.srv?' <span class="muted">'+H(s.srv)+'</span>':''}</span>
      ${s.path?'<span class="k">Chemin</span><span><code class="small">'+H(s.path)+'</code></span>':''}
      <span class="k">Client (Kuma)</span><span>${H(s.kuma_group||'—')}</span>
      <span class="k">Administrateurs</span><span>${adm}</span>
      ${s.via==='rest'?'<span class="k">Identifiants WordPress</span><span id="wpcred"><span class="muted small">chargement…</span></span>':''}
      <span class="k">Collecté</span><span class="muted">${H(s.collected_at||store.fleet.generated_at)}</span></div></div>
    <div class="dsec"><h3>Sauvegardes</h3>
    ${ud?(()=>{ const hF=udHorizon(ud.retain,ud.interval), hD=udHorizon(ud.retain_db,ud.interval_db);
      const rF=udRulesFr(ud.extrarules&&ud.extrarules.files), rD=udRulesFr(ud.extrarules&&ud.extrarules.db);
      return `<div class="kv">
      <span class="k">Fichiers</span><span>${H(udIntervalFr(ud.interval))} · <b>${H(ud.retain||'?')} jeux</b>${hF?` <span class="muted small">≈ ${hF}</span>`:''}${rF?`<br><span class="muted small">puis ${H(rF)}</span>`:''}</span>
      <span class="k">Base de données</span><span>${H(udIntervalFr(ud.interval_db))} · <b>${H(ud.retain_db||'?')} jeux</b>${hD?` <span class="muted small">≈ ${hD}</span>`:''}${rD?`<br><span class="muted small">puis ${H(rD)}</span>`:''}</span>
      <span class="k">Destination</span><span>${H(ud.service||'?')}</span></div>`; })()
      :'<span class="muted">UpdraftPlus non détecté</span>'}</div>
    ${Object.keys(s.errors||{}).length?`<div class="dsec"><h3>Erreurs de collecte</h3><div class="errbox">${H(Object.entries(s.errors).map(([k,v])=>k+': '+v).join('\n\n'))}</div></div>`:''}
    <div class="console" id="console" hidden data-domain="${H(s.domain)}"></div>
    <div class="dsec"><h3>Historique</h3>
    <div id="timeline"><span class="muted small">chargement…</span></div></div>`;
  document.querySelectorAll('#dbody [data-act]').forEach(b=>b.onclick=()=>confirmRun(b));
  document.querySelectorAll('#dbody [data-vizconnect]').forEach(b=>b.onclick=()=>openVizConnect([s]));
  document.querySelectorAll('#dbody [data-vizdisconnect]').forEach(b=>b.onclick=()=>vizDisconnect(b,s));
  const su=document.getElementById('safeup'); if(su) su.onclick=()=>startSafeUpdate(s.srv,s.domain,su);
  loadPolicy(s.srv,s.domain);
  loadRollbackPoints(s.srv,s.domain);
  loadSafeStatus(s.domain);
  loadVizUpStatus(s.srv,s.domain);
  document.querySelectorAll('#dbody .prb').forEach(b=>b.onclick=()=>askVersion(b.dataset.slug,b));
  const pt=document.getElementById('pall-toggle');
  if(pt) pt.onclick=()=>{ const t=document.getElementById('pall-tbl'), hi=document.getElementById('pall-hint');
    t.hidden=!t.hidden; if(hi) hi.hidden=!t.hidden;
    pt.textContent=t.hidden?`Afficher (${t.querySelectorAll('tr').length} à jour)`:'Masquer'; };
  const dr=document.getElementById('drawer');
  dr.classList.add('open'); dr.setAttribute('aria-hidden','false');
  document.getElementById('dback').classList.add('open');
  document.getElementById('dclose').focus();
  loadTimeline(s.srv,s.domain);
  drawerVulns(kName(s)||s.domain);
  if(s.via==='rest') loadWpCred(s.srv,s.domain); }


/* ---- rétablir une version antérieure d'une extension ---- */
let RBPOINTS=[], RBSITE={srv:'',dom:''};
async function loadRollbackPoints(srv,dom){
  const seq=DRAWERSEQ;
  let pts=[];
  try{ const r=await api(`/api/actions/rollback_points?server=${encodeURIComponent(srv)}&domain=${encodeURIComponent(dom)}`);
       pts=r.points||[]; }catch(e){ pts=[]; }
  if(seq!==DRAWERSEQ) return;          // un autre site a été ouvert entre-temps
  RBPOINTS=pts; RBSITE={srv,dom};
  const sec=document.getElementById('drbsec'), list=document.getElementById('drblist');
  if(!sec||!list) return;
  sec.hidden=!RBPOINTS.length;
  list.innerHTML=RBPOINTS.map(pt=>{
    const quand=pt.ts?H(pt.ts.replace(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2}).*$/,'$3/$2 à $4h$5')):'';
    const items=pt.plugins.map(sl=>{
      const v=pt.versions&&pt.versions[sl];
      return `<button class="btn sm rbgo" data-dir="${H(pt.dir)}" data-slug="${H(sl)}"
        title="Remettre ${H(sl)} dans sa version d'avant cette mise à jour">${icon('rotate-ccw')} ${H(sl)}${v?' → '+H(v):''}</button>`;
    }).join(' ');
    return `<div class="vulnrow"><span class="muted small">${quand}</span> ${items}</div>`;
  }).join('');
  list.querySelectorAll('.rbgo').forEach(b=>b.onclick=()=>doRollback(b.dataset.slug,{dir:b.dataset.dir},b));
}
async function doRollback(slug,src,btn){
  const cible={srv:store.cur&&store.cur.srv, dom:store.cur&&store.cur.domain};
  // Garde-fou : une archive appartient au site qui l'a produite. Si le tiroir a
  // changé de site entre l'affichage de la liste et le clic, on refuse plutôt
  // que de restaurer les fichiers d'un site sur un autre.
  if(src.dir&&(RBSITE.srv!==cible.srv||RBSITE.dom!==cible.dom)){
    askInfo('Point de restauration périmé',
      `Cette archive appartient à <b>${H(RBSITE.dom||'un autre site')}</b>, or la fiche ouverte est
       <b>${H(cible.dom||'—')}</b>. Rouvrez le site concerné pour la rétablir.`);
    return; }
  const quoi=src.dir?"depuis l'archive locale, à l'identique":`en version ${src.version}`;
  const intro=document.getElementById('rb-intro'), box=document.getElementById('rb-choices');
  const pied=document.getElementById('rb-cancel');
  intro.innerHTML=`Rétablir <b>${H(slug)}</b> ${H(quoi)} ?`;
  box.innerHTML=`<p class="hint mt2">${icon('triangle-alert')} Seuls les <b>fichiers</b> sont remis en place. Si l'extension a migré
      ses tables, la base reste dans son nouvel état — vérifiez le site après l'opération.</p>`;
  // Un seul bouton dans le pied, qui change de role selon l'etape : avoir
  // « Fermer » et « Annuler » cote a cote ne disait pas lequel faisait quoi.
  pied.textContent='Annuler'; pied.className='btn';
  const valider=document.createElement('button');
  valider.className='btn primary'; valider.id='rb-go'; valider.textContent='Rétablir';
  pied.after(valider);
  valider.onclick=async()=>{
    valider.remove(); pied.disabled=true;
    box.innerHTML='<div class="mt2"><span class="pill mut">opération en cours…</span></div>';
    let r;
    try{ r=await api('/api/actions/plugin_rollback',
        Object.assign({server:cible.srv,domain:cible.dom,slug},src)); }
    catch(e){ r={ok:false,rc:'—',output:String(e)}; }
    intro.innerHTML=r.ok?`<b>${H(slug)}</b> rétabli.`:`Échec du rétablissement de <b>${H(slug)}</b> (rc ${H(r.rc)}).`;
    const sortie=stripPhpNoise(r.output||'');
    box.innerHTML=`<div class="mt2"><span class="pill ${r.ok?'ok':'err'}">${r.ok?'réussi':'échec'}</span></div>`
      +(sortie?`<pre class="tldet mt2">${H(sortie.slice(-800))}</pre>`:'');
    pied.disabled=false; pied.textContent='Fermer'; pied.className='btn primary';
    pied.onclick=()=>{ closeRb(); pied.className='btn'; pied.textContent='Annuler';
      pied.onclick=closeRb; if(r.ok) loadFleet().catch(()=>{}); };
  };
  document.getElementById('rbmodal').classList.add('open');
}

/* choix d'une version : modale maison, les versions se cliquent (pas de saisie) */
function closeRb(){
  document.getElementById('rbmodal').classList.remove('open');
  // Remise a zero du pied : sans elle, une seconde ouverture heriterait de
  // l'etat « Fermer » laisse par l'operation precedente.
  const pied=document.getElementById('rb-cancel');
  if(pied){ pied.textContent='Annuler'; pied.className='btn'; pied.disabled=false; pied.onclick=closeRb; }
  const g=document.getElementById('rb-go'); if(g) g.remove();
}
document.getElementById('rb-cancel').onclick=closeRb;
document.getElementById('rbmodal').onclick=e=>{ if(e.target.id==='rbmodal') closeRb(); };
async function askVersion(slug,btn){
  const lbl=btn.innerHTML; btn.disabled=true; btn.textContent='…';
  let r; try{ r=await api('/api/actions/plugin_versions?slug='+encodeURIComponent(slug)); }
  catch(e){ r=null; }
  btn.disabled=false; btn.innerHTML=lbl;
  const vs=(r&&r.versions)||[], actuelle=(r&&r.current)||'';
  const arc=RBPOINTS.find(p=>p.plugins.includes(slug));
  const intro=document.getElementById('rb-intro'), box=document.getElementById('rb-choices');
  if(!vs.length&&!arc){
    intro.innerHTML=`Aucune version antérieure disponible pour <b>${H(slug)}</b> : cette extension n'est pas publiée sur wordpress.org (extension premium) et aucune archive locale n'existe. Une archive est créée à chaque « MAJ sûre ».`;
    box.innerHTML='';
  } else {
    intro.innerHTML=`Choisissez la version à remettre en place pour <b>${H(slug)}</b>.
      Seuls les <b>fichiers</b> sont remplacés — la base n'est pas touchée.`;
    let h='';
    if(arc){
      h+=`<div class="glbl glbl-sep">Archive locale — restitution à l'identique</div>
        <div class="actions"><button class="btn primary sm rbpick" data-kind="dir" data-val="${H(arc.dir)}">
          ${icon('rotate-ccw')} ${H(arc.versions[slug]||'version précédente')}</button>
          <span class="muted small">telle qu'elle était avant la mise à jour</span></div>`;
    }
    if(vs.length){
      h+=`<div class="glbl glbl-sep">Versions publiées sur wordpress.org</div>
        <div class="actions">`+vs.slice(0,24).map(v=>
          `<button class="btn sm rbpick" data-kind="version" data-val="${H(v)}">${H(v)}${v===actuelle?' <span class="muted">(actuelle)</span>':''}</button>`).join('')+`</div>`;
    }
    box.innerHTML=h;
    box.querySelectorAll('.rbpick').forEach(b=>b.onclick=()=>{
      const src=b.dataset.kind==='dir'?{dir:b.dataset.val}:{version:b.dataset.val};
      closeRb(); doRollback(slug,src,btn);
    });
  }
  document.getElementById('rbmodal').classList.add('open');
}


/* ---- politique de mise à jour par extension (gel) ---- */
let FROZEN=[];
function renderPolicy(){
  const sec=document.getElementById('dfrozensec'), list=document.getElementById('dfrozenlist');
  if(sec&&list){
    sec.hidden=!FROZEN.length;
    list.innerHTML=FROZEN.map(sl=>`<div class="vulnrow"><span class="pill warn">gelée</span>
      <b>${H(sl)}</b><button class="btn sm pthaw" data-slug="${H(sl)}">Dégeler</button></div>`).join('');
  }
  document.querySelectorAll('#dbody [data-plug]').forEach(tr=>{
    const sl=tr.dataset.plug, gel=FROZEN.includes(sl);
    const b=tr.querySelector('.pfreeze'), maj=tr.querySelector('[data-act="plugin_update"]');
    if(b){ b.textContent=gel?'Dégeler':'Geler'; b.classList.toggle('primary',gel); }
    if(maj) maj.disabled=gel;
    tr.classList.toggle('row-frozen',gel);
  });
  document.querySelectorAll('#dbody .pfreeze,#dbody .pthaw').forEach(b=>b.onclick=async()=>{
    const sl=b.dataset.slug, gel=!FROZEN.includes(sl);
    b.disabled=true;
    try{ const r=await api('/api/actions/policy',{server:store.cur.srv,domain:store.cur.domain,slug:sl,frozen:gel});
      FROZEN=r.frozen||[]; }catch(e){}
    b.disabled=false; renderPolicy();
  });
}
async function loadPolicy(srv,dom){
  const seq=DRAWERSEQ;
  let f=[];
  try{ const r=await api('/api/actions/policy?domain='+encodeURIComponent(dom)); f=r.frozen||[]; }
  catch(e){ f=[]; }
  if(seq!==DRAWERSEQ) return;          // le tiroir affiche un autre site : résultat périmé
  FROZEN=f;
  renderPolicy();
}

/* vulnérabilités du site affiché : réutilise le dernier croisement (aucun recalcul) */
async function drawerVulns(dom){
  const seq=DRAWERSEQ;
  const tile=document.getElementById('dvuln'); if(!tile) return;
  try{
    // On ne demande que ce site : le parc entier pèse ~190 Ko.
    const r=await api('/api/sec/vulns?domain='+encodeURIComponent(dom));
    if(seq!==DRAWERSEQ) return;        // fiche d'un autre site entre-temps
    const site=(r.sites||[])[0];
    const n=site?site.count:0, worst=site?site.worst:'';
    tile.className='dstat '+(worst==='critical'||worst==='high'?'err':n?'warn':'ok');
    tile.querySelector('.val').className='val';
    tile.querySelector('.val').textContent=n||'0';
    tile.querySelector('.sub').textContent=n?(SEVLABEL[worst]||worst||'connues'):'aucune';
    const sec=document.getElementById('dvulnsec'); if(!sec||!site) return;
    sec.hidden=false;
    document.getElementById('dvulnsum').innerHTML=sevPill(worst);
    document.getElementById('dvulnlist').innerHTML=site.findings.slice(0,40).map(v=>{
      const fix=v.update_to?`<span class="pill ok">MAJ ${H(v.update_to)}</span>`
        :(v.unfixed?'<span class="pill err">non corrigée</span>':'');
      // safeUrl : le lien vient d'un flux externe, un `javascript:` passerait H().
      const lk=safeUrl(v.link);
      const cve=v.cve?(lk?`<a href="${H(lk)}" target="_blank" rel="noopener noreferrer" class="muted small">${H(v.cve)}</a>`
                         :`<span class="muted small">${H(v.cve)}</span>`):'';
      return `<div class="vulnrow">${sevPill(v.severity)}<b>${H(v.component)}</b>
        <span class="muted small">${H(v.version)}</span>${fix}${cve}</div>`;
    }).join('')+(site.findings.length>40?`<div class="muted small">… +${site.findings.length-40} autres</div>`:'');
  }catch(e){ if(seq===DRAWERSEQ) tile.querySelector('.sub').textContent='indisponible'; }
}


/* ---- mise à jour sûre : archive → MAJ → contrôle → retour arrière si cassé ---- */
function safeVerdictPill(v){
  // « réussie avec anomalies visuelles » n'est PAS vert : la mise à jour tient,
  // mais le rendu a bougé et personne ne l'a encore regardé.
  const ok=v==='réussi', neutre=(v==='rien à faire');
  const cls=ok?'ok':neutre?'mut':(v||'').startsWith('ÉCHEC')?'err':'warn';
  return `<span class="pill ${cls}">${H(v||'…')}</span>`;
}
/* La console est recréée à chaque ouverture du tiroir : la cibler par
   `#console` faisait écrire la progression du site A dans la console du site B.
   On exige le `data-domain` du site concerné. */
function consoleDe(dom){
  const box=document.getElementById('console');
  return (box&&box.dataset.domain===dom)?box:null;
}
function renderSafe(st,dom){
  const box=consoleDe(dom); if(!box) return;
  box.hidden=false;
  const lignes=(st.steps||[]).map(x=>
    `<div class="logline"><span class="pill ${x.warn?'warn':x.ok?'ok':'err'}">${x.warn?'attention':x.ok?'ok':'échec'}</span>
      <b>${H(x.label)}</b> <span class="muted small">${H(x.ts)}</span>
      ${x.detail?`<div class="muted small wrapline ml-8">${H(stripPhpNoise(x.detail))}</div>`:''}</div>`).join('');
  box.innerHTML=`<div class="mb-6"><b>${icon('shield-check')} Mise à jour sûre</b> ${st.running?'<span class="pill mut">en cours…</span>':safeVerdictPill(st.verdict)}</div>${lignes}`;
  box.scrollTop=box.scrollHeight;
}
/* Suivi d'une MAJ sûre : le bouton et la console sont retrouvés à chaque tour
   (le tiroir a pu être refermé/rouvert), et le sondage s'arrête tout seul si le
   site affiché change ou si le backend ne répond plus. */
function suivreSafe(dom,lbl){
  poll('safe',async()=>{
    const st=await api('/api/actions/safe_update_status');
    const boutonEncore=()=>{ const b=document.getElementById('safeup');
      return (store.cur&&store.cur.domain===dom)?b:null; };
    if(!store.cur||store.cur.domain!==dom) return {fini:true};   // le job continue côté serveur
    renderSafe(st,dom);
    if(!st.running){
      const b=boutonEncore();
      if(b){ b.disabled=false; b.innerHTML=lbl||b.dataset.label||b.innerHTML; }
      loadFleet().catch(()=>{});
      return {fini:true}; }
    const b=boutonEncore(); if(b){ b.disabled=true; b.textContent='en cours…'; }
    return {fini:false};
  },{every:3000,maxErrors:5,until:r=>!!(r&&r.fini)});
}
/* Suivi pour la BARRE DE NOTIFICATIONS, indépendant de `suivreSafe` : celui-ci
   s'arrête dès que le tiroir affiche un autre site, et `closeDrawer` l'arrête
   aussi (stopPoll('safe')). La barre, elle, doit tenir jusqu'au verdict.
   Nombre d'étapes attendues d'une MAJ sûre nominale : contrôle avant, liste,
   à mettre à jour, sauvegarde, archivage fichiers, archivage base, mise à jour,
   page d'accueil, WordPress fonctionnel, contrôle visuel, terminé. */
const SAFE_ETAPES=11;
function suivreSafeNotif(dom,nid){
  let tours=0;
  poll('safenotif',async()=>{
    if(++tours>400) return {fini:true};              // ≈ 20 min, garde-fou
    const st=await api('/api/actions/safe_update_status');
    if(!st||st.domain!==dom) return {fini:false};    // le job n'a pas encore pris la main
    const n=(st.steps||[]).length, der=(st.steps||[])[n-1];
    if(st.running){ NOTIF.update(nid,{progress:Math.min(.95,n/SAFE_ETAPES),
      detail:der?der.label:'préparation…'}); return {fini:false}; }
    const v=String(st.verdict||'');
    NOTIF.update(nid,{progress:1});
    NOTIF.done(nid,{ok:v==='réussi'||v==='rien à faire',
      warn:/anomalie/i.test(v),message:v||'terminée'});
    return {fini:true};
  },{every:3000,maxErrors:5,until:r=>!!(r&&r.fini),
     onStop:()=>NOTIF.done(nid,{ok:false,message:'suivi interrompu — voir le tiroir du site'})});
}
/* À l'ouverture du tiroir : si une MAJ sûre tourne encore sur CE site, on
   ré-affiche sa progression et on se raccroche au sondage. */
async function loadSafeStatus(dom){
  const seq=DRAWERSEQ;
  let st=null; try{ st=await api('/api/actions/safe_update_status'); }catch(e){ return; }
  if(seq!==DRAWERSEQ||!st||!st.domain||st.domain!==dom) return;
  if(!(st.steps||[]).length&&!st.running) return;
  renderSafe(st,dom);
  if(st.running){ const b=document.getElementById('safeup');
    if(b){ b.dataset.label=b.dataset.label||b.innerHTML; b.disabled=true; b.textContent='en cours…'; }
    suivreSafe(dom,(b&&b.dataset.label)||(icon('shield-check')+' MAJ sûre'));
    // Rechargement de page ou MAJ lancée ailleurs : la barre reprend le suivi.
    const nid='safe:'+dom;
    if(!NOTIF.encours(nid)){
      NOTIF.start({id:nid,label:'MAJ sûre · '+dom,kind:'safe',progress:0,
        site:{srv:(store.cur&&store.cur.srv)||'',domain:dom}});
      suivreSafeNotif(dom,nid); } }
}
async function startSafeUpdate(srv,dom,btn){
  const withCore=btn.dataset.core==='1';
  await ensureSettings();
  let msg=`Mise à jour sûre de <b>${H(dom)}</b> ?<br><br>Déroulé : sauvegarde UpdraftPlus → archivage de ce qui va changer → mise à jour → contrôle du site → retour arrière automatique si quelque chose casse.`;
  if(withCore) msg+=`<br><br>${icon('triangle-alert')} Le cœur WordPress est inclus. Ses fichiers sont restaurables, mais les migrations de base de données ne sont PAS annulées par le retour arrière : la sauvegarde UpdraftPlus est le recours pour la base.`;
  msg+=`<br><br>L'opération peut durer plusieurs minutes.`;
  // La case est pré-remplie avec le réglage, mais reste modifiable POUR CETTE
  // exécution : c'est au moment de lancer qu'on sait si le site supporte mal
  // une régression visuelle.
  const corps=`<label class="fld"><input type="checkbox" id="su-vizrb"${store.settings.viz_anomaly_rollback?' checked':''}>
      Annuler la mise à jour si VizProof détecte des anomalies visuelles</label>
    <p class="hint hint-loose">Pré-réglé d'après <b>Réglages</b>. Décoché : les anomalies sont signalées et la mise à jour est conservée.</p>`;
  const rep=await new Promise(res=>{
    askOpen('Mise à jour sûre',msg,corps,
      ()=>res({go:true,rb:document.getElementById('su-vizrb').checked}),
      ()=>res({go:false}));
    const b=document.getElementById('ask-ok'); b.textContent='Lancer'; });
  if(!rep.go) return;
  const lbl=btn.innerHTML; btn.dataset.label=lbl;
  btn.disabled=true; btn.textContent='en cours…';
  let r;
  try{ r=await api('/api/actions/safe_update',{server:srv,domain:dom,backup:true,viz:true,
        core:withCore,viz_rollback:rep.rb}); }
  catch(e){ r={error:'lancement impossible : '+e}; }
  if(!r||r.error){ askInfo('Mise à jour sûre impossible',H((r&&r.error)||'réponse vide'));
    btn.disabled=false; btn.innerHTML=lbl; return; }
  suivreSafe(dom,lbl);
  const nid='safe:'+dom;
  NOTIF.start({id:nid,label:'MAJ sûre · '+dom,kind:'safe',progress:0,detail:'démarrage…',
    site:{srv,domain:dom}});
  suivreSafeNotif(dom,nid);
}

/* ---- job « baseline → mise à jour → verdict » (réponse {job:"viz_update"}) ----
   Sur un site relié à VizProof, /api/actions/run ne fait plus la mise à jour
   dans la réponse : elle démarre un job (baseline AVANT, verdict APRÈS) et rend
   la main. Même rendu que la MAJ sûre — une liste d'étapes —, parce que c'est
   la même chose vue par l'utilisateur : une opération longue à suivre. */
const VIZUP_PILL={attente:['mut','attente'],'en cours':['mut','en cours…'],
  ok:['ok','ok'],warn:['warn','attention'],erreur:['err','échec']};
const VIZUP_DETAIL={baseline:'baseline VizProof…',update:'mise à jour…',
  rescan:'inventaire…'};
const MAJ_ACTS=new Set(['core_update','plugins_update_all','plugins_update_except',
  'plugin_update','themes_update_all']);
function vizupLigne(x){ const [c,l]=VIZUP_PILL[x.status]||['mut',String(x.status||'')];
  return `<div class="logline"><span class="pill ${c}">${H(l)}</span> <b>${H(x.label)}</b>
    <span class="muted small">${H(x.ts||'')}</span>
    ${x.detail?`<div class="muted small wrapline ml-8">${H(stripPhpNoise(x.detail))}</div>`:''}</div>`; }
/* Étape en cours (ou la dernière jouée) : ce que la barre de notifications dit. */
function vizupCourante(job){ const st=(job&&job.steps)||[];
  return st.filter(x=>x.status==='en cours').pop()
      || st.filter(x=>x.status!=='attente').pop() || st[0] || null; }
function vizupFaites(job){ return ((job&&job.steps)||[]).filter(x=>x.status!=='attente').length; }
function vizupDetail(st){ if(!st) return 'préparation…';
  // Pour le contrôle visuel, le détail de l'étape EST la phase (attente du scan
  // du plugin, scan en cours, scan dashboard) : on la dit en clair.
  if(st.key==='viz') return VIZ_PHASES[st.detail]||'contrôle visuel…';
  return VIZUP_DETAIL[st.key]||st.label||''; }
/* '' | 'ok' | 'warn' | 'err' — une anomalie visuelle n'est pas un échec du job. */
function vizupFin(job){ const st=(job&&job.steps)||[];
  if(st.some(x=>x.status==='erreur')) return 'err';
  if(st.some(x=>x.status==='warn')) return 'warn';
  return 'ok'; }
function vizupVerdict(job){ const f=vizupFin(job);
  return f==='err'?'échec':f==='warn'?'terminée avec avertissement':'réussie'; }
function renderVizUp(job,dom){
  const box=consoleDe(dom); if(!box) return;
  box.hidden=false;
  const v=(job.result&&job.result.viz)||null;
  const tete=job.running?'<span class="pill mut">en cours…</span>'
    :`<span class="pill ${vizupFin(job)}">${H(vizupVerdict(job))}</span>`;
  box.innerHTML=`<div class="mb-6"><b>${icon('scan-eye')} Mise à jour sous contrôle visuel</b> ${tete}</div>`
    +((job.steps||[]).map(vizupLigne).join(''))
    +(v?vizConsoleLigne(v):'');
  box.scrollTop=box.scrollHeight; }
/* Pendant le job, les boutons de mise à jour du site sont hors service : deux
   mises à jour de front sur le même WordPress, c'est un site cassé sans coupable
   (le serveur refuse d'ailleurs en 409). */
function vizupBoutons(dom,off){
  if(!store.cur||store.cur.domain!==dom) return;
  document.querySelectorAll('#dbody [data-act]').forEach(b=>{
    if(MAJ_ACTS.has(b.dataset.act)) b.disabled=!!off; });
  document.querySelectorAll('#dbody .prb').forEach(b=>{ b.disabled=!!off; });
  const su=document.getElementById('safeup'); if(su) su.disabled=!!off; }
function suivreVizUp(srv,dom,nid){
  let tours=0;
  poll('vizup:'+dom,async()=>{
    if(++tours>600) return {fini:true};        // ≈ 30 min, garde-fou
    const job=await api('/api/actions/viz_update_status?domain='+encodeURIComponent(dom));
    if(!job||!(job.steps||[]).length) return {fini:false};
    if(store.cur&&store.cur.domain===dom){ renderVizUp(job,dom); vizupBoutons(dom,job.running); }
    const n=(job.steps||[]).length||1;
    if(job.running){
      NOTIF.update(nid,{progress:Math.min(.95,vizupFaites(job)/n),
        detail:vizupDetail(vizupCourante(job))});
      return {fini:false}; }
    const v=(job.result&&job.result.viz)||null, f=vizupFin(job);
    NOTIF.update(nid,{progress:1});
    NOTIF.done(nid,{ok:f!=='err',warn:f==='warn',
      message:vizupVerdict(job)+(v?' · '+vizPhrase(v):'')});
    // L'inventaire a été re-scanné côté serveur : on recharge, puis on remet la
    // console du job (openDrawer la réinitialise).
    loadFleet().then(()=>{ if(store.cur&&store.cur.domain===dom){ openDrawer(srv,dom); renderVizUp(job,dom); } })
               .catch(()=>{});
    return {fini:true};
  },{every:3000,maxErrors:5,until:r=>!!(r&&r.fini),
     onStop:()=>{ NOTIF.done(nid,{ok:false,
       message:'suivi interrompu — voir l’historique du site'});
       vizupBoutons(dom,false); }});
}
/* À l'ouverture du tiroir : si un job tourne encore sur CE site, on le
   ré-affiche et on se raccroche — le tiroir a pu être fermé entre-temps. */
async function loadVizUpStatus(srv,dom){
  const seq=DRAWERSEQ;
  let job=null;
  try{ job=await api('/api/actions/viz_update_status?domain='+encodeURIComponent(dom)); }
  catch(e){ return; }
  if(seq!==DRAWERSEQ||!job||!(job.steps||[]).length) return;
  renderVizUp(job,dom);
  if(!job.running) return;
  vizupBoutons(dom,true);
  const nid='vizup:'+dom;
  if(!NOTIF.encours(nid)) NOTIF.start({id:nid,label:'MAJ contrôlée · '+dom,kind:'maj',
    progress:0,detail:'reprise du suivi…',site:{srv,domain:dom}});
  suivreVizUp(srv,dom,nid);
}


/* historique du site (non bloquant — le tiroir s'affiche sans attendre) */
let TLSEQ=0;
const TLKIND={action:'action',collect:'collecte',event:'événement'};
let TLGROUPS=[], TLSHOWN=0;
const TLPAGE=20;
async function loadTimeline(srv,dom){
  const seq=++TLSEQ; const el=document.getElementById('timeline'); if(!el) return;
  el.innerHTML='<span class="muted small">chargement…</span>';
  let j; try{ j=await api('/api/site/timeline?server='+encodeURIComponent(srv)+'&domain='+encodeURIComponent(dom)); }
  catch(e){ if(seq===TLSEQ) el.innerHTML='<span class="muted small">historique indisponible</span>'; return; }
  if(seq!==TLSEQ) return;
  const ev=(j&&Array.isArray(j.events))?j.events.filter(x=>x&&typeof x==='object'):[];
  if(!ev.length){ el.innerHTML='<span class="muted small">aucun événement enregistré.</span>'; return; }
  ev.sort((a,b)=>((tsMs(b.ts)??0)-(tsMs(a.ts)??0)));
  // Regroupement des répétitions : une même mise à jour relancée quatre fois
  // n'a pas à occuper quatre blocs identiques.
  TLGROUPS=[];
  for(const e of ev){
    const cle=[e.kind,e.label,e.status,tlDetail(e)].join('|');
    const last=TLGROUPS[TLGROUPS.length-1];
    if(last&&last.cle===cle){ last.n++; continue; }
    TLGROUPS.push({cle,e,n:1});
  }
  TLSHOWN=TLPAGE; renderTimeline();
}

function tlRow({e,n},i){
  const kind=String(e.kind??''), lab=String(e.label??''), stt=String(e.status??'').toLowerCase();
  const det=tlDetail(e);
  const brut=String(e.detail??'');
  // On propose le dépliage dès que la source dit plus que le résumé affiché.
  const depliable=brut && brut.trim()!==det.trim();
  let c='mut';
  if(kind==='action') c=stt.includes('ok')?'ok':(stt.includes('anomal')?'warn':'err');
  else if(kind==='event') c=TLCRIT.test(lab)?'err':'mut';
  else if(kind==='collect') c=(stt==='alerte')?'err':'mut';
  const titre=(kind==='event'?(EVLABEL[lab]||lab):lab)||'—';
  return `<div class="tlrow${depliable?' tlopenable':''}"${depliable?` data-tl="${i}"`:''}>
    <span class="tlic ${c}">${TLICON[kind]||icon('diamond',{size:14})}</span>
    <div class="tlmain">
      <div class="tltop"><b>${H(titre)}</b>${n>1?`<span class="pill mut">×${n}</span>`:''}
        ${depliable?`<span class="tlchev">${icon('chevron-right',{size:14})}</span>`:''}
        <span class="muted small tlwhen" title="${H(absTime(e.ts))}">${H(relTime(e.ts))}</span></div>
      ${det?`<div class="muted small tlsub">${H(det)}</div>`:''}
      ${depliable?`<pre class="tldet" hidden>${H(brut.slice(0,4000))}</pre>`:''}
    </div></div>`;
}

function renderTimeline(){
  const el=document.getElementById('timeline'); if(!el) return;
  const vus=TLGROUPS.slice(0,TLSHOWN);
  const reste=TLGROUPS.length-vus.length;
  el.innerHTML=vus.map(tlRow).join('')
    +(reste>0?`<button id="tlmore" class="btn sm mt3">Voir plus (${reste})</button>`
             :(TLGROUPS.length>TLPAGE?'<div class="muted small mt2">fin de l\'historique</div>':''));
  el.querySelectorAll('.tlopenable').forEach(r=>r.onclick=()=>{
    const pre=r.querySelector('.tldet'); if(!pre) return;
    pre.hidden=!pre.hidden; r.classList.toggle('open',!pre.hidden);
  });
  const more=document.getElementById('tlmore');
  if(more) more.onclick=()=>{ TLSHOWN+=TLPAGE; renderTimeline(); };
}

// Un pictogramme par nature d'événement : action lancée d'ici, événement poussé
// par l'agent du site, collecte automatique.
const TLICON={action:icon('diamond',{size:14}),event:icon('activity',{size:14}),
  collect:icon('refresh-cw',{size:14})};
const TLCRIT=/admin|user_register|set_user_role|grant_super|deleted_user/i;
const EVLABEL={
  upgrader_process_complete:'Mise \u00e0 jour termin\u00e9e', wp_login:'Connexion administrateur',
  user_register:'Compte cr\u00e9\u00e9', set_user_role:'R\u00f4le modifi\u00e9', deleted_user:'Compte supprim\u00e9',
  activated_plugin:'Extension activ\u00e9e', deactivated_plugin:'Extension d\u00e9sactiv\u00e9e',
  switch_theme:'Th\u00e8me chang\u00e9', grant_super_admin:'Super administrateur accord\u00e9',
  wp_initialize_site:'Sous-site cr\u00e9\u00e9'
};
/* Detail d'un evenement rendu lisible : l'agent pousse du JSON brut. */
function tlDetail(e){
  const raw=e.detail; if(raw==null||raw==='') return '';
  if(e.kind!=='event') return stripPhpNoise(raw);
  let d; try{ d=JSON.parse(raw); }catch(err){ return stripPhpNoise(raw).slice(0,220); }
  if(!d||typeof d!=='object') return String(raw).slice(0,220);
  const slug=f=>String(f).split('/')[0];
  const lab=String(e.label||'');
  if(lab==='upgrader_process_complete'){
    const items=(d.items||[]).map(slug).filter(Boolean);
    const quoi={plugin:'extension',theme:'th\u00e8me',core:'c\u0153ur',translation:'traduction'}[d.type]||d.type||'\u00e9l\u00e9ment';
    if(!items.length) return `${quoi} \u00b7 ${d.action||'mise \u00e0 jour'}`;
    return `${quoi}${items.length>1?'s':''} : ${items.join(', ')}`;
  }
  if(lab==='wp_login') return `${d.login||'?'}${d.ip?' \u00b7 depuis '+d.ip:''}`;
  if(lab==='user_register'||lab==='set_user_role'||lab==='grant_super_admin')
    return `${d.login||'?'}${d.email?' <'+d.email+'>':''}${(d.roles||[]).length?' \u00b7 '+d.roles.join(', '):''}`;
  if(lab==='deleted_user') return `${d.login||d.id||'?'}`;
  if(lab==='activated_plugin'||lab==='deactivated_plugin') return slug(d.plugin||d.file||'?');
  if(lab==='switch_theme') return d.name||d.stylesheet||'?';
  return Object.entries(d).filter(([,v])=>v!==null&&v!==''&&v!==undefined)
    .map(([k,v])=>`${k} : ${Array.isArray(v)?v.map(slug).join(', '):v}`).join(' \u00b7 ').slice(0,220);
}
function closeDrawer(){
  const dr=document.getElementById('drawer');
  // Le focus doit SORTIR du tiroir avant qu'il ne devienne aria-hidden :
  // masquer un ancêtre de l'élément focalisé est une erreur d'accessibilité.
  const o=DRAWEROPENER; DRAWEROPENER=null;
  if(dr.contains(document.activeElement)){
    if(o&&o.isConnected&&typeof o.focus==='function'){ try{ o.focus(); }catch(e){} }
    // L'ouvreur n'a peut-être pas pris le focus (nœud non focusable) : on sort
    // le focus du tiroir avant de le masquer aux technologies d'assistance.
    if(dr.contains(document.activeElement)&&document.activeElement.blur) document.activeElement.blur();
  }
  dr.classList.remove('open'); dr.setAttribute('aria-hidden','true');
  document.getElementById('dback').classList.remove('open');
  stopPoll('safe');                    // le job continue côté serveur, pas le sondage
  DRAWERSEQ++;                         // toute réponse encore en vol devient périmée
  fermerTips(); }

document.getElementById('dclose').onclick=closeDrawer; document.getElementById('dback').onclick=closeDrawer;
/* Seules les actions qui MODIFIENT le site demandent confirmation : un re-scan,
   un scan visuel ou un vidage de cache n'ont rien a confirmer, et tout
   confirmer revient a ne plus rien signaler. */
/* `plugins_update_except` a disparu avec la « MAJ plugins sauf… » : le gel par
   extension l'a remplacé. */
const ACT_RISQUE=new Set(['core_update','plugins_update_all',
  'plugin_update','themes_update_all','autoupdate_on','autoupdate_off','vizproof_install']);
function confirmRun(btn){
  if(!ACT_RISQUE.has(btn.dataset.act)){ runAction(btn); return; }
  if(btn.dataset.confirm){ runAction(btn); return; }
  btn.dataset.confirm='1'; btn.dataset.label=btn.innerHTML; btn.textContent='Confirmer ?'; btn.classList.add('danger');
  setTimeout(()=>{ if(btn.dataset.confirm){ delete btn.dataset.confirm; btn.innerHTML=btn.dataset.label; btn.classList.remove('danger'); } },4000); }
async function runAction(btn){ const act=btn.dataset.act, arg=btn.dataset.arg||null, s=store.cur;
  delete btn.dataset.confirm; btn.classList.remove('danger'); setBusy(btn);
  const head=`$ ${act}${arg?' '+arg:''} sur ${s.domain}\n`;
  const con=document.getElementById('console'); con.hidden=false; con.textContent=head+'…';
  const nid=NOTIF.start({label:notifLabel(act,arg,s),site:{srv:s.srv,domain:s.domain},
    kind:ACT_KIND[act]||'action'});
  try{ const j=await api('/api/actions/run',{server:s.srv,domain:s.domain,action:act,arg})||{};
    /* Site relié à VizProof : la route a démarré un job (baseline → MAJ →
       verdict) au lieu de faire la mise à jour dans sa réponse. */
    if(j.job==='viz_update'){
      renderVizUp({running:true,steps:j.steps||[],result:null},s.domain);
      vizupBoutons(s.domain,true);
      NOTIF.update(nid,{progress:0,detail:'démarrage…'});
      suivreVizUp(s.srv,s.domain,nid);
      return; }
    /* rc 2 sur un scan visuel = anomalies détectées, pas un échec technique */
    const anom=!j.ok&&Number(j.rc)===2&&/^viz_/.test(act);
    const verdict=j.ok?`<b class="ok">${icon('circle-check')} OK</b>`
      :anom?`<b class="warn">${icon('triangle-alert')} anomalies visuelles détectées</b>`
      :`<b class="err">${icon('circle-x')} rc ${H(j.rc??'?')}</b>`;
    // Contrôle visuel de fin de MAJ : le serveur dit s'il l'a lancé, pourquoi
    // pas, ou qu'il tourne encore (cf. suivreVizLast).
    const v=(j.viz&&typeof j.viz==='object')?j.viz:null;
    con.innerHTML=H(head+(j.output||'')+'\n\n')+verdict+(v?'\n'+vizConsoleLigne(v):'');
    if(v&&v.pending) NOTIF.update(nid,{detail:'contrôle visuel : '+vizPhrase(v),progress:null});
    else NOTIF.done(nid,{ok:!!(j.ok||anom),warn:anom||(v?vizEtat(v)==='warn':false),
      message:anom?'anomalies visuelles détectées'
        :(j.ok?(v?'contrôle visuel : '+vizPhrase(v):'')
              :stripPhpNoise(String(j.output||j.error||'')).slice(-160)||('rc '+(j.rc??'?')))});
    if((j.ok||anom)&&act!=='rescan'&&act!=='verify_checksums'){ await api('/api/actions/run',{server:s.srv,domain:s.domain,action:'rescan'}); }
    const html=con.innerHTML;
    await loadFleet(); openDrawer(s.srv,s.domain); const c2=document.getElementById('console'); c2.hidden=false; c2.innerHTML=html;
    if(v&&v.pending) suivreVizLast(s.srv,s.domain,nid);
  }catch(e){ con.innerHTML+=H('\n')+`<b class="err">${icon('circle-x')} ${H(String(e))}</b>`; setIdle(btn,btn.dataset.label||act);
    NOTIF.done(nid,{ok:false,message:String(e)}); } }

/* ---- branchements de la coque -------------------------------------------- */
registerModalCloser('vizmodal',closeViz);
registerModalCloser('rbmodal',closeRb);
registerDrawerCloser(closeDrawer);

/* Le tableau se redessine quand la flotte ou le statut Kuma changent : c'est
   l'abonnement au store qui déclenche, plus un appel depuis le chargeur. */
export function onFleetChange(){
  if(!store.fleet) return;
  const sel=document.getElementById('fsrv');
  const avant=store.filt.srv;
  sel.innerHTML='<option value="">Tous les serveurs</option>'
    +(store.fleet?.servers||[]).map(s=>`<option>${H(s.name)}</option>`).join('');
  sel.value=avant;
  const grps=[...new Set(allSites().map(s=>s.kuma_group).filter(Boolean))].sort();
  const g=document.getElementById('fgrp');
  const avantG=store.filt.grp;
  g.innerHTML='<option value="">Tous les clients</option>'+grps.map(x=>`<option>${H(x)}</option>`).join('');
  g.value=avantG;
  render();
}

export { render, openDrawer, closeDrawer, confirmRun, vizOf, vizInfo, loadViews, openVizConnect };

