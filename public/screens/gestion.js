/* Écran Gestion — installs découverts, sites en mode REST, moniteurs Kuma,
   docroots, serveurs, ajout d'un WordPress et autorisation d'application.
   Repris tel quel : la phase 4 remplacera l'éditeur JSON par des formulaires. */

import { api } from '../lib/api.js';
import { esc as H } from '../lib/dom.js';
import { relTime, absTime, safeUrl, hostOf } from '../lib/format.js';
import { icon } from '../lib/icons.js';
import { store, kName, loadFleet, loadStatus, cacheFrais, cacheVider } from '../lib/state.js';
import { askConfirm, askInfo, askChoice, registerModalCloser } from '../components/confirm.js';
import { confirm2, setBusy, setIdle } from '../components/button.js';
import { vizOf, vizInfo } from '../components/viz.js';
import { confirmRun } from './site.js';

/* ===== GESTION ===== */
async function loadMgmt(force){
  if(cacheFrais('mgmt',force)) return;
  loadCandidates(); loadRestSites();   /* volontairement non attendus : indépendants de /api/mgmt/state */
  // Un /api/mgmt/state en échec ne doit pas laisser la page muette ni empêcher
  // les deux sections ci-dessus de s'afficher.
  try{ store.mgmt=await api('/api/mgmt/state'); }
  catch(e){ cacheVider('mgmt');
    document.getElementById('mgmt-tb').innerHTML=`<tr><td colspan="7"><span class="pill err">état indisponible</span> <span class="muted small">${H(String(e))}</span></td></tr>`;
    document.getElementById('mon-tb').innerHTML='<tr><td colspan="4"><span class="muted small">moniteurs indisponibles</span></td></tr>';
    return; }
  if(!store.mgmt||typeof store.mgmt!=='object'||store.mgmt.error){ cacheVider('mgmt');
    document.getElementById('mgmt-tb').innerHTML=`<tr><td colspan="7"><span class="pill err">état indisponible</span> <span class="muted small">${H((store.mgmt&&store.mgmt.error)||'réponse vide')}</span></td></tr>`;
    return; }
  store.mgmt.kuma_monitors=store.mgmt.kuma_monitors||[]; store.mgmt.kuma_groups=store.mgmt.kuma_groups||[];
  store.mgmt.overrides=store.mgmt.overrides||{}; store.mgmt.servers=store.mgmt.servers||[];
  const monById={}; store.mgmt.kuma_monitors.forEach(m=>monById[m.id]=m);
  const installs=[]; (store.fleet?.servers||[]).forEach(s=>(s.sites||[]).forEach(x=>installs.push({srv:s.name,...x})));
  document.getElementById('mgmt-count').textContent=`(${installs.length})`;
  document.getElementById('mgmt-tb').innerHTML=installs.map(s=>{
    const ov=store.mgmt.overrides[s.domain]||{}; const vis=ov.visible; const mon=kName(s);
    const monCell=mon?`<span class="pill ok">${H(mon)}</span>`:`<button class="btn sm" data-create="${H(s.domain)}">${icon('plus')} créer moniteur</button>`;
    return `<tr><td><b>${H(s.domain)}</b><div class="sub">${H(s.blogname||'')}</div></td><td>${H(s.srv)}</td><td>${monCell}</td>
      <td><select data-vis="${H(s.domain)}" aria-label="Visibilité"><option value="auto"${vis==null?' selected':''}>auto (Kuma)</option><option value="show"${vis===true?' selected':''}>toujours afficher</option><option value="hide"${vis===false?' selected':''}>masquer</option></select></td>
      <td><input class="inp w-xs" data-alias="${H(s.domain)}" value="${H(ov.alias||'')}" placeholder="nom du moniteur"></td>
      <td><button class="btn sm" data-dashconn="${H(s.domain)}" data-dashsrv="${H(s.srv)}">Connecter</button> <span data-dashres="${H(s.domain)}"></span></td>
      <td><button class="btn sm" data-saveov="${H(s.domain)}" title="Enregistrer la visibilité et l'alias">${icon('check',{label:'Enregistrer'})}</button></td></tr>`; }).join('');
  document.querySelectorAll('[data-dashconn]').forEach(b=>b.onclick=()=>confirm2(b,async()=>{
    const dom=b.dataset.dashconn, srv=b.dataset.dashsrv;
    const res=document.querySelector(`[data-dashres="${CSS.escape(dom)}"]`);
    setBusy(b); if(res) res.innerHTML='';
    try{ const j=await api('/api/mgmt/dash_connect',{server:srv,domain:dom})||{};
      const ok=!!j.ok, out=String(j.output??j.error??'').slice(-400);
      if(res) res.innerHTML=`<span class="pill ${ok?'ok':'err'}" title="${H(out)}">${ok?'connecté':'échec'}</span>`;
    }catch(e){ if(res) res.innerHTML=`<span class="pill err" title="${H(String(e))}">échec</span>`; }
    setIdle(b,'Connecter'); }));
  document.querySelectorAll('[data-saveov]').forEach(b=>b.onclick=async()=>{ const d=b.dataset.saveov;
    const vis=document.querySelector(`[data-vis="${CSS.escape(d)}"]`).value;
    const alias=document.querySelector(`[data-alias="${CSS.escape(d)}"]`).value;
    setBusy(b); await api('/api/mgmt/override',{domain:d,visible:vis==='show'?true:vis==='hide'?false:null,alias});
    setIdle(b,icon('check',{label:'Enregistré'})); await loadFleet(); });
  document.querySelectorAll('[data-create]').forEach(b=>b.onclick=async()=>{ const d=b.dataset.create;
    const gid=await askChoice('Créer le moniteur','Dans quel client ce moniteur doit-il être rangé ?',
      (store.mgmt.kuma_groups||[]).map(g=>({value:g.id,label:g.name})), store.mgmt.kuma_groups[0]?.id);
      if(!gid) return;
      // Deux vraies options : un confirm() détourné en choix (« OK = ceci,
      // Annuler = cela ») obligeait à deviner ce que fait chaque bouton.
      const type=await askChoice('Type de surveillance',
        "Le contrôle par mot-clé détecte aussi un site en ligne mais cassé ; le contrôle HTTP se contente du code de réponse.",
        [{value:'keyword',label:'Mot-clé sur /wp-login.php (recommandé pour WordPress)'},
         {value:'http',label:"Contrôle HTTP simple de la page d'accueil"}],'keyword');
      if(!type) return;
    setBusy(b,'redémarrage Kuma…'); const r=await api('/api/mgmt/kuma/create',{domain:d,group_id:gid,type});
      askInfo(r.ok?'Moniteur créé':'Échec de la création',
        r.ok?'Kuma redémarre — le statut apparaîtra dans une quinzaine de secondes.':H(r.output||r.error||''));
      setTimeout(()=>{ loadStatus(); loadMgmt(true); },16000); });
  // moniteurs
  document.getElementById('mon-tb').innerHTML=store.mgmt.kuma_monitors.map(m=>{
    const grp=m.parent?(monById[m.parent]?.name||''):''; return `<tr><td><b>${H(m.name)}</b></td><td>${H(grp)}</td>
      <td>${m.active?'<span class="pill ok">actif</span>':'<span class="pill mut">en pause</span>'}</td>
      <td><button class="btn sm" data-pause="${H(m.id)}" data-active="${m.active?1:0}">${m.active?'Pause':'Réactiver'}</button>
      <button class="btn sm danger" data-del="${H(m.id)}" data-name="${H(m.name)}">Retirer</button></td></tr>`; }).join('')
    ||'<tr><td colspan="4"><span class="muted small">aucun moniteur</span></td></tr>';
  document.querySelectorAll('[data-pause]').forEach(b=>b.onclick=async()=>{ setBusy(b);
    await api('/api/mgmt/kuma/pause',{monitor_id:+b.dataset.pause,active:b.dataset.active==='1'?0:1}).catch(()=>{});
    setTimeout(()=>{ loadStatus(); loadMgmt(true); },16000); });
  document.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{
    if(!await askConfirm(`Retirer le moniteur <b>${H(b.dataset.name)}</b> ?<br><br>Kuma redémarre : ~15 s d'interruption du monitoring.`,
        {titre:'Retirer un moniteur',ok:'Retirer',danger:true})) return;
    setBusy(b); await api('/api/mgmt/kuma/delete',{monitor_id:+b.dataset.del}).catch(()=>{});
    setTimeout(()=>{ loadStatus(); loadMgmt(true); },16000); });
  // docroots
  const dl=document.getElementById('doc-list');
  dl.innerHTML=(store.mgmt.extra_docroots||[]).map((d,i)=>`<div class="logline"><b>${H(d.server)}</b> · <code>${H(d.path)}</code> <button class="btn sm danger fr" data-rmdoc="${H(i)}">Retirer</button></div>`).join('')||'<span class="muted small">aucun</span>';
  document.getElementById('doc-srv').innerHTML=store.mgmt.servers.map(s=>`<option>${H(s.name)}</option>`).join('');
  document.querySelectorAll('[data-rmdoc]').forEach(b=>b.onclick=async()=>{ const docs=(store.mgmt.extra_docroots||[]).slice(); docs.splice(+b.dataset.rmdoc,1); await api('/api/mgmt/docroots',{docroots:docs}); loadMgmt(true); });
  document.getElementById('srv-json').value=JSON.stringify(store.mgmt.servers,null,1); }
document.getElementById('doc-add').onclick=async()=>{ const server=document.getElementById('doc-srv').value, path=document.getElementById('doc-path').value.trim();
  if(!path) return; const docs=(store.mgmt.extra_docroots||[]).slice(); docs.push({server,path}); await api('/api/mgmt/docroots',{docroots:docs}); document.getElementById('doc-path').value=''; loadMgmt(true); };
document.getElementById('srv-save').onclick=async()=>{ let servers; try{ servers=JSON.parse(document.getElementById('srv-json').value); }catch(e){ document.getElementById('srv-msg').textContent='JSON invalide'; return; }
  const r=await api('/api/mgmt/servers',{servers}); document.getElementById('srv-msg').textContent=r.ok?'enregistré':'erreur : '+(r.error||''); };

/* ===== SITES SUPERVISÉS NON GÉRÉS ===== */
async function loadCandidates(){ const bd=document.getElementById('cand-body'), cnt=document.getElementById('cand-count');
  bd.innerHTML='<span class="muted small">chargement…</span>'; cnt.textContent='';
  let j; try{ j=await api('/api/mgmt/candidates'); }
  catch(e){ bd.innerHTML='<span class="muted small">liste indisponible</span>'; return; }
  const list=(j&&Array.isArray(j.candidates))?j.candidates.filter(x=>x&&typeof x==='object'):[];
  cnt.textContent=list.length?`(${list.length})`:'';
  if(!list.length){ bd.innerHTML='<span class="pill ok">tous les sites supervisés sont gérés</span>'; return; }
  bd.innerHTML=`<div class="wrap"><table><thead><tr><th>Site</th><th>URL</th><th>Pourquoi</th><th></th></tr></thead><tbody>`
    +list.map(c=>{ const u=safeUrl(c.url), raw=String(c.url??'');
      return `<tr><td><b>${H(c.name||hostOf(raw)||'—')}</b>${c.source?`<div class="sub">${H(c.source)}</div>`:''}</td>
        <td class="sub">${u?`<a href="${H(u)}" target="_blank" rel="noopener noreferrer">${H(raw)}</a>`:H(raw||'—')}</td>
        <td><span class="pill mut">${H(c.reason||'non géré')}</span></td>
        <td><button class="btn sm primary" data-cand="${H(raw)}">Ajouter</button></td></tr>`; }).join('')
    +`</tbody></table></div>`;
  bd.querySelectorAll('[data-cand]').forEach(b=>b.onclick=()=>openAdd(b.dataset.cand,true)); }

/* ===== SITES EN MODE REST (sans SSH) ===== */
function restList(j){ if(Array.isArray(j)) return j; if(!j||typeof j!=='object') return [];
  for(const k of ['rest_sites','sites']) if(Array.isArray(j[k])) return j[k];   // clés réellement renvoyées par la route
  return []; }
function restDomain(x){ return String((x&&(x.domain||hostOf(x.url)))||''); }
/* colonne « WordPress » d'une ligne REST : état des identifiants + autorisation en 1 clic */
async function wpCellFill(root,dom,srv){
  if(!dom) return; const sel=`[data-wpcell="${CSS.escape(dom)}"]`;
  const cell=(root&&root.querySelector(sel))||document.querySelector(sel); if(!cell) return;
  let j=null; try{ j=await api('/api/mgmt/wp_credentials?domain='+encodeURIComponent(dom)); }catch(e){ j=null; }
  const c=(root&&root.querySelector(sel))||document.querySelector(sel); if(!c) return;
  if(!j||typeof j!=='object'||j.error){ c.innerHTML='<span class="muted small">—</span>'; return; }
  if(j.has_password){ c.innerHTML=`<span class="pill ok">autorisé${j.user?' · '+H(j.user):''}</span>`
      +(j.verified===false?' <span class="pill warn" title="dernier contrôle non concluant">à vérifier</span>':''); return; }
  if(!WPAUTH_ENABLED){ c.innerHTML='<span class="pill mut">sans SSH</span>'; return; }
  c.innerHTML=`<span class="pill warn">non autorisé</span> <button class="btn sm primary" data-wpauthrow="${H(dom)}" title="${H(WPAUTH_HELP)}">${icon('link')} Autoriser</button> <span data-wpmsg class="small"></span>`;
  const b=c.querySelector('[data-wpauthrow]'), msg=c.querySelector('[data-wpmsg]');
  if(b) b.onclick=()=>wpAuthorize(b,srv,dom,(ok,err)=>{
    if(!ok){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(err)}</span>`; return; }
    if(msg) msg.innerHTML='<span class="pill warn">en attente d\'approbation…</span>';
    b.innerHTML=icon('refresh-cw')+' Vérifier'; b.classList.remove('primary');
    b.onclick=()=>wpCellFill(root,dom,srv); }); }
async function loadRestSites(){ const bd=document.getElementById('rest-body'), cnt=document.getElementById('rest-count');
  bd.innerHTML='<span class="muted small">chargement…</span>'; cnt.textContent='';
  let j; try{ j=await api('/api/mgmt/rest_sites'); }
  catch(e){ bd.innerHTML='<span class="muted small">liste indisponible</span>'; return; }
  const list=restList(j).filter(x=>x&&typeof x==='object');
  cnt.textContent=list.length?`(${list.length})`:'';
  if(!list.length){ bd.innerHTML='<span class="muted small">aucun site en mode REST pour le moment.</span>'; return; }
  bd.innerHTML=`<div class="wrap"><table><thead><tr><th>Domaine</th><th>Nom</th><th>Ajouté le</th><th>Multisite</th><th>WordPress</th><th></th></tr></thead><tbody>`
    +list.map(x=>{ const d=restDomain(x), u=safeUrl(x.url);
      return `<tr><td><b>${u?`<a href="${H(u)}" target="_blank" rel="noopener noreferrer">${H(d)}</a>`:H(d||'—')}</b></td>
        <td>${H(x.name||'—')}</td>
        <td class="sub" title="${H(absTime(x.added_at))}">${H(x.added_at?relTime(x.added_at):'—')}</td>
        <td>${x.multisite?'<span class="pill warn">oui</span>':'<span class="pill mut">non</span>'}</td>
        <td data-wpcell="${H(d)}"><span class="muted small">…</span></td>
        <td><button class="btn sm danger" data-restdel="${H(d)}">Retirer</button> <span data-restres="${H(d)}" class="small"></span></td></tr>`; }).join('')
    +`</tbody></table></div>`;
  list.forEach(x=>wpCellFill(bd,restDomain(x),x.server||x.srv||''));
  bd.querySelectorAll('[data-restdel]').forEach(b=>b.onclick=()=>confirm2(b,async()=>{
    const d=b.dataset.restdel, res=bd.querySelector(`[data-restres="${CSS.escape(d)}"]`);
    setBusy(b);
    try{ const r=await api('/api/mgmt/rest_sites/delete',{domain:d})||{};
      if(r.ok===false){ if(res) res.innerHTML=`<span class="pill err" title="${H(r.error||'')}">échec</span>`; setIdle(b,'Retirer'); return; }
      loadRestSites(); loadFleet();
    }catch(e){ if(res) res.innerHTML=`<span class="pill err" title="${H(String(e))}">échec</span>`; setIdle(b,'Retirer'); } })); }
document.getElementById('rest-add').onclick=async()=>{ const url=document.getElementById('rest-url').value.trim(),
    name=document.getElementById('rest-name').value.trim(), msg=document.getElementById('rest-msg');
  if(!url){ msg.innerHTML='<span class="muted">indiquez une URL</span>'; return; }
  msg.innerHTML='<span class="muted">…</span>';
  try{ const j=await api('/api/mgmt/rest_sites',{url,name})||{};
    if(j.ok===false){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'')}</span>`; return; }
    msg.innerHTML='<span class="pill ok">ajouté</span>';
    document.getElementById('rest-url').value=''; document.getElementById('rest-name').value='';
    loadRestSites(); loadFleet();
  }catch(e){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; } };

/* ===== AJOUTER UN WORDPRESS (URL → méthode → appairage) ===== */
const ADD0={open:false,step:1,url:'',info:null,method:null,domain:'',expires:0,timer:null,poll:null,pollUntil:0};
let ADD={...ADD0};
function addStop(){ if(ADD.timer){ clearInterval(ADD.timer); ADD.timer=null; }
  if(ADD.poll){ clearTimeout(ADD.poll); ADD.poll=null; } }
function closeAdd(){ addStop(); ADD.open=false; document.getElementById('addmodal').classList.remove('open'); }
function openAdd(url,auto){ addStop(); ADD={...ADD0,open:true,url:String(url||'').trim()};
  document.getElementById('addmodal').classList.add('open'); addRender();
  if(auto&&ADD.url) addDiscover(); }
document.getElementById('addsite').onclick=()=>openAdd('',false);
document.getElementById('add-close').onclick=closeAdd;
document.getElementById('addmodal').onclick=e=>{ if(e.target.id==='addmodal') closeAdd(); };

function addRender(){
  document.getElementById('add-steps').innerHTML=[[1,'URL'],[2,'Méthode'],[3,ADD.method==='ssh'?'Connexion SSH':'Appairage']]
    .map(([n,t])=>`<span class="pill ${n===ADD.step?'ok':'mut'}">${n}. ${H(t)}</span>`).join(` <span class="muted">${icon('chevron-right',{size:14})}</span> `);
  const bd=document.getElementById('add-body');
  bd.innerHTML=ADD.step===1?addStep1():ADD.step===2?addStep2():addStep3();
  const on=(id,fn)=>{ const el=document.getElementById(id); if(el) el.onclick=fn; };
  const inp=document.getElementById('add-url');
  if(inp){ inp.oninput=e=>{ ADD.url=e.target.value; }; inp.onkeydown=e=>{ if(e.key==='Enter') addDiscover(); }; inp.focus(); }
  on('add-scan',addDiscover);
  on('add-next',()=>{ ADD.step=2; addRender(); });
  on('add-back',()=>{ addStop(); ADD.step=ADD.step===3?2:1; addRender(); });
  on('add-gen',addGen);
  on('add-goinstalls',addGoInstalls);
  bd.querySelectorAll('.card[data-m]').forEach(c=>c.onclick=()=>{ ADD.method=c.dataset.m; ADD.step=3; addRender(); }); }

function addStep1(){ return `
  <p class="hint">Saisissez l'URL du site à ajouter : l'analyse détecte WordPress, l'état de l'API REST, le multisite et un agent déjà installé.</p>
  <div class="filters">
    <input class="inp w-lg" id="add-url" placeholder="https://exemple.fr" value="${H(ADD.url)}">
    <button class="btn primary sm" id="add-scan">Analyser</button>
    <span id="add-msg" class="small"></span>
  </div>
  <div id="add-res">${ADD.info?addInfo(ADD.info):''}</div>`; }

function addInfo(i){ const shown=i.url_effective||i.home||ADD.url||'', u=safeUrl(shown),
    ns=Array.isArray(i.namespaces)?i.namespaces.join(' · '):'';
  return `<div class="kv mt4">
    <span class="k">Site</span><span><b>${H(i.name||'—')}</b></span>
    <span class="k">URL</span><span>${u?`<a href="${H(u)}" target="_blank" rel="noopener noreferrer">${H(shown)}</a>`:H(shown||'—')}</span>
    <span class="k">WordPress</span><span><span class="pill ${i.is_wordpress?'ok':'err'}">${i.is_wordpress?'détecté':'non détecté'}</span></span>
    <span class="k">API REST</span><span><span class="pill ${i.rest_open?'ok':'warn'}"${ns?` title="${H(ns)}"`:''}>${i.rest_open?'ouverte':'fermée ou filtrée'}</span></span>
    <span class="k">Agent Dash</span><span>${i.has_agent?'<span class="pill ok">déjà installé</span>':'<span class="pill mut">absent</span>'}${i.has_vizproof?' <span class="pill ok">VizProof présent</span>':''}</span>
    <span class="k">Multisite</span><span>${i.multisite?'<span class="pill warn">oui — réglages dans Réseau → Dash Agent</span>':'<span class="pill mut">non</span>'}</span>
    <span class="k">Dans le parc</span><span>${i.already_known?'<span class="pill warn">déjà connu du dashboard</span>':'<span class="pill ok">nouveau</span>'}</span></div>
  ${i.is_wordpress?'':'<p class="hint mt3">WordPress n\'a pas été reconnu à cette adresse : vérifiez l\'URL (redirection, sous-dossier, site en maintenance) avant de continuer.</p>'}
  <div class="actions mt4"><button class="btn primary sm" id="add-next">${i.is_wordpress?'Continuer':'Continuer quand même'}</button></div>`; }

async function addDiscover(){ const msg=document.getElementById('add-msg'), res=document.getElementById('add-res');
  const inp=document.getElementById('add-url'); if(inp) ADD.url=inp.value.trim();
  if(!ADD.url){ if(msg) msg.innerHTML='<span class="muted">indiquez une URL</span>'; return; }
  if(msg) msg.innerHTML='<span class="muted">analyse…</span>'; if(res) res.innerHTML='';
  let j; try{ j=await api('/api/mgmt/discover',{url:ADD.url})||{}; }
  catch(e){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; return; }
  if(!ADD.open) return;
  if(j.ok===false||!j||typeof j!=='object'){
    if(msg) msg.innerHTML=`<span class="pill err">analyse impossible</span> <span class="muted small">${H((j&&j.error)||'réponse vide')}</span>`;
    ADD.info=null; ADD.step=1; return; }
  ADD.info=j; ADD.domain=hostOf(j.url_effective||j.home||ADD.url);
  if(msg) msg.innerHTML='';
  if(res) res.innerHTML=addInfo(j);
  const nx=document.getElementById('add-next'); if(nx) nx.onclick=()=>{ ADD.step=2; addRender(); }; }

function addStep2(){ const i=ADD.info||{}, ssh=i.suggestion==='ssh';
  const card=(m,title,rec,txt)=>`<div class="card choice ${ADD.method===m?'sel':''}" data-m="${m}">
      <b>${H(title)}${rec?' <span class="pill ok">recommandé</span>':''}</b><small>${H(txt)}</small></div>`;
  return `<p class="hint">${ssh
      ? "Ce site est hébergé sur un serveur déjà connecté au dashboard : la voie SSH est la plus rapide."
      : "Aucun serveur SSH connu n'héberge ce site : l'appairage est la voie adaptée."}</p>
    <div class="cards">
      ${card('ssh','Via SSH',ssh,"Le serveur est déjà connecté : l'agent s'installe en une commande depuis « Installs découverts », sans rien toucher dans wp-admin.")}
      ${card('pair','Sans SSH (appairage)',!ssh,"L'API REST de WordPress n'installe que des extensions publiées sur wordpress.org, or notre agent est privé : on télécharge son ZIP, on l'installe depuis wp-admin, puis on colle un code d'appairage.")}
    </div>
    <div class="actions mt4"><button class="btn sm" id="add-back">← Retour</button></div>`; }

function addStep3(){ const i=ADD.info||{}, dom=ADD.domain||hostOf(ADD.url);
  if(ADD.method==='ssh') return `
    <p class="hint">Rien à installer à la main : la liaison se pose en SSH depuis la liste des installs.</p>
    <div class="steps"><ol class="small">
      <li>Dans « Installs découverts », repérez la ligne <b>${H(dom||'du site')}</b>.</li>
      <li>Colonne « Dashboard » : cliquez sur <b>Connecter</b>, puis confirmez le second clic.</li>
      <li>La pastille passe à <span class="pill ok">connecté</span> — le site pousse alors ses événements en temps réel.</li>
    </ol></div>
    <div class="actions mt4"><button class="btn sm" id="add-back">← Retour</button>
      <button class="btn primary sm" id="add-goinstalls">Aller à la ligne « ${H(dom||'?')} »</button>
      <span id="add-msg3" class="small"></span></div>`;
  return `
    <p class="hint">Environ deux minutes dans l'admin du site. L'agent est une extension privée : elle ne peut pas être installée à distance par l'API REST, d'où le ZIP + le code d'appairage.</p>
    <div class="actions">
      <a class="btn sm" id="add-zip" href="/api/mgmt/agent.zip" download>${icon('download')} Télécharger l'agent (.zip)</a>
      <button class="btn primary sm" id="add-gen">Générer un code</button>
      <span id="add-genmsg" class="small"></span>
    </div>
    <div id="add-code"></div>
    <div class="steps"><ol class="small">
      <li>Dans wp-admin : <b>Extensions → Ajouter → Téléverser une extension</b>, puis choisissez le ZIP téléchargé.</li>
      <li><b>Activer</b> l'extension.</li>
      <li>Ouvrez <b>${i.multisite?'Réseau → Dash Agent':'Réglages → Dash Agent'}</b>${i.multisite?' (site multisite : le réglage est au niveau du réseau)':' — en multisite, passez par <b>Réseau → Dash Agent</b>'}.</li>
      <li>Collez le code ci-dessus, puis validez.</li>
    </ol></div>
    <div id="add-wait" class="small muted mt3">Générez un code pour démarrer l'appairage.</div>
    <div class="actions mt4"><button class="btn sm" id="add-back">← Retour</button></div>`; }

function addWait(html){ const el=document.getElementById('add-wait'); if(el) el.innerHTML=html; }
function addTick(){ const el=document.getElementById('add-exp');
  if(!el||!ADD.open){ if(ADD.timer){ clearInterval(ADD.timer); ADD.timer=null; } return; }
  const s=Math.max(0,Math.ceil((ADD.expires-Date.now())/1000));
  if(s<=0){ el.innerHTML='<span class="pill err">code expiré — générez-en un nouveau</span>';
    clearInterval(ADD.timer); ADD.timer=null; return; }
  el.textContent='expire dans '+Math.floor(s/60)+':'+String(s%60).padStart(2,'0'); }

async function addGen(){ const msg=document.getElementById('add-genmsg');
  addStop(); if(msg) msg.innerHTML='<span class="muted">…</span>';
  let j; try{ j=await api('/api/mgmt/pair_code',{url:ADD.url})||{}; }
  catch(e){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; return; }
  if(!ADD.open) return;
  const code=String((j&&j.code)||'');
  if(!code){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H((j&&j.error)||'aucun code renvoyé')}</span>`; return; }
  if(msg) msg.innerHTML='';
  ADD.expires=Date.now()+(Number(j.expires_in)||0)*1000;
  const box=document.getElementById('add-code');
  if(box) box.innerHTML=`<div class="codebox"><span class="codebig" id="add-codeval">${H(code)}</span>
      <span class="muted small ml-8" id="add-exp"></span></div>
    <div class="muted small">Code à usage unique : cliquez dessus pour le sélectionner.</div>`;
  addTick(); ADD.timer=setInterval(addTick,1000);
  ADD.pollUntil=Date.now()+360000;
  addWait('<span class="pill warn">en attente d\'appairage…</span> <span class="muted small">vérification toutes les 5 s</span>');
  ADD.poll=setTimeout(addPoll,5000); }

async function addPoll(){ ADD.poll=null; if(!ADD.open) return;
  if(Date.now()>ADD.pollUntil){ addWait('<span class="pill mut">appairage non détecté</span> <span class="muted small">générez un nouveau code et réessayez.</span>'); return; }
  let j=null; try{ j=await api('/api/mgmt/rest_sites'); }catch(e){}
  if(!ADD.open) return;
  const want=ADD.domain||hostOf(ADD.url);
  const hit=restList(j).some(x=>x&&hostOf(restDomain(x)||x.url)===want);
  if(hit){ addStop();
    addWait(`<span class="pill ok">${icon('circle-check')} site appairé</span> <span class="muted small">il apparaît maintenant dans le parc.</span>
      ${WPAUTH_ENABLED?`<div class="mt3"><button class="btn primary sm" id="add-wpauth">${icon('link')} Autoriser l'installation d'extensions (1 clic)</button>
        <span id="add-wpmsg" class="small"></span>
        <div class="muted small mt1"><b>Étape facultative.</b> ${H(WPAUTH_HELP)} Le dashboard pourra alors installer les extensions publiques (VizProof…) sans SSH.</div></div>`:''}`);
    const ab=document.getElementById('add-wpauth');
    if(ab) ab.onclick=()=>wpAuthorize(ab,'',want,(ok,err)=>{ const m=document.getElementById('add-wpmsg'); if(!m) return;
      m.innerHTML=ok?'<span class="pill warn">approuvez dans l\'onglet ouvert…</span>'
        :`<span class="pill err">échec</span> <span class="muted small">${H(err)}</span>`; });
    loadRestSites(); loadFleet(); return; }
  ADD.poll=setTimeout(addPoll,5000); }

function addGoInstalls(){ const dom=ADD.domain||hostOf(ADD.url), msg=document.getElementById('add-msg3');
  let btn=document.querySelector(`[data-dashconn="${CSS.escape(dom)}"]`);
  if(!btn) btn=[...document.querySelectorAll('[data-dashconn]')].find(b=>hostOf(b.dataset.dashconn)===dom)||null;
  if(!btn){ if(msg) msg.innerHTML='<span class="pill warn">ligne introuvable</span> <span class="muted small">lancez une collecte pour que le site apparaisse.</span>'; return; }
  closeAdd();
  const tr=btn.closest('tr');
  btn.scrollIntoView({block:'center'});
  if(tr){ tr.classList.add('flash'); setTimeout(()=>{ tr.classList.remove('flash'); },4000); } }

/* ===== AUTORISATION WORDPRESS (mot de passe d'application, 1 clic) ===== */
const WPAUTH_HELP="Vous serez redirigé vers l'administration du site pour approuver la connexion. WordPress crée alors un mot de passe d'application dédié, révocable à tout moment depuis le profil utilisateur.";
/* ouvre le flux natif authorize-application.php dans un onglet ; after(ok,erreur) pour le retour d'écran */
/* Autorisation WordPress (mot de passe d'application) : interrupteur global,
   conservé pour pouvoir masquer d'un coup tout le parcours d'autorisation. */
const WPAUTH_ENABLED=true;
async function wpAuthorize(btn,server,domain,after){
  const lbl=btn.innerHTML; setBusy(btn);
  let j=null; try{ j=await api('/api/mgmt/wp_authorize',{server:server||'',domain}); }catch(e){ j={error:String(e)}; }
  setIdle(btn,lbl);
  const u=safeUrl(j&&j.authorize_url);
  if(!u){ if(after) after(false,(j&&j.error)||"aucune URL d'autorisation renvoyée"); return false; }
  window.open(u,'_blank','noopener');
  if(after) after(true,''); return true; }

/* bandeau de retour : /?wpauth=ok|refuse|expired|invalid|error&domain=… */
let WPAUTHTO=null;
function wpauthBanner(){
  let p; try{ p=new URLSearchParams(location.search); }catch(e){ return; }
  const stt=p.get('wpauth'); if(!stt) return;
  const dom=p.get('domain')||'', cible=dom?'<b>'+H(dom)+'</b>':'ce site';
  const M={ ok:['ok','autorisé','Site autorisé — le dashboard peut désormais installer des extensions sur '+cible+'.'],
    refuse:['warn','refusé',"Autorisation refusée sur le site : la connexion n'a pas été approuvée dans wp-admin."],
    expired:['warn','expiré',"Lien d'autorisation expiré, relancez la connexion depuis le dashboard."],
    invalid:['err','erreur',"L'autorisation n'a pas pu être validée. Relancez la connexion depuis la page du site."],
    error:['err','erreur',"L'autorisation a échoué. Vérifiez que le site est joignable, puis relancez la connexion."] };
  const [cls,tag,txt]=M[stt]||M.error;
  const box=document.getElementById('wpauthbox'), msg=document.getElementById('wpauth-msg');
  if(!box||!msg) return;
  msg.innerHTML=`<span class="pill ${cls}">${H(tag)}</span> ${txt}`;
  box.hidden=false;
  try{ history.replaceState(null,'',location.pathname+location.hash); }catch(e){}
  loadFleet();
  if(WPAUTHTO) clearTimeout(WPAUTHTO);
  WPAUTHTO=setTimeout(()=>{ box.hidden=true; WPAUTHTO=null; },6000); }

/* état des identifiants dans la page d'un site REST */
let WPCSEQ=0;
async function loadWpCred(srv,dom){
  const seq=++WPCSEQ; const cell=document.getElementById('wpcred'); if(!cell) return;
  if(!WPAUTH_ENABLED){   // backend d'autorisation absent : on n'interroge rien
    cell.innerHTML='<span class="pill mut">aucun</span> <span class="muted small">inventaire en lecture seule, aucune action distante possible.</span>';
    wpCredActions(false); return; }
  let j=null; try{ j=await api('/api/mgmt/wp_credentials?domain='+encodeURIComponent(dom)); }catch(e){ j=null; }
  if(seq!==WPCSEQ) return; const c=document.getElementById('wpcred'); if(!c) return;
  if(!j||typeof j!=='object'||j.error){ c.innerHTML='<span class="muted small">état des identifiants indisponible</span>'; wpCredActions(false); return; }
  wpCredRender(c,srv,dom,j); }

function wpCredRender(c,srv,dom,j){
  const has=!!j.has_password;
  if(has){
    c.innerHTML=`<span class="pill ok">autorisé${j.user?' · '+H(j.user):''}</span>`
      +(j.verified===false?' <span class="pill warn" title="dernier contrôle non concluant">à vérifier</span>':'')
      +(j.checked_ts?` <span class="muted small" title="${H(absTime(j.checked_ts))}">contrôlé ${H(relTime(j.checked_ts))}</span>`:'')
      +` <button class="btn sm" data-wprevoke="${H(dom)}">Révoquer</button> <span data-wpmsg class="small"></span>`;
  } else if(!WPAUTH_ENABLED){
    c.innerHTML='<span class="pill mut">aucun</span> <span class="muted small">le dashboard n\'a pas d\'identifiant WordPress sur ce site (inventaire en lecture seule).</span>';
  } else {
    c.innerHTML=`<span class="pill warn">non autorisé</span>
      <button class="btn sm primary" data-wpauth="${H(dom)}">${icon('link')} Autoriser en un clic</button> <span data-wpmsg class="small"></span>
      <div class="muted small mt1">${H(WPAUTH_HELP)}</div>`;
  }
  const msg=c.querySelector('[data-wpmsg]');
  const ab=c.querySelector('[data-wpauth]');
  if(ab) ab.onclick=()=>wpAuthorize(ab,srv,dom,(ok,err)=>{
    if(!ok){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(err)}</span>`; return; }
    if(msg) msg.innerHTML='<span class="pill warn">en attente d\'approbation…</span>';
    ab.innerHTML=icon('refresh-cw')+' Vérifier'; ab.classList.remove('primary');
    ab.onclick=()=>{ if(msg) msg.innerHTML='<span class="muted">…</span>'; loadWpCred(srv,dom); }; });
  const rb=c.querySelector('[data-wprevoke]');
  if(rb) rb.onclick=()=>confirm2(rb,async()=>{
    setBusy(rb);
    try{ const r=await api('/api/mgmt/wp_credentials/delete',{domain:dom})||{};
      if(r.ok===false){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(r.error||'')}</span>`;
        setIdle(rb,'Révoquer'); return; }
      loadWpCred(srv,dom);
    }catch(e){ if(msg) msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`;
      setIdle(rb,'Révoquer'); } });
  wpCredActions(has); }

/* avec des identifiants, l'installation d'extensions publiques redevient possible sans SSH */
function wpCredActions(has){
  const slot=document.getElementById('rest-vizslot'), note=document.getElementById('rest-note');
  if(slot){ const can=has&&store.cur&&!(vizOf(store.cur)||vizInfo(store.cur));
    slot.innerHTML=can?'<button class="btn sm" data-act="vizproof_install">Installer vizproof</button> ':'';
    slot.querySelectorAll('[data-act]').forEach(b=>b.onclick=()=>confirmRun(b)); }
  if(note) note.innerHTML=has
    ? "Site géré <b>sans SSH</b> : seules les installations d'extensions publiques sont possibles via l'autorisation WordPress."
    : `Site géré <b>sans SSH</b> : l'agent est en lecture seule, les actions distantes (mises à jour, backup, checksums, caches)
       ne sont pas disponibles ici. À faire depuis wp-admin, ou en rattachant le serveur en SSH depuis Gestion → Serveurs.`; }

registerModalCloser('addmodal',closeAdd);

export { loadMgmt, loadCandidates, loadRestSites, loadWpCred, wpauthBanner, openAdd };

