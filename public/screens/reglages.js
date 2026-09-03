/* Écran Réglages — en phase 1 c'est encore une modale : cadence de collecte,
   clés SSH, mise à jour sûre, jeton VizProof, alertes Telegram.
   La phase 4 en fera une page à sections. */

import { api } from '../lib/api.js';
import { esc as H } from '../lib/dom.js';
import { icon } from '../lib/icons.js';
import { store } from '../lib/state.js';
import { askConfirm } from '../components/confirm.js';
import { setBusy, setIdle } from '../components/button.js';
import { loadSched } from '../components/shell.js';

/* ===== RÉGLAGES — clés SSH ===== */
let KEYS=null;
function keyOpts(cur){ return (KEYS?.keys||[]).map(k=>`<option value="${H(k.path)}"${k.path===cur?' selected':''}>${H(k.name)}</option>`).join(''); }
function refreshKeySelects(){ document.querySelectorAll('#set-body select[data-akey], #set-body select#k-allsel').forEach(sel=>{ sel.innerHTML=keyOpts(sel.value); }); }
/* Ouvre la modale Réglages. La coque l'appelle depuis la barre latérale ET
   depuis la route #reglages : le bouton n'est plus le seul chemin. */
function ouvrirReglages(){ document.getElementById('setmodal').classList.add('open');
  loadSchedule(); loadKeys(); loadSettings(); loadAlerts(); }
document.getElementById('setbtn').onclick=ouvrirReglages;
document.getElementById('setmodal').onclick=e=>{ if(e.target.id==='setmodal') e.target.classList.remove('open'); };

async function loadKeys(){ const bd=document.getElementById('set-body');
  bd.innerHTML='<span class="muted small">chargement…</span>';
  try{ KEYS=await api('/api/mgmt/sshkeys'); }catch(e){ bd.innerHTML=`<span class="pill err">erreur de chargement</span> <span class="muted small">${H(String(e))}</span>`; return; }
  const keys=KEYS.keys||[], asg={}; (KEYS.assignments||[]).forEach(a=>asg[a.server]=a.key);
  const srvNames=[...new Set([...(store.fleet?.servers||[]).map(s=>s.name),...(KEYS.assignments||[]).map(a=>a.server)])].sort();
  const keyRows=keys.length?keys.map((k,i)=>
    `<tr><td><b>${H(k.name)}</b><div class="sub">${H(k.path||'')}</div></td><td><span class="pill mut">${H(k.type||'?')}</span></td>
      <td class="sub">${H(k.fingerprint||'')}</td>
      <td><button class="btn sm" data-pub="${i}">voir la clé publique</button></td></tr>
     <tr data-pubrow="${i}" hidden><td colspan="4"><textarea class="code short" readonly>${H(k.pub||'')}</textarea></td></tr>`).join('')
    :'<tr><td colspan="4"><span class="muted small">aucune clé détectée</span></td></tr>';
  const asgRows=srvNames.length?srvNames.map(n=>
    `<tr><td><b>${H(n)}</b></td><td><select data-akey="${H(n)}">${keyOpts(asg[n])}</select></td>
      <td><button class="btn sm" data-ktest="${H(n)}">Tester</button> <button class="btn sm" data-kassign="${H(n)}">Assigner</button>
      <span data-kres="${H(n)}" class="small"></span></td></tr>`).join('')
    :'<tr><td colspan="3"><span class="muted small">aucun serveur</span></td></tr>';
  bd.innerHTML=`
    <h3>Clés disponibles</h3>
    <p class="hint">La clé publique sert à l'enrôlement manuel sur les serveurs (<code>~/.ssh/authorized_keys</code>).</p>
    <div class="wrap"><table><thead><tr><th>Nom</th><th>Type</th><th>Fingerprint</th><th></th></tr></thead><tbody>${keyRows}</tbody></table></div>
    <h3>Générer une clé dédiée</h3>
    <div class="filters"><input class="inp w-sm" id="k-name" placeholder="dashboard">
      <button class="btn sm" id="k-gen">Générer</button> <span id="k-genmsg" class="small"></span></div>
    <div id="k-genout"></div>
    <h3>Affectation par serveur</h3>
    <p class="hint">${icon('triangle-alert')} Assigner une clé non enrôlée casse la collecte du serveur concerné — toujours tester avant d'assigner.</p>
    <div class="wrap"><table><thead><tr><th>Serveur</th><th>Clé</th><th></th></tr></thead><tbody>${asgRows}</tbody></table></div>
    <div class="filters mt3"><select id="k-allsel">${keyOpts('')}</select>
      <button class="btn sm danger" id="k-all">Assigner cette clé à TOUS les serveurs</button> <span id="k-allmsg" class="small"></span></div>`;
  bd.querySelectorAll('[data-pub]').forEach(b=>b.onclick=()=>{ const r=bd.querySelector(`[data-pubrow="${b.dataset.pub}"]`);
    r.hidden=!r.hidden; b.textContent=r.hidden?'voir la clé publique':'masquer la clé publique'; });
  bd.querySelectorAll('[data-ktest]').forEach(b=>b.onclick=async()=>{ const n=b.dataset.ktest;
    const k=bd.querySelector(`[data-akey="${CSS.escape(n)}"]`).value, res=bd.querySelector(`[data-kres="${CSS.escape(n)}"]`);
    setBusy(b); res.innerHTML='';
    try{ const j=await api('/api/mgmt/sshkeys/test',{server:n,key:k});
      res.innerHTML=`<span class="pill ${j.ok?'ok':'err'}">${j.ok?'joignable':'échec'}</span> <span class="muted small">${H((j.output||'').slice(-160))}</span>`;
    }catch(e){ res.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; }
    setIdle(b,'Tester'); });
  bd.querySelectorAll('[data-kassign]').forEach(b=>b.onclick=async()=>{ const n=b.dataset.kassign;
    const k=bd.querySelector(`[data-akey="${CSS.escape(n)}"]`).value, res=bd.querySelector(`[data-kres="${CSS.escape(n)}"]`);
    if(!k) return;
    if(!await askConfirm(`Assigner cette clé au serveur <b>${H(n)}</b> ?<br><br>Si elle n'y est pas enrôlée, la collecte de ce serveur cassera.`,
      {titre:'Assigner une clé',ok:'Assigner',danger:true})) return;
    setBusy(b);
    try{ const j=await api('/api/mgmt/sshkeys/assign',{server:n,key:k});
      res.innerHTML=j.ok?'<span class="pill ok">assignée</span>':`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'')}</span>`;
    }catch(e){ res.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; }
    setIdle(b,'Assigner'); });
  document.getElementById('k-gen').onclick=async()=>{ const name=(document.getElementById('k-name').value||'dashboard').trim();
    const msg=document.getElementById('k-genmsg'), out=document.getElementById('k-genout'); msg.textContent='…'; out.innerHTML='';
    try{ const j=await api('/api/mgmt/sshkeys/generate',{name});
      if(!j.ok){ msg.innerHTML=`<span class="pill err">${H(j.error||'échec — cette clé existe déjà ?')}</span>`; return; }
      msg.innerHTML='<span class="pill ok">créée</span>';
      out.innerHTML=`<p class="hint">Clé publique à enrôler sur les serveurs (<code>~/.ssh/authorized_keys</code>), puis assigner ci-dessous.</p>
        <textarea class="code short" readonly>${H(j.pub||'')}</textarea>
        <div class="muted small">${H(j.path||'')}</div>`;
      KEYS.keys=[...(KEYS.keys||[]),{name,path:j.path,type:'',pub:j.pub,fingerprint:''}]; refreshKeySelects();
    }catch(e){ msg.innerHTML=`<span class="pill err">${H(String(e))}</span>`; } };
  document.getElementById('k-all').onclick=async()=>{ const k=document.getElementById('k-allsel').value; if(!k) return;
    const kn=(KEYS.keys||[]).find(x=>x.path===k), msg=document.getElementById('k-allmsg');
    if(!await askConfirm(`Assigner la clé <b>${H(kn?kn.name:k)}</b> à <b>TOUS</b> les serveurs ?<br><br>Tout serveur où elle n'est pas enrôlée deviendra injoignable.`,
      {titre:'Assigner à tous les serveurs',ok:'Assigner partout',danger:true})) return;
    msg.textContent='…';
    try{ const j=await api('/api/mgmt/sshkeys/assign',{server:'*',key:k});
      msg.innerHTML=j.ok?'<span class="pill ok">assignée partout</span>':`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'')}</span>`;
      if(j.ok) setTimeout(loadKeys,1500);
    }catch(e){ msg.innerHTML=`<span class="pill err">${H(String(e))}</span>`; } }; }

/* ===== RÉGLAGES — mise à jour sûre =====
   store.settings est mémorisé : la modale de confirmation de la MAJ sûre pré-coche sa
   case avec ce réglage sans refaire un aller-retour réseau à chaque ouverture. */
/* Les valeurs par défaut vivent dans le store ; ici on ne retient que le fait
   d'avoir déjà interrogé le serveur. */
let SETTINGSLU=false;
/* Lecture paresseuse : la modale de MAJ sûre a besoin du réglage même si
   personne n'a jamais ouvert Réglages. Un seul appel par session. */
async function ensureSettings(){ if(SETTINGSLU) return store.settings;
  try{ const j=await api('/api/mgmt/settings');
    if(j&&j.settings&&typeof j.settings==='object') store.settings=j.settings; SETTINGSLU=true;
  }catch(e){}
  return store.settings; }
async function loadSettings(){ const bd=document.getElementById('mset-body');
  bd.innerHTML='<span class="muted small">chargement…</span>';
  let j; try{ j=await api('/api/mgmt/settings'); }
  catch(e){ bd.innerHTML=`<span class="pill mut">réglages indisponibles</span> <span class="muted small">${H(String(e))}</span>`;
    renderVizSettings(store.settings); return; }
  if(j&&j.settings&&typeof j.settings==='object'){ store.settings=j.settings; SETTINGSLU=true; }
  bd.innerHTML=`<label class="fld"><input type="checkbox" id="set-vizrb"${store.settings.viz_anomaly_rollback?' checked':''}>
      Retour arrière automatique sur anomalie visuelle</label>
    <span id="set-vizrbmsg" class="small muted"></span>
    <p class="hint hint-loose">Décoché (défaut) : une anomalie détectée par VizProof après une mise à jour est
      <b>signalée</b> et la mise à jour est conservée — le verdict devient « réussie avec anomalies visuelles ».
      Coché : la mise à jour est <b>annulée</b> automatiquement. Un rendu qui change n'est pas toujours un rendu cassé
      (bandeau de cookies, carrousel, publicité), d'où le défaut prudent côté « avertir ».</p>
    <label class="fld mt3"><input type="checkbox" id="set-vizscan"${store.settings.viz_scan_after_update===false?'':' checked'}>
      Contrôle visuel VizProof après chaque mise à jour (verdict du scan lancé par le plugin, sinon scan par le dashboard)</label>
    <span id="set-vizscanmsg" class="small muted"></span>
    <p class="hint hint-loose">Coché (défaut) : après une mise à jour lancée depuis le tiroir (cœur, extensions,
      thèmes), le dashboard récupère en arrière-plan le verdict visuel des sites reliés à VizProof. L'extension
      <b>scanne d'elle-même</b> après chaque mise à jour quand son option « scan après mise à jour » est active : on attend
      donc <b>son</b> scan plutôt que d'en lancer un second, et on ne scanne nous-mêmes que si elle ne l'a pas fait. Il
      <b>informe seulement</b> — le bouton unitaire n'archive rien, il n'y a donc rien à annuler ; le résultat s'affiche dans
      la barre de notifications, dans la console du tiroir et dans l'historique du site.</p>
    <label class="fld mt3"><input type="checkbox" id="set-vizbase"${store.settings.viz_baseline_before_update===false?'':' checked'}>
      Baseline VizProof avant chaque mise à jour unitaire (sites reliés)</label>
    <span id="set-vizbasemsg" class="small muted"></span>
    <p class="hint hint-loose">Coché (défaut) : sur un site relié, la mise à jour lancée depuis le tiroir part
      dans un <b>déroulé suivi</b> — baseline VizProof, mise à jour, verdict visuel, inventaire — au lieu d'être exécutée
      d'un bloc. Sans baseline, le contrôle d'après compare au <b>dernier état connu</b> de VizProof, qui peut dater de la
      veille et mêler d'autres changements ; avec elle, le verdict porte sur <b>cette</b> mise à jour.</p>
    <label class="fld mt3"><input type="checkbox" id="set-vizbasereq"${store.settings.viz_baseline_required?' checked':''}>
      Exiger la baseline : ne pas mettre à jour si elle échoue</label>
    <span id="set-vizbasereqmsg" class="small muted"></span>
    <p class="hint hint-loose">Décoché (défaut) : une baseline ratée est un <b>avertissement</b> et la mise à
      jour se fait quand même — VizProof est un filet, pas une condition. Coché : la mise à jour est <b>annulée</b> tant
      qu'aucun témoin d'avant n'a pu être pris.</p>`;
  bindSetting('set-vizrb','viz_anomaly_rollback');
  bindSetting('set-vizscan','viz_scan_after_update');
  bindSetting('set-vizbase','viz_baseline_before_update');
  bindSetting('set-vizbasereq','viz_baseline_required');
  renderVizSettings(store.settings); }
/* Une case = un réglage booléen, enregistré à la volée. Le témoin voisin porte
   le même identifiant suffixé « msg » ; en cas d'échec la case revient à son
   état d'avant, pour ne jamais afficher un réglage qui n'a pas été écrit. */
function bindSetting(id,cle){
  const el=document.getElementById(id); if(!el) return;
  const m=document.getElementById(id+'msg');
  el.onchange=async e=>{
    const v=e.target.checked; if(m) m.textContent='…';
    try{ const r=await api('/api/mgmt/settings',{settings:{[cle]:v}});
      if(r&&r.settings) store.settings=r.settings;
      if(m) m.innerHTML='<span class="pill ok">enregistré</span>';
    }catch(err){ e.target.checked=!v;
      if(m) m.innerHTML=`<span class="pill err">échec</span> ${H(String(err))}`; }
    setTimeout(()=>{ if(m) m.innerHTML=''; },2500); }; }

/* ===== RÉGLAGES — VizProof (jeton de compte) =====
   Même modèle que le jeton Telegram : le champ reste vide, la valeur
   enregistrée n'est jamais renvoyée par l'API — seuls un témoin et les
   4 derniers caractères reviennent. Vide à l'enregistrement = inchangé ;
   effacer est un geste explicite. */
function renderVizSettings(cfg){
  const bd=document.getElementById('viz-body'); if(!bd) return;
  cfg=cfg||{};
  const pose=!!cfg.vizproof_token_set;
  const ph=pose?`token enregistré (…${cfg.vizproof_token_tail||''}) — laisser vide pour le conserver`
                :'vrt_… (VizProof → Réglages → API)';
  bd.innerHTML=`<div class="filters">
      <input class="inp w-lg" id="viz-token" type="password" autocomplete="off" spellcheck="false"
             aria-label="token VizProof" placeholder="${H(ph)}">
      <button class="btn primary sm" id="viz-save">Enregistrer</button>
      <button class="btn sm" id="viz-test"${pose?'':' disabled'}>Tester</button>
      <button class="btn sm" id="viz-forget"${pose?'':' disabled'}>Effacer</button>
      <span id="viz-msg" class="small"></span>
    </div>
    <p class="hint hint-loose">Le token se crée dans <b>VizProof → Réglages → API</b> ; il sert à retrouver ou créer le site VizProof d'après l'URL, puis à relier le plugin.</p>
    <p class="hint hint-loose"><button class="btn sm" id="viz-advbtn">Options avancées</button></p>
    <div id="viz-advset" hidden><div class="filters filters-baseline">
      <label class="fld small">base API
        <input class="inp w-md" id="viz-base" autocomplete="off" spellcheck="false"
               value="${H(cfg.vizproof_api_base||'')}" placeholder="https://vizproof.com"></label>
      <button class="btn sm" id="viz-basesave">Enregistrer la base</button>
    </div></div>`;
  // `dire` relit l'élément à chaque fois : un enregistrement réussi redessine
  // la section (placeholder du token, boutons activés) et détache l'ancien.
  const dire=(html,ms)=>{ const m=document.getElementById('viz-msg'); if(!m) return;
    m.innerHTML=html;
    if(ms) setTimeout(()=>{ const m2=document.getElementById('viz-msg');
      if(m2&&m2.innerHTML===html) m2.innerHTML=''; },ms); };
  const majuscule=j=>{ if(j&&j.settings){ store.settings=j.settings; SETTINGSLU=true; renderVizSettings(store.settings); } };
  document.getElementById('viz-advbtn').onclick=()=>{ const b=document.getElementById('viz-advset');
    b.hidden=!b.hidden; document.getElementById('viz-advbtn').textContent=b.hidden?'Options avancées':'Masquer les options'; };
  document.getElementById('viz-save').onclick=async()=>{
    const v=document.getElementById('viz-token').value.trim();
    if(!v){ dire('<span class="pill mut">rien à enregistrer</span> <span class="muted">saisissez un token.</span>',3000); return; }
    dire('<span class="muted">…</span>');
    try{ const j=await api('/api/mgmt/settings',{settings:{vizproof_token:v}})||{};
      if(j.error||!j.settings){ dire(`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'réponse vide')}</span>`); return; }
      majuscule(j); dire('<span class="pill ok">enregistré</span>',2500);
    }catch(e){ dire(`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`); } };
  document.getElementById('viz-test').onclick=async()=>{
    dire('<span class="muted">…</span>');
    try{ const j=await api('/api/mgmt/vizproof/test',{})||{};
      dire(j.ok?`<span class="pill ok">${H(j.total??'?')} site(s) accessible(s)</span>`
               :`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'')}</span>`);
    }catch(e){ dire(`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`); } };
  document.getElementById('viz-forget').onclick=async()=>{
    if(!await askConfirm("Effacer le token VizProof enregistré ?<br><br>Les connexions « en un clic » demanderont de nouveau un token.",
        {titre:'Effacer le token VizProof',ok:'Effacer',danger:true})) return;
    dire('<span class="muted">…</span>');
    try{ const j=await api('/api/mgmt/settings',{settings:{vizproof_token:''},vizproof_token_clear:true})||{};
      majuscule(j); dire('<span class="pill ok">effacé</span>',2500);
    }catch(e){ dire(`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`); } };
  document.getElementById('viz-basesave').onclick=async()=>{
    dire('<span class="muted">…</span>');
    try{ const j=await api('/api/mgmt/settings',
                           {settings:{vizproof_api_base:document.getElementById('viz-base').value.trim()}})||{};
      if(j.error||!j.settings){ dire(`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'réponse vide')}</span>`); return; }
      majuscule(j); dire('<span class="pill ok">base enregistrée</span>',2500);
    }catch(e){ dire(`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`); } }; }

/* ===== RÉGLAGES — alertes Telegram ===== */
const AL_CHK=[['new_admin','nouvel administrateur'],['checksum_fail','checksums en anomalie'],['viz_anomaly','anomalie visuelle VizProof'],['site_down','site down (Kuma)']];
const AL_NUM=[['backup_stale_h','backup plus vieux que (h)',48],['cert_days','certificat expirant sous (j)',21],['collect_dead_h','collecte muette depuis (h)',6]];
/* Cadence de la collecte automatique (réécrit le cron côté serveur) */
const SCHED_LABELS={0:'désactivée (manuelle uniquement)',15:'toutes les 15 minutes',30:'toutes les 30 minutes',
  60:'toutes les heures',120:'toutes les 2 heures',180:'toutes les 3 heures',360:'toutes les 6 heures',
  720:'toutes les 12 heures',1440:'une fois par jour (3h17)'};
async function loadSchedule(){ const bd=document.getElementById('sched-body');
  let s; try{ s=await api('/api/mgmt/schedule'); }catch(e){ bd.innerHTML='<span class="pill mut">cadence indisponible</span>'; return; }
  const ch=(s.choices||[0,60]);
  bd.innerHTML=`<div class="filters filters-flat">
      <select id="sched-sel" aria-label="Cadence de collecte">${ch.map(v=>`<option value="${H(v)}"${v===s.interval_minutes?' selected':''}>${H(SCHED_LABELS[v]||v+' min')}</option>`).join('')}</select>
      <button class="btn sm" id="sched-save">Enregistrer</button>
      <span id="sched-msg" class="small muted">${s.cron?'cron actuel : <code>'+H(s.cron)+'</code>':''}</span>
    </div>
    <p class="hint hint-loose">Une collecte complète du parc prend environ 1 min 30. Le bouton « Collecter » reste disponible à tout moment.</p>`;
  document.getElementById('sched-save').onclick=async()=>{
    const v=parseInt(document.getElementById('sched-sel').value,10);
    const m=document.getElementById('sched-msg'); m.textContent='…';
    try{ const r=await api('/api/mgmt/schedule',{interval_minutes:v}); loadSched();
      m.innerHTML=r.ok?('enregistré — cron : <code>'+H(r.cron||'désactivé')+'</code>'):('échec — '+H(r.error||'inconnu'));
    }catch(e){ m.textContent='erreur réseau'; } }; }

async function loadAlerts(){ const bd=document.getElementById('alert-body');
  bd.innerHTML='<span class="muted small">chargement…</span>';
  let a; try{ a=await api('/api/mgmt/alerts'); }
  catch(e){ bd.innerHTML=`<span class="pill mut">alertes indisponibles</span> <span class="muted small">${H(String(e))}</span>`; return; }
  if(!a||typeof a!=='object'||a.error){ bd.innerHTML=`<span class="pill mut">alertes indisponibles</span> <span class="muted small">${H((a&&a.error)||'réponse vide')}</span>`; return; }
  const r=(a.rules&&typeof a.rules==='object')?a.rules:{};
  const ph=a.token_set?`token enregistré (${a.token_tail||'…'}) — laisser vide pour le conserver`:'bot_token (ex. 123456789:AA…)';
  bd.innerHTML=`
    <p class="hint">Créez le bot avec <b>@BotFather</b> sur Telegram (commande <code>/newbot</code>) pour obtenir le <code>bot_token</code> ; écrivez ensuite un message au bot et relevez votre <code>chat_id</code> via <b>@userinfobot</b> ou sur <code>api.telegram.org/bot&lt;token&gt;/getUpdates</code>.</p>
    <div class="filters">
      <label class="fld"><input type="checkbox" id="al-enabled"${a.enabled?' checked':''}> alertes activées</label>
      <input class="inp w-lg" id="al-token" type="password" autocomplete="new-password" placeholder="${H(ph)}">
      <input class="inp w-sm" id="al-chat" value="${H(a.chat_id??'')}" placeholder="chat_id (ex. -1001234567890)">
    </div>
    <p class="hint mhead"><b>Déclencheurs</b></p>
    <div>${AL_CHK.map(([k,l])=>`<label class="fld"><input type="checkbox" data-arule="${k}"${r[k]?' checked':''}> ${H(l)}</label>`).join('')}</div>
    <div class="mt1">${AL_NUM.map(([k,l,d])=>`<label class="fld">${H(l)} <input class="inp w-num" type="number" min="0" step="1" data-arule="${k}" value="${H(r[k]??d)}"></label>`).join('')}</div>
    <div class="filters mt3">
      <button class="btn primary sm" id="al-save">Enregistrer</button>
      <button class="btn sm" id="al-test">Envoyer un test</button>
      <span id="al-msg" class="small"></span>
    </div>
    <p class="hint hint-loose">Le test utilise la configuration enregistrée : pensez à enregistrer avant.</p>`;
  document.getElementById('al-save').onclick=async()=>{ const msg=document.getElementById('al-msg'); msg.innerHTML='<span class="muted">…</span>';
    const rules={}; bd.querySelectorAll('[data-arule]').forEach(el=>{
      if(el.type==='checkbox') rules[el.dataset.arule]=el.checked;
      else { const v=el.value.trim(); rules[el.dataset.arule]=v===''?null:Number(v); } });
    const body={enabled:document.getElementById('al-enabled').checked,token:document.getElementById('al-token').value,
      chat_id:document.getElementById('al-chat').value.trim(),rules};
    try{ const j=await api('/api/mgmt/alerts',body)||{};
      if(j.ok===false){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'')}</span>`; return; }
      document.getElementById('al-token').value=''; msg.innerHTML='<span class="pill ok">enregistré</span>';
    }catch(e){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; } };
  document.getElementById('al-test').onclick=async()=>{ const msg=document.getElementById('al-msg'); msg.innerHTML='<span class="muted">…</span>';
    try{ const j=await api('/api/mgmt/alerts/test',{})||{};
      msg.innerHTML=j.ok?'<span class="pill ok">message envoyé</span>'
        :`<span class="pill err">échec</span> <span class="muted small">${H(j.error||'')}</span>`;
    }catch(e){ msg.innerHTML=`<span class="pill err">échec</span> <span class="muted small">${H(String(e))}</span>`; } }; }

export { ensureSettings, loadKeys, loadSettings, loadAlerts, loadSchedule, ouvrirReglages };

