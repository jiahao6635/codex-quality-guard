const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('web/index.html','utf8'),script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
// A small DOM stub exercises the actual page script and bridge contract, without a UI test dependency.
class El {
 constructor(tag='div'){this.tag=tag;this.children=[];this.textContent='';this.dataset={};this.style={};this.attributes={};this.value='';}
 append(...e){this.children.push(...e);}
 replaceChildren(...e){this.children=e;}
 setAttribute(k,v){this.attributes[k]=v;}
 showModal(){this.open=true;}
 close(){this.open=false;}
 focus(){}
 select(){this.selected=true;}
}
const clone=v=>JSON.parse(JSON.stringify(v));
const count=b=>b.attempts.filter(a=>!a.error&&a.number_count!=null).length;
let serial=0;
const attempt=(error=null)=>({at_ms:Date.now(),challenge_id:'test-'+(++serial),prompt:'prompt <script>',expected_count:300,request_id:'req',output:error?null:'1, 2, 3 <script>',number_count:error?null:300,error});
const flatten=e=>[e,...e.children.flatMap(flatten)];
async function boot({initial=0,failures=0,budgetStop=false,stopAfter=0,visualFailures=0,logicVerdict='pass',logicFailure=false,settingsPage=false,settingsFailure=null,customOutput=4096,missingAccount=false}={}){
 const els=new Map(),ctx={TextDecoder,Date,Number,JSON,Boolean,Error,console,setInterval,clearInterval,encodeURIComponent};
 let posts=0,reads=0,evidenceReads=0,visualPosts=0,visualReads=0,logicPosts=0,logicReads=0,reviews=0,settingsReads=0,settingsPosts=0;
 const targets=[],batch={started_at_ms:Date.now(),completed_at_ms:null,model:'gpt-test',attempts:Array.from({length:initial},()=>attempt()),score:null,verdict:null,error:null};
 const accounts=['one','two'].map(id=>({account_id:'acct-'+id,name:'OpenAI '+id,email:id+'@example.test',enabled:true,quality:{phase:'pending',lease_until_ms:0,next_probe_at_ms:0},batch:id==='one'&&initial?batch:null,history:[],last_sample:null,visual_tests:[],logic_tests:[]}));
 const status={enabled:true,key_scopes_ok:true,probe_budget_ok:true,auto_probe:false,maintenance:{ok:true},model:'gpt-test',visual_models:['gpt-test','gpt-other','gpt-6-astra'],visual_efforts:['low','medium','high'],visual_timeout_ms:110000,probe_limits:{max_daily_attempts:6,max_output_tokens:4096,max_daily_output_tokens:24576},budget:{day:Math.floor(Date.now()/86400000),attempts:initial,reserved_output_tokens:initial*4096},accounts};
 const settings={revision:7,config:{enabled:true,auto_probe:false,account_ids:missingAccount?['acct-one','acct-missing']:['acct-one'],model:'gpt-test',max_daily_attempts:6,max_output_tokens:customOutput},accounts:[...accounts.map(({account_id,name,email,enabled})=>({account_id,name,email,enabled})),{account_id:'acct-disabled',name:'Unavailable <script>',enabled:false}],models:status.visual_models,fixed:{confidence_threshold:.99,max_daily_output_tokens:30000,probe_daily_usd:'5',probe_weekly_usd:'25',max_quarantined_percent:50,business_key_ids:['key-untouched'],policy:{samples_per_round:3,anomaly_rounds:2,recovery_rounds:2,anomaly_spacing_ms:300000,recovery_spacing_ms:600000,healthy_interval_ms:3600000,unknown_retry_ms:300000,cooldown_initial_ms:3600000,cooldown_max_ms:86400000}}},settingsPayloads=[];
 ctx.document={getElementById:id=>{if(!els.has(id)){const el=new El();if(id==='visual-count')el.value='1';if(id==='visual-effort')el.value='medium';els.set(id,el);}return els.get(id);},createElement:tag=>new El(tag),documentElement:new El('html'),querySelectorAll:()=>[...els.values()].flatMap(flatten).filter(e=>e.dataset.elapsed),execCommand:command=>command==='copy'};
 ctx.DOMParser=class{parseFromString(source,type){assert.equal(type,'text/html');return {documentElement:{source}};}};
 ctx.XMLSerializer=class{serializeToString(e){return '<html xmlns="http://www.w3.org/1999/xhtml">'+e.source+'</html>';}};
 ctx.window={addEventListener(){},codexProxyPlugin:{theme:'dark',page:{id:settingsPage?'probe-settings':'quality-probes'},async request({method,path,body}){
  let result;const input=body?JSON.parse(body):null,account=input?accounts.find(a=>a.account_id===input.account_id):null;
  if(path==='settings'){
   if(method==='GET'){settingsReads++;result=clone(settings);}
   else{settingsPosts++;settingsPayloads.push(input);if(settingsFailure)return {status:409,body:new TextEncoder().encode(JSON.stringify({error:settingsFailure})).buffer};assert.equal(input.expected_revision,settings.revision);const {expected_revision,...next}=input;if(next.max_daily_attempts!==settings.config.max_daily_attempts||next.max_output_tokens!==settings.config.max_output_tokens)settings.fixed.max_daily_output_tokens=next.max_daily_attempts*next.max_output_tokens;settings.config=clone(next);settings.revision++;result={status:'settings_saved',revision:settings.revision};}
  }else if(method==='GET'){
   reads++;result=clone(status);for(const a of result.accounts){for(const t of a.batch?.attempts||[]){delete t.prompt;delete t.output;}for(const t of [...a.visual_tests,...a.logic_tests]){delete t.prompt;delete t.output;}}
  }else if(path==='evidence'){
   evidenceReads++;assert(account);result={account_id:account.account_id,batch:account.batch,history:account.history,quality:account.quality};
  }else if(path==='visual-evidence'){
   visualReads++;assert(account);result={account_id:account.account_id,visual_tests:account.visual_tests};
  }else if(path==='logic-evidence'){
   logicReads++;assert(account);result={account_id:account.account_id,logic_tests:account.logic_tests};
  }else if(path==='visual-review'){
   reviews++;assert(account);const sample=account.visual_tests.find(v=>v.id===input.sample_id);assert(sample);sample.assessment={verdict:input.verdict,source:'manual'};result={status:'visual_reviewed',account_id:account.account_id,visual_sample:sample};
  }else if(path==='logic'){
   logicPosts++;assert(account);targets.push(input);assert.equal(input.model,'gpt-6-astra');assert.equal(input.reasoning_effort,'medium');
   const sample={id:'logic-'+logicPosts,account_id:account.account_id,model:input.model,reasoning_effort:input.reasoning_effort,started_at_ms:Date.now()-500,completed_at_ms:Date.now(),duration_ms:500,request_id:'req-l-'+logicPosts,output:logicVerdict==='pass'?'最少取出21颗糖果。':'最少取出29颗糖果。',prompt:'糖果原题',status:'completed',error:null,assessment:{verdict:logicVerdict,expected_answer:21,answer:logicVerdict==='pass'?21:logicVerdict==='fail'?29:null,note:'识别明确的最终结论'}};
   if(logicFailure){sample.status='error';sample.error='logic_timeout';sample.output=null;sample.assessment={verdict:'unknown',expected_answer:21,answer:null,note:'无法判定'};}
   account.logic_tests.push(sample);result={status:'logic_recorded',account_id:account.account_id,logic_sample:sample};
  }else if(path==='visual'){
   visualPosts++;assert(account);targets.push(input);assert.equal(input.model,'gpt-other');assert.equal(input.reasoning_effort,'medium');
   const sample={id:'visual-'+visualPosts,account_id:account.account_id,model:input.model,reasoning_effort:input.reasoning_effort,started_at_ms:Date.now()-1824,completed_at_ms:Date.now(),duration_ms:1824,request_id:'req-v-'+visualPosts,output:'<!doctype html><html><body><svg><text>Pelican</text></svg><script>window.PWNED=true</script></body></html>',prompt:'Draw a pelican riding a bicycle',status:'completed',error:null};
   if(visualPosts<=visualFailures){sample.status='error';sample.error='visual_timeout';sample.output='<!doctype html><html>partial';}
   account.visual_tests.push(sample);result={status:'visual_recorded',account_id:account.account_id,visual_sample:sample};
   if(stopAfter&&visualPosts===stopAfter)vm.runInContext('stopRequested=true',ctx);
  }else{
   posts++;assert.equal(path,'probe');assert.equal(input.account_id,'acct-one');targets.push(input);
   if(budgetStop&&posts===2)result={status:'daily_budget_exhausted'};
   else{batch.attempts.push(attempt(posts<=failures?'probe_timeout':null));account.batch=batch;const done=count(batch)===3||batch.attempts.length===6;
    if(done){batch.completed_at_ms=Date.now();batch.verdict=count(batch)===3?'healthy':'unknown';batch.score=count(batch)===3?{predicted_model:'gpt-test',predicted_probability:.99,expected_probability:.99,sample_count:3,candidates:[{model:'gpt-test',probability:.99},{model:'gpt-other',probability:.01}]}:null;}
    result={status:done?'batch_completed':'challenge_recorded',account_id:account.account_id,batch,quality:account.quality};
    if(stopAfter&&posts===stopAfter)vm.runInContext('stopRequested=true',ctx);
   }
  }
  return {status:200,body:new TextEncoder().encode(JSON.stringify(result)).buffer};
 }}};
 vm.createContext(ctx);vm.runInContext(script,ctx);await new Promise(setImmediate);
 return {ctx,els,status,batch,targets,settings,settingsPayloads,run:code=>vm.runInContext(code,ctx),counts:()=>({posts,reads,evidenceReads,visualPosts,visualReads,logicPosts,logicReads,reviews,settingsReads,settingsPosts})};
}
async function fingerprint(options){const r=await boot(options);await r.run('probe(snapshot.accounts[0])');assert.equal(r.run('busy'),false);assert.equal(r.run('running'),false);assert(r.counts().reads>=2);assert.equal(r.ctx.document.documentElement.dataset.theme,'dark');return r;}
(async()=>{
 let defaults=await boot();assert.equal(defaults.els.get('visual-model').value,'gpt-6-astra');assert.equal(defaults.els.get('visual-effort').value,'medium');assert.match(html,/<option value="medium" selected>/);
 let r=await fingerprint();assert.equal(r.counts().posts,3);assert.match(r.els.get('notice').textContent,/三题检测结束/);assert.equal(r.batch.score.sample_count,3);
 // Status summaries must not discard already loaded complete output.
 assert.equal(r.run("snapshot.accounts[0].batch.attempts[0].output"),'1, 2, 3 <script>');
 await r.run('loadEvidence(snapshot.accounts[0])');assert.equal(r.counts().evidenceReads,1);assert.match(r.els.get('notice').textContent,/不发起模型请求/);
 assert(flatten(r.els.get('identity')).some(e=>e.textContent==='one@example.test'));assert(flatten(r.els.get('identity')).some(e=>e.textContent==='acct-one'));
 await r.run('downloadAll()');assert.equal(r.els.get('export-dialog').open,true);assert.match(r.els.get('export-content').value,/1, 2, 3 <script>/);r.run('copyExport()');assert.match(r.els.get('export-note').textContent,/已复制/);
 r=await fingerprint({initial:2});assert.equal(r.counts().posts,1);
 r=await fingerprint({failures:1});assert.equal(r.counts().posts,4);
 r=await fingerprint({failures:6});assert.equal(r.counts().posts,6);assert.equal(r.batch.score,null);assert.match(r.els.get('notice').textContent,/无法判定/);
 r=await fingerprint({budgetStop:true});assert.equal(r.counts().posts,2);assert.equal(count(r.batch),1);assert.match(r.els.get('notice').textContent,/预算已用尽/);
 r=await fingerprint({stopAfter:1});assert.equal(r.counts().posts,1);assert.equal(count(r.batch),1);assert.match(r.els.get('notice').textContent,/已停止后续挑战/);
 r=await boot();r.run("selectedId='acct-two';mode='visual';$('visual-model').value='gpt-other';$('visual-effort').value='medium';$('visual-count').value='2';render()");await r.run('manualProbe(currentAccount())');
 assert.equal(r.counts().visualPosts,2);assert(r.targets.every(t=>t.account_id==='acct-two'));assert.equal(r.run("visualResults.get('acct-one').length"),0);assert.equal(r.run("visualResults.get('acct-two').length"),2);assert.equal(r.status.accounts[1].quality.phase,'pending');
 assert.equal(r.els.get('case-prompt-text').textContent,'创建一个HTML，内容是SVG绘制一个鹈鹕骑自行车的2D动画，你不需要任何测试');
 const images=flatten(r.els.get('outputs')).filter(e=>e.tag==='img');assert.equal(images.length,2);assert.match(images[0].src,/^data:image\/svg\+xml/);assert.equal(r.ctx.window.PWNED,undefined);assert.equal(flatten(r.els.get('outputs')).filter(e=>e.tag==='iframe').length,0);assert.match(decodeURIComponent(images[0].src),/foreignObject/);
 const exportedSource=r.run("visualResults.get('acct-two')[0].output");
 const htmlButton=flatten(r.els.get('outputs')).find(e=>e.tag==='button'&&e.textContent==='导出 HTML');assert(htmlButton);htmlButton.onclick();assert.equal(r.els.get('export-content').value,exportedSource);assert.match(r.els.get('export-filename').textContent,/\.html$/);
 const fenced='```HTML\n'+exportedSource+'\n```';r.ctx.testFenced=fenced;assert.equal(r.run('htmlDocument(testFenced)'),exportedSource);r.ctx.testNested='```\n'+fenced+'\n```';assert.equal(r.run('htmlDocument(testNested)'),r.ctx.testNested);r.ctx.testIncomplete='```html\nmissing closing fence';assert.equal(r.run('htmlDocument(testIncomplete)'),r.ctx.testIncomplete);
 r.run("visualResults.get('acct-two')[0].output=testFenced;render()");flatten(r.els.get('outputs')).find(e=>e.tag==='button'&&e.textContent==='导出 HTML').onclick();assert.equal(r.els.get('export-content').value,exportedSource);assert.equal(r.run("visualResults.get('acct-two')[0].output"),fenced);
 for(const code of ['visual_timeout','incomplete_html_document','expired_or_clock_shifted_visual','output_too_large','request_encode','invalid_model_metadata','invalid_event_batch','event_count_mismatch','invalid_wire_json','invalid_wire_sse','unvalidated_wire_body','non_text_response','ambiguous_output','incomplete_or_duplicate_completion','missing_completed_text','invalid_output_encoding']){r.ctx.testError=code;assert.match(r.run('errorLabel(testError)'),/[\u4e00-\u9fff]/);}
 const normal=flatten(r.els.get('outputs')).find(e=>e.tag==='button'&&e.textContent==='绘图正常');assert(normal);await normal.onclick();assert.equal(r.counts().reviews,1);assert.equal(r.run("visualResults.get('acct-two')[0].assessment.verdict"),'pass');assert.match(r.els.get('notice').textContent,/人工判定已保存.*通过/);
 await r.run('refresh()');assert.equal(r.run("visualResults.get('acct-two')[0].assessment.verdict"),'pass');
 const abnormal=flatten(r.els.get('outputs')).find(e=>e.tag==='button'&&e.textContent==='绘图异常／疑似降智');await abnormal.onclick();assert.equal(r.run("visualResults.get('acct-two')[0].assessment.verdict"),'fail');assert(flatten(r.els.get('outputs')).some(e=>e.textContent==='未通过／疑似降智'));assert.equal(r.status.accounts[1].quality.phase,'pending');
 r.ctx.testProse='下面是实现：\n```html\n'+exportedSource+'\n```\n以上为完整源码。';assert.equal(r.run('htmlDocument(testProse)'),exportedSource);
 r.run('visualResults.clear()');await r.run('refresh()');assert.equal(r.run("Object.hasOwn(visualResults.get('acct-two')[0],'output')"),false);await r.run('loadManualEvidence(currentAccount())');assert.equal(r.counts().visualReads,1);assert.match(r.run("visualResults.get('acct-two')[0].output"),/Pelican/);
 await r.run('downloadAll()');assert.equal(JSON.parse(r.els.get('export-content').value).account_id,'acct-two');assert.equal(JSON.parse(r.els.get('export-content').value).visual_tests.length,2);assert.equal(r.run('busy'),false);
 r=await boot({stopAfter:1});r.run("selectedId='acct-two';mode='visual';$('visual-model').value='gpt-other';$('visual-effort').value='medium';$('visual-count').value='4'");await r.run('manualProbe(currentAccount())');assert.equal(r.counts().visualPosts,1);assert.match(r.els.get('notice').textContent,/已停止后续生成/);
 r=await boot({visualFailures:1});r.run("selectedId='acct-two';mode='visual';$('visual-model').value='gpt-other';$('visual-effort').value='medium';$('visual-count').value='1'");await r.run('manualProbe(currentAccount())');assert.equal(r.counts().visualPosts,1);assert.match(r.els.get('notice').textContent,/已完成 0 \/ 1 份，1 份未完成/);assert.match(r.els.get('notice').textContent,/查看失败原因/);assert.doesNotMatch(r.els.get('notice').textContent,/预览/);assert.match(r.els.get('work-status').textContent,/完成 0 \/ 未完成 1/);assert(flatten(r.els.get('outputs')).some(e=>e.textContent==='可视化生成超时，未取得完整 HTML'));assert.equal(flatten(r.els.get('outputs')).filter(e=>e.tag==='img').length,0);
 assert.match(r.run("errorLabel('visual_timeout; model_stream_cleanup_pending')"),/可视化生成超时.*等待宿主完成取消收尾/);
 const failedNodes=flatten(r.els.get('outputs'));assert.equal(failedNodes.find(e=>e.tag==='button'&&e.textContent==='导出 HTML').disabled,true);assert(!failedNodes.some(e=>e.tag==='button'&&e.textContent==='绘图正常'));assert(failedNodes.some(e=>e.textContent==='<!doctype html><html>partial'));
 for(const verdict of ['pass','fail','unknown']){r=await boot({logicVerdict:verdict});r.run("selectedId='acct-two';mode='logic';render()");assert.equal(r.els.get('visual-controls').hidden,false);assert.equal(r.els.get('case-prompt').hidden,false);assert.match(r.els.get('case-prompt-text').textContent,/苹果味 桃子味 西瓜味 圆形 7 9 8 五角星形 7 6 4$/);await r.run('manualProbe(currentAccount())');assert.equal(r.counts().logicPosts,1);assert.equal(r.counts().visualPosts,0);assert.equal(r.targets[0].account_id,'acct-two');assert.equal(r.status.accounts[1].quality.phase,'pending');assert.equal(r.run("logicResults.get('acct-one').length"),0);assert.equal(r.run("visualResults.get('acct-two').length"),0);assert.equal(r.run("logicResults.get('acct-two')[0].assessment.verdict"),verdict);
  const label=verdict==='pass'?'通过':verdict==='fail'?'未通过／疑似降智':'无法判定';assert(flatten(r.els.get('outputs')).some(e=>e.textContent===label));assert.equal(flatten(r.els.get('outputs')).filter(e=>e.tag==='img').length,0);
  r.run("selectedId='acct-one';render()");assert(!flatten(r.els.get('outputs')).some(e=>e.textContent==='最少取出21颗糖果。'));r.run("selectedId='acct-two';logicResults.clear()");await r.run('refresh()');assert.equal(r.run("Object.hasOwn(logicResults.get('acct-two')[0],'output')"),false);await r.run('loadManualEvidence(currentAccount())');assert.equal(r.counts().logicReads,1);await r.run('downloadAll()');const exported=JSON.parse(r.els.get('export-content').value);assert.equal(exported.type,'candy_logic');assert.equal(exported.account_id,'acct-two');assert.equal(exported.logic_tests[0].assessment.verdict,verdict);assert.equal(r.counts().logicPosts,1);
 }
 r=await boot({logicFailure:true});r.run("mode='logic';render()");await r.run('manualProbe(currentAccount())');assert.match(r.els.get('notice').textContent,/无法判定/);assert(flatten(r.els.get('outputs')).some(e=>e.textContent==='逻辑测试超时，无法判定'));assert(!flatten(r.els.get('outputs')).some(e=>e.textContent==='未通过／疑似降智'));
 // Settings use safe controls and a revision-checked six-field patch; hidden rules and spend stay unchanged.
 r=await boot({settingsPage:true,customOutput:3000,missingAccount:true});assert.equal(r.run('settingsOpen'),true);assert.equal(r.counts().settingsReads,1);assert.equal(r.counts().reads,0);assert.equal(r.counts().posts+r.counts().visualPosts+r.counts().logicPosts,0);assert.equal(r.els.get('settings-output').value,'3000');assert(flatten(r.els.get('settings-output')).some(e=>e.value==='3000'));assert.equal(r.els.get('settings-enabled').checked,true);assert.match(r.els.get('settings-token-cap').textContent,/30,000.*当前配置/);
 let choices=flatten(r.els.get('settings-accounts'));assert(choices.some(e=>e.tag==='input'&&e.value==='acct-missing'&&e.checked));assert(choices.some(e=>e.tag==='input'&&e.value==='acct-disabled'&&e.disabled));assert(choices.some(e=>e.textContent==='Unavailable <script>'));assert.match(r.els.get('settings-account-count').textContent,/已选 2/);assert(flatten(r.els.get('settings-fixed')).some(e=>String(e.textContent).includes('实际 Key 预算独立管理')));
 r.run("$('settings-search').value='TWO@EXAMPLE';renderSettingsAccounts()");choices=flatten(r.els.get('settings-accounts'));assert.equal(choices.filter(e=>e.tag==='input').length,1);const two=choices.find(e=>e.tag==='input');two.checked=true;two.onchange();assert.equal(r.run('settingsAccounts.size'),3);r.run("$('settings-search').value='';renderSettingsAccounts()");
 const originalBudget=clone(r.status.budget),fixed=clone(r.settings.fixed);await r.run('saveSettings()');assert.equal(r.counts().settingsPosts,1);assert.deepEqual(Object.keys(r.settingsPayloads[0]).sort(),['expected_revision','enabled','auto_probe','account_ids','model','max_daily_attempts','max_output_tokens'].sort());assert(r.settingsPayloads[0].account_ids.includes('acct-missing'));assert.equal(r.settingsPayloads[0].max_output_tokens,3000);assert.equal(r.settingsPayloads[0].expected_revision,7);assert.deepEqual(r.settings.fixed,fixed);assert.deepEqual(r.status.budget,originalBudget);assert.match(r.els.get('settings-notice').textContent,/保存并读取确认/);assert.equal(r.counts().settingsReads,2);assert.equal(r.counts().posts+r.counts().visualPosts+r.counts().logicPosts,0);
 r.run("$('settings-attempts').value='8';settingsBudget()");assert.match(r.els.get('settings-token-cap').textContent,/24,000.*请求次数/);r.run("settingsAccounts.delete('acct-missing');$('settings-model').value='gpt-6-astra';settingsBudget()");assert.match(r.els.get('settings-changes').textContent,/重新准入.*冷却仍保留/);assert.match(r.els.get('settings-changes').textContent,/取消纳管 1.*清理/);await r.run('saveSettings()');assert.equal(r.settings.fixed.max_daily_output_tokens,24000);assert.equal(r.settings.fixed.confidence_threshold,.99);assert.equal(r.settings.fixed.probe_daily_usd,'5');assert.deepEqual(r.settings.fixed.business_key_ids,['key-untouched']);
 // A stale save preserves every edited control, performs no verification read and does not claim success.
 r=await boot({settingsFailure:'settings_conflict'});await r.run('showSettings()');r.run("$('settings-attempts').value='17';$('settings-auto').value='true';settingsAccounts.add('acct-two')");await r.run('saveSettings()');assert.equal(r.els.get('settings-attempts').value,'17');assert.equal(r.els.get('settings-auto').value,'true');assert.equal(r.run("settingsAccounts.has('acct-two')"),true);assert.match(r.els.get('settings-notice').textContent,/其他页面修改.*填写内容已保留/);assert.equal(r.counts().settingsReads,1);assert.equal(r.run('busy'),false);assert.equal(r.els.get('settings-save').disabled,false);await r.run('leaveSettings()');await r.run('showSettings()');assert.equal(r.els.get('settings-attempts').value,'17');assert.equal(r.counts().settingsReads,1);
 const saves=r.counts().settingsPosts;for(const n of ['', '1.5','10001']){r.run("$('settings-attempts').value="+JSON.stringify(n));await r.run('saveSettings()');assert.equal(r.counts().settingsPosts,saves);assert.match(r.els.get('settings-notice').textContent,/1 至 10000/);}r.run("$('settings-attempts').value='6';settingsAccounts.clear();$('settings-enabled').checked=true");await r.run('saveSettings()');assert.equal(r.counts().settingsPosts,saves);assert.match(r.els.get('settings-notice').textContent,/至少选择一个/);r.run("settingsAccounts=new Set(Array.from({length:101},(_,i)=>'acct-'+i))");await r.run('saveSettings()');assert.match(r.els.get('settings-notice').textContent,/最多选择 100/);assert.equal(r.counts().settingsPosts,saves);
 r.run('busy=true;settingsNavigation()');assert.equal(r.els.get('settings-fields').disabled,true);assert.equal(r.els.get('settings-save').disabled,true);assert.equal(r.els.get('settings-back').disabled,true);await r.run('saveSettings()');assert.equal(r.counts().settingsPosts,saves);await r.run('leaveSettings()');assert.equal(r.run('settingsOpen'),true);r.run('busy=false;settingsNavigation()');await r.run('readSettings()');assert.equal(r.els.get('settings-attempts').value,'6');assert.equal(r.run('settingsAccounts.size'),1);
 assert(!script.includes('.innerHTML'));assert(!script.includes('srcdoc'));assert(!script.includes('createObjectURL'));assert(html.includes('prefers-reduced-motion'));assert(html.includes('aria-live="polite"'));
 console.log('UI checks passed: three-answer attribution, resume/retry/budget bounds, fixed-account manual probes, inert previews, complete exports, independent verdicts, six-field settings, account selection/search, unavailable selections and custom values preserved, revision conflict retains draft, hidden rules and used budgets preserved, validation, busy guards, theme and accessible controls.');
})().catch(e=>{console.error(e);process.exitCode=1;});
