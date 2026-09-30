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
async function boot({initial=0,failures=0,budgetStop=false,stopAfter=0,visualFailures=0}={}){
 const els=new Map(),ctx={TextDecoder,Date,Number,JSON,Boolean,Error,console,setInterval,clearInterval,encodeURIComponent};
 let posts=0,reads=0,evidenceReads=0,visualPosts=0,visualReads=0;
 const targets=[],batch={started_at_ms:Date.now(),completed_at_ms:null,model:'gpt-test',attempts:Array.from({length:initial},()=>attempt()),score:null,verdict:null,error:null};
 const accounts=['one','two'].map(id=>({account_id:'acct-'+id,name:'OpenAI '+id,email:id+'@example.test',enabled:true,quality:{phase:'pending',lease_until_ms:0,next_probe_at_ms:0},batch:id==='one'&&initial?batch:null,history:[],last_sample:null,visual_tests:[]}));
 const status={enabled:true,key_scopes_ok:true,probe_budget_ok:true,auto_probe:false,maintenance:{ok:true},model:'gpt-test',visual_models:['gpt-test','gpt-other'],visual_efforts:['low','medium','high'],visual_timeout_ms:110000,probe_limits:{max_daily_attempts:6,max_output_tokens:4096,max_daily_output_tokens:24576},budget:{day:Math.floor(Date.now()/86400000),attempts:initial,reserved_output_tokens:initial*4096},accounts};
 ctx.document={getElementById:id=>{if(!els.has(id)){const el=new El();if(id==='visual-count')el.value='1';if(id==='visual-effort')el.value='low';els.set(id,el);}return els.get(id);},createElement:tag=>new El(tag),documentElement:new El('html'),querySelectorAll:()=>[...els.values()].flatMap(flatten).filter(e=>e.dataset.elapsed),execCommand:command=>command==='copy'};
 ctx.DOMParser=class{parseFromString(source,type){assert.equal(type,'text/html');return {documentElement:{source}};}};
 ctx.XMLSerializer=class{serializeToString(e){return '<html xmlns="http://www.w3.org/1999/xhtml">'+e.source+'</html>';}};
 ctx.window={addEventListener(){},codexProxyPlugin:{theme:'dark',async request({method,path,body}){
  let result;const input=body?JSON.parse(body):null,account=input?accounts.find(a=>a.account_id===input.account_id):null;
  if(method==='GET'){
   reads++;result=clone(status);for(const a of result.accounts){for(const t of a.batch?.attempts||[]){delete t.prompt;delete t.output;}for(const t of a.visual_tests){delete t.prompt;delete t.output;}}
  }else if(path==='evidence'){
   evidenceReads++;assert(account);result={account_id:account.account_id,batch:account.batch,history:account.history,quality:account.quality};
  }else if(path==='visual-evidence'){
   visualReads++;assert(account);result={account_id:account.account_id,visual_tests:account.visual_tests};
  }else if(path==='visual'){
   visualPosts++;assert(account);targets.push(input);assert.equal(input.model,'gpt-other');assert.equal(input.reasoning_effort,'medium');
   const sample={id:'visual-'+visualPosts,account_id:account.account_id,model:input.model,reasoning_effort:input.reasoning_effort,started_at_ms:Date.now()-1824,completed_at_ms:Date.now(),duration_ms:1824,request_id:'req-v-'+visualPosts,output:'<!doctype html><html><body><svg><text>Pelican</text></svg><script>window.PWNED=true</script></body></html>',prompt:'Draw a pelican riding a bicycle',status:'completed',error:null};
   if(visualPosts<=visualFailures){sample.status='error';sample.error='visual_timeout';sample.output=null;}
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
 return {ctx,els,status,batch,targets,run:code=>vm.runInContext(code,ctx),counts:()=>({posts,reads,evidenceReads,visualPosts,visualReads})};
}
async function fingerprint(options){const r=await boot(options);await r.run('probe(snapshot.accounts[0])');assert.equal(r.run('busy'),false);assert.equal(r.run('running'),false);assert(r.counts().reads>=2);assert.equal(r.ctx.document.documentElement.dataset.theme,'dark');return r;}
(async()=>{
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
 r=await boot();r.run("selectedId='acct-two';mode='visual';$('visual-model').value='gpt-other';$('visual-effort').value='medium';$('visual-count').value='2';render()");await r.run('visualProbe(currentAccount())');
 assert.equal(r.counts().visualPosts,2);assert(r.targets.every(t=>t.account_id==='acct-two'));assert.equal(r.run("visualResults.get('acct-one').length"),0);assert.equal(r.run("visualResults.get('acct-two').length"),2);assert.equal(r.status.accounts[1].quality.phase,'pending');
 const images=flatten(r.els.get('outputs')).filter(e=>e.tag==='img');assert.equal(images.length,2);assert.match(images[0].src,/^data:image\/svg\+xml/);assert.equal(r.ctx.window.PWNED,undefined);assert.equal(flatten(r.els.get('outputs')).filter(e=>e.tag==='iframe').length,0);assert.match(decodeURIComponent(images[0].src),/foreignObject/);
 const exportedSource=r.run("visualResults.get('acct-two')[0].output");
 const htmlButton=flatten(r.els.get('outputs')).find(e=>e.tag==='button'&&e.textContent==='导出 HTML');assert(htmlButton);htmlButton.onclick();assert.equal(r.els.get('export-content').value,exportedSource);assert.match(r.els.get('export-filename').textContent,/\.html$/);
 const fenced='```HTML\n'+exportedSource+'\n```';r.ctx.testFenced=fenced;assert.equal(r.run('htmlDocument(testFenced)'),exportedSource);r.ctx.testNested='```\n'+fenced+'\n```';assert.equal(r.run('htmlDocument(testNested)'),fenced);r.ctx.testIncomplete='```html\nmissing closing fence';assert.equal(r.run('htmlDocument(testIncomplete)'),r.ctx.testIncomplete);
 r.run("visualResults.get('acct-two')[0].output=testFenced;render()");flatten(r.els.get('outputs')).find(e=>e.tag==='button'&&e.textContent==='导出 HTML').onclick();assert.equal(r.els.get('export-content').value,exportedSource);assert.equal(r.run("visualResults.get('acct-two')[0].output"),fenced);
 for(const code of ['visual_timeout','incomplete_html_document','expired_or_clock_shifted_visual','output_too_large','request_encode','invalid_model_metadata','invalid_event_batch','event_count_mismatch','invalid_wire_json','invalid_wire_sse','unvalidated_wire_body','non_text_response','ambiguous_output','incomplete_or_duplicate_completion','missing_completed_text','invalid_output_encoding']){r.ctx.testError=code;assert.match(r.run('errorLabel(testError)'),/[\u4e00-\u9fff]/);}
 r.run('visualResults.clear()');await r.run('refresh()');assert.equal(r.run("Object.hasOwn(visualResults.get('acct-two')[0],'output')"),false);await r.run('loadVisualEvidence(currentAccount())');assert.equal(r.counts().visualReads,1);assert.match(r.run("visualResults.get('acct-two')[0].output"),/Pelican/);
 await r.run('downloadAll()');assert.equal(JSON.parse(r.els.get('export-content').value).account_id,'acct-two');assert.equal(JSON.parse(r.els.get('export-content').value).visual_tests.length,2);assert.equal(r.run('busy'),false);
 r=await boot({stopAfter:1});r.run("selectedId='acct-two';mode='visual';$('visual-model').value='gpt-other';$('visual-effort').value='medium';$('visual-count').value='4'");await r.run('visualProbe(currentAccount())');assert.equal(r.counts().visualPosts,1);assert.match(r.els.get('notice').textContent,/已停止后续生成/);
 r=await boot({visualFailures:1});r.run("selectedId='acct-two';mode='visual';$('visual-model').value='gpt-other';$('visual-effort').value='medium';$('visual-count').value='1'");await r.run('visualProbe(currentAccount())');assert.equal(r.counts().visualPosts,1);assert.match(r.els.get('notice').textContent,/已完成 0 \/ 1 份，1 份失败/);assert.match(r.els.get('notice').textContent,/查看失败原因/);assert.doesNotMatch(r.els.get('notice').textContent,/预览/);assert.match(r.els.get('work-status').textContent,/成功 0 \/ 失败 1/);assert(flatten(r.els.get('outputs')).some(e=>e.textContent==='可视化生成超时，未取得完整 HTML'));assert.equal(flatten(r.els.get('outputs')).filter(e=>e.tag==='img').length,0);
 assert.match(r.run("errorLabel('visual_timeout; model_stream_cleanup_pending')"),/可视化生成超时.*等待宿主完成取消收尾/);
 assert(!script.includes('.innerHTML'));assert(!script.includes('srcdoc'));assert(!script.includes('createObjectURL'));assert(html.includes('prefers-reduced-motion'));assert(html.includes('aria-live="polite"'));
 console.log('UI checks passed: three-answer attribution, resume/retry/budget bounds, stop after current, fixed visual account and model, saved raw evidence, inert image preview, raw JSON/HTML copy export, Chinese error messages and failed-run counts, theme and accessible controls.');
})().catch(e=>{console.error(e);process.exitCode=1;});
