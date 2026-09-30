const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const script=fs.readFileSync('web/index.html','utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
class El {constructor(tag='div'){this.tag=tag;this.children=[];this.textContent='';this.dataset={};}append(...e){this.children.push(...e);}replaceChildren(...e){this.children=e;}}
const count=b=>b.attempts.filter(a=>!a.error&&a.number_count!=null).length;
const attempt=(error=null)=>({at_ms:Date.now(),challenge_id:'test',prompt:'prompt <script>',expected_count:300,request_id:'req',output:error?null:'1, 2, 3 <script>',number_count:error?null:300,error});
async function run({initial=0,failures=0,budgetStop=false,load=false}){
 const els=new Map(),ctx={TextDecoder,Date,Number,JSON,Boolean,Error,console},q={phase:'pending',lease_until_ms:0,next_probe_at_ms:0};
 let posts=0,reads=0,evidenceReads=0;
 const batch={started_at_ms:Date.now(),completed_at_ms:null,model:'test-model',attempts:Array.from({length:initial},()=>attempt()),score:null,verdict:null,error:null};
 const account={account_id:'acct-one',name:'test account',enabled:true,quality:q,batch:initial?batch:null,history:[],last_sample:null};
 const status={enabled:true,key_scopes_ok:true,probe_budget_ok:true,auto_probe:false,maintenance:{ok:true},model:'test-model',probe_limits:{max_daily_attempts:6,max_output_tokens:4096,max_daily_output_tokens:24576},budget:{day:Math.floor(Date.now()/86400000),attempts:initial,reserved_output_tokens:initial*4096},accounts:[account]};
 ctx.document={getElementById:id=>{if(!els.has(id))els.set(id,new El());return els.get(id);},createElement:tag=>new El(tag),documentElement:new El('html')};
 ctx.window={addEventListener(){},codexProxyPlugin:{theme:'dark',async request({method,path,body}){
  let result;if(method==='GET'){reads++;result=JSON.parse(JSON.stringify(status));for(const a of result.accounts)for(const t of a.batch?.attempts||[]){delete t.prompt;delete t.output;}}else if(path==='evidence'){evidenceReads++;assert.equal(JSON.parse(body).account_id,'acct-one');result={account_id:'acct-one',batch,history:[],quality:q};}else{posts++;assert.equal(JSON.parse(body).account_id,'acct-one');
   if(budgetStop&&posts===2)result={status:'daily_budget_exhausted'};
   else{batch.attempts.push(attempt(posts<=failures?'probe_timeout':null));account.batch=batch;const done=count(batch)===3||batch.attempts.length===6;
    if(done){batch.completed_at_ms=Date.now();batch.verdict=count(batch)===3?'healthy':'unknown';batch.score=count(batch)===3?{predicted_model:'test-model',predicted_probability:.99,expected_probability:.99,sample_count:3,candidates:[{model:'test-model',probability:.99}]}:null;}
    result={status:done?'batch_completed':'challenge_recorded',batch,quality:q};
   }
  }
  return {status:200,body:new TextEncoder().encode(JSON.stringify(result)).buffer};
 }}};
 vm.createContext(ctx);vm.runInContext(script,ctx);await new Promise(setImmediate);
 await vm.runInContext('probe(snapshot.accounts[0])',ctx);
 if(load){assert.equal(vm.runInContext("Object.hasOwn(snapshot.accounts[0].batch.attempts[0],'output')",ctx),false);await vm.runInContext('loadEvidence(snapshot.accounts[0])',ctx);assert.equal(vm.runInContext("snapshot.accounts[0].batch.attempts[0].output",ctx),'1, 2, 3 <script>');assert.equal(evidenceReads,1);}
 assert.equal(vm.runInContext('busy',ctx),false);assert(reads>=2);assert.equal(ctx.document.documentElement.dataset.theme,'dark');
 return {posts,batch,notice:els.get('notice').textContent,ctx};
}
(async()=>{
 let r=await run({});assert.equal(r.posts,3);assert.match(r.notice,/三题检测结束/);assert.equal(r.batch.score.sample_count,3);
 r=await run({initial:2});assert.equal(r.posts,1);
 r=await run({failures:1});assert.equal(r.posts,4);
 r=await run({failures:6});assert.equal(r.posts,6);assert.equal(r.batch.score,null);assert.match(r.notice,/无法判定/);
 r=await run({budgetStop:true});assert.equal(r.posts,2);assert.equal(count(r.batch),1);assert.match(r.notice,/预算已用尽/);
 r=await run({load:true});assert.equal(r.posts,3);assert.match(r.notice,/不发起模型请求/);
 console.log('UI checks passed: on-demand full evidence,  3-answer run, resume, failed retry, 6-attempt bound, budget stop; no dependency added.');
})().catch(e=>{console.error(e);process.exitCode=1;});
