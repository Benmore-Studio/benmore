// Exercise pending inbox reads across native session boundaries using the actual SDK.
import assert from 'node:assert/strict';
let serial = 0;
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return {promise, resolve}; };
const flush = async () => { for (let i=0;i<12;i++) await new Promise(r=>setImmediate(r)); };
const response = (data, status=200) => ({ok:status<300,status,headers:{get:()=> 'application/json'},text:async()=>JSON.stringify(data)});
globalThis.document = {querySelector:()=>({content:'synthetic-csrf'})};
async function fixture(phase) {
 const bm=(await import('./bm.js?notification-session-'+(++serial))).default;
 let actor='alpha', hold=true, reached=false, calls=0, denied=false;
 const gate=deferred(), sources=[], delivered=[];
 const inbox={alpha:[{id:100,body:'alpha baseline'}],beta:[{id:10,body:'beta baseline'}]};
 globalThis.EventSource=class {constructor(){sources.push(this);}addEventListener(name,fn){if(name==='change')this.change=fn;}close(){this.closed=true;}};
 globalThis.fetch=async (path,init) => {
  if(path.startsWith('/api/_notifications')) {
   calls++;const who=actor,q=new URL(path,'https://fixture.example').searchParams;
   const rows=inbox[who].filter(n=>!q.has('after_id')||n.id>Number(q.get('after_id'))).slice(0,100);
   const latest_id=inbox[who].at(-1)?.id||0;
   if(hold && who==='alpha' && q.has('after_id')===(phase==='drain')) {hold=false;reached=true;await gate.promise;}
   return response({notifications:rows,latest_id});
  }
  if(path==='/login')return response(denied?{error:'refused'}:{user:{id:actor==='alpha'?1:2}},denied?403:200);
  if(path==='/api/_auth/profile')return response({id:actor==='alpha'?1:2});
  return response({ok:true});
 };
 const stop=bm.notifications.onNew(n=>delivered.push(n));
 const emit=()=>sources.at(-1).change({data:JSON.stringify({table:'_benmore_notifications',action:'insert'})});
 await flush();
 if(phase==='drain'){inbox.alpha.push({id:101,body:'alpha pending'});emit();await flush();}
 assert.ok(reached,'controlled old '+phase+' did not reach the response boundary');
 return {bm,gate,sources,delivered,inbox,stop,emit,setActor:v=>actor=v,setDenied:v=>denied=v,calls:()=>calls};
}
for(const phase of ['initialize','drain']) for(const operation of ['signIn','signOutThenSignIn','tenant','actAs','refresh']) {
 const f=await fixture(phase);
 try {
  if(operation==='signOutThenSignIn') {
   const before=f.calls();await f.bm.auth.signOut();await flush();
   assert.equal(f.calls(),before,'logout must not start an unauthenticated inbox request');
  }
  f.setActor('beta');
  if(operation==='signIn'||operation==='signOutThenSignIn')await f.bm.auth.signIn('beta','synthetic-password');
  else if(operation==='tenant')await f.bm.api.post('/api/_switch_group',{group_id:2});
  else if(operation==='actAs')await f.bm.api.post('/api/_auth/act_as',{group_id:2});
  else await f.bm.auth.refreshMe();
  await flush();
  f.inbox.beta.push({id:11,body:'beta new'});f.emit();await flush();
  assert.deepEqual(f.delivered.map(n=>n.id),[11],operation+' '+phase+': old pending work blocked the new account cursor');
  f.gate.resolve();await flush();
  assert.deepEqual(f.delivered.map(n=>n.id),[11],operation+' '+phase+': old inbox result crossed accounts');
  f.inbox.beta.push({id:12,body:'beta next'});f.emit();await flush();
  assert.deepEqual(f.delivered.map(n=>n.id),[11,12],operation+' '+phase+': late old response replaced the current cursor');
 } finally {f.stop();f.gate.resolve();await flush();}
}
// Refused authentication must not suppress valid notifications for the current user.
{
 const f=await fixture('drain');
 try {f.setDenied(true);await assert.rejects(f.bm.auth.signIn('other','wrong'));f.gate.resolve();await flush();assert.deepEqual(f.delivered.map(n=>n.id),[101]);}
 finally {f.stop();f.gate.resolve();await flush();}
}
// Unsubscribe removes its auth listener, even while its old response is pending.
{
 const f=await fixture('drain');f.stop();const before=f.calls();f.setActor('beta');await f.bm.auth.signIn('beta','synthetic-password');await flush();assert.equal(f.calls(),before);f.gate.resolve();await flush();assert.deepEqual(f.delivered,[]);
}
// Independent listeners both remain usable after a native account change.
{
 const f=await fixture('drain'),other=[];const stopOther=f.bm.notifications.onNew(n=>other.push(n.id));
 try {await flush();f.setActor('beta');await f.bm.auth.signIn('beta','synthetic-password');await flush();f.stop();f.inbox.beta.push({id:11,body:'beta new'});f.emit();await flush();assert.deepEqual(other,[11]);assert.deepEqual(f.delivered,[]);}
 finally {stopOther();f.stop();f.gate.resolve();await flush();}
}
console.log('all notification session assertions passed');
