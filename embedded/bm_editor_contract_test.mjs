import assert from 'node:assert/strict';
import bm from './bm.js';
globalThis.document={querySelector:()=>null};
const base=process.env.BM_EDITOR_TEST_URL;
const fetchHTTP=globalThis.fetch;
globalThis.fetch=(path,init={})=>{
 const headers=new Headers(init.headers);
 headers.set('Authorization','Bearer '+process.env.BM_EDITOR_TEST_TOKEN);
 return fetchHTTP(new URL(path,base),{...init,headers});
};
let failures=0;
async function check(name,fn){try{await fn();}catch(e){failures++;console.error(name+': '+e.message);}}
const notes=bm.table('notes');
await check('three stable SDK pages exclude foreign and deleted articles',async()=>{
 const pages=[];
 for(const offset of [0,3,6])pages.push((await notes.list({limit:3,offset,sort:'id',order:'asc'})).map(x=>x.id));
 assert.deepEqual(pages,[[1,3,4],[6,7,8],[9,10]]);
});
await check('SDK cursor page unwraps data and honors filters',async()=>{
 assert.deepEqual((await notes.list({cursor:0,limit:3,where:{title:'article'}})).map(x=>x.id),[3,4,6]);
});
await check('SDK preserves update receipt, history metadata and revert receipt',async()=>{
 const original=await notes.get(1);
 const updated=await notes.update(1,{title:'edited in SDK'});
 assert.deepEqual(updated,{status:'updated'});
 assert.equal((await notes.get(1)).title,'edited in SDK');
 const history=await notes.versions(1);
 assert.equal(history.id,'1'); assert.ok(Array.isArray(history.versions));
 const revision=history.versions.find(v=>v._version===1);
 assert.ok(revision && revision._valid_from && Object.hasOwn(revision,'_changed_by'));
 const receipt=await notes.revertTo(1,revision._version);
 assert.equal(receipt.status,'reverted'); assert.equal(receipt.reverted_to_version,'1');
 assert.equal((await notes.get(1)).title,original.title);
});
await check('SDK list retains bare-array and rows-envelope compatibility',async()=>{
 const real=globalThis.fetch;
 try{
  for(const payload of [[{id:7}],{rows:[{id:7}]},{data:[{id:7}],page:1,total:1}]){
   globalThis.fetch=async()=>({ok:true,status:200,headers:{get:()=> 'application/json'},text:async()=>JSON.stringify(payload)});
   assert.deepEqual(await notes.list(),[{id:7}]);
  }
  globalThis.fetch=async()=>({ok:true,status:200,headers:{get:()=> 'application/json'},text:async()=>JSON.stringify({data:[],next_cursor:null})});
  assert.deepEqual(await notes.list({cursor:'10'}),[]);
 }finally{globalThis.fetch=real;}
});
if(failures)process.exit(1);
console.log('editor SDK runtime journey passed');
