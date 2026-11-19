import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {publicHost,limitedModelFetch} from './public-host.mjs';

const origin='https://lockey.example';
function client(check){
 const res=new EventEmitter();
 let cookie;
 res.setHeader=(_name,value)=>{cookie=value.split(';')[0]};
 assert.equal(check({method:'GET',headers:{host:'lockey.example'}},res,'/'),0);
 return {method:'POST',headers:{host:'lockey.example',origin,cookie}};
}
test('public requests require the configured host, origin and a session',()=>{
 const check=publicHost(origin),req=client(check),res=new EventEmitter();
 for(const key of ['host','origin','cookie']){
  assert.equal(check({...req,headers:{...req.headers,[key]:'other'}},res,'/api/model-check'),403);
 }
 assert.equal(check(req,res,'/api/project-test'),403);
 assert.equal(check(req,res,'/api/model-check'),0);
 res.emit('finish');res.emit('close');
});
test('a busy session releases its slots and has a per-minute budget',()=>{
 let now=10_000_000;
 const check=publicHost(origin,()=>now),req=client(check),open=[];
 for(let i=0;i<5;i++){open.push(new EventEmitter());assert.equal(check(req,open[i],'/api/model-check'),0)}
 assert.equal(check(req,new EventEmitter(),'/api/model-check'),429);
 for(const res of open)res.emit('close');
 for(let i=5;i<40;i++){const res=new EventEmitter();assert.equal(check(req,res,'/api/model-check'),0);res.emit('finish')}
 assert.equal(check(req,new EventEmitter(),'/api/model-check'),429);
 now+=60_000;
 assert.equal(check(req,new EventEmitter(),'/api/model-check'),0);
});
test('at most two model requests are in flight; news feeds use their own path',async()=>{
 let active=0,peak=0;
 const endpoint='http://127.0.0.1:30001/v1/systemone';
 const limited=limitedModelFetch(endpoint, async url=>{
  if(url!==endpoint)return new Response('feed');
  active++;peak=Math.max(peak,active);
  await new Promise(resolve=>setTimeout(resolve,5));
  active--;return new Response('{}');
 });
 await Promise.all(Array.from({length:5},()=>limited(endpoint,{})));
 assert.equal(peak,2);
 assert.equal(await (await limited('https://news.example/feed',{})).text(),'feed');
});
