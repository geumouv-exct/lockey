import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {readPublicIndexHash} from './public-link-check.mjs';
import {observeProjectDeployment} from './deployment-observation.mjs';

test('GET root comparison pins a public address and hashes bounded content',async()=>{
 let sent;const request=(_url,options,callback)=>{sent=options;const req=new EventEmitter();req.end=()=>{const res=new EventEmitter();res.statusCode=200;res.resume=()=>{};res.destroy=()=>{};queueMicrotask(()=>{callback(res);res.emit('data',Buffer.from('hello'));res.emit('end')})};return req};
 const out=await readPublicIndexHash('https://example.com/',{resolve:async()=>['8.8.8.8'],transport:request});assert.equal(sent.method,'GET');assert.equal(out.sha256,createHash('sha256').update('hello').digest('hex'));sent.lookup('example.com',{},(_err,ip)=>assert.equal(ip,'8.8.8.8'));
 await assert.rejects(readPublicIndexHash('https://example.com/',{resolve:async()=>['127.0.0.1'],transport:request}));
});
test('folder index is compared locally and only safe source-derived routes are queried',async()=>{
 const baseline={files:[{path:'index.html',text:'hello'}],findings:[{key:'x',id:'sql-interpolation',path:'src/q.js',lines:[5],flowEvidence:[{kind:'request_to_sql_project',sinkPath:'src/q.js',line:5,route:'/api/users'},{kind:'request_to_sql_project',sinkPath:'src/q.js',line:5,route:'/users/:id'}]}]};
 const seen=[];const r=await observeProjectDeployment('https://example.com/',baseline,{indexReader:async()=>({sha256:createHash('sha256').update('hello').digest('hex')}),head:async url=>{seen.push(url);return {status:'checked',httpStatus:200}}});
 assert.equal(r.staticFile.status,'matched');assert.deepEqual(seen,['https://example.com/api/users']);assert.equal(r.findings[0].key,'x');assert.match(r.notice,/증명이 아닙니다/);
});
test('unavailable or mismatched static source does not claim deployment identity',async()=>{
 const f={files:[{path:'index.html',text:'source'}],findings:[]};const mismatch=await observeProjectDeployment('https://example.com',f,{indexReader:async()=>({sha256:'no-match'})});assert.equal(mismatch.staticFile.status,'mismatch');
 const failure=await observeProjectDeployment('https://example.com',f,{indexReader:async()=>{throw Error('offline')}});assert.equal(failure.staticFile.status,'inconclusive');
 await assert.rejects(observeProjectDeployment('https://example.com/not-root',f));
});
