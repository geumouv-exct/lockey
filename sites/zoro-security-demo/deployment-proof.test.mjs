import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHmac,randomBytes} from 'node:crypto';
import {createLockeyAttestation} from './integrations/lockey-attestation.mjs';
import {verifyDeploymentProof} from './deployment-proof.mjs';

test('authenticated self-attestation binds loaded source and route without exposing the key',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'lockey-proof-')),secret='ab'.repeat(32);
 try{
  const route='routes.mjs',sink='query.mjs',routeText='export const routes = true;',sinkText='export const query = true;';
  await writeFile(path.join(root,route),routeText);await writeFile(path.join(root,sink),sinkText);
  const agent=createLockeyAttestation({root,secret});await agent.recordModule(path.join(root,route));await agent.recordModule(path.join(root,sink));
  const f={key:'finding-1',id:'sql-interpolation',path:sink,lines:[3],flowEvidence:[{kind:'request_to_sql_project',sourcePath:route,sourceLine:1,routePath:route,routeLine:2,sinkPath:sink,line:3,route:'/api/users'}]};
  const baseline={files:[{path:route,text:routeText},{path:sink,text:sinkText}],findings:[f]};let sent=0;
  const request=async(_url,urlPath,options)=>{sent++;assert.ok(!JSON.stringify(options.headers).includes(secret));const output={status:0,headers:{},body:''};const res={status(v){output.status=v;return this},set(k,v){output.headers[k.toLowerCase()]=v;return this},send(v){output.body=v;return this},end(){return this}};const req={method:options.method,originalUrl:urlPath,headers:options.headers};if(options.method==='GET')await agent.manifest(req,res);else agent.routeProbe(req,res,()=>{output.status=404});return {status:output.status,body:output.body,signature:output.headers['x-lockey-response'],routeSignature:output.headers['x-lockey-route'],instanceId:output.headers['x-lockey-instance']}};
  const proof=await verifyDeploymentProof('https://example.com',secret,baseline,{request});assert.equal(proof.status,'self_attested');assert.equal(proof.findings.length,1);assert.equal(sent,2);assert.ok(!JSON.stringify(proof).includes(secret));
  const anotherInstance=await verifyDeploymentProof('https://example.com',secret,baseline,{request:async(...args)=>{const r=await request(...args);if(args[1]==='/api/users')r.instanceId='0'.repeat(32);return r}});assert.equal(anotherInstance.findings.length,0);
  const forgedRoute=await verifyDeploymentProof('https://example.com',secret,baseline,{request:async(...args)=>{const r=await request(...args);if(args[1]==='/api/users')r.routeSignature='0'.repeat(64);return r}});assert.equal(forgedRoute.findings.length,0);
  const wrong=await verifyDeploymentProof('https://example.com','cd'.repeat(32),baseline,{request});assert.equal(wrong.status,'unverified');assert.equal(wrong.findings.length,0);
  await writeFile(path.join(root,sink),'different');const changed=await verifyDeploymentProof('https://example.com',secret,baseline,{request});assert.equal(changed.findings.length,0);
 }finally{await rm(root,{recursive:true,force:true})}
});
test('invalid signed responses and invalid keys never set an access vector',async()=>{
 const baseline={files:[],findings:[]};await assert.rejects(verifyDeploymentProof('https://example.com','weak',baseline));const out=await verifyDeploymentProof('https://example.com','aa'.repeat(32),baseline,{request:async()=>({status:200,signature:'0'.repeat(64),body:'{}'})});assert.equal(out.status,'unverified');assert.deepEqual(out.findings,[]);
});
test('a signed challenge cannot be replayed or reused for another route',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'lockey-replay-')),secret='ab'.repeat(32);
 try{const agent=createLockeyAttestation({root,secret}),n=Date.now().toString(16).padStart(12,'0')+randomBytes(26).toString('hex'),signature=createHmac('sha256',Buffer.from(secret,'hex')).update(`lockey:request:v1\n${n}\nGET\n/.well-known/lockey-attestation`).digest('hex'),headers={'x-lockey-nonce':n,'x-lockey-request':signature};
  const call=async()=>{const out={status:0};const res={status(v){out.status=v;return this},set(){return this},send(){return this},end(){return this}};await agent.manifest({method:'GET',originalUrl:'/.well-known/lockey-attestation',headers},res);return out.status};
  assert.equal(await call(),200);assert.equal(await call(),404);let next=false;agent.routeProbe({method:'HEAD',originalUrl:'/api/x',headers},{set(){throw Error('unexpected')}},()=>{next=true});assert.equal(next,true);
 }finally{await rm(root,{recursive:true,force:true})}
});
