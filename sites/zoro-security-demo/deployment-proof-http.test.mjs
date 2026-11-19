import {test} from 'node:test';import assert from 'node:assert/strict';import http from 'node:http';import os from 'node:os';import path from 'node:path';import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {createLockeyAttestation} from './integrations/lockey-attestation.mjs';import {verifyDeploymentProof} from './deployment-proof.mjs';

test('actual local HTTP protocol verifies server self-report',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'lockey-http-proof-')),secret='5a'.repeat(32),files=[{path:'routes.mjs',text:'export const route = 1;'},{path:'query.mjs',text:'export const query = 1;'}];
 for(const f of files)await writeFile(path.join(root,f.path),f.text);
 const agent=createLockeyAttestation({root,secret});for(const f of files)await agent.recordModule(path.join(root,f.path));
 const server=http.createServer((req,res)=>{req.originalUrl=req.url;req.get=name=>req.headers[name.toLowerCase()];res.status=n=>{res.statusCode=n;return res};res.set=(k,v)=>{res.setHeader(k,v);return res};res.send=body=>res.end(body);if(req.url==='/.well-known/lockey-attestation')agent.manifest(req,res);else if(req.url==='/api/users')agent.routeProbe(req,res,()=>{res.statusCode=404;res.end()});else{res.statusCode=404;res.end()}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{const finding={key:'x',id:'sql-interpolation',path:'query.mjs',lines:[1],flowEvidence:[{kind:'request_to_sql_project',routePath:'routes.mjs',routeLine:1,sourcePath:'routes.mjs',sourceLine:1,sinkPath:'query.mjs',line:1,route:'/api/users'}]};const baseline={files,findings:[finding]};
  const request=(_target,urlPath,{method,headers})=>new Promise((resolve,reject)=>{const req=http.request({hostname:'127.0.0.1',port:server.address().port,path:urlPath,method,headers},res=>{const chunks=[];res.on('data',x=>chunks.push(x));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString(),signature:res.headers['x-lockey-response'],routeSignature:res.headers['x-lockey-route'],instanceId:res.headers['x-lockey-instance']}))});req.on('error',reject);req.end()});
  const proof=await verifyDeploymentProof('https://example.com',secret,baseline,{request});assert.equal(proof.findings.length,1);
 }finally{await new Promise(resolve=>server.close(resolve));await rm(root,{recursive:true,force:true})}
});
