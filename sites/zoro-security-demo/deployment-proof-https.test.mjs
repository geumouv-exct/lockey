import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import {createLockeyAttestation} from './integrations/lockey-attestation.mjs';
import {requestDeploymentProof} from './public-link-check.mjs';
import {verifyDeploymentProof} from './deployment-proof.mjs';

test('authenticated deployment proof over a real local TLS server',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'lockey-tls-')),secret='ae'.repeat(32),files=[{path:'routes.mjs',text:'export const route = 1;'},{path:'query.mjs',text:'export const query = 1;'}];let server;
 try{
  for(const f of files)await writeFile(path.join(root,f.path),f.text);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(root,'test.key'),'-out',path.join(root,'test.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});
  const cert=await readFile(path.join(root,'test.crt')),key=await readFile(path.join(root,'test.key'));
  const agent=createLockeyAttestation({root,secret});for(const f of files)await agent.recordModule(path.join(root,f.path));
  server=https.createServer({key,cert},(req,res)=>{req.originalUrl=req.url;req.get=name=>req.headers[name.toLowerCase()];res.status=n=>{res.statusCode=n;return res};res.set=(k,v)=>{res.setHeader(k,v);return res};res.send=body=>res.end(body);if(req.url==='/.well-known/lockey-attestation')agent.manifest(req,res);else if(req.url==='/api/users')agent.routeProbe(req,res,()=>{res.statusCode=404;res.end()});else{res.statusCode=404;res.end()}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const finding={key:'x',id:'sql-interpolation',path:'query.mjs',lines:[1],flowEvidence:[{kind:'request_to_sql_project',routePath:'routes.mjs',routeLine:1,sourcePath:'routes.mjs',sourceLine:1,sinkPath:'query.mjs',line:1,route:'/api/users'}]};
  // Redirect only this test transport to the local TLS server, trusting its ephemeral certificate.
  const transport=(url,options,callback)=>https.request({hostname:'localhost',port:server.address().port,path:url.pathname,method:options.method,headers:options.headers,servername:'localhost',ca:cert,family:4,timeout:options.timeout},callback);
  const request=(url,route,options)=>requestDeploymentProof(url,route,{...options,resolve:async()=>['8.8.8.8'],transport});
  const result=await verifyDeploymentProof('https://example.com',secret,{files,findings:[finding]},{request});
  assert.equal(result.status,'self_attested');assert.equal(result.findings.length,1);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await rm(root,{recursive:true,force:true})}
});
