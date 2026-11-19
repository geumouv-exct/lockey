// Optional, explicitly installed Node.js/Express deployment instrumentation.
// This is self-attestation by the application, not independent runtime attestation.
import {createHash,createHmac,timingSafeEqual,randomBytes} from 'node:crypto';
import {readFile,realpath,stat} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const mac=(key,text)=>createHmac('sha256',key).update(text).digest('hex');
const secureEqual=(left,right)=>typeof left==='string'&&typeof right==='string'&&/^[a-f0-9]{64}$/.test(left)&&/^[a-f0-9]{64}$/.test(right)&&timingSafeEqual(Buffer.from(left,'hex'),Buffer.from(right,'hex'));
const header=(req,name)=>req.get?.(name)??req.headers?.[name.toLowerCase()];
const safePath=x=>typeof x==='string'&&x.length<=128&&/^\/(?:[A-Za-z0-9_-]+\/?)*$/.test(x)&&x!=='/';

export function createLockeyAttestation({root,secret}){
 if(typeof secret!=='string'||!/^[a-f0-9]{64}$/i.test(secret))throw Error('LOCKEY_ATTESTATION_KEY must be 32 random bytes in hexadecimal.');
 const key=Buffer.from(secret,'hex'),rootPromise=realpath(root),loaded=new Map(),seen=new Map(),instanceId=randomBytes(16).toString('hex');
 function authorized(req,method,route){const nonce=header(req,'x-lockey-nonce'),proof=header(req,'x-lockey-request'),now=Date.now();if(!/^[a-f0-9]{64}$/.test(nonce||'')||Math.abs(now-parseInt(nonce.slice(0,12),16))>60000||!secureEqual(proof,mac(key,`lockey:request:v1\n${nonce}\n${method}\n${route}`)))return null;for(const [id,time] of seen)if(now-time>120000)seen.delete(id);if(seen.has(nonce)||seen.size>=1000)return null;seen.set(nonce,now);return nonce}
 async function recordModule(file){
  const base=await rootPromise,absolute=await realpath(file instanceof URL?fileURLToPath(file):file),relative=path.relative(base,absolute);
  if(!relative||relative.startsWith('..'+path.sep)||relative==='..'||path.isAbsolute(relative))throw Error('Module is outside the attested root.');
  const name=relative.split(path.sep).join('/');if(!/^[A-Za-z0-9_./-]+\.(?:[cm]?[jt]s|[jt]sx)$/.test(name)||name.length>500||loaded.size>=200&&!loaded.has(name))throw Error('Unsupported attested module.');
  if((await stat(absolute)).size>300000)throw Error('Attested module exceeds the size limit.');const bytes=await readFile(absolute);if(bytes.length>300000)throw Error('Attested module exceeds the size limit.');
  loaded.set(name,{absolute,sha256:createHash('sha256').update(bytes).digest('hex')});
 }
 async function manifest(req,res){
  const nonce=req.method==='GET'&&req.originalUrl==='/.well-known/lockey-attestation'?authorized(req,'GET','/.well-known/lockey-attestation'):null;if(!nonce)return res.status(404).end();
  try{const modules=[];for(const [name,item] of loaded){if((await stat(item.absolute)).size>300000)continue;const bytes=await readFile(item.absolute);if(bytes.length<=300000&&createHash('sha256').update(bytes).digest('hex')===item.sha256)modules.push({path:name,sha256:item.sha256})}
   const body=JSON.stringify({version:1,nonce,instanceId,modules});res.set('Cache-Control','no-store');res.set('Content-Type','application/json');res.set('X-Lockey-Response',mac(key,`lockey:manifest:v1\n${body}`));return res.status(200).send(body);
  }catch{return res.status(503).end()}
 }
 function routeProbe(req,res,next){
  const route=req.originalUrl||req.url;if(req.method!=='HEAD'||!safePath(route))return next();const nonce=authorized(req,'HEAD',route);
  if(!nonce)return next();
  res.set('Cache-Control','no-store');res.set('X-Lockey-Instance',instanceId);res.set('X-Lockey-Route',mac(key,`lockey:route:v1\n${nonce}\n${route}\n${instanceId}`));return res.status(204).end();
 }
 return {recordModule,manifest,routeProbe};
}
