import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {requestDeploymentProof} from './public-link-check.mjs';

const mac=(key,text)=>createHmac('sha256',key).update(text).digest('hex');
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&/^[a-f0-9]{64}$/.test(a)&&/^[a-f0-9]{64}$/.test(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const nonce=()=>Date.now().toString(16).padStart(12,'0')+randomBytes(26).toString('hex');
const safeRoute=x=>typeof x==='string'&&x.length<=128&&/^\/(?:[A-Za-z0-9_-]+\/?)*$/.test(x)&&x!=='/';
const challenge=(key,method,route)=>{const n=nonce();return {nonce:n,headers:{'x-lockey-nonce':n,'x-lockey-request':mac(key,`lockey:request:v1\n${n}\n${method}\n${route}`)}}};

export async function verifyDeploymentProof(url,secret,baseline,{request=requestDeploymentProof,clock=()=>new Date()}={}){
 if(typeof secret!=='string'||!/^[a-f0-9]{64}$/i.test(secret))throw Error('배포 검증 키는 32바이트의 16진수여야 합니다.');
 if(!Array.isArray(baseline?.files)||!Array.isArray(baseline?.findings))throw Error('프로젝트 검사 결과를 확인할 수 없습니다.');
 const key=Buffer.from(secret,'hex'),c=challenge(key,'GET','/.well-known/lockey-attestation');let response;
 try{response=await request(url,'/.well-known/lockey-attestation',{method:'GET',headers:c.headers})}catch{return {status:'unavailable',findings:[],note:'인증된 배포 검증 응답을 받지 못했습니다.'}}
 if(response.status!==200||!equal(response.signature,mac(key,`lockey:manifest:v1\n${response.body}`)))return {status:'unverified',findings:[],note:'배포 검증 키 또는 서명이 일치하지 않습니다.'};
 let manifest;try{manifest=JSON.parse(response.body)}catch{return {status:'unverified',findings:[],note:'배포 검증 응답 형식이 올바르지 않습니다.'}}
 if(manifest?.version!==1||manifest.nonce!==c.nonce||!/^[a-f0-9]{32}$/.test(manifest.instanceId||'')||!Array.isArray(manifest.modules)||manifest.modules.length>200)return {status:'unverified',findings:[],note:'배포 검증 응답 형식이 올바르지 않습니다.'};
 const modules=new Map();for(const item of manifest.modules){if(!item||typeof item.path!=='string'||item.path.length>500||!/^[a-f0-9]{64}$/.test(item.sha256||'')||modules.has(item.path))return {status:'unverified',findings:[],note:'로드 모듈 목록이 올바르지 않습니다.'};modules.set(item.path,item.sha256)}
 const sources=new Map(baseline.files.map(f=>[f.path,createHash('sha256').update(f.text,'utf8').digest('hex')]));
 const eligible=[];for(const f of baseline.findings){if(!Array.isArray(f.lines))continue;for(const e of f.flowEvidence||[]){if(e.kind!=='request_to_sql_project'||e.sinkPath!==f.path||!f.lines.includes(e.line)||!safeRoute(e.route))continue;const names=[e.routePath,e.sourcePath,e.sinkPath];if(names.every(p=>sources.has(p)&&sources.get(p)===modules.get(p)))eligible.push({key:f.key,route:e.route,routePath:e.routePath,routeLine:e.routeLine})}}
 const routes=[...new Set(eligible.map(x=>x.route))].slice(0,5),verified=new Set();
 for(const route of routes){const q=challenge(key,'HEAD',route);try{const result=await request(url,route,{method:'HEAD',headers:q.headers});if(result.status===204&&result.instanceId===manifest.instanceId&&equal(result.routeSignature,mac(key,`lockey:route:v1\n${q.nonce}\n${route}\n${manifest.instanceId}`)))verified.add(route)}catch{/* unresolved paths remain unknown */}}
 const checkedAt=clock().toISOString();return {status:'self_attested',checkedAt,findings:eligible.filter(x=>verified.has(x.route)).map(x=>({...x,verified:true,checkedAt})),note:'배포 앱이 자체 보고한 로드 모듈 해시와 인증된 라우트 응답을 대조했습니다. 서버 신뢰나 취약 코드의 실행·악용을 독립적으로 증명하지 않습니다.'};
}
