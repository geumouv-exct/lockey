import {createHash} from 'node:crypto';
import {validatePublicUrl,readPublicIndexHash,checkPublicLink} from './public-link-check.mjs';
import {verifyDeploymentProof} from './deployment-proof.mjs';

const safeRoute=x=>typeof x==='string'&&x.length<=128&&/^\/(?:[A-Za-z0-9_-]+\/?)*$/.test(x)&&x!=='/';
export async function observeProjectDeployment(url,baseline,{indexReader=readPublicIndexHash,head=checkPublicLink,secret='',proofVerifier=verifyDeploymentProof}={}){
 const root=validatePublicUrl(url);if(root.protocol!=='https:'||root.pathname!=='/')throw Error('프로젝트 대조는 공개 HTTPS 루트 주소를 사용해 주세요.');
 if(!Array.isArray(baseline?.files)||!Array.isArray(baseline?.findings))throw Error('프로젝트 검사 결과를 확인할 수 없습니다.');
 if(secret&&(typeof secret!=='string'||!/^[a-f0-9]{64}$/i.test(secret)))throw Error('배포 검증 키는 32바이트의 16진수여야 합니다.');
 const candidates=baseline.files.filter(f=>['index.html','public/index.html'].includes(f.path)&&typeof f.text==='string');
 let staticFile={status:'not_available',reason:'선택한 프로젝트에 루트 index.html 또는 public/index.html이 없습니다.'};
 if(candidates.length){try{const remote=await indexReader(root.href);const matches=candidates.filter(f=>createHash('sha256').update(f.text,'utf8').digest('hex')===remote.sha256).map(f=>f.path);staticFile={status:matches.length?'matched':'mismatch',files:matches,reason:matches.length?'표시된 HTML 파일의 바이트만 일치합니다. 다른 파일과 서버 코드는 확인되지 않았습니다.':'선택한 HTML 파일과 공개 응답의 바이트가 일치하지 않습니다.'}}catch{staticFile={status:'inconclusive',reason:'공개 루트 HTML을 읽지 못해 바이트를 비교하지 못했습니다.'}}}
 const entries=[];for(const finding of baseline.findings){for(const e of finding.flowEvidence||[]){if(e.kind==='request_to_sql_project'&&safeRoute(e.route)&&e.sinkPath===finding.path&&finding.lines.includes(e.line))entries.push({key:finding.key,route:e.route})}}
 const routes=[...new Set(entries.map(e=>e.route))],selected=routes.slice(0,5),observations={};
 for(const route of selected){try{const r=await head(new URL(route,root.origin).href);observations[route]={status:r.status,httpStatus:r.httpStatus}}catch{observations[route]={status:'inconclusive',httpStatus:null}}}
 const proof=secret?await proofVerifier(root.href,secret,baseline):{status:'not_requested',findings:[],note:'배포 앱의 자체 검증 연동을 사용하지 않았습니다.'};
 return {staticFile,routeCount:routes.length,checkedRoutes:selected.length,findings:entries.filter(e=>Object.hasOwn(observations,e.route)).map(e=>({...e,...observations[e.route]})),proof,notice:'정적 HTML 대조와 일반 라우트 응답만으로 서버 코드의 배포·실행을 증명할 수 없습니다. 자체 검증은 배포 앱의 보고이며 독립적인 무결성 증명이 아닙니다.'};
}
