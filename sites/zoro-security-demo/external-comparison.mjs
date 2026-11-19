import {randomUUID} from 'node:crypto';
import {validateSnapshot} from './project-actions.mjs';
const baselines=new Map(),ttl=30*60*1000;
export function registerBaseline(files,projectName,findings,context=[]){
 if(typeof projectName!=='string'||!projectName||projectName.length>255)return null;
 validateSnapshot(files);
 for(const [key,item] of baselines)if(Date.now()-item.created>ttl&&!item.busy)baselines.delete(key);
 if(baselines.size>=24){const oldest=[...baselines].find(([,x])=>!x.busy);if(!oldest)return null;baselines.delete(oldest[0])}
 const token=randomUUID();baselines.set(token,{created:Date.now(),context:structuredClone(context),files:structuredClone(files),projectName,findings:structuredClone(findings),busy:false});return token;
}
// Retrieves only the finding bound to the original project snapshot.
export function baselineFinding(token,path,id,lines){
 const {files,findings,projectName,context}=baselineFindings(token,path,[{id,lines}]);
 return {files,finding:findings[0],projectName,context};
}
export function baselineFindings(token,path,requested){
 const s=baselines.get(token);
 if(!s||Date.now()-s.created>ttl)throw Error('검사 세션이 만료되었습니다. 프로젝트를 다시 검사하세요.');
 if(!Array.isArray(requested)||!requested.length||requested.length>s.findings.length)throw Error('수정 요청 항목을 확인하세요.');
 const findings=requested.map(({id,lines})=>{
  const finding=s.findings.find(f=>f.path===path&&f.id===id&&JSON.stringify(f.lines)===JSON.stringify(lines));
  if(!finding)throw Error('선택한 경고를 원본 검사에서 확인할 수 없습니다.');
  return finding;
 });
 return {files:structuredClone(s.files),findings:structuredClone(findings),projectName:s.projectName,context:structuredClone(s.context)};
}
// Reuse the validated in-memory project session; do not send source to a deployment.
export function baselineSnapshot(token){
 const s=baselines.get(token);if(!s||Date.now()-s.created>ttl)throw Error('검사 세션이 만료되었습니다. 프로젝트를 다시 검사하세요.');
 return {files:structuredClone(s.files),findings:structuredClone(s.findings)};
}
