import {classification} from './classifications.mjs';
// Findings without a CWE are grouped by their rule, never into one unknown group.
export function groupFindings(findings){
 const groups=new Map();
 for(const finding of findings){
  const cwe=classification(finding).cwe;
  const key=cwe==='미확인'?'rule:'+String(finding.id||finding.key):'cwe:'+cwe;
  if(!groups.has(key))groups.set(key,{key,findings:[]});
  groups.get(key).findings.push(finding);
 }
 return [...groups.values()];
}
// A grouped card must not pretend that its first file represents every occurrence.
export function representativeFinding(group){
 return [...group.findings].sort((a,b)=>{
  const falseDiff=(a.status==='locally_false'?1:0)-(b.status==='locally_false'?1:0);if(falseDiff)return falseDiff;
  const traceDiff=Number(Boolean(b.trace))-Number(Boolean(a.trace));if(traceDiff)return traceDiff;
  const generated=f=>/(?:\.bundle|\.min)\.[cm]?[jt]sx?$/i.test(f.path||'')?1:0;
  return generated(a)-generated(b);
 })[0];
}
