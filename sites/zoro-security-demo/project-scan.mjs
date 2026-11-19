import {analyzeFlow,inertLiteralHtmlLines,htmlPropertyCandidates} from './dataflow.mjs';
import {scanText,isExample,attachProjectFlows} from '../../security-review-mvp/scanner.mjs';
import {wstgForRule} from '../../security-review-mvp/wstg.mjs';
import {attachBrowserContext} from './browser-context.mjs';
const MAX_FILES=200,MAX_FILE=300_000,MAX_TOTAL=3_000_000;
const denyPart=/^(?:\.git|node_modules|vendor|dist|build|coverage|\.next|\.venv|venv|__pycache__)$/i;
const allowed=/\.(?:[cm]?[jt]sx?|json|sql|rules|ya?ml|toml|html?|py|go|rb|php)$/i;
const extras={'debug-enabled':'WSTG-v42-CONF-02','cookie-httponly-false':'WSTG-v42-SESS-02','public-secret':'WSTG-v42-INFO-05','private-key':'WSTG-v42-INFO-05','wildcard-policy':'WSTG-v42-ATHZ-02','service-role':'WSTG-v42-ATHZ-03','jwt-decode-only':'WSTG-v42-ATHN-04','fail-open':'WSTG-v42-ERRH-01','tls-disabled':'WSTG-v42-CRYP-01'};
export function eligibleProjectPath(path){if(typeof path!=='string'||path.length>500||path.includes('\\')||path.startsWith('/')||path.includes('\0'))return false;const parts=path.split('/');return parts.every(p=>p&&p!=='.'&&p!=='..'&&!denyPart.test(p)&&!/^\.env/i.test(p)&&!/\.(?:pem|key|p12|pfx)$/i.test(p))&&allowed.test(path)&&!isExample(path)}
export function scanProject(files){
 if(!Array.isArray(files)||files.length===0||files.length>MAX_FILES)throw Error('검사 파일은 1~200개여야 합니다.');let bytes=0;const seen=new Set(),findings=[];const flowCoverage={analyzed:0,parse_error:0,unsupported:0,limited:0};
 for(const f of files){if(!f||!eligibleProjectPath(f.path)||typeof f.text!=='string'||seen.has(f.path))throw Error('지원하지 않거나 중복된 파일이 포함되어 있습니다.');seen.add(f.path);const n=Buffer.byteLength(f.text);if(n>MAX_FILE)throw Error('파일 크기 제한을 초과했습니다.');bytes+=n;if(bytes>MAX_TOTAL)throw Error('전체 크기 제한을 초과했습니다.');
 const flow=analyzeFlow(f.path,f.text);flowCoverage[flow.status]++;if(flow.limited)flowCoverage.limited++;const patterns=scanText(f.path,f.text);for(const match of flow.findings){const old=patterns.find(p=>p.id===match.id&&p.lines.includes(match.lines[0]));if(old&&old.lines.length===1){old.trace=match.trace;old.traceLimit=match.traceLimit}else{if(old)old.lines=old.lines.filter(n=>n!==match.lines[0]);patterns.push(match)}}
 const inertLines=inertLiteralHtmlLines(f.path,f.text),htmlProps=htmlPropertyCandidates(f.path,f.text);
 for(const original of patterns){
  const safe=original.id==='dangerous-html'?original.lines.filter(n=>inertLines.has(n)):[],remaining=original.lines.filter(n=>!safe.includes(n));
  const parts=[...(remaining.length?[{...original,lines:remaining,...(original.id==='dangerous-html'&&remaining.every(n=>htmlProps.has(n))?{frameworkHtmlEvidence:{kind:'html_prop_to_sink_candidate',path:f.path,lines:remaining}}:{})}]:[]),...(safe.length?[{...original,lines:safe,staticHtmlProof:{kind:'inert_literal_html',path:f.path,lines:safe}}]:[])];
  for(const item of parts){const refs=wstgForRule(item.id);const id=refs[0]?.id||extras[item.id]||null;findings.push({...item,key:`issue-${findings.length+1}`,category:item.title,reference:refs[0]?.url||'https://cheatsheetseries.owasp.org/',wstg:id,status:item.staticHtmlProof?'locally_false':'candidate'});}
 }}
 // Extend the existing per-file scan with bounded project-wide flow evidence.
 // The scanner receives source text in memory and emits only paths and line numbers.
 for(const item of findings)if(!Array.isArray(item.flowEvidence))item.flowEvidence=[];
 const prior=findings.length;
 attachProjectFlows(files,findings);
 for(let i=prior;i<findings.length;i++){
  const item=findings[i],refs=wstgForRule(item.id);
  Object.assign(item,{key:`issue-${i+1}`,category:item.title,reference:refs[0]?.url||'https://cheatsheetseries.owasp.org/',wstg:refs[0]?.id||extras[item.id]||null,status:'candidate'});
 }
 attachBrowserContext(files,findings);
 return {findings,files:files.length,bytes,flowCoverage};
}
export const PROJECT_LIMITS={MAX_FILES,MAX_FILE,MAX_TOTAL};
