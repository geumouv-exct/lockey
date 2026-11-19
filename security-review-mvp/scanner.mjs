import {analyzeFlows,analyzeProjectFlows} from './flow-analysis.mjs';
// Deterministic, line-based signals. These are review candidates, not proven vulnerabilities.
export const AGENTS = [
 {id:'phase1',label:'1차 분석',owasp:['A01','A04','A05'],description:'접근 정책, 비밀값, 인젝션 관련 제한된 패턴'},
 {id:'phase2',label:'2차 분석',owasp:['A02','A03','A07'],description:'설정, 공급망 설정 및 인증 관련 제한된 패턴'},
 {id:'phase3',label:'3차 분석',owasp:['A04','A08','A10'],description:'암호화, 무결성 및 예외 처리 관련 제한된 패턴'},
 {id:'self',label:'자가진단',owasp:['A06','A09'],description:'자동으로 확정할 수 없는 설계 및 로깅 항목을 직접 확인'}
];
export const SELF_CHECKS = [
 {id:'business-pricing',owasp:'A06',title:'가격·할인·결제 금액을 서버에서 검증하나요?',description:'테스트 환경에서 상품 가격과 할인, 최종 결제 금액을 서버가 신뢰할 수 있는 정보로 검증하는지 확인하세요.'},
 {id:'business-abuse',owasp:'A06',title:'중복 주문과 혜택 악용을 방지하나요?',description:'중복 결제·쿠폰 중복 사용·요청 제한 등 서비스에 필요한 규칙을 확인하세요.'},
 {id:'security-logs',owasp:'A09',title:'중요한 보안 이벤트가 기록되나요?',description:'로그인 실패, 관리자 권한 변경 등 중요한 이벤트의 기록 여부를 운영 환경에서 확인하세요.'},
 {id:'security-alerts',owasp:'A09',title:'의심스러운 활동에 대한 알림이 있나요?',description:'로그가 담당자에게 필요한 알림으로 이어지는지 운영 환경에서 확인하세요.'},
 {id:'log-secrets',owasp:'A09',title:'로그에 비밀번호나 토큰이 남지 않나요?',description:'애플리케이션 및 외부 로깅 서비스에서 민감정보 마스킹 설정을 확인하세요.'}
];
export const RULES = [
 {id:'private-key',agent:'phase1',owasp:'A04',title:'비밀키가 코드에 포함된 것으로 보여요',severity:'확인 필요',pattern:/(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|\bghp_[A-Za-z0-9]{20,}\b)/,why:'서버 전용 키가 저장소에 남아 있으면 다른 사람이 사용할 수 있습니다.',fix:'실제 비밀키라면 먼저 폐기·재발급하고 서버 환경변수로 옮기세요.'},
 {id:'service-role',agent:'phase1',owasp:'A01',title:'관리자 권한 키 사용을 확인해 주세요',severity:'확인 필요',pattern:/(?:process\.env\.|import\.meta\.env\.|\b(?:const|let|var)\s+)[A-Z_]*SUPABASE_SERVICE_ROLE_KEY\b/i,why:'관리자 권한 키가 클라이언트에 포함되면 접근 통제가 우회될 수 있습니다.',fix:'키가 서버에서만 사용되는지 확인하세요.'},
 {id:'public-secret',agent:'phase1',owasp:'A04',title:'공개 환경변수에 민감한 이름이 있어요',severity:'확인 필요',pattern:/\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE)[A-Z0-9_]*/i,why:'이 접두어의 값은 클라이언트 번들에 포함될 수 있습니다.',fix:'공개해도 되는 값인지 확인하고 비밀값이라면 서버 전용 환경변수로 변경하세요.'},
 {id:'wildcard-policy',agent:'phase1',owasp:'A01',title:'폭넓은 접근 허용 정책을 확인해 주세요',severity:'확인 필요',pattern:/\b(?:allow\s+(?:read|write|delete|update|create)(?:\s*,\s*(?:read|write|delete|update|create))*\s*:\s*if\s+true|using\s*\(\s*true\s*\))/i,why:'데이터 접근 정책이 광범위한 요청을 허용할 수 있습니다.',fix:'정책 적용 대상과 다른 보호 계층을 확인하세요.'},
 {id:'dangerous-html',agent:'phase1',owasp:'A05',title:'화면에 HTML을 직접 넣는 부분이 있어요',severity:'확인 필요',pattern:/\b(?:dangerouslySetInnerHTML|innerHTML\s*=)/,why:'신뢰할 수 없는 값이 그대로 삽입되면 스크립트 실행 위험이 생길 수 있습니다.',fix:'입력 출처와 정제 과정을 확인하고 가능한 경우 텍스트로 렌더링하세요.'},
 {id:'sql-interpolation',agent:'phase1',owasp:'A05',title:'SQL 문자열의 값 결합을 확인해 주세요',severity:'확인 필요',pattern:/\b(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/i,why:'외부 입력이 SQL에 직접 결합되면 인젝션 위험이 있을 수 있습니다.',fix:'데이터의 출처를 확인하고 매개변수화된 쿼리를 사용하세요.'},
 {id:'debug-enabled',agent:'phase2',owasp:'A02',title:'디버그 설정을 확인해 주세요',severity:'확인 필요',pattern:/\b(?:DEBUG|debug)\s*[:=]\s*(?:true|1)\b/i,why:'운영 환경에 개발용 디버그 설정이 적용되면 내부 정보가 노출될 수 있습니다.',fix:'이 설정이 운영 환경에 적용되는지 확인하세요.'},
 {id:'cors-wildcard',agent:'phase2',owasp:'A02',title:'CORS 공개 범위를 확인해 주세요',severity:'확인 필요',pattern:/(?:access-control-allow-origin["']?\s*[,=:]\s*["']\*|\borigin\s*:\s*["']\*["'])/i,why:'모든 출처를 허용하는 CORS 설정은 보호가 필요한 응답에 부적합할 수 있습니다.',fix:'해당 응답의 공개 의도와 인증 방식, 필요한 출처 범위를 확인하세요.'},
 {id:'actions-floating-ref',agent:'phase2',owasp:'A03',title:'고정되지 않은 GitHub Actions 참조가 있어요',severity:'확인 필요',pattern:/^\s*-?\s*uses\s*:\s*[^\s@]+@(?:main|master|latest)\s*(?:#.*)?$/i,paths:/\.github\/workflows\/[^/]+\.ya?ml$/i,why:'브랜치나 이동 가능한 태그를 사용하면 실행 코드가 예고 없이 바뀔 수 있습니다.',fix:'사용하는 액션의 출처를 확인하고 검증된 커밋 SHA에 고정하는 방안을 검토하세요.'},
 {id:'cookie-secure-false',agent:'phase2',owasp:'A07',title:'쿠키 Secure 설정을 확인해 주세요',severity:'확인 필요',pattern:/\bsecure\s*:\s*false\b/i,why:'인증 쿠키에 적용되면 암호화되지 않은 연결로 전달될 수 있습니다.',fix:'쿠키의 용도와 운영 환경을 확인하고 HTTPS에서 Secure를 활성화하세요.'},
 {id:'hardcoded-credential',agent:'phase1',owasp:'A04',title:'코드에 자격 증명으로 보이는 값이 있습니다',severity:'확인 필요',pattern:/\b(?:password|api[_-]?key|client[_-]?secret)\s*[:=]\s*["\x27][^"\x27\s]{12,}["\x27]/i,why:'소스에 민감한 값이 포함될 수 있습니다.',fix:'실제 자격 증명인지 확인하고 노출된 경우 폐기·재발급하세요.'},
 {id:'cookie-httponly-false',agent:'phase2',owasp:'A07',title:'쿠키의 HttpOnly 설정을 확인해 주세요',severity:'확인 필요',pattern:/\bhttpOnly\s*:\s*false\b/i,why:'인증에 쓰이는 쿠키가 스크립트에 노출될 수 있습니다.',fix:'이 쿠키가 인증용인지와 프레임워크의 최종 쿠키 설정을 확인하세요.'},
 {id:'jwt-decode-only',agent:'phase2',owasp:'A07',title:'토큰을 검증 없이 해석하는 부분을 확인해 주세요',severity:'확인 필요',pattern:/\b(?:jwt|jsonwebtoken)\.decode\s*\(/i,why:'토큰을 해석하는 것만으로 서명이나 권한을 검증할 수는 없습니다.',fix:'이 값이 인증·권한 결정에 사용되는 경우 서명과 발급자 등 필요한 검증을 확인하세요.'},
 {id:'weak-hash',agent:'phase3',owasp:'A04',title:'오래된 해시 알고리즘 사용을 확인해 주세요',severity:'확인 필요',pattern:/\bcreateHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i,why:'비밀번호나 보안 무결성 검증에 부적절한 알고리즘일 수 있습니다.',fix:'사용 목적을 확인하고 비밀번호라면 적절한 비밀번호 해싱 방식을 사용하세요.'},
 {id:'git-object-sha1',agent:'phase3',owasp:'A04',title:'Git 객체 형식의 SHA-1 사용이 발견됐어요',status:'정보',severity:'정보',pattern:/\bcreateHash\s*\(\s*["']sha1["']\s*\)/i,why:'Git 객체 식별 형식과 유사합니다. 이는 비밀번호 해싱이라는 뜻은 아니며, SHA-1은 충돌에 취약해 신뢰 경계에서 단독 보안 검증으로 충분하지 않을 수 있습니다.',fix:'Git 호환 목적과 비교 대상의 신뢰성을 확인하고, 민감한 무결성 검증에는 충돌 저항성이 있는 별도 검증을 고려하세요.'},
 {id:'signature-disabled',agent:'phase3',owasp:'A08',title:'서명 검증을 끄는 설정을 확인해 주세요',severity:'확인 필요',pattern:/\b(?:verifySignature|verify_signature|signatureVerification)\s*[:=]\s*false\b/,why:'서명 검증을 생략하면 변조된 데이터가 신뢰될 수 있습니다.',fix:'설정이 실제 배포에 적용되는지와 별도의 서명 검증이 있는지 확인하세요.'},
 {id:'tls-disabled',agent:'phase3',owasp:'A04',title:'TLS 인증서 검증 비활성화 설정을 확인해 주세요',severity:'확인 필요',pattern:/\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0)/,why:'연결 상대의 인증서 검증이 비활성화될 수 있습니다.',fix:'운영 환경 적용 여부를 확인하고 인증서 검증을 활성화하세요.'},
 {id:'fail-open',agent:'phase3',owasp:'A10',title:'오류가 발생했을 때 허용하는 코드를 확인해 주세요',severity:'확인 필요',pattern:/\bcatch\s*(?:\([^)]*\))?\s*\{\s*return\s+true\s*;?\s*\}/,why:'오류 시 true를 반환하는 동작이 인증·권한 검사에 쓰이면 허용 상태로 실패할 수 있습니다.',fix:'이 함수의 용도를 확인하고 인증·권한 검사라면 오류 시 요청을 차단하세요.'}
];
const allowed=/\.(?:[cm]?[jt]sx?|json|sql|rules|ya?ml|toml|html?|py|go|rb|php|env|example)$/i;
export function eligible(path,size){const p=path.replaceAll('\\','/');return size<=1_000_000&&!/(?:^|\/)(?:node_modules|\.git|dist|build|coverage|\.next|vendor)(?:\/|$)/i.test(p)&&(allowed.test(p)||/(?:^|\/)\.env(?:\.[\w-]+)?$/i.test(p));}
export function isExample(path){return /(?:^|\/)(?:__tests__|tests?|fixtures?|examples?|samples?)(?:\/|$)|(?:^|\/)[^/]+\.(?:test|spec)\.[^/]+$/i.test(path.replaceAll('\\','/'))||/(?:^|\/)\.env\.example$/i.test(path)}
// Only classify an immediately chained Git blob header; ambiguous hashes stay review candidates.
function isGitObjectHash(line){return !/(?:password|passwd|passphrase|\bpwd\b)/i.test(line)&&(line.match(/\bcreateHash\s*\(/g)||[]).length===1&&/\bcreateHash\s*\(\s*["']sha1["']\s*\)\s*\.update\s*\(\s*`blob\s+\$\{[^}]+\}\\0`\s*\)/i.test(line)}
function isPlainConstantHtml(line){return (line.match(/\binnerHTML\s*=/g)||[]).length===1&&!/\bdangerouslySetInnerHTML\b/.test(line)&&/\binnerHTML\s*=\s*(?:'[\p{L}\p{N} _.,!?-]*'|"[\p{L}\p{N} _.,!?-]*")\s*;?\s*(?:\/\/.*)?$/u.test(line)}
// Bounded, single-statement source-to-sink patterns; no execution or interprocedural analysis.
// The evidence contains line numbers and fixed identifiers, never source text.
export function directFlowEvidence(ruleId,path,text,lines){
 if(!/\.[cm]?[jt]sx?$/i.test(path))return [];
 const code=text.split(/\r?\n/);const evidence=[];let block=false;const blocked=new Set();
 // Ignore every line inside or containing block comments; never mistake commented examples for code.
 for(let i=0;i<code.length;i++){const line=code[i];if(block||line.includes('/*'))blocked.add(i+1);if(line.includes('/*')&&!line.includes('*/'))block=true;else if(block&&line.includes('*/'))block=false;}
 for(const lineNo of lines){if(blocked.has(lineNo))continue;const line=code[lineNo-1]?.trim()||'';
  if(ruleId==='sql-interpolation' && /^(?:await\s+)?[\w$]+\.(?:query|execute)\(\s*`\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{\s*req\.(?:query|params|body)\.[\w$]+\s*\}[^`]*`\s*\)\s*;?$/i.test(line))evidence.push({kind:'request_to_sql',line:lineNo});
  if(ruleId==='dangerous-html' && /^[\w$]+\.innerHTML\s*=\s*window\.location\.(?:hash|search)\s*;?$/.test(line))evidence.push({kind:'location_to_html',line:lineNo});
 }
 return evidence;
}
export function scanForAgent(agent,path,text){
 if(agent==='self'||!AGENTS.some(a=>a.id===agent)||isExample(path))return [];
 const lines=text.split(/\r?\n/),results=[];
 for(const rule of RULES.filter(r=>r.agent===agent&&(!r.paths||r.paths.test(path.replaceAll('\\','/'))))){
  const hits=[];
  for(let i=0;i<lines.length;i++){const line=lines[i];if(/^\s*(?:\/\/|\*|#)/.test(line)||/\bpattern\s*:\s*\//.test(line))continue;if(rule.id==='weak-hash'&&isGitObjectHash(line))continue;if(rule.id==='git-object-sha1'&&!isGitObjectHash(line))continue;if(rule.id==='dangerous-html'&&isPlainConstantHtml(line))continue;if(rule.pattern.test(line))hits.push(i+1);if(hits.length>=10)break}
  if(hits.length)results.push({id:rule.id,agent:rule.agent,owasp:rule.owasp,path,lines:hits,title:rule.title,severity:rule.severity,why:rule.why,fix:rule.fix,status:rule.status||'확인 필요',flowEvidence:directFlowEvidence(rule.id,path,text,hits)});
 }
 if(agent==='phase1')for(const flow of analyzeFlows(path,text)){
  const id=flow.kind==='request_to_sql'?'sql-interpolation':'dangerous-html';const rule=RULES.find(r=>r.id===id);
  let found=results.find(f=>f.id===id);
  if(!found){found={id:rule.id,agent:rule.agent,owasp:rule.owasp,path,lines:[],title:rule.title,severity:rule.severity,why:rule.why,fix:rule.fix,status:rule.status||'확인 필요',flowEvidence:[]};results.push(found)}
  if(!found.lines.includes(flow.line)&&found.lines.length<10)found.lines.push(flow.line);
  if(found.lines.includes(flow.line)&&found.flowEvidence.length<10)found.flowEvidence.push({...flow,kind:flow.kind+'_path'});
 }
 return results;
}
export function scanText(path,text){return AGENTS.flatMap(a=>scanForAgent(a.id,path,text))}
// Project data stays in memory; only fixed evidence labels and file/line locations leave the scanner.
export function attachProjectFlows(files,findings){
 for(const flow of analyzeProjectFlows(files)){
  const rule=RULES.find(r=>r.id==='sql-interpolation');let finding=findings.find(f=>f.id===rule.id&&f.path===flow.sinkPath);
  if(!finding){finding={id:rule.id,agent:rule.agent,owasp:rule.owasp,path:flow.sinkPath,lines:[],title:rule.title,severity:rule.severity,why:rule.why,fix:rule.fix,status:'확인 필요',flowEvidence:[]};findings.push(finding)}
  if(!finding.lines.includes(flow.line)&&finding.lines.length<10)finding.lines.push(flow.line);
  if(finding.lines.includes(flow.line)&&finding.flowEvidence.length<10)finding.flowEvidence.push(flow);
 }
 return findings;
}

