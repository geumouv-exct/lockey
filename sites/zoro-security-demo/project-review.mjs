import {createRequire} from 'node:module';
import {scanText} from '../../security-review-mvp/scanner.mjs';
const require=createRequire(import.meta.url);
const acorn=require('../../security-agent/vendor/acorn/acorn.js');
const labels={'sql-interpolation':'SQL 값 결합','dangerous-html':'HTML 삽입'};
function walk(node,visit){if(!node||typeof node!=='object')return;if(node.type)visit(node);for(const [k,v] of Object.entries(node)){if(['loc','start','end'].includes(k))continue;if(Array.isArray(v))for(const child of v)walk(child,visit);else if(v&&typeof v==='object')walk(v,visit)}}
function parse(source){return acorn.parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true,allowHashBang:true})}
function member(node,prop){return node?.type==='MemberExpression'&&!node.computed&&node.property.type==='Identifier'&&node.property.name===prop}

// Recognize one unambiguous module-level driver binding. Shadowed or reused
// names are conservatively left for manual review.
function driverFor(tree, receiver) {
 if (receiver?.type !== 'Identifier') return null;
 const counts = new Map();
 walk(tree, n => {
   if(n.type==='Identifier') counts.set(n.name,(counts.get(n.name)||0)+1);
 });
 for (const statement of tree.body) {
   if(statement.type!=='VariableDeclaration'||statement.kind!=='const') continue;
   for(const binding of statement.declarations) {
     if(binding.id?.name!==receiver.name || counts.get(receiver.name)!==2) continue;
     const init=binding.init, factory=init?.callee;
     if(factory?.type!=='MemberExpression'||factory.computed) continue;
     const lib=tree.body.find(n=>n.type==='ImportDeclaration'&&n.specifiers.some(sp=>
       sp.type==='ImportDefaultSpecifier'&&sp.local.name===factory.object.name));
     if(!lib || counts.get(factory.object.name)!==2) continue;
     if(lib.source.value==='pg' && init.type==='NewExpression' && factory.property.name==='Pool') return 'pg';
     if(lib.source.value==='mysql2/promise' && init.type==='CallExpression' && factory.property.name==='createPool') return 'mysql2';
   }
 }
 return null;
}
// The returned proposal is memory-only; no user code is executed or changed on disk.
export function reviewProject(files,findings,choice){
 const manual={review_secrets:'실제 비밀정보인지 확인하고 노출된 경우 폐기·재발급하세요.',review_session:'인증 방식과 실제 쿠키·토큰 검증 설정을 확인하세요.',review_access:'사용자별 보호 정책과 접근 권한을 확인하세요.'};
 if(manual[choice])return {status:'manual_review',message:manual[choice]+' 실제 서비스 검증은 미실행입니다.',items:[]};
 if(choice==='review_eval'||choice==='review_ssrf')return {status:'manual_review',message:choice==='review_eval'?'동적 코드 실행 후보의 입력 출처와 실행 경로를 확인하세요. 자동 수정과 실행 검증은 미지원입니다.':'요청 주소 후보의 목적지 검증과 접근 경로를 확인하세요. 자동 수정과 실행 검증은 미지원입니다.',items:[]};
 const id=choice==='review_sql'?'sql-interpolation':choice==='review_html'?'dangerous-html':null;
 if(!id)return {status:'deferred',message:'Zoro-1이 추가 검토를 보류했습니다.',items:[]};
 const candidate=findings.find(f=>f.id===id&&/\.[cm]?js$/i.test(f.path));
 if(!candidate)return {status:'unsupported',message:`${labels[id]}: 지원되는 JavaScript 후보가 없습니다.`,items:[]};
 const file=files.find(f=>f.path===candidate.path);let ast;
 try{ast=parse(file.text)}catch{return {status:'unsupported',message:`${candidate.path}: JavaScript 구문을 분석할 수 없어 수정안을 만들지 않았습니다.`,items:[]}}
 let target=null;
 walk(ast,node=>{
  if(target||!candidate.lines.includes(node.loc.start.line))return;
  if(id==='dangerous-html'&&node.type==='AssignmentExpression'&&node.operator==='='&&member(node.left,'innerHTML'))target={start:node.left.property.start,end:node.left.property.end,before:'innerHTML',after:'textContent',line:node.loc.start.line};
  if(id==='sql-interpolation'&&node.type==='CallExpression'&&member(node.callee,'query')&&node.arguments.length===1&&node.arguments[0].type==='TemplateLiteral'){
   const arg=node.arguments[0];if(arg.expressions.length!==1)return;
   const [left,right]=arg.quasis.map(q=>q.value.cooked);
   const driver=driverFor(ast,node.callee.object);
   if(!driver || node.loc.start.line!==node.loc.end.line || left==null || right==null)return;
   // Only a single scalar equality at the end of a simple SELECT.
   const value=/^(SELECT\s+(?:\*|[\w]+(?:\s*,\s*[\w]+)*)\s+FROM\s+[\w]+\s+WHERE\s+[\w]+\s*=\s*)('?)$/i.exec(left);
   if(!value || right!==value[2] || !['Identifier','MemberExpression'].includes(arg.expressions[0].type))return;
   const expr=file.text.slice(arg.expressions[0].start,arg.expressions[0].end);
   const sql=value[1]+(driver==='pg'?'$1':'?');
   const method=driver==='pg'?'query':'execute';
   target={start:node.start,end:node.end,after:node.callee.object.name+'.'+method+'('+JSON.stringify(sql)+', ['+expr+'])',line:node.loc.start.line};
  }
 });
 if(!target)return {status:'unsupported',message:`${candidate.path}: 드라이버·값 위치 또는 변경 대상을 확인할 수 없어 수동 검토가 필요합니다.`,items:[]};
 const revised=file.text.slice(0,target.start)+target.after+file.text.slice(target.end);
 let syntax=false;try{parse(revised);syntax=true}catch{}
 const beforeLine=file.text.split('\n')[target.line-1]||'';
 const afterLine=revised.split('\n')[target.line-1]||'';
 const beforeHit=scanText(candidate.path,beforeLine).some(x=>x.id===id);
 const afterHit=scanText(candidate.path,afterLine).some(x=>x.id===id);
 const sameRuleBefore=scanText(candidate.path,file.text).filter(x=>x.id===id).flatMap(x=>x.lines).length;
 const sameRuleAfter=scanText(candidate.path,revised).filter(x=>x.id===id).flatMap(x=>x.lines).length;
 return {status:syntax&&beforeHit&&!afterHit?'completed':'inconclusive',revised,items:[{id,path:candidate.path,line:target.line,before:beforeLine,after:afterLine,checks:{syntax,before_pattern:beforeHit,after_pattern:afterHit,remaining_rule_hits:sameRuleAfter,previous_rule_hits:sameRuleBefore},limit:id==='sql-interpolation'?'확인된 드라이버에 맞는 바인딩을 적용했습니다. DB 실행·악용 검증은 하지 않았습니다.':'HTML 마크업이 일반 텍스트로 바뀝니다. 의도된 화면 동작과 실제 브라우저 보안을 확인하세요.',note:'임시 수정본의 구문과 같은 정적 규칙만 재검사했습니다. 취약점 해결이나 전체 코드 안전성을 증명하지 않습니다.'}]};
}
