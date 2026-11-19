import {requestControlEvidence} from './request-controls.mjs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const acorn=require('../../security-agent/vendor/acorn/acorn.js');
const rules={
 'code-evaluation':{title:'외부 입력이 동적 코드 실행에 도달할 수 있습니다',owasp:'A05',why:'요청 입력이 eval에 전달될 수 있습니다.',fix:'eval을 제거하고 용도에 맞는 파서와 입력 범위 검증을 사용하세요.'},
 'dangerous-html':{title:'외부 입력이 HTML 삽입에 도달할 수 있습니다',owasp:'A05',why:'요청 입력이 HTML 삽입에 전달될 수 있습니다.',fix:'텍스트 렌더링 또는 검증된 HTML 정제를 사용하세요.'},
 'sql-interpolation':{title:'외부 입력이 SQL 문자열에 도달할 수 있습니다',owasp:'A05',why:'요청 입력이 쿼리 문자열에 전달될 수 있습니다.',fix:'DB 드라이버에 맞는 매개변수화 쿼리를 사용하세요.'},
 'command-input':{title:'외부 입력이 시스템 명령에 도달할 수 있습니다',owasp:'A05',why:'요청 입력이 셸 명령에 전달될 수 있습니다.',fix:'셸 호출을 피하고 허용 목록과 인자 분리를 적용하세요.'},
 'request-url':{title:'외부 입력이 서버 요청 주소에 도달할 수 있습니다',owasp:'A01',why:'요청 입력이 외부 요청 주소에 전달될 수 있습니다.',fix:'프로토콜과 목적지를 허용 목록으로 제한하세요.'}
};
function name(n){if(n?.type==='Identifier')return n.name;if(n?.type==='MemberExpression'){const parent=name(n.object),prop=n.computed?(n.property?.type==='Literal'&&typeof n.property.value==='string'?n.property.value:''):n.property.name;return parent&&prop?parent+'.'+prop:''}return ''}
function children(n){return Object.entries(n||{}).filter(([k,v])=>!['loc','start','end'].includes(k)&&v&&typeof v==='object').flatMap(([,v])=>Array.isArray(v)?v:[v]).filter(x=>x?.type)}
const clone=v=>v?{...v,steps:[...v.steps],sanitizers:[...v.sanitizers],branches:[...v.branches]}:null;
function merge(a,b){if(!a)return clone(b);if(!b)return clone(a);return {...clone(a),sanitizers:[...new Set([...a.sanitizers,...b.sanitizers])],branches:[...new Set([...a.branches,...b.branches])]}}
export function analyzeFlow(path,text){
 if(!/\.[cm]?js$/i.test(path))return {findings:[],status:'unsupported'};
 let tree;try{tree=acorn.parse(text,{ecmaVersion:'latest',sourceType:'module',locations:true,allowHashBang:true})}catch{return {findings:[],status:'parse_error'}}
 const functions=new Map(),findings=[],seen=new Set();let operations=0,limited=false;const activeBranches=[];
 function record(id,v,sink,line){if(!v)return;const key=[id,line,v.source,v.line].join(':');if(seen.has(key))return;seen.add(key);findings.push({id,path,lines:[line],...rules[id],severity:'확인 필요',status:'candidate',agent:'dataflow',trace:{source:v.source,sourceKind:v.sourceKind||'request_or_url',sourceLine:v.line,sink,sinkLine:line,steps:v.steps,branches:[...new Set([...v.branches,...activeBranches])],sanitizers:v.sanitizers},traceLimit:'정적 흐름 후보입니다. 호출 대상·분기 실행 가능성과 정제 효과는 별도 검증이 필요합니다.'})}
 for(const n of tree.body){const v=n.type==='ExportNamedDeclaration'?n.declaration:n;if(v?.type==='FunctionDeclaration'&&v.id)functions.set(v.id.name,v)}
 function expression(n,env,stack){
  if(!n)return null;
  if(++operations>30000){limited=true;return null}
  const pathName=name(n);
  if(/^(req|request)\.(query|params|body)(\.|$)/.test(pathName))return {source:pathName,line:n.loc.start.line,steps:[],sanitizers:[],branches:[]};
  if(/^(?:window\.)?location\.(?:hash|search)$/.test(pathName)||pathName==='document.URL')return {source:pathName,line:n.loc.start.line,steps:[],sanitizers:[],branches:[]};
  if(n.type==='Identifier')return clone(env.get(n.name));
  if(n.type==='Literal'||n.type==='FunctionExpression'||n.type==='ArrowFunctionExpression')return null;
  if(n.type==='CallExpression'){
   const callee=name(n.callee),args=n.arguments.map(a=>expression(a,env,stack));
   if(/^(?:window\.)?(?:localStorage|sessionStorage)\.getItem$/.test(callee))return {source:callee,line:n.loc.start.line,steps:[],sanitizers:[],branches:[],sourceKind:'browser_storage'};
   if(callee==='eval')record('code-evaluation',args[0],callee,n.loc.start.line);
   if(/(^|\.)(exec|execSync)$/.test(callee))record('command-input',args[0],callee,n.loc.start.line);
   if(['needle.get','fetch','axios.get'].includes(callee))record('request-url',args[0],callee,n.loc.start.line);
   if(/\.(query|execute)$/.test(callee)&&['TemplateLiteral','Identifier','BinaryExpression'].includes(n.arguments[0]?.type))record('sql-interpolation',args[0],callee,n.loc.start.line);
   if(functions.has(callee)&&!stack.includes(callee)&&stack.length<5){const fn=functions.get(callee),local=new Map();fn.params.forEach((p,i)=>{if(p.type==='Identifier'&&args[i])local.set(p.name,clone(args[i]))});return block(fn.body.body,local,[...stack,callee],n.loc.start.line).returned}
   let value=args.reduce(merge,null);
   if(value){value.steps.push(`${callee||'동적 함수'} 호출 (${n.loc.start.line}행)`);if(/(?:sanitize|escape|encode|validate|clean)/i.test(callee))value.sanitizers.push(`${callee} (${n.loc.start.line}행, 효과 미검증)`)}
   return value;
  }
  return children(n).reduce((v,c)=>merge(v,expression(c,env,stack)),null);
 }
 function block(statements,env,stack,callLine){
  let returned=null;
  for(const n of statements){
   if(++operations>30000){limited=true;break}
   if(n.type==='ReturnStatement'){returned=merge(returned,expression(n.argument,env,stack));break}
   if(n.type==='IfStatement'){
    const label=`${n.loc.start.line}행 조건 분기`;
    const yes=new Map([...env].map(([k,v])=>[k,clone(v)])),no=new Map([...env].map(([k,v])=>[k,clone(v)]));
    const list=x=>x?.type==='BlockStatement'?x.body:x?[x]:[];
    activeBranches.push(label+' 참');const left=block(list(n.consequent),yes,stack,callLine);activeBranches.pop();
    activeBranches.push(label+' 거짓');const right=block(list(n.alternate),no,stack,callLine);activeBranches.pop();
    returned=merge(returned,merge(left.returned,right.returned));
    for(const k of new Set([...yes.keys(),...no.keys()])){const v=merge(yes.get(k),no.get(k));if(v){v.branches.push(label);env.set(k,v)}else env.delete(k)}
    continue;
   }
   if(n.type==='BlockStatement'){returned=merge(returned,block(n.body,env,stack,callLine).returned);continue}
   if(n.type==='VariableDeclaration'){for(const d of n.declarations)if(d.id.type==='Identifier'){const v=expression(d.init,env,stack);if(v)env.set(d.id.name,v);else env.delete(d.id.name)}continue}
   if(n.type==='ExpressionStatement'){
    const e=n.expression;
    if(e.type==='AssignmentExpression'&&e.left.type==='Identifier'){const v=expression(e.right,env,stack);if(v)env.set(e.left.name,v);else env.delete(e.left.name);continue}
    let id,arg,sink;
    if(e.type==='AssignmentExpression'&&name(e.left).endsWith('.innerHTML')){id='dangerous-html';arg=e.right;sink=name(e.left)}
    if(id)record(id,expression(arg,env,stack),sink,e.loc.start.line);
    else expression(e,env,stack);
   }
  }
  if(returned&&callLine)returned.steps.push(`${stack.at(-1)} 반환 (${callLine}행 호출)`);
  return {returned};
 }
 function discover(n){if(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(n.type)){const stack=[name(n.id)||'<callback>'];if(n.body.type==='BlockStatement')block(n.body.body,new Map(),stack,null);else expression(n.body,new Map(),stack)}for(const child of children(n))discover(child)}
 discover(tree);
 let requestReviews=0;
 for(const finding of findings)if(finding.id==='request-url'){
  if(requestReviews++<50)finding.trace.requestReview=requestControlEvidence(tree,finding.lines[0],finding.trace.sink);
  else{limited=true;finding.trace.requestReview={status:'unverified',observations:[],missing:['구문 검토 개수 한도 초과'],note:'검토 한도를 초과해 보호 구문 분석을 수행하지 않았습니다. 안전 여부는 미확인입니다.'}}
 }
 return {findings,status:'analyzed',limited};
}

// A deliberately narrow proof: all HTML values must be literal, inert strings.
// This does not prove anything about other assignments or the surrounding application.
export function inertLiteralHtmlLines(path,text){
 if(!/\.[cm]?js$/i.test(path))return new Set();
 const generated=/(?:\.bundle|\.min)\.[cm]?js$/i.test(path);
 let tree;try{tree=acorn.parse(text,{ecmaVersion:'latest',sourceType:'module',locations:true,allowHashBang:true})}catch{return new Set()}
 const byLine=new Map();
 const inert=s=>!/<\s*\/?\s*(?:script|iframe|object|embed|link|style|svg|math)\b|\bon[a-z]+\s*=|(?:javascript|data)\s*:/i.test(s);
 function fixed(n){if(generated)return n?.type==='Literal'&&typeof n.value==='string'&&/^<script\s*>\s*<\/script\s*>$/i.test(n.value);if(n?.type==='Literal'&&typeof n.value==='string')return inert(n.value);if(n?.type==='TemplateLiteral'&&!n.expressions.length)return n.quasis.every(q=>inert(q.value.cooked||''));if(n?.type==='ConditionalExpression')return fixed(n.consequent)&&fixed(n.alternate);return false}
 function visit(n){if(n.type==='AssignmentExpression'&&n.operator==='='&&n.left?.type==='MemberExpression'&&(!n.left.computed&&n.left.property?.name==='innerHTML'||n.left.computed&&n.left.property?.value==='innerHTML')){const line=n.loc.start.line,old=byLine.get(line)||[];old.push(fixed(n.right));byLine.set(line,old)}for(const c of children(n))visit(c)}
 visit(tree);const source=text.split(/\r?\n/);
 return new Set([...byLine].filter(([line,values])=>values.every(Boolean)&&!source[line-1].includes('dangerouslySetInnerHTML')&&(source[line-1].match(/\binnerHTML\s*=/g)||[]).length===values.length).map(([line])=>line));
}

// Recognize a framework property-to-sink shape as a lead, never as proof of an attacker-controlled input.
export function htmlPropertyCandidates(path,text){
 if(!/(?:\.bundle|\.min)\.[cm]?js$/i.test(path))return new Set();
 let tree;try{tree=acorn.parse(text,{ecmaVersion:'latest',sourceType:'module',locations:true,allowHashBang:true})}catch{return new Set()}
 const candidates=new Set();
 function inspectCase(n){
  const aliases=new Set(),sinks=[];
  function visit(x){
   if(!x||typeof x!=='object')return;
   if(x.type==='AssignmentExpression'&&x.operator==='='){
    if(x.left?.type==='Identifier'&&x.right?.type==='MemberExpression'&&!x.right.computed&&x.right.property?.name==='__html')aliases.add(x.left.name);
    if(x.left?.type==='MemberExpression'&&!x.left.computed&&x.left.property?.name==='innerHTML'&&x.right?.type==='Identifier')sinks.push({line:x.loc.start.line,alias:x.right.name});
   }
   for(const c of children(x))visit(c);
  }
  for(const x of n.consequent)visit(x);
  for(const sink of sinks)if(aliases.has(sink.alias))candidates.add(sink.line);
 }
 function visit(n){if(n.type==='SwitchCase'&&n.test?.type==='Literal'&&n.test.value==='dangerouslySetInnerHTML')inspectCase(n);else for(const c of children(n))visit(c)}
 visit(tree);return candidates;
}
