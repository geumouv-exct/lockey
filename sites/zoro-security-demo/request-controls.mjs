// Syntax observations only: none of these checks prove an SSRF defense is effective.
const name=n=>{if(n?.type==='Identifier')return n.name;if(n?.type!=='MemberExpression')return '';const parent=name(n.object),prop=n.computed?(n.property?.type==='Literal'&&typeof n.property.value==='string'?n.property.value:''):n.property.name;return parent&&prop?`${parent}.${prop}`:''};
function children(n){return Object.entries(n||{}).filter(([k,v])=>!['loc','start','end'].includes(k)&&v&&typeof v==='object').flatMap(([,v])=>Array.isArray(v)?v:[v]).filter(x=>x?.type)}
function walk(node,visit,root=true){if(!node)return;visit(node);if(!root&&['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(node.type))return;for(const child of children(node))walk(child,visit,false)}
function throwsWithin(node){let found=false;walk(node,n=>{if(n.type==='ThrowStatement')found=true});return found}
function propertyLiteral(object,key,value){
 if(object?.type!=='ObjectExpression')return null;
 const props=object.properties;let found=null;
 for(const p of props){if(p.type==='SpreadElement'||p.computed)return null;const k=p.key?.name??p.key?.value;if(k===key)found=p;}
 return found?.value?.type==='Literal'&&found.value.value===value?found:null;
}
export function requestControlEvidence(tree,line,sink){
 const matches=[];
 function locate(node,fn){
  if(!node)return;
  if(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(node.type))fn=node;
  if(node.type==='CallExpression'&&node.loc.start.line===line&&name(node.callee)===sink)matches.push({call:node,fn});
  for(const child of children(node))locate(child,fn);
 }
 locate(tree,null);
 const base={status:'unverified',observations:[],missing:['실제 허용 대상 정책과 모든 경로','DNS 확인과 실제 연결 주소의 일치','리다이렉트·프록시와 HTTP 클라이언트의 실제 동작'],note:'아래는 구문에서 관찰한 단서이며 안전성 증명이 아닙니다. 실제 프로젝트에서 격리 테스트와 수동 검토가 필요합니다.'};
 if(matches.length!==1||!matches[0].fn)return base;
 const {call,fn}=matches[0];let arg=call.arguments[0];const object=arg?.type==='MemberExpression'&&arg.property?.name==='href'?name(arg.object):null;
 const observations=[];
 if(object){
  let origin=false,protocol=false,credentials=false,guardLine=null;
  walk(fn.body,n=>{
   if(n.type!=='IfStatement'||n.loc.start.line>=call.loc.start.line||!throwsWithin(n.consequent))return;
   let o=false,p=false,c=false;
   walk(n.test,x=>{const member=name(x);if(member===`${object}.origin`)o=true;if(member===`${object}.protocol`)p=true;if(member===`${object}.username`||member===`${object}.password`)c=true});
   if(o||p||c){origin ||= o;protocol ||= p;credentials ||= c;guardLine=n.loc.start.line}
  });
  if(origin)observations.push({kind:'origin_condition',line:guardLine,label:'요청 URL의 origin 조건과 예외 처리 구문'});
  if(protocol)observations.push({kind:'protocol_condition',line:guardLine,label:'요청 URL의 프로토콜 조건과 예외 처리 구문'});
  if(credentials)observations.push({kind:'credentials_condition',line:guardLine,label:'요청 URL의 사용자 정보 조건과 예외 처리 구문'});
 }
 if(sink==='needle.get'){
  const opts=call.arguments[1];
  for(const [key,value,kind,label] of [['follow_max',0,'redirect_option','리다이렉트 횟수 0 설정'],['proxy',null,'proxy_option','프록시 null 설정'],['use_proxy_from_env_var',false,'env_proxy_option','환경 프록시 비활성 설정'],['rejectUnauthorized',true,'tls_option','TLS 인증서 검증 옵션']]){const p=propertyLiteral(opts,key,value);if(p)observations.push({kind,line:p.loc.start.line,label})}
  if(opts?.type==='ObjectExpression'&&!opts.properties.some(p=>p.type==='SpreadElement'||p.computed)){const agent=opts.properties.filter(p=>(p.key?.name??p.key?.value)==='agent').at(-1);if(agent)observations.push({kind:'agent_option',line:agent.loc.start.line,label:'요청에 agent 옵션을 전달하는 구문'})}
 }
 return {...base,status:observations.length?'observed_unverified':'unverified',observations};
}
