import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const require=createRequire(import.meta.url);
const acorn=require('../../security-agent/vendor/acorn/acorn.js');
const execFileAsync=promisify(execFile);
const root=dirname(fileURLToPath(import.meta.url));
function walk(n,fn){if(!n||typeof n!=='object')return;if(n.type)fn(n);for(const [k,v] of Object.entries(n)){if(['loc','start','end'].includes(k))continue;if(Array.isArray(v))v.forEach(x=>walk(x,fn));else if(v&&typeof v==='object')walk(v,fn)}}
function member(n){if(n?.type==='Identifier')return n.name;if(n?.type==='MemberExpression'&&!n.computed){const base=member(n.object);return base?`${base}.${n.property.name}`:''}return ''}
export function traceSample(source){
 const tree=acorn.parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true});
 const flows=[];
 walk(tree,n=>{
  if(n.type==='CallExpression'&&member(n.callee)==='db.query'&&n.arguments[0]?.type==='TemplateLiteral'){
   for(const expr of n.arguments[0].expressions)if(member(expr)==='req.query.name')flows.push({id:'sql-interpolation',source:'req.query.name',sourceLine:expr.loc.start.line,sink:'db.query(문자열 조합)',sinkLine:n.loc.start.line});
  }
  if(n.type==='AssignmentExpression'&&member(n.left)==='element.innerHTML'&&member(n.right)==='product.description')flows.push({id:'dangerous-html',source:'product.description',sourceLine:n.right.loc.start.line,sink:'element.innerHTML',sinkLine:n.left.loc.start.line});
 });
 return flows;
}
export async function reviewSample(){
 try{
  const source=await readFile(join(root,'fixtures/shop.js'),'utf8');
  const fixtures={'fixtures/shop.js':'07c1626498dbb1ab233f92479cd325e5f3a4eea9cfd9f28800e29d344bfb173e','fixtures/shop-safe.mjs':'d3286502dc706687fe4dd12d41099f6ecde059c2b28fbf14fa2ca31c8ced266c','fixture-probe.mjs':'ae152f8652a3a82566516447f518627f90f2691533ae810157048a983d141adc'};
  for(const [path,expected] of Object.entries(fixtures)){const bytes=await readFile(join(root,path));if(createHash('sha256').update(bytes).digest('hex')!==expected)throw new Error('fixture integrity mismatch');}
  const traces=traceSample(source);
  const {stdout}=await execFileAsync(process.execPath,[join(root,'fixture-probe.mjs')],{timeout:5000,maxBuffer:16384,env:{PATH:process.env.PATH||'/usr/bin:/bin',NODE_NO_WARNINGS:'1'}});
  const data=JSON.parse(stdout);
  const checks=[
   {id:'sql-interpolation',observed:data?.vulnerable?.sql?.markerInQuery===true&&data?.vulnerable?.sql?.markerInParams===false&&data?.safe?.sql?.markerInQuery===false&&data?.safe?.sql?.markerInParams===true,test:'테스트 입력이 SQL 문자열에 포함됨. 수정 대조군에서는 쿼리와 매개변수가 분리됨.',fixCode:"db.query('SELECT * FROM products WHERE name = ?', [req.query.name]);",limit:'실제 DB 실행이나 SQL 인젝션 악용은 검증하지 않았습니다.'},
   {id:'dangerous-html',observed:data?.vulnerable?.html?.markerInInnerHTML===true&&data?.safe?.html?.markerInInnerHTML===false&&data?.safe?.html?.markerInTextContent===true,test:'테스트 HTML이 innerHTML에 전달됨. 수정 대조군에서는 textContent에 전달됨.',fixCode:'element.textContent = product.description;',limit:'실제 브라우저의 스크립트 실행이나 입력 출처는 검증하지 않았습니다.'}
  ];
  return {status:'completed',method:'AST 데이터 흐름 확인 + 전용 가상 함수 테스트 및 수정 대조군',items:checks.map(c=>{const trace=traces.find(x=>x.id===c.id);return {...c,trace:trace||null,status:trace&&c.observed?'flow_verified':'inconclusive'}}),scope:'저장소에 포함된 고정 샘플만 실행; 실제 서비스는 미검사'};
 }catch{return {status:'error',items:[],scope:'코드 흐름 검사 또는 샘플 프로브 실행 실패'}}
}
