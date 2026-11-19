import {parse} from 'parse5';
import {parse as parseSource} from '@babel/parser';
import {readPublicHtml} from './public-link-check.mjs';
import {eligibleProjectPath} from './project-scan.mjs';
import {validateSnapshot} from './project-actions.mjs';
import {surveyContext} from './service-survey.mjs';
import {validModelUrl} from './zoro.mjs';

const signals={
 password:['login','비밀번호 로그인'], social:['login','소셜 로그인'],
 owner:['private','소유자 ID 비교'], group:['private','팀 ID 비교'], role:['private','사용자 역할 검사'],
 text:['input','글·댓글 작성'],file:['input','파일 입력']
};

function htmlEvidence(text,record){
 const stack=[{node:parse(text,{sourceCodeLocationInfo:true}),form:''}];
 while(stack.length){
  const {node,form}=stack.pop();
  const attr=Object.fromEntries((node.attrs||[]).map(a=>[a.name,a.value]));
  if(['template','script','style','noscript'].includes(node.tagName)||'hidden' in attr||'disabled' in attr)continue;
  const formInfo=node.tagName==='form'?[attr.action,attr.id,attr.name].join(' '):form;
  const line=node.sourceCodeLocation?.startLine;
  if(node.tagName==='input'&&attr.type?.toLowerCase()==='password'&&
     (/login|sign[-_]?in|register|sign[-_]?up/i.test(formInfo)||/^(?:new|current)-password$/i.test(attr.autocomplete||'')))record('password',line);
  if(node.tagName==='input'&&attr.type?.toLowerCase()==='file')record('file',line);
  if(['textarea','input'].includes(node.tagName)&&/comment|reply|post|게시글|댓글/i.test([formInfo,attr.name,attr.id].join(' ')))record('text',line);
  for(const child of node.childNodes||[])stack.push({node:child,form:formInfo});
 }
}
function member(node){
 if(node?.type==='Identifier')return node.name;
 if(node?.type!=='MemberExpression'||node.computed)return '';
 return member(node.object)+'.'+node.property.name;
}
function jsEvidence(text,record,path){
 let tree;
 try{tree=parseSource(text,{sourceType:'unambiguous',plugins:['estree',...(/\.[cm]?tsx?$/i.test(path)?['typescript']:[]),...(/\.[jt]sx?$/i.test(path)?['jsx']:[])]})}catch{return false}
 const stack=[tree];
 while(stack.length){
  const n=stack.pop(),line=n.loc.start.line;
  if(n.type==='JSXOpeningElement'){
   const tag=n.name?.name,attrs=Object.fromEntries(n.attributes.filter(a=>a.type==='JSXAttribute').map(a=>[a.name.name,a.value?.value]));
   if(tag==='input'&&attrs.type==='file')record('file',line);
   if(tag==='input'&&attrs.type==='password'&&/^(?:new|current)-password$/.test(attrs.autoComplete||''))record('password',line);
   if(['input','textarea'].includes(tag)&&/comment|reply|post/i.test([attrs.name,attrs.id].join(' ')))record('text',line);
  }
  if(n.type==='CallExpression'){
   const call=member(n.callee);
   if(/\.signInWithPassword$|^signInWithEmailAndPassword$/.test(call))record('password',line);
   if(/\.signInWithOAuth$|^signInWithPopup$/.test(call))record('social',line);
   if(/^(?:upload|multerUpload)\.(?:single|array|fields)$/.test(call))record('file',line);
   if(/\.(?:post|put)$/.test(call)&&/\/(?:comments?|posts?|replies)(?:\/|$)/i.test(n.arguments[0]?.value||''))record('text',line);
  }
  if(n.type==='BinaryExpression'&&['===','!==','==','!='].includes(n.operator)){
   const sides=[member(n.left),member(n.right)],identity=sides.some(s=>/(?:^|\.)(?:user|session\.user|auth)\.(?:id|uid|userId)$/i.test(s));
   if(identity&&sides.some(s=>/\.(?:ownerId|owner_id|authorId|author_id)$/i.test(s)))record('owner',line);
   if(sides.every(s=>/\.(?:teamId|team_id|groupId|group_id)$/i.test(s))&&sides[0]!==sides[1])record('group',line);
   if(sides.some(s=>/(?:^|\.)user\.role$/i.test(s))&&[n.left,n.right].some(v=>typeof v.value==='string'))record('role',line);
  }
  for(const child of Object.values(n)){
   if(Array.isArray(child)){for(const item of child)if(item?.type)stack.push(item)}
   else if(child?.type)stack.push(child);
  }
 }
 return true;
}

export async function verifyService(input,{readPage=readPublicHtml}={}){
 if(!input?.serviceProfile)throw Error('서비스 기능을 먼저 선택해 주세요.');
 const statements=surveyContext(input.serviceProfile),files=input.files??[],url=input.url??'';
 if(!Array.isArray(files)||typeof url!=='string'||(!files.length&&!url))throw Error('웹사이트 주소나 프로젝트 폴더를 선택해 주세요.');
 if(files.length)validateSnapshot(files);
 const evidence=[],seen=new Set();
 const recorder=(source,path)=>(signal,line)=>{
  const key=source+'-'+signal;
  if(seen.has(key))return;
  seen.add(key);evidence.push({signal,source,path,line,label:signals[signal][1]});
 };
 let linkStatus='absent',readableFiles=0;
 if(url){
  try{const html=await readPage(url);htmlEvidence(html,recorder('link',''));linkStatus='read'}
  catch{linkStatus='unavailable'}
 }
 for(const f of files){
  if(!eligibleProjectPath(f.path))continue;
  const add=recorder('source',f.path);
  if(/\.html?$/i.test(f.path)){htmlEvidence(f.text,add);readableFiles++}
  else if(/\.[cm]?[jt]sx?$/i.test(f.path)&&jsEvidence(f.text,add,f.path))readableFiles++;
 }
 const checks=statements.map(({feature,answer,detail})=>{
  const observations=evidence.filter(e=>signals[e.signal][0]===feature);
  const found=new Set(observations.map(e=>e.signal));
  const expected=detail==='both'?(feature==='login'?['password','social']:['text','file']):[detail];
  let status='unconfirmed';
  if(found.size){
   if(answer==='no'||detail==='none')status='conflict';
   else if(expected.every(x=>found.has(x)))status='matched';
   else status='partial';
  }
  return {feature,answer,detail,status,observations};
 });
 return {checks,linkStatus,readableFiles,fileCount:files.length};
}

export async function recommendTarget(input,{url,expectedRevision,fetcher=fetch,readPage}={}){
 const report=await verifyService(input,{readPage});
 const criteria={};
 if(report.linkStatus==='read')criteria.link='공개 링크의 응답 설정을 점검';
 if(report.readableFiles)criteria.folder='선택한 프로젝트 소스의 구현을 점검';
 if(criteria.folder&&criteria.link)criteria.code='링크와 로컬 코드를 함께 점검';
 if(!Object.keys(criteria).length)return {...report,status:'insufficient'};
 if(!validModelUrl(url))return {...report,status:'offline'};
 criteria.defer='대조 근거가 부족해 추천 보류';
 const state={link_status:report.linkStatus,source_files:report.fileCount,parsed_files:report.readableFiles,
  service_checks:report.checks.map(({observations,...claim})=>({...claim,evidence:observations.map(({signal,source})=>({signal,source}))}))};
 const request={model:'zoro-1',state,questions:{target:{type:'choice',instructions:'사용자가 제공한 자료와 설문 대조 결과를 바탕으로 유용한 점검 방식을 하나 선택하세요. 부분 일치와 미확인은 사실로 단정하지 마세요. 확인할 근거가 없으면 defer를 선택하세요.',criteria}},reasoning:false};
 try{
  const response=await fetcher(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),redirect:'error',signal:AbortSignal.timeout(60000)});
  if(!response.ok)throw Error();
  const data=await response.json(),choice=data.answers?.target?.choice;
  if(typeof choice!=='string'||!Object.hasOwn(criteria,choice)||(expectedRevision&&data.model!==expectedRevision))throw Error();
  return choice==='defer'?{...report,status:'deferred'}:{...report,status:'recommended',choice};
 }catch{return {...report,status:'offline'}}
}
