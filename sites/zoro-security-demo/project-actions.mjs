import {createHash, randomUUID} from 'node:crypto';
import {scanText} from '../../security-review-mvp/scanner.mjs';
import {eligibleProjectPath} from './project-scan.mjs';
import {isolatedTest} from './isolated-test.mjs';

import {withDependencies} from './npm-bundle.mjs';

const sessions = new Map();
const expires = 30*60*1000;
const testPath = path => /(?:^|\/)(?:tests?|__tests__)\/.*\.[cm]?js$|\.(?:test|spec)\.[cm]?js$/i.test(path);
const snapshotTestPath=path=>testPath(path)||/(?:^|\/)test_[^/]+\.py$|(?:^|\/)[^/]+_test\.py$/i.test(path);
export function validateSnapshot(files) {
  if (!Array.isArray(files) || !files.length || files.length>200) throw Error('프로젝트 파일 수를 확인하세요.');
  const seen = new Set();
  let total=0;
  for (const file of files) {
    const path=file?.path;
    if (typeof path!=='string'||path.length>500||path.split('/').some(part=>
      !part || (part.startsWith('.') && part!=='.github') || /[:\\\x00-\x1f]/.test(part) || /^(node_modules|vendor|build|dist|coverage)$/i.test(part)) ||
      !(eligibleProjectPath(path)||snapshotTestPath(path)) || typeof file.text!=='string') throw Error('지원하지 않는 작업 사본 경로입니다.');
    const key=path.normalize('NFC').toLowerCase();
    const size=Buffer.byteLength(file.text);
    if (seen.has(key)||size>300000||(total+=size)>3000000) throw Error('파일 중복 또는 크기 제한 초과');
    seen.add(key);
  }
}
export function registerProposal(review,files,projectName) {
  if(review.status!=='completed'||!review.revised)return null;
  validateSnapshot(files);
  for(const [id,s] of sessions) if(Date.now()-s.created>expires&&!s.busy)sessions.delete(id);
  if(sessions.size>=24) {
    const oldest=[...sessions].find(([,s])=>!s.busy);
    if(!oldest)throw Error('검사 세션이 가득 찼습니다.');
    sessions.delete(oldest[0]);
  }
  const id=randomUUID();
  const item=review.items[0];
  sessions.set(id,{created:Date.now(),id:item.id,path:item.path,projectName,files:structuredClone(files),
    preview:{line:item.line,before:item.before,after:item.after},revised:review.revised,applied:false,busy:false});
  return id;
}
function session(token) {
  const value=sessions.get(token);
  if(!value||Date.now()-value.created>expires)throw Error('검사 세션이 만료되었습니다.');
  return value;
}
export function promptEvidence(token,id,path,lines,baselineFiles) {
  if(!token)return null;
  const s=session(token);
  if(s.id!==id||s.path!==path||!lines.includes(s.preview.line))return null;
  if(Array.isArray(baselineFiles)){const files=new Map(s.files.map(file=>[file.path,file.text]));if(files.size!==baselineFiles.length||baselineFiles.some(file=>files.get(file.path)!==file.text))return null;}
  return {...s.preview,test:s.selectedTest};
}
function patchLines(text,marker) {
  const lines=text.split('\n');
  const ended=lines.pop();
  return [...lines.map(line=>marker+line), ...(ended?[marker+ended,'\\ No newline at end of file']:[])];
}
function filePatch(path,before,after) {
  const quoted=prefix=>JSON.stringify(prefix+'/'+path);
  const count=text=>text.split('\n').length-Number(text.endsWith('\n'));
  return ['--- '+quoted('a'),'+++ '+quoted('b'),'@@ -1,'+count(before)+' +1,'+count(after)+' @@',
    ...patchLines(before,'-'),...patchLines(after,'+'),''].join('\n');
}
export function applyProposal(token) {
  const s=session(token);
  if(s.applied)throw Error('이미 적용한 수정안입니다.');
  const original=s.files.find(file=>file.path===s.path);
  s.applied=true;
  return {status:'applied',path:s.path,projectName:s.projectName,patch:filePatch(s.path,original.text,s.revised),
    sha256:createHash('sha256').update(s.revised).digest('hex'),tests:s.files.map(f=>f.path).filter(testPath)};
}
export async function testApplied(token,command,selectedFile) {
  const s=session(token);
  if(!s.applied||s.busy)throw Error('수정 적용 상태 또는 테스트 진행 상태를 확인하세요.');
  if(!['node-test','npm-test'].includes(command))throw Error('지원하지 않는 테스트 명령입니다.');
  if(selectedFile && (command!=='node-test'||!testPath(selectedFile)||!s.files.some(f=>f.path===selectedFile)))
    throw Error('검사 세션에서 회귀 테스트 파일을 선택하세요.');
  s.busy=true;
  try {
    const revised=s.files.map(f=>f.path===s.path?{...f,text:s.revised}:f);
    const {baseline,after,dependencyCount}=await withDependencies(s.files,async bundle=>{
      const baseline=selectedFile?await isolatedTest(s.files,command,selectedFile,bundle):null;
      const after=await isolatedTest(revised,command,selectedFile,bundle);
      return {baseline,after,dependencyCount:bundle?.count??0};
    });
    const hits=scanText(s.path,s.revised).find(f=>f.id===s.id)?.lines||[];
    const recovered=after.events.filter(e=>e.passed && e.file==='/tmp/project/'+selectedFile &&
      baseline?.events.some(old=>!old.passed&&old.assertion&&old.name===e.name&&old.file===e.file&&old.line===e.line));
    let status='failed';
    if(after.code===0) {
      if(command==='npm-test')status='count_unknown';
      else if(!after.events.length)status='no_tests';
      else if(selectedFile && baseline?.code!==0 && recovered.length && !hits.length)status='regression_passed';
      else status='suite_passed';
    }
    if(selectedFile)s.selectedTest=selectedFile;
    return {status,dependencyCount,exitCode:after.code,command:command==='npm-test'?'npm test':'node --test',
      testCount:command==='npm-test'?null:after.events.length,ruleHits:hits,output:after.output,
      baselineExit:baseline?.code??null,regression:recovered.map(e=>e.name),selectedFile};
  } finally {s.busy=false;}
}
