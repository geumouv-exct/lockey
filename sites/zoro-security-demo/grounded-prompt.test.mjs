import test from 'node:test';
import assert from 'node:assert/strict';
import {repairPrompt} from './repair-prompt.mjs';
import {scanProject} from './project-scan.mjs';
import {registerBaseline} from './external-comparison.mjs';
import {reviewProject} from './project-review.mjs';
import {registerProposal} from './project-actions.mjs';
const source={path:'src/view.mjs',text:'export function render(element, text) {\n  element.innerHTML = text;\n}\n'};
const testFile={path:'tests/view.test.mjs',text:'// test file\n'};
const files=[source,testFile];const findings=scanProject([source]).findings;const finding=findings.find(f=>f.id==='dangerous-html');
const options={url:'http://localhost/v1/systemone',expectedRevision:'fixture',fetcher:async(_,init)=>{const state=JSON.parse(init.body);assert.ok(!init.body.includes(source.path));assert.ok(!init.body.includes('element.innerHTML'));return {ok:true,json:async()=>({model:'fixture',answers:{focus:{choice:'repair'}}})}}};
test('원본 세션의 실제 경고 줄, 사용자 답변, 확인된 수정안과 테스트 후보를 반영',async()=>{
 const token=registerBaseline(files,'demo',findings),review=reviewProject([source],findings,'review_html'),proposal=registerProposal(review,files,'demo');
 const r=await repairPrompt({...finding,baselineToken:token,token:proposal,inputOrigin:'external'},options);
 assert.equal(r.sourceVerified,true);assert.equal(r.reviewedEdit,true);assert.match(r.text,/src\/view.mjs:2/);assert.match(r.text,/2:   element\.innerHTML = text;/);assert.match(r.text,/element\.textContent = text;/);assert.match(r.text,/방문자 입력 가능/);assert.match(r.text,/tests\/view\.test\.mjs/);
});
test('텍스트 목적이 확인되지 않으면 제안 코드를 조건부로 제시',async()=>{
 const token=registerBaseline(files,'demo',findings),proposal=registerProposal(reviewProject([source],findings,'review_html'),files,'demo');
 const r=await repairPrompt({...finding,baselineToken:token,token:proposal},options);assert.match(r.text,/일반 텍스트 용도임을 확인한 경우에만/);
});
test('다른 작업 사본의 수정안은 경고 위치가 같아도 사용하지 않는다',async()=>{
 const token=registerBaseline(files,'demo',findings),other=[source,{...testFile,text:'// 다른 프로젝트 테스트\n'}],proposal=registerProposal(reviewProject([source],findings,'review_html'),other,'other');
 const r=await repairPrompt({...finding,baselineToken:token,token:proposal},options);assert.equal(r.reviewedEdit,false);assert.doesNotMatch(r.text,/element\.innerHTML = text; 를/);assert.match(r.text,/tests\/view\.test\.mjs/);
});
test('자격 증명 후보의 실제 값은 수정 요청에 포함하지 않는다',async()=>{
 const secret={path:'src/config.js',text:'const password = "super_secret_password_123456";\n'},fs=scanProject([secret]).findings,f=fs.find(x=>x.id==='hardcoded-credential');
 const r=await repairPrompt({...f,baselineToken:registerBaseline([secret],'demo',fs)},options);assert.doesNotMatch(r.text,/super_secret_password_123456/);assert.match(r.text,/민감정보 보호/);
});
test('소스 경고와 세션이 일치하지 않으면 생성하지 않으며 숫자 포함 규칙을 지원',async()=>{
 const token=registerBaseline(files,'demo',findings);await assert.rejects(repairPrompt({...finding,path:'other.mjs',baselineToken:token},options),/경고/);
 const out=await repairPrompt({id:'git-object-sha1',path:'src/git.js',lines:[1],status:'candidate'},options);assert.match(out.text,/src\/git\.js:1/);
});
