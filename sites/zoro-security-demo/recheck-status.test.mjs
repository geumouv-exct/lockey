import test from 'node:test';import assert from 'node:assert/strict';import {recheckStatus} from './recheck-status.mjs';
const original={hasCode:true,hasLink:true,url:'https://example.com',projectName:'demo',paths:['src/app.js','test/a.test.js']};
const current={...original,codeFindings:0,linkFindings:0,linkStatus:'checked',httpStatus:200,audit:{status:'completed',packages:0,omitted:0,detailsIncomplete:false}};
test('같은 범위의 재점검에서 후보가 없을 때만 완료',()=>{assert.equal(recheckStatus(original,current).status,'clear');assert.equal(recheckStatus(original,{...current,codeFindings:1}).status,'findings')});
test('대상 누락·다른 링크·제외된 파일·대조 실패는 완료하지 않음',()=>{for(const next of [{...current,hasCode:false},{...current,url:'https://other.example'},{...current,paths:['src/app.js']},{...current,audit:{status:'error'}},{...current,linkStatus:'redirect'}])assert.equal(recheckStatus(original,next).status,'incomplete');});
test('발견과 비교 불가가 동시에 있을 때 발견을 표시하고 누락 근거를 보존',()=>{const r=recheckStatus(original,{...current,hasCode:false,linkFindings:1});assert.equal(r.status,'findings');assert.ok(r.missing.length)});
