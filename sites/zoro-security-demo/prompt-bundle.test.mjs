import {test} from 'node:test';
import assert from 'node:assert/strict';
import {selectPromptItems, combinePromptItems} from './prompt-bundle.mjs';
test('다음 단계는 모든 코드·링크 경고를 한 요청으로 묶는다', () => {
 const code=[{key:'a',title:'HTML',link:false},{key:'b',title:'SQL',link:false}], links=[{index:0,title:'CSP',link:true}];
 const items=selectPromptItems(code,links,null), text=combinePromptItems(items,['a 코드','b 코드','c 헤더'],null);
 assert.equal(items.length,3); for(const s of ['HTML','SQL','CSP','a 코드','b 코드','c 헤더'])assert.ok(text.includes(s));
 assert.throws(()=>combinePromptItems(items,['a 코드','b 코드'],null));
});
test('개별 버튼은 고른 경고 하나만 사용하며 링크와 코드 경고를 구분한다', () => {
 const code=[{key:'a',title:'HTML',link:false},{key:'b',title:'SQL',link:false}],links=[{index:0,title:'CSP',link:true}];
 const selected=selectPromptItems(code,links,{type:'code',key:'b'});assert.deepEqual(selected,[code[1]]);
 assert.match(combinePromptItems(selected,['b 코드'],{type:'code',key:'b'}),/b 코드/);
 assert.deepEqual(selectPromptItems(code,links,{type:'link',index:0}),links);
 assert.deepEqual(selectPromptItems(code,links,{type:'code',key:'missing'}),[]);
});
test('의존성 권고도 통합하고 개별 요청은 같은 권고만 선택한다',()=>{
 const code=[{key:'c',title:'코드',link:false}],dep={key:'lodash@4.17.20|GHSA-35jh-r3h4-6jhm',title:'lodash 권고',link:true,dependency:true};
 assert.deepEqual(selectPromptItems(code,[dep],null),[code[0],dep]);
 const selected=selectPromptItems(code,[dep],{type:'dependency',key:dep.key});assert.deepEqual(selected,[dep]);
 assert.match(combinePromptItems(selected,['수정 버전 4.17.21'],{type:'dependency',key:dep.key}),/4\.17\.21/);
});
