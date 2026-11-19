import test from 'node:test';
import assert from 'node:assert/strict';
import {codeDiff} from './code-diff.mjs';
test('코드 변경 전후의 삭제 및 추가 부분을 구분하고 원문을 보존',()=>{
 const before='element.innerHTML = message;',after='element.textContent = message;',d=codeDiff(before,after);
 assert.equal(d.before.map(x=>x.text).join(''),before);assert.equal(d.after.map(x=>x.text).join(''),after);
 assert.deepEqual(d.before.filter(x=>x.changed).map(x=>x.text),['innerHTML']);assert.deepEqual(d.after.filter(x=>x.changed).map(x=>x.text),['textContent']);
 assert.deepEqual(codeDiff('안녕','안녕'),{before:[{text:'안녕',changed:false}],after:[{text:'안녕',changed:false}]});
});
test('긴 코드도 제한된 메모리로 안전하게 비교',()=>{const d=codeDiff('a'.repeat(2000),'b'.repeat(2000));assert.equal(d.before[0].changed,true);assert.equal(d.after[0].changed,true)});
test('큰 비교에서도 공통 접두사와 접미사는 강조하지 않는다',()=>{
 const shared=Array.from({length:1100},(_,i)=>`t${i} `).join('');
 const d=codeDiff(shared+'before '+shared,shared+'after '+shared);
 assert.equal(d.before[0].changed,false);assert.equal(d.after[0].changed,false);
 assert.equal(d.before.at(-1).changed,false);assert.equal(d.after.at(-1).changed,false);
 assert.equal(d.before.map(x=>x.text).join(''),shared+'before '+shared);
});
