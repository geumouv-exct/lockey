import test from 'node:test';import assert from 'node:assert/strict';import {groupFindings} from './finding-groups.mjs';
test('동일 CWE는 파일과 규칙이 달라도 하나로 묶고 각 발견 위치는 보존',()=>{
 const a={id:'dangerous-html',key:'a',path:'a.js',lines:[1]},b={id:'dangerous-html',key:'b',path:'b.js',lines:[9]},c={id:'sql-interpolation',key:'c',path:'b.js',lines:[3]},d={id:'private-key',key:'d'},e={id:'hardcoded-credential',key:'e'};
 const groups=groupFindings([a,b,c,d,e]);assert.equal(groups.length,3);assert.deepEqual(groups[0].findings,[a,b]);assert.deepEqual(groups[2].findings,[d,e]);
});
test('CWE 미확인인 서로 다른 규칙을 임의로 하나로 합치지 않는다',()=>{
 const g=groupFindings([{id:'actions-floating-ref',key:'a'},{id:'git-object-sha1',key:'b'}]);assert.equal(g.length,2);
});
test('근거가 많은 위치를 대표로 선택하고 같은 경우 생성된 번들보다 원본을 선택한다',async()=>{
 const {representativeFinding}=await import('./finding-groups.mjs');
 const bundle={id:'dangerous-html',path:'x.bundle.js',lines:[1]},source={id:'dangerous-html',path:'source.js',lines:[2]},traced={...bundle,trace:{source:'location.hash',sourceLine:1,sinkLine:1}};
 const findings=[bundle,source];assert.equal(representativeFinding({findings}),source);assert.deepEqual(findings,[bundle,source]);assert.equal(representativeFinding({findings:[source,traced]}),traced);
});
