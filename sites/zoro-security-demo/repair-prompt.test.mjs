import test from 'node:test';
import assert from 'node:assert/strict';
import {repairPrompt} from './repair-prompt.mjs';
const item={id:'dangerous-html',path:'private/module.js',lines:[5],status:'candidate'};
test('Zoro selects the prompt focus without receiving source paths',async()=>{
 const result=await repairPrompt(item,{url:'http://localhost/v1/systemone',expectedRevision:'fixture',fetcher:async(_,init)=>{
   assert.ok(!init.body.includes(item.path));
   return {ok:true,json:async()=>({model:'fixture',answers:{focus:{choice:'test'}}})};
 }});
 assert.match(result.text,/CWE-79/);assert.ok(result.text.includes(item.path));assert.match(result.text,/CWE-79\)\n검증: .*\n수정: /);
 await assert.rejects(repairPrompt(item,{}),/연결/);
});
test('서버 요청 수정 지침은 연결 주소·리다이렉트·프록시와 실제 검증을 명시하고 음슴체를 사용한다',async()=>{
 const result=await repairPrompt({id:'request-url',path:'src/request.js',lines:[7],status:'candidate'},{url:'http://localhost/v1/systemone',fetcher:async()=>({ok:true,json:async()=>({answers:{focus:{choice:'repair'}}})})});
 for(const term of ['src/request.js:7','DNS','실제 연결','리다이렉트','프록시','실제 HTTP 클라이언트'])assert.ok(result.text.includes(term),term);
 assert.doesNotMatch(result.text,/하라\.|바꿔라\.|주세요\./);
});
