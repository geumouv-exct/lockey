import test from 'node:test';
import assert from 'node:assert/strict';
import {decide,validModelUrl} from './zoro.mjs';
const url='http://127.0.0.1:30001/v1/systemone';
test('System One 계약으로 요청하고 실제 응답 필드를 검증한다',async()=>{
 let request;
 const result=await decide([{category:'SQL'}],{url,fetcher:async(u,init)=>{request=JSON.parse(init.body);return {ok:true,json:async()=>({model:'zoro-1',answers:{next_step:{type:'choice',choice:'verify_access',probabilities:{review_code:.1,verify_access:.8,defer:.1}}}})}}});
 assert.equal(request.model,'zoro-1');assert.equal(request.reasoning,false);assert.equal(request.questions.next_step.type,'choice');assert.equal(result.choice,'verify_access');assert.equal(result.model_verified,false);
});
test('모델 미설정과 허용하지 않는 주소는 연결하지 않는다',async()=>{assert.equal(validModelUrl('http://example.com/v1/systemone'),false);assert.equal((await decide([],{url:''})).status,'not_connected')});
test('누락된 확률, 알 수 없는 선택, 서버 오류를 실패로 처리한다',async()=>{for(const data of [{answers:{next_step:{choice:'verify_access'}}},{answers:{next_step:{choice:'unknown',probabilities:{review_code:0,verify_access:0,defer:1}}}}]){const r=await decide([],{url,fetcher:async()=>({ok:true,json:async()=>data})});assert.equal(r.status,'error')}const r=await decide([],{url,fetcher:async()=>({ok:false,status:500})});assert.equal(r.status,'error')});
test('서버가 보고한 모델 리비전을 설정된 리비전과 비교한다',async()=>{
 const fake=async()=>({ok:true,json:async()=>({model:'revision-a',answers:{next_step:{choice:'defer',probabilities:{review_code:.1,verify_access:.2,defer:.7}}}})});
 assert.equal((await decide([],{url,expectedRevision:'revision-a',fetcher:fake})).model_verified,true);
 assert.equal((await decide([],{url,expectedRevision:'revision-b',fetcher:fake})).status,'error');
});
