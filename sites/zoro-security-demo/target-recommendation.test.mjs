import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyService,recommendTarget} from './target-recommendation.mjs';

const profile={login:{answer:'yes',detail:'both'},private:{answer:'unknown',detail:'owner'},input:{answer:'no'}};
const page='<form action="/login"><input type="password"></form><!-- <input type="file"> --><script>"<input type=file>"</script>';
const source={path:'src/view.tsx',text:`export const matches = (user: User, item: Item) => user.id === item.ownerId;
export const Form = () => <input type="file" />;`};
const url='http://127.0.0.1:30001/v1/systemone';
test('실제 요소와 코드 구문만 대조하고 부분 일치·상충·출처를 보존',async()=>{
 const report=await verifyService({serviceProfile:profile,url:'https://site.example/login',files:[source]},{readPage:async()=>page});
 assert.deepEqual(report.checks.map(c=>c.status),['partial','matched','conflict']);
 assert.deepEqual(report.checks[2].observations.map(x=>[x.source,x.path,x.line]),[['source',source.path,2]]);
 assert.equal(report.checks[0].observations[0].source,'link');
});
test('자료를 읽지 못하면 추천 모델을 호출하지 않는다',async()=>{
 let calls=0;
 const report=await recommendTarget({serviceProfile:profile,url:'https://site.example/'},{url,fetcher:()=>calls++,readPage:async()=>{throw Error()}});
 assert.equal(calls,0);assert.equal(report.status,'insufficient');
 assert.ok(report.checks.every(x=>x.status==='unconfirmed'));
});
test('모델에는 선택값과 대조 결과만 보내고 잘못된 추천을 버린다',async()=>{
 const input={serviceProfile:profile,files:[source]};
 const reply=choice=>async(_,init)=>{
  const req=JSON.parse(init.body);
  assert.ok(!init.body.includes(source.path)&&!init.body.includes(source.text));
  assert.deepEqual(Object.keys(req.questions.target.criteria),['folder','defer']);
  assert.equal(req.state.service_checks[2].status,'conflict');
  return {ok:true,json:async()=>({answers:{target:{choice}},model:'revision'})};
 };
 assert.equal((await recommendTarget(input,{url,fetcher:reply('link')})).status,'offline');
 assert.equal((await recommendTarget(input,{url,fetcher:reply('defer')})).status,'deferred');
 assert.equal((await recommendTarget(input,{url,expectedRevision:'wrong',fetcher:reply('folder')})).status,'offline');
 assert.equal((await recommendTarget(input,{url,expectedRevision:'revision',fetcher:reply('folder')})).choice,'folder');
});
