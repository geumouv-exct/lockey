import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateRepair} from './ai-repair.mjs';
const finding={id:'dangerous-html',path:'src/view.js',lines:[1]};
const files=[{path:'src/view.js',text:'element.innerHTML = input;\n'}];
const config={url:'http://127.0.0.1:30001/v1/systemone',expectedRevision:'rev'};
function mock(answer,extras={}){return async (url,options)=>{assert.equal(url,'http://127.0.0.1:30001/v1/chat/completions');const req=JSON.parse(options.body);assert.equal(req.model,'zoro-1');assert.match(req.messages[1].content,/innerHTML/);return {ok:true,json:async()=>({model:'rev',choices:[{finish_reason:'stop',message:{content:JSON.stringify(answer)}}],...extras})}}}
test('returns full Zoro-1 repair and rescans the selected rule',async()=>{const result=await generateRepair(finding,files,{...config,fetcher:mock({status:'proposed',reason:'텍스트로 표시',code:'element.textContent = input;\n'})});assert.equal(result.status,'proposed');assert.equal(result.path,finding.path);assert.deepEqual(result.remaining,[])});
test('model may defer when context is insufficient',async()=>{const result=await generateRepair(finding,files,{...config,fetcher:mock({status:'defer',reason:'추가 맥락 필요'})});assert.equal(result.status,'deferred')});
test('rejects truncated, invalid and wrong revision responses',async()=>{for(const fetcher of [mock({status:'proposed',reason:'x',code:'safe'}, {model:'other'}),mock({status:'proposed',reason:'x',code:'safe'}, {choices:[{finish_reason:'length',message:{content:'{}'}}]}),mock({status:'proposed',reason:'x',code:files[0].text})])await assert.rejects(generateRepair(finding,files,{...config,fetcher}) )});
test('does not send unsupported files or untrusted model URLs',async()=>{let called=false;const fetcher=async()=>{called=true};await assert.rejects(generateRepair(finding,files,{...config,url:'http://example.com/v1/systemone',fetcher}));await assert.rejects(generateRepair({...finding,path:'package.json'},[{path:'package.json',text:'{}'}],{...config,fetcher}));assert.equal(called,false)});
test('같은 파일의 모든 경고를 하나의 모델 요청으로 전달한다',async()=>{
 const second={...finding,id:'hardcoded-credential',lines:[2]};
 let calls=0;
 const fetcher=async(url,opts)=>{
  calls++;
  const input=JSON.parse(JSON.parse(opts.body).messages[1].content);
  assert.deepEqual(input.findings,[finding,second].map(f=>({finding_type:f.id,lines:f.lines})));
  return mock({status:'proposed',reason:'수정',code:'element.textContent = input;'})(url,opts);
 };
 await generateRepair([finding,second],files,{...config,fetcher});
 assert.equal(calls,1);
});

test('형식이 깨진 응답은 같은 파일만 다시 요청하고 JSON 코드 블록도 검증한다',async()=>{
 const proposal={status:'proposed',reason:'텍스트로 표시',code:'element.textContent = input;'};
 const replies=['invalid','```json\n'+JSON.stringify(proposal)+'\n```'];
 const fetcher=async(url,options)=>{
  const request=JSON.parse(options.body);
  assert.equal(request.response_format.type,'json_object');
  assert.equal(JSON.parse(request.messages[1].content).source,files[0].text);
  return {ok:true,json:async()=>({model:'rev',choices:[{finish_reason:'stop',message:{content:replies.shift()}}]})};
 };
 const answer=await generateRepair(finding,files,{...config,fetcher});
 assert.equal(answer.code,proposal.code);
 assert.equal(replies.length,0);
});

test('두 번째 응답도 형식이 잘못되면 적용할 코드를 반환하지 않는다',async()=>{
 let calls=0;
 const fetcher=async()=>{calls++;return {ok:true,json:async()=>({model:'rev',choices:[{message:{content:'not JSON'}}]})}};
 await assert.rejects(generateRepair(finding,files,{...config,fetcher}),/유효한 수정안 형식/);
 assert.equal(calls,2);
});
