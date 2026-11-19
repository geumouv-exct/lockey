import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
const close=server=>new Promise(resolve=>server.close(resolve));
test('모의 System One 선택에 따라 로컬 검증을 실행하거나 건너뛴다',async()=>{
 let choice='verify_access',lastRequest;
 const mock=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;lastRequest=JSON.parse(body);res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({model:'test-stub',answers:{next_step:{type:'choice',choice,probabilities:{review_code:choice==='review_code'?.8:.1,verify_access:choice==='verify_access'?.8:.1,defer:.1}}}}))});
 const mockPort=await listen(mock);process.env.ZORO_EXPECTED_REVISION='test-stub';process.env.ZORO_DECIDE_URL=`http://127.0.0.1:${mockPort}/v1/systemone`;
 const {createServer}=await import('./server.mjs');const server=createServer();const port=await listen(server);
 try{
  const scan=async()=>{const res=await fetch(`http://127.0.0.1:${port}/api/scan`,{method:'POST'});assert.equal(res.status,200);return res.json()};
  const verified=await scan();assert.equal(lastRequest.model,'zoro-1');assert.equal(verified.model.choice,'verify_access');assert.equal(verified.model.model_verified,true);assert.equal(verified.dynamic.status,'skipped');
  choice='review_code';const reviewed=await scan();assert.equal(reviewed.model.choice,'review_code');assert.equal(reviewed.dynamic.status,'skipped');assert.equal(reviewed.flow.status,'completed');assert.equal(reviewed.findings.filter(f=>f.status==='flow_verified').length,2);
 }finally{await close(server);await close(mock)}
});
