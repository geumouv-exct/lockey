import test from 'node:test';
import assert from 'node:assert/strict';
import {scanProject} from './project-scan.mjs';
import {reviewProject} from './project-review.mjs';
import {chooseProjectReview} from './zoro.mjs';
const review=(text,choice)=>{const files=[{path:'src/app.js',text}];return reviewProject(files,scanProject(files).findings,choice)};
test('SQL 수정안을 만들고 원본 및 수정본에 같은 규칙을 다시 적용한다',()=>{const r=review('import pg from "pg"; const db=new pg.Pool(); function get(req){return db.query(`SELECT * FROM items WHERE id = \'${req.query.id}\'`)}','review_sql');assert.equal(r.status,'completed');const x=r.items[0];assert.match(x.after,/\$1\", \[req\.query\.id\]/);assert.equal(x.checks.before_pattern,true);assert.equal(x.checks.after_pattern,false);assert.equal(x.checks.syntax,true);assert.equal(x.checks.remaining_rule_hits,0)});
test('HTML 대입의 변경안을 만들되 브라우저 검증은 주장하지 않는다',()=>{const r=review('function render(el, data){el.innerHTML = data.html;}','review_html');assert.equal(r.status,'completed');assert.match(r.items[0].after,/el\.textContent = data\.html/);assert.match(r.items[0].limit,/브라우저/)});
test('복잡한 SQL과 구문 분석 불가 프로젝트는 수정안을 제시하지 않는다',()=>{assert.equal(review('db.query(`SELECT * FROM t WHERE x = \'prefix${req.query.x}\'`)','review_sql').status,'unsupported');assert.equal(review('const x = <div/>; el.innerHTML = value;','review_html').status,'unsupported');assert.equal(review('el.innerHTML = x;','defer').status,'deferred')});
test('Zoro-1은 코드 없이 탐지 유형을 바탕으로 허용된 검토를 선택한다',async()=>{let body;const findings=[{id:'sql-interpolation',path:'src/app.js',code:'sensitive marker'}];const out=await chooseProjectReview(findings,{url:'http://127.0.0.1:30001/v1/systemone',fetcher:async(_url,req)=>{body=JSON.parse(req.body);return{ok:true,json:async()=>({model:'rev',answers:{review_step:{choice:'review_sql',probabilities:{review_sql:0.8,defer:0.2}}}})}}});assert.equal(out.choice,'review_sql');assert.equal(JSON.stringify(body).includes('sensitive marker'),false);assert.equal(JSON.stringify(body).includes('src/app.js'),false);});
test('모델이 미허용 선택이나 잘못된 확률을 반환하면 검토를 실행하지 않는다',async()=>{const findings=[{id:'dangerous-html',path:'src/a.js'}];const out=await chooseProjectReview(findings,{url:'http://127.0.0.1:30001/v1/systemone',fetcher:async()=>({ok:true,json:async()=>({answers:{review_step:{choice:'review_sql',probabilities:{review_sql:1}}}})})});assert.equal(out.status,'error')});
test('SQL driver and scalar position must be recognized',()=>{
 for(const sql of ['SELECT * FROM \${table}', 'SELECT * FROM t ORDER BY \${column}']){
 const file='import pg from "pg"; const db=new pg.Pool(); db.query(`'+sql+'`)';
 assert.equal(review(file,'review_sql').status,'unsupported');
 }
 assert.equal(review('db.query(`SELECT * FROM t WHERE id = \${id}`)','review_sql').status,'unsupported');
 const mysql=review('import mysql from "mysql2/promise"; const db=mysql.createPool({}); db.query(`SELECT * FROM t WHERE id = \${id}`)','review_sql');
 assert.match(mysql.items[0].after,/db\.execute\(/);
});
test('프로젝트 설문 답변을 모델에 전달한다',async()=>{
 const context=[{feature:'login',answer:'yes',detail:'social'}];
 let state;
 await chooseProjectReview([{id:'sql-interpolation',path:'a.js'}],{context,url:'http://localhost/v1/systemone',fetcher:async(_,req)=>{
   state=JSON.parse(req.body).state;return {ok:false,status:503};
 }});
 assert.deepEqual(state.user_statements,context);
});
