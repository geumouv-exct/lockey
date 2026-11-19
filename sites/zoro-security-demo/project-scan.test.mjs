import test from 'node:test';
import assert from 'node:assert/strict';
import {scanProject,eligibleProjectPath} from './project-scan.mjs';
import {surveyContext} from './service-survey.mjs';
test('프로젝트 코드의 위험 후보를 파일 위치와 WSTG와 연결한다',()=>{const r=scanProject([{path:'src/app.js',text:'const query = (req, db) => db.query(`SELECT * FROM x WHERE id=${req.query.id}`);'}]);assert.equal(r.files,1);assert.equal(r.findings[0].id,'sql-interpolation');assert.equal(r.findings[0].wstg,'WSTG-v42-INPV-05');assert.equal(r.findings[0].status,'candidate')});
test('비밀 파일, 제외 폴더, 경로 이탈 및 큰 파일을 거부한다',()=>{for(const p of ['.env','src/.ENV.local','src/key.pem','node_modules/a.js','../x.js','tests/a.js'])assert.equal(eligibleProjectPath(p),false,p);assert.throws(()=>scanProject([{path:'src/a.js',text:'x'.repeat(300001)}]));});
test('서비스 기능이 없으면 후속 답을 보내지 않는다',()=>{
 const profile={login:{answer:'no',detail:'social'},private:{answer:'no'},input:{answer:'no'}};
 assert.deepEqual(surveyContext(profile),Object.keys(profile).map(feature=>({feature,answer:'no'})));
 assert.deepEqual(surveyContext(undefined),[]);
});
test('해당하거나 모르는 기능에만 선택한 답을 전달한다',()=>{
 const profile={login:{answer:'yes',detail:'password'},private:{answer:'no'},input:{answer:'unknown',detail:'none'}};
 assert.deepEqual(surveyContext(profile),Object.entries(profile).map(([feature,item])=>({feature,...item})));
 for(const detail of [undefined,'arbitrary','none'])assert.throws(()=>surveyContext({...profile,login:{answer:'yes',detail}}));
 assert.throws(()=>surveyContext({...profile,private:{answer:''}}));
});
test('탐지 유형에 관련 CWE 후보만 연결하고 CVE를 추측하지 않는다',async()=>{const {classification}=await import('./classifications.mjs');const sql=classification({id:'sql-interpolation'});assert.equal(sql.cwe,'CWE-89');assert.equal(sql.cweName,'Improper Neutralization of Special Elements used in an SQL Command');assert.equal(sql.cve,'미확인');assert.ok(sql.summary);assert.ok(sql.fix);assert.equal(classification({id:'actions-floating-ref'}).cwe,'미확인');assert.equal(classification({id:'unknown'}).cve,'미확인')});
