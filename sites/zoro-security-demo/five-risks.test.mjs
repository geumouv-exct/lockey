import test from 'node:test';
import assert from 'node:assert/strict';
import {scanProject} from './project-scan.mjs';
import {summarizeRisks} from './five-risks.mjs';
import {extractPackages,queryOsv} from './dependency-audit.mjs';

test('다섯 범주별 후보와 의존성 확인 가능 여부를 표시하고 비밀값을 노출하지 않는다',()=>{
 const text='const password="this-is-a-fake-password";\nconst cookie = {secure: false};\nfunction show(req,el){el.innerHTML = req.query.x;}\n';
 const files=[{path:'src/a.js',text},{path:'package-lock.json',text:'{}'}];
 const findings=scanProject(files).findings;const groups=summarizeRisks(findings,files);
 assert.deepEqual(groups.map(g=>g.id),['access','secrets','session','injection','dependencies']);
 assert.equal(groups.find(g=>g.id==='secrets').items[0].id,'hardcoded-credential');
 assert.equal(groups.find(g=>g.id==='session').items[0].id,'cookie-secure-false');
 assert.equal(groups.find(g=>g.id==='injection').items[0].id,'dangerous-html');
 assert.equal(groups.find(g=>g.id==='dependencies').status,'대조 가능');
 assert.ok(!JSON.stringify(groups).includes('this-is-a-fake-password'));
});
test('OSV 결과 페이지를 취합하고 패키지와 버전만 전달한다',async()=>{
 const lock=JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/a':{version:'1.0.0'}}});let calls=0;
 const out=await queryOsv(lock,{includeDetails:false,fetcher:async(url,init)=>{assert.equal(url,'https://api.osv.dev/v1/querybatch');const q=JSON.parse(init.body).queries[0];assert.deepEqual(q.package,{ecosystem:'npm',name:'a'});assert.equal(q.version,'1.0.0');calls++;return {ok:true,json:async()=>({results:[calls===1?{vulns:[{id:'GHSA-abcd-efgh-ijkl'}],next_page_token:'next'}:{vulns:[{id:'CVE-2024-12345'}]}]})}}});
 assert.equal(calls,2);assert.deepEqual(out.packages[0].advisories,['GHSA-abcd-efgh-ijkl','CVE-2024-12345']);
});
test('미지원 잠금 파일과 실패한 OSV 조회는 안전하다고 표시하지 않는다',async()=>{
 assert.throws(()=>extractPackages('{}'),/lockfileVersion/);
 const lock=JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/a':{version:'1.0.0'}}});
 await assert.rejects(queryOsv(lock,{fetcher:async()=>({ok:false,status:503})}),/OSV 조회 실패/);
});
