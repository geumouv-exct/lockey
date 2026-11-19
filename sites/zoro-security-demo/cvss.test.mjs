import test from 'node:test';import assert from 'node:assert/strict';
import {cvssBase,advisoryCvss} from './cvss.mjs';
import {queryOsv} from './dependency-audit.mjs';
test('CVSS v3 기본 점수 계산과 잘못된 벡터 거부',()=>{
 assert.equal(cvssBase('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score,9.8);
 assert.equal(cvssBase('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N').score,6.1);
 assert.equal(cvssBase('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N').score,0);
 assert.equal(cvssBase('CVSS:3.1/AV:N/AC:L'),null);assert.equal(cvssBase('CVSS:4.0/AV:N'),null);
 assert.deepEqual(advisoryCvss({severity:[{type:'CVSS_V3',score:'not-a-vector'}]}),[]);
});
test('패키지 버전과 매칭된 OSV 권고의 벡터만 점수로 표시',async()=>{
 const lock=JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/a':{version:'1.0.0'}}});
 const v='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
 const r=await queryOsv(lock,{fetcher:async url=>url.endsWith('/querybatch')?{ok:true,json:async()=>({results:[{vulns:[{id:'GHSA-abcd-efgh-ijkl'}]}]})}:{ok:true,json:async()=>({id:'GHSA-abcd-efgh-ijkl',aliases:['CVE-2024-12345'],severity:[{type:'CVSS_V3',score:v}],affected:[]})}});
 assert.equal(r.packages[0].details[0].cvss[0].score,9.8);assert.equal(r.packages[0].details[0].cvss[0].vector,v);
});
