import test from 'node:test';
import assert from 'node:assert/strict';
import {traceSample,reviewSample} from './code-flow.mjs';
test('샘플 위험 흐름을 안전한 대조군과 함께 확인한다',async()=>{const result=await reviewSample();assert.equal(result.status,'completed');assert.deepEqual(result.items.map(i=>i.status),['flow_verified','flow_verified']);assert(result.items.every(i=>i.limit.includes('검증하지 않았습니다')))});
test('바인딩된 쿼리와 textContent는 위험한 흐름으로 보고하지 않는다',()=>{const source="function search(req, db) { return db.query('SELECT * FROM t WHERE x=?', [req.query.name]); } function renderDescription(element, product) { element.textContent = product.description; }";assert.deepEqual(traceSample(source),[])});
test('유효하지 않은 자바스크립트는 분석 실패로 처리한다',()=>{assert.throws(()=>traceSample('function ('))});
