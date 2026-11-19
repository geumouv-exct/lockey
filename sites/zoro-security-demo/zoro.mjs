const CHOICES=['review_code','verify_access','defer'];
export function validModelUrl(url){try{const u=new URL(url);return u.protocol==='http:'&&['127.0.0.1','localhost','::1','[::1]'].includes(u.hostname)&&u.pathname==='/v1/systemone'&&!u.username&&!u.password&&!u.search&&!u.hash}catch{return false}}
export async function decide(findings,{url,expectedRevision,fetcher=fetch,timeoutMs=60000}={}){
 if(!validModelUrl(url))return {status:'not_connected',message:'ZORO_DECIDE_URL에 로컬 Zoro-1 /v1/systemone 주소를 설정해 주세요.'};
 const request={model:'zoro-1',state:{finding_count:findings.length,categories:[...new Set(findings.map(f=>f.category))],scope:'가상 샘플 코드와 로컬 API만 검사'},questions:{next_step:{type:'choice',instructions:'현재 범위에서 다음 검사 단계를 선택하세요.',criteria:{review_code:'탐지된 코드의 데이터 흐름을 검토한다',verify_access:'허용된 로컬 API의 접근 통제를 검증한다',defer:'근거 부족으로 수동 검토를 요청한다'}}},reasoning:false};
 try{
  const response=await fetcher(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),redirect:'error',signal:AbortSignal.timeout(timeoutMs)});
  if(!response.ok)throw Error(`HTTP ${response.status}`);
  const data=await response.json();const answer=data?.answers?.next_step;const probs=answer?.probabilities;const choice=answer?.choice;
  if(!CHOICES.includes(choice)||!probs||CHOICES.some(k=>typeof probs[k]!=='number'||!Number.isFinite(probs[k])||probs[k]<0||probs[k]>1)||Math.abs(CHOICES.reduce((a,k)=>a+probs[k],0)-1)>0.02)throw Error('모델 응답 형식이나 선택지를 확인할 수 없습니다');
  const reportedModel=typeof data.model==='string'?data.model:null; if(expectedRevision&&reportedModel!==expectedRevision)throw Error('모델 리비전이 설정된 값과 일치하지 않습니다'); return {status:'connected',choice,probabilities:probs,reported_model:reportedModel,provenance:'서버가 보고한 리비전과 설정값 비교; 암호학적 검증이 아닙니다',model_verified:Boolean(expectedRevision&&reportedModel===expectedRevision)};
 }catch(e){return {status:'error',message:`모델 호출 실패: ${e.name==='TimeoutError'?'시간 초과':e.message}`}}
}

export async function chooseProjectReview(findings,{context=[],url,expectedRevision,fetcher=fetch,timeoutMs=60000}={}){
 if(!validModelUrl(url))return {status:'not_connected',message:'Zoro-1 연결이 필요합니다.'};
 const criteria={};if(findings.some(x=>x.id==='sql-interpolation'&&/\.[cm]?js$/i.test(x.path)))criteria.review_sql='SQL 문자열 결합 후보의 수정 전후를 정적으로 검토';if(findings.some(x=>x.id==='dangerous-html'&&/\.[cm]?js$/i.test(x.path)))criteria.review_html='HTML 직접 삽입 후보의 수정 전후를 정적으로 검토';
 if(findings.some(x=>['private-key','public-secret','service-role','hardcoded-credential'].includes(x.id)))criteria.review_secrets='비밀정보 노출 여부와 폐기·재발급 절차를 수동 검토';
 if(findings.some(x=>['cookie-httponly-false','cookie-secure-false','jwt-decode-only'].includes(x.id)))criteria.review_session='인증과 세션 설정의 적용 범위를 수동 검토';
 if(findings.some(x=>['wildcard-policy','fail-open'].includes(x.id)))criteria.review_access='접근 정책과 사용자별 권한을 수동 검토';
 if(findings.some(x=>x.id==='code-evaluation'))criteria.review_eval='요청 값의 동적 코드 실행 후보를 수동 검토';
 if(findings.some(x=>x.id==='request-url'))criteria.review_ssrf='서버 요청 주소의 외부 입력 후보를 수동 검토';
 if(!Object.keys(criteria).length)return {status:'not_needed',message:'자동 수정안 검토가 가능한 유형이 없습니다.'};
 criteria.defer='근거가 부족하면 수동 검토로 보류';
 const request={model:'zoro-1',state:{user_statements:context,detected_types:[...new Set(findings.map(f=>f.id))],scope:'선택한 규칙 하나에 한해 실행 없이 정적 검토'},questions:{review_step:{type:'choice',instructions:'다음 검토 단계를 선택하세요.',criteria}},reasoning:false};
 try{const response=await fetcher(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),redirect:'error',signal:AbortSignal.timeout(timeoutMs)});if(!response.ok)throw Error(`HTTP ${response.status}`);const data=await response.json();const a=data?.answers?.review_step;const probs=a?.probabilities;if(!a||!Object.hasOwn(criteria,a.choice)||!probs||Object.keys(criteria).some(k=>typeof probs[k]!=='number'||!Number.isFinite(probs[k])||probs[k]<0||probs[k]>1)||Math.abs(Object.keys(criteria).reduce((v,k)=>v+probs[k],0)-1)>0.02)throw Error('유효하지 않은 모델 응답');if(expectedRevision&&data.model!==expectedRevision)throw Error('모델 리비전 불일치');return {status:'connected',choice:a.choice,probabilities:probs,reported_model:data.model||null};}catch(e){return {status:'error',message:`Zoro-1 추가 검토 선택 실패: ${e.message}`};}
}

