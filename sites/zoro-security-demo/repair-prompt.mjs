import {classification} from './classifications.mjs';
import {promptEvidence} from './project-actions.mjs';
import {baselineFinding} from './external-comparison.mjs';
import {validModelUrl} from './zoro.mjs';

const directions = {
  inspect: '사용 지점의 조건을 확인하고 수정',
  repair: '위험 연산을 안전한 연산으로 교체',
  test: '보안 동작을 회귀 테스트로 고정한 뒤 수정'
};
const edits={
  'dependency-advisory':['권고에 명시된 영향 범위와 의존성 경로를 확인하고 프로젝트와 호환되는 수정 버전으로 업데이트하라.','잠금 파일 갱신 후 해당 권고를 다시 대조하고 관련 기능과 회귀 테스트를 실행하라.'],
  'link-csp':['이 응답을 제공하는 서버 또는 프록시 설정을 찾아 실제로 필요한 출처만 허용하는 Content-Security-Policy를 추가하라. 인라인 스크립트와 외부 리소스 호환성을 확인하라.','수정 후 응답 헤더와 정상 페이지 렌더링을 확인하라.'],
  'link-nosniff':['이 응답을 제공하는 서버 또는 프록시에서 X-Content-Type-Options: nosniff를 설정하고 리소스별 Content-Type을 정확히 지정하라.','응답 헤더와 정상 리소스 로딩을 확인하라.'],
  'link-frame':['이 응답을 제공하는 서버 또는 프록시에서 실제 허용 정책에 맞는 CSP frame-ancestors를 설정하라.','허용되지 않은 사이트의 삽입이 차단되고 필요한 삽입은 유지되는지 확인하라.'],
  'link-http':['서비스에 HTTPS를 적용하고 HTTP 요청을 HTTPS로 리디렉션하라.','HTTPS 연결 및 리디렉션과 기존 정상 기능을 확인하라.'],
  'cookie-secure-false':['인증 쿠키의 secure: false를 운영 환경에서 true로 변경하라.','HTTPS 로그인 응답의 Set-Cookie에 Secure가 있는지 확인하라.'],
  'hardcoded-credential':['실제 노출된 자격 증명을 폐기·재발급하고 서버 비밀 저장소에서 읽도록 변경하라.','원본 비밀값이 코드와 배포 결과에 남지 않았는지 확인하라.'],
  'code-evaluation':['요청 값을 eval에 전달하는 코드를 제거하고 형식과 범위를 검증하는 파서를 사용하라.','정상 입력은 유지되고 코드 형태의 입력이 실행되지 않는지 테스트하라.'],
  'command-input':['셸 명령 결합을 제거하고 실행 파일과 인자를 분리하라. 입력은 허용 목록으로 검증하라.','메타문자가 명령으로 실행되지 않는지 확인하라.'],
  'request-url':['서버 요청 대상의 프로토콜·호스트·포트를 허용 목록으로 제한하라. DNS로 확인한 주소에 실제 연결하고 내부·예약 주소를 차단하라. 자동 리다이렉트와 의도하지 않은 프록시 사용을 비활성화하라.','허용 요청은 성공하고 내부 주소, DNS 재바인딩, 리다이렉트 및 프록시 우회는 차단되는지 실제 HTTP 클라이언트로 테스트하라.'],
  'dangerous-html':['일반 텍스트를 출력하는 HTML 삽입 지점을 textContent 대입 또는 프레임워크의 텍스트 바인딩으로 바꿔라. 마크업이 필수이면 허용 목록 기반 HTML 정제를 적용하라.', '꺾쇠가 포함된 사용자 입력이 일반 텍스트로 표시되는지 확인하라.'],
  'sql-interpolation':['쿼리에 삽입한 입력값을 드라이버의 바인딩 인자로 분리하라. 열 이름처럼 바인딩할 수 없는 식별자는 허용 목록에서 선택하라.', '입력값이 SQL 본문과 분리되고 기존 조회 결과가 유지되는지 테스트하라.'],
  'cookie-httponly-false':['인증 쿠키의 httpOnly: false를 true로 변경하라.', '로그인 응답의 실제 Set-Cookie 헤더에 HttpOnly가 있는지 확인하라.'],
  'cors-wildcard':['보호된 응답에 지정한 와일드카드를 프로젝트의 명시적 허용 출처 목록으로 바꿔라.', '등록된 출처와 미등록 출처의 응답 헤더를 비교하라.'],
  'debug-enabled':['운영 환경에서 debug를 false로 설정하고 개발 환경에서만 명시적으로 켜라.', '운영 설정으로 시작했을 때 오류 응답에 디버그 세부 정보가 없는지 테스트하라.'],
  'idor':['주문을 반환하기 전에 인증된 사용자에게 해당 주문의 조회 권한이 있는지 검사하라.', '소유자 요청은 성공하고 다른 계정의 요청은 거부되는지 테스트하라.'],
  'jwt-decode-only':['인증에 쓰는 decode 호출을 서명·발급자·만료를 검사하는 검증 API로 바꿔라.', '유효한 토큰은 허용하고 잘못된 서명은 거부하는지 확인하라.'],
  'wildcard-policy':['무조건 허용하는 접근 정책을 객체 소유자와 허용된 역할 조건으로 제한하라.', '권한이 다른 두 계정의 허용·거부 결과를 확인하라.'],
  'fail-open':['권한 검사의 예외 처리에서 true를 반환하는 경로를 거부 응답으로 변경하라.', '검사 중 오류가 발생하면 접근이 차단되는지 확인하라.'],
  'private-key':['코드에 포함된 실제 키를 폐기·재발급하고 서버의 비밀 저장소 참조로 교체하라.', '새 비밀값이 소스·로그·클라이언트 번들에 포함되지 않는지 확인하라.'],
  'public-secret':['민감한 값을 공개 환경변수에서 서버 전용 설정으로 옮겨라.', '클라이언트 빌드 결과에서 비밀값이 제외되는지 확인하라.'],
  'service-role':['관리자 키를 사용하는 호출을 서버로 옮기고 사용자 권한을 검사하라.', '클라이언트 번들에 관리자 키가 포함되지 않는지 확인하라.'],
  'signature-disabled':['서명 검증 비활성화 옵션을 제거하고 신뢰하는 키를 지정하라.', '서명이 일치하지 않으면 요청이 거부되는지 확인하라.'],
  'tls-disabled':['인증서 검증 비활성화 옵션을 제거하고 필요한 CA를 명시하라.', '신뢰되지 않은 인증서의 연결이 거부되는지 확인하라.'],
  'weak-hash':['해시의 용도를 확인해 비밀번호 저장에는 비밀번호 전용 해시를, 보안 무결성 검사에는 충돌 저항성 해시를 사용하라.', '기존 데이터와의 호환성 및 마이그레이션 경로를 테스트하라.'],
  'actions-floating-ref':['워크플로의 이동 가능한 액션 참조를 검토한 커밋 SHA로 고정하라.', '같은 액션 버전으로 워크플로가 통과하는지 확인하라.'],
  'git-object-sha1':['Git 객체 식별과 보안 무결성 판정을 구분하고, 보안 판정에 사용한 경로만 별도 검증으로 보완하라.', 'Git 객체 식별 결과가 유지되는지 확인하라.']
};
function terse(text){return String(text).replace(/하지 마라\./g,'하면 안 됨.').replace(/바꿔라\./g,'변경 필요.').replace(/옮겨라\./g,'이동 필요.').replace(/켜라\./g,'켜야 함.').replace(/하라\./g,'해야 함.').replace(/필요하다\./g,'필요함.').replace(/미확인이다\./g,'미확인임.')}
function replacement(id, preview){
  if(!preview)return null;
  if(id==='dangerous-html'){
    const assignment=preview.before.match(/^\s*([\w$.]+)\.innerHTML\s*=\s*([\w$.]+);?\s*$/);
    if(assignment)return assignment[1]+'.innerHTML = '+assignment[2]+'; 를 '+assignment[1]+'.textContent = '+assignment[2]+'; 로 교체 필요.';
  }
  if(id==='sql-interpolation' && /^(?:\s*return )?\s*\w+\.(?:query|execute)\(.+\);?\s*$/.test(preview.after))
    return '문자열 결합 쿼리 호출을 다음 바인딩 호출로 변경 필요.\n'+preview.after.trim();
  return null;
}
export async function repairPrompt(input,{url,expectedRevision,fetcher=fetch}) {
  const {id,path,lines,status}=input;
  if(typeof id!=='string' || !/^[a-z][a-z0-9-]{1,40}$/.test(id) || typeof path!=='string'||path.length>500||
    !Array.isArray(lines)||lines.length>10||!lines.every(n=>Number.isSafeInteger(n)&&n>0)) throw Error('발견 항목을 다시 선택하세요.');
  const meta=classification({id});
  if(!meta.summary)throw Error('지원하지 않는 발견 항목입니다.');
  if(!validModelUrl(url))throw Error('Zoro-1 연결이 필요합니다.');
  const baseline=input.baselineToken?baselineFinding(input.baselineToken,path,id,lines):null;
  const source=baseline?.files.find(file=>file.path===path)?.text;
  const evidence={candidate:'정적 패턴 발견',flow_verified:'고정 샘플의 코드 흐름 확인',confirmed:'가상 API 테스트에서 확인',inconclusive:'판단 보류'}[baseline?.finding?.status||status]||'판단 보류';
  let preview=null;
  if(input.token){try{preview=promptEvidence(input.token,id,path,lines,baseline?.files)}catch(e){if(!/검사 세션이 만료/.test(e.message))throw e}}
  if(baseline&&!source)throw Error('검사한 원본 파일을 확인할 수 없습니다.');
  if(lines.length!==1)preview=null;
  let res;try{res=await fetcher(url,{method:'POST',headers:{'Content-Type':'application/json'},redirect:'error',signal:AbortSignal.timeout(60000),
    body:JSON.stringify({model:'zoro-1',state:{rule:id,cwe:meta.cwe,evidence,reviewed_edit:Boolean(preview)},reasoning:false,
      questions:{focus:{type:'choice',instructions:'초보 개발자를 위한 방어적 수정 요청의 첫 단계를 선택하세요.',criteria:directions}}})});}catch{throw Error('Zoro-1 모델 서버에 연결할 수 없습니다. Brev 포트 포워딩과 모델 서버를 확인하세요.')}
  if(!res.ok)throw Error('Zoro-1 응답을 받지 못했습니다.');
  const data=await res.json(), choice=data.answers?.focus?.choice;
  if(!Object.hasOwn(directions,choice)||(expectedRevision&&data.model!==expectedRevision))throw Error('모델 선택 또는 리비전을 확인할 수 없습니다.');
  const file=input.sample && path==='shop.js'?'fixtures/shop.js':path;
  const target=preview?file+':'+preview.line:file+(lines.length?':'+lines.join(', '):'');
  const rule=edits[id]||[meta.fix||'위치와 사용 조건을 확인하고 안전하게 수정하라.','기존 정상 동작과 보안 관련 경계를 테스트하라.'];
  const secretPattern=/(?:password|secret|token|api[_-]?key|private[_-]?key|bearer|ghp_|sk-(?:proj-)?|-----BEGIN|[A-Za-z0-9_\/-]{40,})/i;
  const sensitive=['private-key','hardcoded-credential','public-secret','service-role'].includes(id);
  const safePreview=preview&&!sensitive&&!secretPattern.test(preview.before)&&!secretPattern.test(preview.after)?preview:null;
  const directEdit=replacement(id,safePreview);
  const guard=directEdit&&id==='dangerous-html'&&input.intent!=='plain_text'?'해당 출력이 일반 텍스트 용도임을 확인한 경우에만 ':'';
  const edit=directEdit?guard+directEdit:terse(rule[0]);
  const command=preview?.test ? "\n실행: node --test '"+preview.test.replaceAll("'","'\\''")+"'" : '';
  const goal='';
  const actions=choice==='test' ? ['검증: '+terse(rule[1]), '수정: '+edit] : ['수정: '+edit,'검증: '+terse(rule[1])];
  const code=source?lines.map(n=>{const line=source.split(/\r?\n/)[n-1];if(typeof line!=='string')return null;return `  ${n}: ${sensitive||secretPattern.test(line)?'[민감정보 보호를 위해 생략]':line.slice(0,600)}`}).filter(Boolean).join('\n'):'';
  const origin=['external','internal','unknown'].includes(input.inputOrigin)?({external:'사용자 설명: 방문자 입력 가능. 실제 입력 경로는 코드에서 확인 필요.',internal:'사용자 설명: 내부 데이터 사용. 실제 입력 경로는 코드에서 확인 필요.',unknown:'입력 출처 미확인.'}[input.inputOrigin]):'';
  const candidateTests=baseline?.files.filter(f=>/(?:^|\/)(?:tests?|__tests__)\/.*\.[cm]?js$|\.(?:test|spec)\.[cm]?js$|(?:^|\/)test_[^/]+\.py$|(?:^|\/)[^/]+_test\.py$/i.test(f.path)).map(f=>f.path).slice(0,4)||[];
  const supportingTests=!preview?.test&&candidateTests.length?'\n프로젝트에서 확인된 테스트 파일(관련성 확인 필요): '+candidateTests.join(', '):'';
  const note=baseline?'근거: '+evidence+' · 실제 악용 여부는 별도 확인 필요.':'';
  return {choice,text:[target+' ('+meta.cwe+')',...(note?[note]:[]),...(code?['확인된 코드:\n'+code]:[]),...(origin?[origin]:[]),...actions].join('\n')+goal+command+supportingTests,sourceVerified:Boolean(baseline),reviewedEdit:Boolean(safePreview)};
}
