// Curated references to OWASP WSTG v4.2. A code signal is only a lead,
// never evidence that the full WSTG scenario was performed or passed.
const base='https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/';
export const WSTG_SCENARIOS=Object.freeze({
 'WSTG-v42-INPV-05':{title:'SQL 인젝션',url:base+'07-Input_Validation_Testing/05-Testing_for_SQL_Injection/'},
 'WSTG-v42-CLNT-01':{title:'DOM 기반 XSS',url:base+'11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting/'},
 'WSTG-v42-CLNT-07':{title:'CORS 설정',url:base+'11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/'},
 'WSTG-v42-SESS-02':{title:'쿠키 속성',url:base+'06-Session_Management_Testing/02-Testing_for_Cookies_Attributes/'},
 'WSTG-v42-SESS-05':{title:'CSRF 방어',url:base+'06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery/'},
 'WSTG-v42-ATHZ-04':{title:'객체별 접근 권한',url:base+'05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References/'},
 'WSTG-v42-ATHN-03':{title:'로그인 시도 제한',url:base+'04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism/'},
 'WSTG-v42-CRYP-01':{title:'전송 구간 TLS',url:base+'09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/'},
 'WSTG-v42-BUSL-01':{title:'업무 데이터 검증',url:base+'10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation/'},
 'WSTG-v42-BUSL-05':{title:'기능 사용 횟수 제한',url:base+'10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits/'}
});
const RULE_SCENARIOS=Object.freeze({
 'sql-interpolation':['WSTG-v42-INPV-05'],
 'dangerous-html':['WSTG-v42-CLNT-01'],
 'cors-wildcard':['WSTG-v42-CLNT-07'],
 'cookie-httponly-false':['WSTG-v42-SESS-02']
});
export function wstgForRule(ruleId){return (RULE_SCENARIOS[ruleId]||[]).map(id=>({id,...WSTG_SCENARIOS[id]}));}
export const WSTG_CHECKS=[
 {id:'wstg-idor',owasp:'A01',wstg:'WSTG-v42-ATHZ-04',title:'다른 사용자의 데이터에 접근할 수 없나요?',description:'허가된 테스트 환경에서 테스트 계정 두 개를 만들고, 한 계정으로 다른 계정의 테스트 데이터 조회·수정 요청이 거부되는지 확인하세요.'},
 {id:'wstg-lockout',owasp:'A07',wstg:'WSTG-v42-ATHN-03',title:'로그인 시도 제한이 적용되나요?',description:'테스트 계정으로 사전에 정한 소수의 실패 요청을 보내 제한과 복구 절차를 확인하세요. 실제 사용자 계정 잠금을 유발하지 않도록 테스트 범위를 정하세요.'},
 {id:'wstg-cookie',owasp:'A07',wstg:'WSTG-v42-SESS-02',title:'로그인 쿠키가 안전하게 설정되나요?',description:'테스트 로그인 응답의 쿠키에서 Secure, HttpOnly, SameSite와 유효 범위를 확인하고 서비스의 로그인 방식에 맞는지 검토하세요.'},
 {id:'wstg-csrf',owasp:'A01',wstg:'WSTG-v42-SESS-05',title:'로그인 상태의 중요 요청을 보호하나요?',description:'테스트 환경에서 상태를 변경하는 요청의 CSRF 방어와 서버 측 검증이 동작하는지 확인하세요. 쿠키를 사용하지 않는 인증 방식은 적용 여부를 먼저 판단하세요.'},
 {id:'wstg-sqli',owasp:'A05',wstg:'WSTG-v42-INPV-05',title:'데이터베이스 입력을 안전하게 처리하나요?',description:'테스트 데이터와 테스트 환경에서 입력 지점과 매개변수화된 쿼리를 검토하고, 예상 밖 입력에 대한 서버 응답을 확인하세요.'},
 {id:'wstg-domxss',owasp:'A05',wstg:'WSTG-v42-CLNT-01',title:'사용자 입력이 화면에서 안전하게 처리되나요?',description:'테스트 환경에서 사용자 입력이 HTML에 들어가는 경로와 정제·인코딩을 확인하세요. 코드 패턴 탐지 결과만으로 실행 가능 여부를 확정할 수 없습니다.'},
 {id:'wstg-cors',owasp:'A02',wstg:'WSTG-v42-CLNT-07',title:'민감한 응답의 CORS 범위가 적절한가요?',description:'테스트 환경에서 허용된 출처와 허용되지 않은 출처의 응답 및 인증정보 허용 설정을 비교하세요. 공개 API라면 공개 의도를 함께 확인하세요.'},
 {id:'wstg-tls',owasp:'A04',wstg:'WSTG-v42-CRYP-01',title:'서비스의 HTTPS와 인증서가 유효한가요?',description:'배포 환경의 인증서 유효성, HTTPS 연결 및 TLS 설정을 확인하세요. 로컬 코드 검사만으로 배포 설정을 확인할 수 없습니다.'},
 {id:'wstg-business',owasp:'A06',wstg:'WSTG-v42-BUSL-01',title:'금액과 수량이 서버에서도 검증되나요?',description:'테스트 주문에서 입력한 금액·수량을 변경해도 서버가 신뢰할 수 있는 기준으로 계산하고 잘못된 값을 거부하는지 확인하세요.'},
 {id:'wstg-repeat',owasp:'A06',wstg:'WSTG-v42-BUSL-05',title:'쿠폰이나 중요 작업을 중복 사용할 수 없나요?',description:'테스트 데이터로 허용 횟수를 넘는 반복 요청을 확인하고, 서버가 제한을 적용하는지 검토하세요.'}
];
