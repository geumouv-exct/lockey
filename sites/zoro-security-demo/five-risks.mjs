const categories = [
 {id:'access',title:'접근 제어',ids:['wildcard-policy','service-role','fail-open'],check:'보호 자원에 대해 인증된 두 계정과 소유자 대조군을 비교하세요.',fix:'서버와 데이터베이스에서 요청자 권한과 객체 소유권을 확인하세요.'},
 {id:'secrets',title:'비밀정보 노출',ids:['private-key','public-secret','service-role','hardcoded-credential'],check:'실제 비밀값 여부와 저장소·브라우저 번들 노출 범위를 확인하세요. 값은 공유하지 마세요.',fix:'노출된 실제 자격 증명은 폐기·재발급하고 서버 비밀 저장소로 이동하세요.'},
 {id:'session',title:'인증과 세션',ids:['jwt-decode-only','cookie-httponly-false','cookie-secure-false','cookie-samesite-none'],check:'인증에 사용하는 토큰 검증과 운영 환경의 Set-Cookie 헤더를 확인하세요.',fix:'서명·발급자·만료를 검증하고 쿠키의 HttpOnly·Secure·SameSite 설정을 확인하세요.'},
 {id:'injection',title:'인젝션과 XSS',ids:['dangerous-html','sql-interpolation','command-input','code-evaluation'],check:'입력 출처와 위험 지점, 정제와 매개변수화 적용 경로를 확인하세요.',fix:'문자열을 직접 실행·삽입하지 말고 바인딩과 맥락에 맞는 출력 처리를 사용하세요.'},
 {id:'dependencies',title:'취약한 의존성',ids:[],check:'npm 잠금 파일의 패키지와 버전을 공개 취약점 데이터와 대조하세요.',fix:'영향받는 패키지를 수정된 버전으로 올리고 호환성과 회귀 테스트를 확인하세요.'}
];
export function summarizeRisks(findings, files){
 return categories.map(category=>{
  const items=findings.filter(f=>category.ids.includes(f.id)).map(f=>({key:f.key,id:f.id,path:f.path,lines:f.lines,evidence:f.trace?'정적 패턴 및 코드 흐름 후보':'정적 패턴 후보'}));
  const hasLock=files.some(f=>f.path==='package-lock.json');
  return {id:category.id,title:category.title,items,check:category.check,fix:category.fix,
   status:category.id==='dependencies'?(hasLock?'대조 가능':'잠금 파일 없음'):items.length?'검토 필요':'검사 범위 확인 필요',
   limitation:category.id==='dependencies'?'OSV 대조 전에는 알려진 취약점 여부를 판단하지 않습니다.':'실제 접근·실행 또는 악용 여부는 별도 검증이 필요합니다.'};
 });
}
