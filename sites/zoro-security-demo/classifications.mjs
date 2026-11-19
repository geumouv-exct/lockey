// Rule-level associations are review candidates, not proof of a weakness.
const info = {
  'link-csp': ['CWE-693', '페이지에서 허용할 콘텐츠를 제한하는 설정이 보이지 않아요.', '콘텐츠 보안 정책을 실제 응답에 적용'],
  'link-nosniff': ['CWE-693', '브라우저가 응답 형식을 임의로 판단할 수 있어요.', '응답에 X-Content-Type-Options: nosniff 적용'],
  'link-frame': ['CWE-1021', '다른 사이트가 이 화면을 몰래 끼워 넣을 수 있어요.', 'frame-ancestors 또는 X-Frame-Options 설정'],
  'link-http': ['CWE-319', '암호화되지 않은 연결로 응답을 받았어요.', 'HTTPS를 사용하고 HTTP에서 HTTPS로 이동'],
  'cookie-secure-false': ['CWE-614', '로그인 정보가 암호화되지 않은 연결로 전송될 수 있어요.', '인증 쿠키에 Secure 적용 확인'],
  'hardcoded-credential': ['CWE-798', '암호나 API 키로 보이는 값이 코드에 들어 있어요.', '실제 비밀이면 폐기·재발급'],
  'code-evaluation': ['CWE-95', '사용자가 입력한 내용이 프로그램 코드로 실행될 수 있어요.', 'eval 제거 및 입력값 검증'],
  'command-input': ['CWE-78', '사용자가 입력한 내용이 서버 명령을 바꿀 수 있어요.', '셸 호출을 피하고 입력을 제한'],
  'request-url': ['CWE-918', '사용자가 서버의 접속 주소를 바꿀 수 있어요.', '허용된 목적지만 요청'],
  'dangerous-html': ['CWE-79', '방문자가 쓴 글이 화면 코드로 실행될 수 있어요.', '입력 출처를 확인하고 텍스트로 렌더링'],
  'sql-interpolation': ['CWE-89', '사용자가 입력한 값이 데이터베이스 명령을 바꿀 수 있어요.', '매개변수화된 쿼리 사용'],
  'cors-wildcard': ['CWE-942', '예상하지 못한 다른 웹사이트에서도 응답에 접근할 수 있어요.', '허용할 출처와 인증 범위 확인'],
  'cookie-httponly-false': ['CWE-1004', '화면에서 실행되는 코드가 로그인 쿠키를 읽을 수 있어요.', '인증 쿠키의 HttpOnly 활성화'],
  'debug-enabled': ['CWE-489', '운영 중 오류에 내부 정보가 함께 나타날 수 있어요.', '운영 환경의 디버그 설정 확인'],
  'jwt-decode-only': ['CWE-347', '변조된 로그인 정보를 검증 없이 믿을 수 있어요.', '인증에 사용한다면 서명과 발급자 검증'],
  'signature-disabled': ['CWE-347', '데이터가 중간에 바뀌었는지 확인하지 못할 수 있어요.', '서명 검증 활성화 여부 확인'],
  'tls-disabled': ['CWE-295', '접속한 서버가 진짜인지 확인하지 못할 수 있어요.', '인증서 검증 활성화'],
  'fail-open': ['CWE-636', '권한 확인 중 오류가 나도 접근을 허용할 수 있어요.', '인증·권한 오류 시 접근 차단'],
  'wildcard-policy': ['CWE-862', '다른 사용자의 정보에 접근할 수 있는지 확인이 필요해요.', '실제 접근 정책과 보호 계층 확인'],
  'private-key': ['CWE-798', '비밀키로 보이는 값이 코드에 포함되어 있어요.', '실제 키라면 폐기·재발급'],
  'public-secret': ['CWE-200', '비밀로 보이는 설정이 브라우저에 공개될 수 있어요.', '비밀값이면 서버 전용으로 이동'],
  'service-role': ['CWE-200', '관리자 권한의 키가 방문자에게 노출될 수 있어요.', '키가 서버에서만 쓰이는지 확인'],
  'weak-hash': ['CWE-327', '비밀번호 등을 충분히 안전하게 보호하지 못할 수 있어요.', '사용 목적에 맞는 안전한 해시 적용'],
  'dependency-advisory': [null, '의존성 권고를 확인하세요.', '해당 권고와 호환되는 수정 버전 확인'],
  'idor': ['CWE-639', '다른 사용자의 주문 접근 가능', '서버에서 객체별 권한 검증'],
  'actions-floating-ref': [null, '고정되지 않은 액션 참조', '검증된 커밋 SHA로 고정 검토'],
  'git-object-sha1': [null, 'Git 객체 형식의 SHA-1 사용', '무결성 검증 용도 확인'],
};
const cweNames={'CWE-693':'Protection Mechanism Failure','CWE-1021':'Improper Restriction of Rendered UI Layers or Frames','CWE-319':'Cleartext Transmission of Sensitive Information','CWE-614':'Sensitive Cookie in HTTPS Session Without Secure Attribute','CWE-798':'Use of Hard-coded Credentials','CWE-95':'Improper Neutralization of Directives in Dynamically Evaluated Code','CWE-78':'Improper Neutralization of Special Elements used in an OS Command','CWE-918':'Server-Side Request Forgery','CWE-79':'Improper Neutralization of Input During Web Page Generation','CWE-89':'Improper Neutralization of Special Elements used in an SQL Command','CWE-942':'Permissive Cross-domain Policy with Untrusted Domains','CWE-1004':'Sensitive Cookie Without HttpOnly Flag','CWE-489':'Active Debug Code','CWE-347':'Improper Verification of Cryptographic Signature','CWE-295':'Improper Certificate Validation','CWE-636':'Not Failing Securely','CWE-862':'Missing Authorization','CWE-200':'Exposure of Sensitive Information to an Unauthorized Actor','CWE-327':'Use of a Broken or Risky Cryptographic Algorithm','CWE-639':'Authorization Bypass Through User-Controlled Key'};
export function classification(finding) {
  const [cwe, summary, fix] = info[finding.id] || [null, finding.title, finding.fix];
  return {cwe: cwe || '미확인', cweName:cweNames[cwe]||'미확인', cve: '미확인', summary, fix};
}
