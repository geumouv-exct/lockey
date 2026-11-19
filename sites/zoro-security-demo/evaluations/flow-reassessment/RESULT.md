# 명령 실행 및 서버 요청 재평가

2026-11-19. 대상은 이전 평가의 합성 `runtime` 예제다. AI에게 노출되는 데이터는 합성 코드다.

## 명령 실행

이전 분석기는 표현식 문장에 있는 `exec`만 처리해 `return exec(req.query.cmd)`를 놓쳤다. 수정한 분석기는 동일 파일에서 `command-input` / CWE-78을 검토 후보로 탐지한다. 반환문 외에 `await`, 변수 초기화, 중첩 호출 및 표현식 화살표 함수의 직접 호출도 회귀 테스트했다. 셸이 아닌 `execFile` 호출이라는 이유만으로 외부 명령 실행 전체를 안전하다고 확정하지는 않는다.

새 탐지 결과로 Zoro-1 서버에 검토 방향을 요청해 생성한 [수정 요청](prompt.txt)을 Codex에 변경 없이 전달했다. AI가 별도 예제 사본에서 허용된 `status`만 받아 `execFile('/usr/bin/uptime', [], {shell:false})`을 호출하도록 수정했다. [AI 응답](ai-response.txt) · [수정 전 코드](command-before/src/command.mjs) · [수정 후 코드](command-after/src/command.mjs)

| 항목 | AI 수정 전 | AI 수정 후 |
| --- | --- | --- |
| 수정된 분석기의 `command-input` | 1건 | 미검출 |
| 동일한 기존 테스트 | 4/5 통과 | 5/5 통과 |
| AI 추가 테스트 포함 | 해당 없음 | 6/6 통과 |

실행은 전후 별도의 읽기 전용 컨테이너에서 `--network none`, 권한 제한 및 같은 기존 테스트 파일을 사용했다. 테스트 성공과 정적 미검출은 예제의 지정된 동작에 대한 결과이며 모든 명령 실행 경로가 안전함을 증명하지 않는다.

## 서버 요청

이전 예제의 원본과 기존 AI 수정본을 새 분석기로 다시 검사했다. 둘 다 `request-url` 정적 후보가 남는다. 수정본에는 origin·프로토콜·사용자 정보 조건, `follow_max: 0`, 프록시·TLS·agent 옵션 구문이 관찰되며, 원본에서는 해당 단서가 관찰되지 않았다. 이는 구문의 존재만 뜻하며 조건의 유효성, 모든 실행 경로, agent 및 실제 HTTP 클라이언트 동작을 검증하지 않는다. 따라서 **둘 다 안전 판정 보류**다.

같은 기존 테스트 파일 중 `only the configured HTTPS API origin is requested` 테스트만 네트워크 차단 컨테이너에서 실행하면 수정 전 0/1, 수정 후 1/1이다. 이 테스트는 가짜 클라이언트를 사용한다. 기존 AI 테스트는 DNS와 클라이언트 옵션도 대역으로 확인하지만, 실제 Needle 연결·리다이렉트·DNS 재바인딩은 검증하지 않았다. OWASP는 목적지 통제와 HTTP 리다이렉트 처리, DNS 관련 위험을 함께 검토하도록 설명한다: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

[기계 판독 결과](result.json) · [서버 요청 테스트 결과](ssrf-result.json) · [수정 전/후 원본 코드](../ai-prompt-multicase/runtime/)
