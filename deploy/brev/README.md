# Brev 웹 배포

Brev HTTPS 주소 → Caddy(8040) → Node.js(루프백 4178) → Zoro-1(루프백 30001). GPU 인스턴스가 가동 중일 때 웹 서비스와 모델 사용 가능. TLS 인증서는 Brev HTTPS 입구에서 관리.

같은 VM에 Zoro-1 모델이 실행 중인 상태에서 해당 공개 호스트로 배포.

```sh
export LOCKEY_PUBLIC_HOST=lockey-7ikpnqdpi.gobrev.dev
docker compose -f deploy/brev/compose.yml up -d --build
```

- Brev에 8040번 포트를 HTTP 대상으로 연결하고 공개 HTTPS 주소 사용. Node.js와 모델 포트는 루프백 전용.
- 웹·Caddy 프로세스는 읽기 전용 컨테이너에서 구동. 재시작 정책은 `unless-stopped`. 사용자 프로젝트 테스트 명령을 GPU 서버에서 실행하는 API는 차단.
- 공개 POST 요청에 정확한 출처와 익명 브라우저 세션 요구. 브라우저당 API 분당 40회, 동시 5개, 모델 시간당 240회. 서비스 전체 모델 동시 호출 2개. 30분 동안 활동이 없는 세션은 새로고침으로 재발급.
- 선택한 소스는 분석 서버 메모리에서 처리. AI 수정안 생성 시 해당 파일을 모델에 전달. 변경은 사용자 브라우저의 파일 쓰기 승인 후 적용.
