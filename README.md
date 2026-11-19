# lockey
for saving vibecoders

## Lockey 제출 시나리오

세 워크플로가 사진동아리, 모퉁이 텃밭, 골목책방을 각각 독립적으로 실행합니다. 테스트와 입력 데이터, 기대 동작은 [시나리오 안내](sites/zoro-security-demo/submission/README.md)에서 확인할 수 있습니다. Actions 실행의 마지막 단계에 해당 실행에서 생성한 로그가 표시됩니다.

러너는 Node.js, npm, Playwright에 맞는 Chromium과 `lockey-submission` 레이블을 사용합니다. 러너의 루프백 주소에서 Lockey 서비스(4768)와 Zoro-1 서버(30001)에 접속할 수 있어야 합니다. 사진동아리 시나리오는 해당 작업의 임시 브라우저 프로필에서만 파일을 변경합니다. 골목책방의 뉴스 원문 입력은 저장된 보도이며, 선별과 요약은 실행할 때 모델에 요청합니다.
