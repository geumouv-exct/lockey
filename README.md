# Lockey

초보 바이브코더를 위한 웹 프로젝트 보안 점검 도구. 프로젝트에서 확인할 문제, 수정할 코드, 수정 후 재점검 결과를 한 흐름으로 제공.

## 제출 시나리오

**GitHub Actions 독립 실행 3건 모두 성공** · 실제 Zoro-1 Arena 사용 · [텃밭 검증 커밋 `5a05611`](https://github.com/geumouv-exct/lockey/commit/5a05611e041749444f5f6753ea5a1a1e85ffe470) · [사진동아리 검증 커밋 `ffff607`](https://github.com/geumouv-exct/lockey/commit/ffff607aa28d1d2988c40a380a0cddd0fee0e983) · [책방 검증 커밋 `9dedbd2`](https://github.com/geumouv-exct/lockey/commit/9dedbd21a691be4b32cb9efc6011a96e9fc09eb9)

| 시나리오 | Lockey 시연 기능 | Zoro-1 Arena 역할 | 실행 결과 | 제출용 로그 |
| --- | --- | --- | --- | --- |
| **느티 사진동아리** | 설문·소스 대조 → 로컬 폴더 추천 → 이슈별 대표 뉴스와 코드 비교 → 일괄 승인·저장 → 재점검 | 점검 대상 선택 및 전시 달력 SQL 값 결합과 인화소 TLS 인증서 검증 설정의 수정안 생성 | Arista·Check Point 관련 뉴스 각 1건, 브라우저 격리 폴더에서 **파일 2개 일괄 수정**, 정적 점검 **2건 → 0건** | [사진동아리 실행로그](https://github.com/geumouv-exct/lockey/actions/runs/44607798121/job/135856046043) |
| **모퉁이 텃밭** | 같은 설문으로 작업 수첩 스크립트 1개 → 전체 프로젝트 3개 제공 | 로그인·본인 당번표·글 입력에 대한 설문과 소스 근거를 바탕으로 점검 대상 선택 | 근거 미확인 시 **추천 보류** → 세 항목 모두 파일·행 단위로 확인된 뒤 **로컬 폴더 점검 추천** → 3개 파일 점검, 정적 발견 0건 | [텃밭 실행로그](https://github.com/geumouv-exct/lockey/actions/runs/44601387590/job/135833436740) |
| **골목책방** | PHP 보안 뉴스 기간 검색 → 같은 사건의 보도 통합 → 선택 기사로 내 프로젝트 점검 프롬프트 생성 | PHP가 주제인 이슈 선별, 초보자용 헤드라인과 프로젝트에서 확인할 사항 요약 | 보관 보도 **2건 → 이슈 1건**, 점검 프롬프트에 두 출처 포함. 같은 검색어로 직전 주 조회 시 **0건** | [책방 실행로그](https://github.com/geumouv-exct/lockey/actions/runs/44595722081/job/135813309260) |

## 실행 환경

- **공통** — Node.js, npm, 러너 레이블 `lockey-public-scenarios`. 각 작업에서 해당 커밋의 Lockey 서버를 4768번 포트로 기동. 실제 Zoro-1 서버는 러너의 루프백 30001번 포트로 연결.
- **사진동아리** — Playwright와 호환되는 Chromium 필요. 작업별 임시 브라우저 프로필에서 수정·저장 검증.
- **골목책방** — 동일한 검색 조건을 재현하기 위해 보도 두 건을 입력 데이터로 고정. 기사 선별과 요약은 실행 시 모델에 요청.

[Lockey 실행 방법](sites/zoro-security-demo/README.md) · [시나리오별 테스트 데이터와 실행 명령](sites/zoro-security-demo/submission/README.md)

## 공개 체험

[Lockey 열기](https://lockey-7ikpnqdpi.gobrev.dev) · [Brev 배포 구성](deploy/brev/README.md)

폴더 선택 시 지원 소스를 Lockey 서버에 전송해 점검. 실제 파일 변경은 Chrome 또는 Edge에서 수정안 확인과 쓰기 승인 후 진행.
