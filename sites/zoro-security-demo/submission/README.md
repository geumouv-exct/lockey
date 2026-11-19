# Lockey 시연 실행로그

| 프로젝트 | 시연할 장면 | 실행 결과 |
| --- | --- | --- |
| [느티 사진동아리](fixtures/team-notes) | 두 파일의 Zoro-1 수정안을 비교하고 한 번에 승인한 뒤 재점검 | [Chrome 실행로그](logs/team-notes.log) |
| [모퉁이 텃밭](fixtures/garden-journal) | 같은 설문으로 작업 수첩 스크립트만 제공한 뒤 전체 소스를 제공해 Zoro-1의 추천 보류와 로컬 폴더 점검 추천을 비교 | [설문과 소스 대조 로그](logs/garden-journal.log) |
| [골목책방](fixtures/corner-books) | 이달의 책과 낭독회를 소개하는 PHP 사이트 운영자가 PHP 뉴스를 검색하고 기사별 프로젝트 점검 프롬프트 생성 | [검색·요약·프롬프트 로그](logs/corner-books.log) |

## 다시 실행하기

Lockey 프로젝트 폴더에서 실행한다. 첫 번째와 두 번째 시나리오는 실행 중인 Lockey 서버를 사용한다. 첫 번째에는 Chrome이 필요하다. 사진동아리 원본은 읽기만 하고, 실제 쓰기와 재점검은 매번 새 브라우저 프로필의 격리 폴더에서 수행한다.

```sh
node submission/run-scenario.mjs team-notes
node submission/run-scenario.mjs garden-journal
node submission/run-scenario.mjs corner-books
```

기본 Lockey 주소는 `http://127.0.0.1:4768`이며 `LOCKEY_URL`로 바꿀 수 있다. 세 번째 시나리오는 저장된 [보도 두 건](fixtures/news.json)을 서비스의 뉴스 처리 함수에 입력하고 검색과 요약은 실제 Zoro-1에 요청한다. 운영 환경의 PHP 버전이 자료에 없으므로 로그는 영향 확인용 프롬프트 생성까지 다룬다. 모델 서버 주소와 리비전은 `ZORO_DECIDE_URL`, `ZORO_EXPECTED_REVISION`으로 지정할 수 있다.
