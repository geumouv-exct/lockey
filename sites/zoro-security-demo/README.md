# Trace — 로컬 웹 보안 데모

Node.js 20 이상. 프로젝트 루트에서:

```sh
npm ci --prefix sites/zoro-security-demo
node sites/zoro-security-demo/server.mjs
```

http://127.0.0.1:4178 에서 샘플 검사를 시작합니다. 지정 포트: `PORT=4180 node sites/zoro-security-demo/server.mjs`.

코드 변경 후에는 데모 서버를 다시 시작하고 브라우저를 새로고침하세요. 이전 서버가 같은 포트를 계속 사용하면 새 화면 파일과 오래된 서버의 모듈 경로가 달라져 화면이 멈출 수 있습니다. 기존 작업을 종료하기 어렵다면 사용하지 않는 다른 포트로 새 서버를 실행하세요. 별도의 실제 격리 테스트에는 Docker 실행 환경과 해당 격리 이미지가 필요합니다.


## 로컬 프로젝트 검사와 체크리스트

1. 로그인, 비공개 정보, 방문자 입력 기능을 선택합니다. 예 또는 잘 모르겠어요를 고른 항목만 추가로 답합니다.
2. 브라우저에서 **프로젝트 폴더 선택**을 누르고 로컬 폴더를 선택합니다. 선택한 폴더의 지원 파일 전체를 검사합니다. 선택한 점검 방식에 필요한 자료를 입력하면 공개 페이지 또는 소스에서 선택한 기능의 단서를 확인한 뒤 Zoro-1이 점검 방식을 추천합니다.
3. **프로젝트 검사**를 누릅니다. 결과 아래에 첨부된 체크리스트의 열을 참고한 검사 체크리스트와 발견 사항 요약이 나타납니다. 각 표의 CSV 저장 버튼으로 Excel에서 열 수 있는 파일을 내려받을 수 있습니다.

브라우저에서 고른 소스는 로컬 서버로 전송해 메모리에서 검사합니다. GPU 모델에는 소스와 경로가 아니라 발견된 규칙 ID와 사용자 진술을 나타내는 제한된 선택값을 전달합니다. `.env`, 키 파일, 의존성·빌드 폴더와 예제는 제외합니다. 지원하는 JS 테스트 파일은 격리 검증용으로 포함합니다. 지원 파일 최대 200개, 파일당 300KB, 전체 3MB로 제한합니다.

사용자 프로젝트는 제한된 정적 패턴 검사와 아래의 선택적 정적 수정안 검토를 수행합니다. 발견 사항은 취약점 후보이며, 미검사는 통과가 아닙니다. 영향도·가능성·위험도는 미평가로 남습니다. 서비스를 직접 기동하는 기능, 범용 코드 흐름 분석, 외부 URL 침투 테스트, Semgrep·Gitleaks·SCA 및 사용자 확인 없는 수정 적용은 구현되지 않았습니다. 사용자가 선택하면 프로젝트 테스트 명령을 실제 실행합니다. 보안 게이트는 판정하지 않습니다.

Zoro-1: Trida-Stack `/v1/systemone` 서버를 로컬에 준비하거나 Brev의 서버를 SSH 포워딩한 뒤 실행합니다.

```sh
ZORO_DECIDE_URL=http://127.0.0.1:30001/v1/systemone node sites/zoro-security-demo/server.mjs
```


## Brev 연결 준비

Brev CLI로 로그인한 뒤 `brev list orgs`, `brev org set <조직이름>`, `brev list`로 사용 가능한 인스턴스를 확인합니다. `brev shell <인스턴스이름>`으로 GPU에 접속하고 `nvidia-smi`로 확인합니다. Hugging Face의 `trillionlabs/Zoro-1`은 접근 승인이 필요하며 서버에서도 해당 계정 인증이 필요합니다. 토큰을 채팅, 보고서, 소스 코드에 넣지 마세요.

GPU에 [Trida-Stack의 공식 지침](https://github.com/trillion-labs/trida-stack/tree/main/inference/zoro-1)에 따라 Zoro-1 decision 서버를 실행하고, 로컬에서 `brev port-forward <인스턴스이름> --port 30001:30001`을 유지합니다. 서버가 외부에 공개되지 않도록 서버의 바인딩과 네트워크 정책을 확인하세요. 이후 위 `ZORO_DECIDE_URL` 명령으로 데모를 실행합니다.

실제 응답의 `model` 필드는 서버의 자기 보고로, 가중치의 진위를 증명하지 않습니다. GPU에서 로드한 모델 ID와 revision을 별도로 확인하세요. 모델이 없거나 서버가 실패하면 동적 테스트를 실행하지 않습니다. `review_code` 또는 `defer`를 선택해도 접근 제어 테스트는 미실행으로 표시합니다. 자동화 검증: `node --test sites/zoro-security-demo/zoro.test.mjs` 및 `node --test sites/zoro-security-demo/integration.test.mjs`. 후자는 로컬 소켓이 필요하며 모의 서버를 사용합니다.

## 실제 GPU 연결 검증 기록 (2026-11-19)

- Brev `lockey`: NVIDIA L40S. GPU 서버는 `127.0.0.1:30001`에 바인딩한다.
- Hugging Face 모델: `trillionlabs/Zoro-1`, 로드된 revision `bf1b76b9b4df03b05fcbb73444e1cd4db0f566da`. Trida-Stack commit `0ddcf516e458a82892d7fe0d0dabeb113d3cf424`.
- `POST /v1/systemone` 실제 응답 및 데모 화면을 확인했다. 결과는 실행마다 달라질 수 있다. 서버 리비전 비교는 서버 자기 보고이며 암호학적 검증이 아니다.

### 현재 연결 재사용

GPU 서버가 실행 중이면 로컬 터미널에서 포워딩을 유지합니다. `/private/tmp/brev`는 임시 경로이므로 재부팅 등으로 삭제되면 Brev CLI를 다시 설치해야 합니다.

```sh
/private/tmp/brev port-forward lockey --port 30001:30001
```

다른 로컬 터미널에서:

```sh
cd /path/to/lockey
PORT=4181 ZORO_EXPECTED_REVISION=bf1b76b9b4df03b05fcbb73444e1cd4db0f566da ZORO_DECIDE_URL=http://127.0.0.1:30001/v1/systemone node sites/zoro-security-demo/server.mjs
```

브라우저에서 http://127.0.0.1:4181 에 접속합니다. 기존 4178 데모는 다른 프로세스일 수 있으므로 모델 설정 적용 여부를 별도로 확인해야 합니다.

### GPU 서버 재시작

Brev 인스턴스에 접속해 다음을 실행합니다. 실행 중인 서버가 있다면 중복 실행하지 마세요. 이 환경은 CUDA 13.0 패키지, GCC 11 및 가상환경에 생성한 `libcudart.so` 링크에 의존합니다.

```sh
cd ~/workspace/trace-zoro/trida-stack/inference/zoro-1
export CUDA_HOME="$HOME/workspace/trace-zoro/runtime/lib/python3.12/site-packages/nvidia/cu13"
export PATH="$HOME/workspace/trace-zoro/runtime/bin:$CUDA_HOME/bin:$PATH"
export LIBRARY_PATH="$CUDA_HOME/lib" LD_LIBRARY_PATH="$CUDA_HOME/lib"
export CC=/usr/bin/gcc-11 CXX=/usr/bin/g++-11 CUDAHOSTCXX=/usr/bin/g++-11
python serve.py --mode decide --host 127.0.0.1 --port 30001
```

GPU VM이 실행 중이면 비용 또는 행사 크레딧을 사용할 수 있습니다. 팀 사용 현황을 확인한 뒤 인스턴스를 관리하세요.

## 코드 흐름 검증의 범위

샘플의 `req.query.name` → 문자열 조합 → `db.query` 및 `product.description` → `element.innerHTML`만 AST로 추적합니다. 샘플 함수와 수정된 대조군을 별도 프로세스에서 호출하며 DB·DOM 테스트 대역에 테스트 값이 전달되는지 비교합니다. 의도적으로 취약한 고정 샘플과 테스트 실행기의 SHA-256이 바뀌면 프로브 실행을 중단합니다. 다른 코드베이스에 대한 범용 데이터 흐름 분석은 구현하지 않았고 실제 DB SQL 인젝션이나 브라우저 스크립트 실행을 검증한 것은 아닙니다. 수정 예시는 자동 적용되지 않습니다.

### CWE와 CVE

발견 사항에는 규칙과 관련된 **CWE 후보**를 표시합니다. 패턴 일치만으로 CWE 해당 여부를 확정하지 않으며, 매핑하지 않은 규칙은 미확인으로 표시합니다. CVE는 공개된 개별 취약점의 식별자이므로 코드 패턴에서 추정하지 않습니다. 코드 패턴의 CVE는 **미확인**으로 표시합니다. npm 잠금 파일에 대해서만 사용자가 OSV 조회를 선택하면 별도의 권고와 CVE 별칭을 확인할 수 있습니다.

참고: [OWASP CWE Toolkit](https://github.com/OWASP/www-project-cwe-toolkit), [OWASP CVE Assessment Guide](https://owasp.org/projects/cve-assessment-guide), [MITRE CWE](https://cwe.mitre.org/), [CVE Program](https://www.cve.org/).

### Zoro-1 AI 수정과 로컬 적용

프로젝트를 검사한 뒤 발견한 이슈의 **코드 비교 → Zoro-1으로 직접 수정**에서 파일 전송에 동의하고 수정안을 생성합니다. 기존 결정 서버와 같은 루프백 주소의 `/v1/chat/completions`가 텍스트 생성을 지원해야 하며, 서버가 보고하는 모델 리비전은 `ZORO_EXPECTED_REVISION`과 일치해야 합니다. 결정 API의 연결만으로 생성 API 동작이 보장되지는 않습니다. SSH 포워딩된 서버라면 파일이 해당 원격 모델 서버에도 전달됩니다.

로컬 폴더로 분석했다면 AI 수정 요청 화면에서 복사 버튼 왼쪽의 **로컬에 적용**을 선택할 수 있습니다. 요청에 포함된 모든 항목이 직접 수정 조건을 만족할 때만 버튼이 활성화됩니다. 파일별 변경을 검토하고 한 번 승인하면 전체 수정안을 적용합니다. 저장 후 같은 폴더를 다시 읽어 점검합니다. 남은 이슈가 있으면 분석 결과로 이동하고, 같은 범위의 재점검에서 이슈가 0건이면 수정 완료 화면을 표시합니다.

선택한 소스 파일 전체가 모델에 전달됩니다. 해당 파일에 비밀정보가 없는지 확인하세요. JS/TS/Python 소스 파일을 파일당 최대 12KB까지 처리합니다. 다른 파일이 필요한 수정은 보류할 수 있습니다. 모델은 수정할 경로를 지정하거나 명령을 실행할 수 없습니다. 검토 화면의 전체 변경과 설명은 AI 제안이며 정확성이 검증된 결과가 아닙니다.

변경을 확인하고 **내 프로젝트에 적용**을 누르면 브라우저의 폴더 선택창에서 검사한 프로젝트를 다시 선택합니다. 폴더 이름과 대상 파일의 바이트가 검사 당시와 같을 때만 기존 파일을 씁니다. 이 기능에는 File System Access API를 지원하는 Chrome 또는 Edge의 로컬 보안 컨텍스트가 필요합니다. 적용 전 원본 저장 버튼도 있습니다. 쓰기 직전의 비교는 다른 프로그램의 동시 수정을 완전히 잠그지는 못합니다.

생성 후 같은 정적 규칙을 다시 검사하지만 보안 해결이나 기존 기능 유지를 보증하지 않습니다. 테스트는 자동으로 실행하지 않습니다. 적용 후 프로젝트를 다시 검사하고 관련 테스트를 실행하세요. 모델이 잘린 응답이나 유효하지 않은 형식을 반환하거나 설정된 리비전과 다르면 적용하지 않습니다.

### Zoro-1 추가 검토와 수정안 재검사

프로젝트 폴더를 선택하면 브라우저가 선택한 소스, 루트 package.json, 지원하는 JS 테스트 파일로 작업 사본을 구성합니다. 검사·적용·테스트는 같은 스냅샷을 사용합니다. 검토 유형 선택 시 모델에는 탐지된 규칙 유형과 프로젝트 설문의 선택값을 보냅니다. HTML 텍스트 대입과 pg/mysql2의 명확한 단일 값 SELECT 조건만 자동 제안을 지원합니다.

### 수정과 격리 테스트

1. 변경 전후를 검토하고 **사본에 적용**을 누릅니다. 원본 반영용 패치를 내려받아 프로젝트 루트에서 `git apply --check trace.patch` 후 `git apply trace.patch`로 반영할 수 있습니다. 동시 편집 중인 파일은 서버가 직접 덮어쓰지 않습니다.
2. Docker를 실행하고 로컬 이미지가 없으면 저장소 루트에서 `docker build -t security-review-deterministic:local security-review-mvp/deterministic-audit`로 준비합니다. 테스트는 네트워크를 차단한 일반 사용자 컨테이너에서 실행합니다. 읽기 전용 입력을 용량 제한이 있는 임시 공간으로 복사하며 호스트 환경변수·홈 디렉터리·Docker 소켓은 전달하지 않습니다. 외부 패키지는 루트 package.json 및 npm package-lock.json(v2/v3)을 사용합니다. 호스트는 공개 npm 레지스트리의 고정 tarball만 받아 SHA-512를 확인합니다. 같은 파일 묶음으로 수정 전후의 독립 컨테이너에서 npm ci --offline --ignore-scripts를 수행합니다. 잠금 항목 128개, 압축 다운로드 합계 24 MiB까지 지원합니다. 사설 레지스트리, Git·로컬 의존성, workspaces 및 설치 스크립트가 필요한 패키지는 지원 범위 밖입니다.
3. 전체 테스트에는 `node --test` 또는 `npm test`를 선택합니다. Node 실행은 실제 테스트 이벤트를 집계하며, 임의의 npm 스크립트 종료 코드 0은 실행 건수 미확인으로 표시합니다.
4. 수정 항목을 검증하는 프로젝트의 Node 테스트 파일을 지정하면 원본과 수정본을 각각 새 컨테이너에서 실행합니다. 같은 테스트의 단언 실패가 통과로 바뀌고 정적 규칙도 사라지면 테스트 이름을 표시합니다. 해당 테스트가 보안 요구사항을 적절히 검증하는지는 개발자가 판단합니다.

### AI에 보낼 수정 프롬프트

보안 이슈를 열고 **AI에 보낼 수정 프롬프트 만들기**를 누르세요. Zoro-1 Decision Model이 규칙과 근거 상태를 보고 코드 확인, 최소 수정, 회귀 테스트 중 강조점을 선택합니다. 로컬에서 한국어 요청문에 파일 위치, CWE 후보, 권장 조치와 검증 요구를 조합합니다. 복사되는 문구에는 대상 파일·줄, 수정 지시, 검증 조건을 표시합니다. 지원되는 수정안은 실제 대입문이나 바인딩 호출을 넣고, 연결한 회귀 테스트가 있으면 실행 명령도 붙입니다. 모델 연결에 실패하면 다시 시도할 수 있습니다.

### 외부 패키지 회귀 예제

데모에서 [notice-preview](examples/notice-preview) 자체를 프로젝트 폴더로 선택합니다. 루트의 패키지 파일과 테스트도 함께 준비됩니다. HTML 삽입 수정안을 사본에 적용하고 test/notice.test.mjs를 지정해 격리 테스트를 실행하세요. 이 예제는 clsx 2.1.1로 긴급 공지 CSS 클래스를 조합하며, 회귀 테스트는 클래스 유지와 메시지의 텍스트 렌더링을 함께 검사합니다.

### 사용자 프로젝트 정적 데이터 흐름

JavaScript `.js`, `.cjs`, `.mjs`에서 `req`/`request`의 `query`, `params`, `body` 값이 변수와 문자열 연산을 거쳐 HTML 삽입, SQL 쿼리, `exec` 계열, `fetch` 또는 `axios.get`에 도달하는 구문을 후보로 표시합니다. 발견 상세에 출처와 사용 지점의 줄 번호를 표시합니다. 파싱 오류와 다른 확장자는 분석하지 않습니다. 같은 파일에 선언된 일부 함수의 인자와 반환값, if 분기에서 이어지는 흐름을 제한적으로 추적합니다. 정제·검증처럼 보이는 함수 이름은 호출 사실만 표시하고 효과를 판정하지 않습니다. 파일 간 호출, 반복문, 동적 호출·속성, 분기 실행 가능성 및 실제 취약성은 확인하지 않습니다. 분석은 깊이 5와 30,000 연산으로 제한되며 한도 초과를 별도 표시합니다. 따라서 결과가 없어도 안전하다는 뜻은 아닙니다.

### Zoro-1 선택 평가

`ZORO_DECIDE_URL=http://127.0.0.1:30001/v1/systemone ZORO_EXPECTED_REVISION=<revision> node sites/zoro-security-demo/evaluate-zoro.mjs`는 합성 사례 네 개에서 모델이 고른 추가 검토와 HTML을 우선 선택하는 고정 기준선을 비교합니다. 점수는 사전에 정한 유형을 선택하고 제한된 수정안을 생성했는지 확인하는 지표입니다. 실제 취약점 악용, 수정의 정확성 또는 일반화 성능을 평가하지 않습니다. 모델 실패는 연결 실패로 개별 표시합니다.

2026-11-19 실제 Brev 모델 응답 1회에서 기준선 4/4, 모델 4/4였습니다. 서버가 보고한 revision은 `bf1b76b9b4df03b05fcbb73444e1cd4db0f566da`입니다. 이 작은 사례에서 관찰된 차이는 0건이며 성능 우위를 주장할 근거는 없습니다.

### 실제 실습 코드에 대한 평가

OWASP NodeGoat의 의도적으로 취약한 코드 이미지를 사용해 `routes/contributions.js`의 `eval` 32–34행과 `routes/research.js`의 `needle.get` 16행을 평가했습니다. 로컬 이미지 ID는 `sha256:ec8976008b303ee340578bfadb3b36e5de9411b9d2f550254aec0e126b416345`입니다. 해당 두 파일을 기존 정규식 검사로 검사했을 때 정답 행은 0/4였고, 확장된 정적 흐름 검사는 4/4를 후보로 표시했습니다. 실제 Zoro-1은 각각 동적 코드 실행과 서버 요청 주소의 수동 검토를 선택했습니다. 이 두 유형의 자동 수정과 일반 프로젝트 대상 동적 수정 전후 테스트는 지원하지 않습니다. 별도로 contributions 핸들러에 수동으로 작성한 eval → Number 비교안과 테스트 스텁을 Docker에서 실행한 결과 선택된 입력에 대해 수정 전 실패, 수정 후 통과했습니다. Zoro-1이 수정안을 생성한 것은 아니므로 탐지율이나 수정 성공률에 준 추가 효과를 계산할 수 없습니다. 스캐너는 Zoro-1 호출 전에 동작합니다.

같은 이미지에서 app 디렉터리를 준비한 다음 `ZORO_DECIDE_URL=... ZORO_EXPECTED_REVISION=... node sites/zoro-security-demo/evaluate-nodegoat.mjs <app경로>`로 재현할 수 있습니다. 비교는 알려진 두 실습 파일의 네 위치에 한정되며 전체 프로젝트 성능이나 오탐률을 뜻하지 않습니다.

워크플로우와 기능별 구현 현황은 [SERVICE_WORKFLOW.md](SERVICE_WORKFLOW.md)에 정리했습니다.

### 핵심 보안 5가지

프로젝트 검사 결과에 접근 제어, 비밀정보, 인증·세션, 인젝션·XSS, 의존성 카드를 표시합니다. 발견된 코드 위치와 정적 근거, 사람이 확인할 검증 방법과 권장 조치를 제공합니다. 쿠키 `secure: false` 및 소스의 비밀값 형태도 후보로 확인합니다. 값은 결과 카드에 출력하지 않습니다. Zoro-1은 이슈 유형에 따라 접근 제어, 비밀정보 또는 세션의 수동 검토를 선택할 수 있습니다.

루트 `package-lock.json`이 포함된 경우 **OSV 취약점 대조**를 누르면 고정된 npm 패키지 이름과 버전만 OSV API로 전송합니다. 잠금 파일 원문과 소스 코드는 전송하지 않습니다. 최대 100개 고유 버전과 최대 5개 응답 페이지를 대조하며, 최초 20개 권고의 CVE 별칭과 수정 버전을 확인합니다. 누락되거나 조회에 실패한 상세는 미확인으로 표시합니다. 권고의 수정 버전은 개별 권고 기준이며 모든 취약점의 해결 버전이라는 뜻은 아닙니다. 사용자가 해당 권고를 읽고 프로젝트 호환성을 검토해야 합니다. 지원하지 않는 잠금 파일 또는 연결 오류는 확인 실패로 표시합니다. URL: https://google.github.io/osv.dev/post-v1-querybatch/

접근 제어의 실제 계정 간 검증, 실제 비밀값의 유효성 확인, 운영 인증·쿠키 동적 검증은 현재 수행하지 않습니다. HTML/SQL 일부의 사본 수정 및 사용자가 선택한 격리 테스트와 OSV 버전 대조를 제외하면 카드의 검증은 사용자가 수행할 절차입니다.
