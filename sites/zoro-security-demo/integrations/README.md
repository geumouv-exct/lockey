# Node.js / Express 배포 검증 연동

이 기능은 선택한 프로젝트와 **사용자가 제어하는 배포 앱**을 비교하기 위한 선택형 기능이다. 공개 제3자 서비스에는 임의로 설치할 수 없다. 현재 정적 GET 라우트와 Node.js/Express를 지원한다. 실행 중인 앱이 제공하는 자체 보고이므로 신뢰할 수 없는 서버에 대한 독립적·하드웨어 기반 무결성 증명은 아니다.

1. [`lockey-attestation.mjs`](./lockey-attestation.mjs)를 대상 프로젝트에 복사한다. 대상 프로젝트 루트에서 상대 경로가 Lockey에서 선택한 폴더의 경로와 같아야 한다.
2. 32바이트 난수 키를 생성하고, 배포 환경의 비밀값 `LOCKEY_ATTESTATION_KEY`로 안전하게 설정한다. 예: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. 키는 저장소나 클라이언트 코드에 넣지 않는다. 키가 없으면 연동 초기화가 실패하므로 배포 전에 비밀 설정을 완료한다.
3. 앱에서 검증 인스턴스를 하나 만들고, 검사 대상 라우트 등록 파일과 요청 소스·SQL 사용 함수가 들어 있는 각 모듈이 **실제로 로드되는 시점에** `recordModule(import.meta.url)`을 호출한다. 기록한 파일만 비교된다.
4. 라우트와 인증·권한 미들웨어가 통과하는 위치에 `routeProbe`를 연결한다. 아래는 구조를 보여주는 예시이며 기존 보안 미들웨어를 제거하거나 우회하지 않는다.

```js
// lockey-proof-setup.mjs
import { createLockeyAttestation } from './lockey-attestation.mjs';
export const lockeyProof = createLockeyAttestation({
  root: process.cwd(),
  secret: process.env.LOCKEY_ATTESTATION_KEY,
});

// 각 서버 모듈의 최상위: 실제 앱에서 로드될 때만 기록한다.
// import { lockeyProof } from './lockey-proof-setup.mjs';
// await lockeyProof.recordModule(import.meta.url);

// Express 앱 설정 예시
// app.get('/.well-known/lockey-attestation', lockeyProof.manifest);
// app.get('/api/users', existingAuth, lockeyProof.routeProbe, handler);
```

5. 앱을 배포한 후 Lockey에서 **링크와 로컬 폴더**를 선택하고, 배포 URL과 같은 키를 **배포 검증 키**에 입력한다. Lockey는 로컬 서버에서만 키를 사용하며 배포 서버에는 원문 대신 일회용 인증값을 전송한다. 입력값과 키는 저장하지 않는다.

검증은 선택한 폴더의 파일 해시와 배포 앱이 보고한 로드 모듈 해시를 비교하고, 같은 앱 인스턴스의 라우트 미들웨어에서 인증된 HEAD 응답을 확인한다. 라우트 확인용 HEAD는 인증된 검증 요청에 한해 미들웨어에서 종료하며 실제 업무 핸들러는 실행하지 않는다. 사용자의 일반 요청은 기존 핸들러로 전달한다. 배포 프록시가 HEAD 및 `X-Lockey-*` 요청·응답 헤더를 전달하고 응답을 캐시하지 않아야 한다. 여러 인스턴스가 있을 때 매니페스트와 라우트 요청이 다른 인스턴스에 도달하면 검증을 보류한다.

일치하는 요청 소스·라우트·사용 지점의 모듈과 인증된 정적 라우트 응답을 확인한다. 이는 해당 서버의 자체 보고이며 취약 함수 실행, 악용 가능성 또는 서버의 독립적인 무결성을 증명하지 않는다.
