import {classification} from './classifications.mjs';

const projectChecks = {
  'dangerous-html':'방문자가 쓴 글을 화면에 넣는 곳에서 글 안의 기호도 그대로 글자로 보이는지 확인하세요.',
  'sql-interpolation':'검색창이나 입력칸에 쓴 값이 데이터 저장소의 명령문에 그대로 붙는지 확인하세요.',
  'command-input':'방문자가 입력한 값으로 서버가 실행할 명령을 만들고 있는지 확인하세요.',
  'request-url':'방문자가 입력한 주소로 서버가 연결하는 곳에서 허용한 주소만 열 수 있는지 확인하세요.',
  'hardcoded-credential':'이 위치의 값이 실제 비밀번호나 서비스 키인지 확인하세요. 실제 값이라면 발급처에서 교체하세요.',
  'private-key':'이 파일에 실제 비밀키가 들어 있는지 확인하세요. 공개된 키라면 발급처에서 교체하세요.',
  'public-secret':'방문자의 브라우저로 보내는 파일에 비밀키가 포함되는지 확인하세요.'
};

// Only the identifier keys are sent to the news service. Locations stay in the browser.
export function projectNewsContext(findings, linkIssues, packages) {
  const types = new Map(), advisories = new Map();
  for (const finding of findings) {
    if (finding.status === 'locally_false') continue;
    const info = classification(finding);
    if (!/^CWE-\d+$/.test(info.cwe) || types.has(info.cwe)) continue;
    const location = [finding.path, finding.lines?.length && finding.lines[0] + '행'].filter(Boolean).join(' ');
    types.set(info.cwe, {location, check:projectChecks[finding.id] || info.summary});
  }
  for (const issue of linkIssues) {
    if (/^CWE-\d+$/.test(issue.cwe) && !types.has(issue.cwe)) {
      types.set(issue.cwe, {location:'웹사이트 응답 설정', check:issue.summary});
    }
  }
  for (const pkg of packages) {
    const ids = [...(pkg.advisories || []), ...(pkg.details || []).flatMap(detail => [detail.id, ...(detail.cves || [])])];
    for (const id of ids) {
      if (/^CVE-\d{4}-\d{4,19}$/.test(id)) advisories.set(id, pkg.name + ' ' + pkg.version);
    }
  }
  return {types, advisories};
}

export function newsConnection(item, context) {
  const pkg = context.advisories.get(item.id);
  if (pkg) return '설치 목록의 ' + pkg + '에 같은 보안 공지가 있어요. 실제로 사용하는 버전과 원문의 업데이트 안내를 확인하세요.';
  const type = item.cwes.find(id => context.types.has(id));
  if (!type) return '';
  const finding = context.types.get(type);
  return '비슷한 문제가 발견된 위치 · ' + finding.location + ' (' + type + '). ' + finding.check;
}

// Only public facts from the selected article go into the copyable prompt.
export function newsAssessmentPrompt(item) {
  const ids = [...new Set([item.id,...(item.cves || [])].filter(id=>/^CVE-\d{4}-\d{4,19}$/.test(id)))];
  const sources = [...new Set([item.sourceUrl,item.advisoryUrl,item.reportUrl,...(item.sources || []).map(s=>s.url)].filter(Boolean))];
  const headline = item.explanation?.headline || item.guide?.headline || item.name;
  return [
    '현재 열려 있는 내 프로젝트가 아래 기사에서 다룬 보안 문제의 영향을 받는지 점검해 주세요.',
    '',
    '선택한 기사 · '+headline,
    '원문 제목 · '+item.name,
    ...(ids.length?['취약점 번호 · '+ids.join(', ')]:[]),
    ...(item.product ? ['대상 제품 · '+[...new Set([item.vendor,item.product].filter(Boolean))].join(' ')] : []),
    '출처 · '+sources.join('\n       '),
    '',
    !ids.length?'1. 기사에서 확인된 사건과 영향을 받은 서비스, 계정, 데이터를 정리해 주세요. 원인이나 피해가 확인되지 않은 부분은 구분해 주세요.':'1. 이 번호의 공급자 공지에서 영향받는 제품·버전·설정 조건과 수정된 버전을 확인해 주세요. 출처를 열 수 없다면 확인이 필요한 조건을 적어 주세요.',
    '2. 프로젝트의 패키지 목록, 잠금 파일, 컨테이너 이미지, 배포 설정에서 해당 제품과 실제 사용 버전을 찾아 주세요. 간접 의존성이나 앱에 포함된 실행 환경도 살펴보세요.',
    '3. 발견한 버전과 사용 위치를 공지의 조건과 비교하세요. 근거가 되는 파일 경로와 줄 번호를 적고 비밀번호·토큰 값은 생략해 주세요. 파일 변경이나 공격 재현 없이 점검해 주세요.',
    '4. 결론을 “영향 있음”, “영향 없음”, “판단 보류” 중 하나로 써 주세요. 증거가 부족하거나 운영 환경을 확인할 수 없으면 판단을 보류하고, 다음에 확인할 한 가지를 쉬운 말로 알려 주세요.'
  ].join('\n');
}
