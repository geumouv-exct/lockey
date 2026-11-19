import {randomUUID} from 'node:crypto';
import {mkdtemp, mkdir, writeFile, rm, chmod} from 'node:fs/promises';
import {join, dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const execute = promisify(execFile);
const reporter = fileURLToPath(new URL('./test-reporter.mjs', import.meta.url));
const pythonReporter = fileURLToPath(new URL('./python-test-reporter.py', import.meta.url));
const pythonImage='python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89';
export async function isolatedTest(files, command, selectedFile, bundle=null) {
  const parent = await mkdtemp(join(tmpdir(), 'trace-run-'));
  const folder=join(parent,'files');
  const name = 'trace-test-' + randomUUID();
  let attempted = false;
  try {
    await mkdir(folder);
    for (const {path, text} of files) {
      const target = join(folder, path);
      await mkdir(dirname(target), {recursive:true, mode:0o755});
      await writeFile(target, text, {flag:'wx', mode:0o644});
    }
    await chmod(folder, 0o755);
    const program = command === 'python-test' ? ['python3','-I','/python-report.py','./'+selectedFile] : command === 'npm-test' ? ['npm','test'] :
      ['node',...(command==='node-sqlite'?['--experimental-sqlite']:[]),'--test','--test-reporter=/report.mjs', ...(selectedFile ? ['./'+selectedFile] : [])];
    const setup=[
      'mkdir /tmp/project && cp -R /input/. /tmp/project',
      ...(bundle?['mkdir /tmp/install && cd /tmp/install && cp /bundles/package*.json .',
        'npm ci --offline --ignore-scripts --include=dev --no-audit --no-fund >&2 || { echo TRACE_NPM_CI_FAILED >&2; exit 78; }',
        'if [ -d node_modules ]; then mv node_modules /tmp/project/; fi']:[]),
      'cd /tmp/project && exec "$@"'
    ].join(' && ');
    const args = ['run','--rm','--pull=never','--name',name,'--network=none','--read-only',
      '--user','65534:65534','--cap-drop=ALL','--security-opt=no-new-privileges',
      '--pids-limit=96','--memory=384m','--cpus=1','--log-driver=none',
      '--tmpfs','/tmp:rw,nosuid,nodev,size=256m,mode=1777',
      '--mount','type=bind,src='+folder+',dst=/input,readonly',
      '--mount','type=bind,src='+reporter+',dst=/report.mjs,readonly',
      '--mount','type=bind,src='+pythonReporter+',dst=/python-report.py,readonly',
      ...(bundle?['--mount','type=bind,src='+bundle.folder+',dst=/bundles,readonly']:[]),
      '--env','HOME=/tmp','--entrypoint','/bin/sh',command==='python-test'?pythonImage:'security-review-deterministic:local',
      '-ec',setup,'runner',...program];
    attempted = true;
    let code = 0, stdout = '', stderr = '';
    try {
      ({stdout,stderr} = await execute('docker',args,{timeout:60000,maxBuffer:128*1024,killSignal:'SIGKILL'}));
    } catch (error) {
      if (error.killed || error.signal) throw Error('격리 테스트 시간 또는 출력 한도를 초과했습니다.');
      if (bundle && error.code===78 && error.stderr?.includes('TRACE_NPM_CI_FAILED')) throw Error('오프라인 npm ci 실패. 매니페스트와 잠금 파일 일치 여부, 패키지 호환성, 설치 용량을 확인하세요.');
      if (!Number.isInteger(error.code) || [125,126,127].includes(error.code) || /(?:cannot connect to the docker daemon|permission denied.*docker|docker daemon is not running)/i.test(error.stderr||''))
        throw Error(command==='python-test'?'Python 격리 실행기를 시작할 수 없습니다. Docker와 지정된 Python 이미지를 확인하세요.':'격리 실행기를 시작할 수 없습니다. Docker와 로컬 Node 이미지를 확인하세요.');
      ({code,stdout='',stderr=''} = error);
    }
    const events = [];
    if (command !== 'npm-test') for (const line of stdout.trim().split('\n').filter(Boolean)) {
      if(command==='python-test'&&!line.startsWith('TRACE_TEST_EVENT:'))continue;
      try { events.push(JSON.parse(command==='python-test'?line.slice('TRACE_TEST_EVENT:'.length):line)); } catch { throw Error('테스트 결과를 읽을 수 없습니다.'); }
    }
    return {code, events, output:(stdout+'\n'+stderr).slice(0,100000)};
  } finally {
    if (attempted) await execute('docker',['rm','-f',name],{timeout:5000}).catch(()=>{});
    await rm(parent,{recursive:true,force:true});
  }
}
