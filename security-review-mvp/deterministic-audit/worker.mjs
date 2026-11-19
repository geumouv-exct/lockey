import {readdir,readFile,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {Worker,isMainThread,parentPort,workerData} from 'node:worker_threads';
import path from 'node:path';
import {eligible,isExample,scanForAgent,attachProjectFlows,AGENTS} from './scanner.mjs';

const base='/source';
async function runAgent(id){
 if(id==='self')return {id,status:'manual',files:0,errors:0,findings:[]};
 let files=0,errors=0;const findings=[],projectFiles=[];
 async function walk(dir){for(const entry of await readdir(dir,{withFileTypes:true})){const file=path.join(dir,entry.name);if(entry.isSymbolicLink()){errors++;continue}if(entry.isDirectory()){await walk(file);continue}if(!entry.isFile()){errors++;continue}const stat=await lstat(file);const name=path.relative(base,file).split(path.sep).join('/');if(!eligible(name,stat.size)||isExample(name))continue;try{const content=await readFile(file,'utf8');files++;if(id==='phase1'&&projectFiles.length<200&&/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(name)&&content.length<=200000)projectFiles.push({path:name,text:content});findings.push(...scanForAgent(id,name,content));}catch{errors++}if(findings.length>10000)throw Error('결과 제한 초과')}}
 await walk(base);if(id==='phase1')attachProjectFlows(projectFiles,findings);return {id,status:errors?'partial':'completed',files,errors,findings};
}
if(!isMainThread){try{parentPort.postMessage(await runAgent(workerData.id))}catch{parentPort.postMessage({id:workerData.id,status:'failed',files:0,errors:1,findings:[]})}}
else {
 try {
  const source=await readFile(new URL('./scanner.mjs',import.meta.url));const rulesVersion=createHash('sha256').update(source).update(await readFile(new URL('./flow-analysis.mjs',import.meta.url))).update(await readFile(new URL('./vendor/acorn/parser.mjs',import.meta.url))).update(await readFile(new URL('./vendor/babel-parser/parser.mjs',import.meta.url))).digest('hex');
  const tasks=AGENTS.map(agent=>new Promise((resolve,reject)=>{const worker=new Worker(new URL(import.meta.url),{workerData:{id:agent.id}});let result;worker.once('message',value=>{result=value});worker.once('error',reject);worker.once('exit',code=>{if(code||!result)reject(Error('분석 모듈을 완료하지 못했습니다.'));else resolve(result)})}));
  const agents=await Promise.all(tasks);const automated=agents.filter(x=>x.id!=='self');const first=automated[0];if(!first||automated.some(x=>x.files!==first.files))throw Error('분석 모듈 간 파일 수 불일치');
  const findings=agents.flatMap(x=>x.findings);if(findings.length>10000)throw Error('결과 제한 초과');
  process.stdout.write(JSON.stringify({version:2,engine:'deterministic-patterns',rulesVersion,files:first.files,errors:automated.reduce((sum,x)=>sum+x.errors,0),agents:agents.map(({findings,...a})=>a),findings}));
 }catch{process.stderr.write('정적 점검에 실패했습니다.');process.exitCode=1}
}
