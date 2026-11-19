import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {scanText} from '../../security-review-mvp/scanner.mjs';
import {scanProject} from './project-scan.mjs';
import {chooseProjectReview} from './zoro.mjs';

// OWASP NodeGoat deliberately vulnerable routes extracted from the local
// training image. This measures detection coverage, not exploit execution.
const root=process.argv[2];
if(!root)throw Error('NodeGoat app 디렉터리 경로가 필요합니다.');
for(const spec of [{path:'routes/contributions.js',id:'code-evaluation',lines:[32,33,34]},{path:'routes/research.js',id:'request-url',lines:[16]}]){
 const text=await readFile(join(root,spec.path),'utf8');const files=[{path:spec.path,text}];
 const lines=text.split('\n');
 if(spec.path.includes('contributions')&&!spec.lines.every(line=>/eval\(req\.body\./.test(lines[line-1])))throw Error('NodeGoat 코드 버전이 평가 기준과 다릅니다.');
 if(spec.path.includes('research')&&!/needle\.get\(url/.test(lines[15]))throw Error('NodeGoat 코드 버전이 평가 기준과 다릅니다.');
 const before=scanText(spec.path,text),after=scanProject(files).findings;
 const match=list=>list.filter(f=>f.id===spec.id).flatMap(f=>f.lines).filter(line=>spec.lines.includes(line));
 const model=await chooseProjectReview(after,{url:process.env.ZORO_DECIDE_URL,expectedRevision:process.env.ZORO_EXPECTED_REVISION});
 console.log(JSON.stringify({case:spec.path,expected:spec.lines,previous_hits:match(before),current_hits:match(after),model_status:model.status,model_choice:model.choice||null,model_message:model.message||null,repair_verification:'not_run',reason:'Zoro-1은 수동 검토를 선택하지만 해당 유형의 수정안·수정 전후 테스트는 제공하지 않습니다.'}));
}
