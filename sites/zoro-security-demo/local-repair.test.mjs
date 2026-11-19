import {test} from 'node:test';
import assert from 'node:assert/strict';
import {applyLocalRepair} from './local-repair.mjs';
function fixture(content){let value=content,writes=0;const handle={getFile:async()=>({arrayBuffer:async()=>new TextEncoder().encode(value).buffer}),createWritable:async()=>({write:async v=>{value=v;writes++},close:async()=>{},abort:async()=>{}})};return {root:{name:'demo',getDirectoryHandle:async name=>{assert.equal(name,'src');return {getFileHandle:async name=>{assert.equal(name,'view.js');return handle}}}},get value(){return value},get writes(){return writes}}}
const options={projectName:'demo',path:'src/view.js',before:'original',after:'revised'};
test('writes the approved repair to the selected existing file',async()=>{const f=fixture('original');await applyLocalRepair({...options,root:f.root});assert.equal(f.value,'revised');assert.equal(f.writes,1)});
test('does not overwrite a changed file or stale session',async()=>{const f=fixture('edited');await assert.rejects(applyLocalRepair({...options,root:f.root}),/변경/);await assert.rejects(applyLocalRepair({...options,root:f.root,isCurrent:()=>false}),/세션/);assert.equal(f.writes,0)});
test('rejects a different folder and traversal',async()=>{const f=fixture('original');await assert.rejects(applyLocalRepair({...options,root:f.root,projectName:'other'}));await assert.rejects(applyLocalRepair({...options,root:f.root,path:'../view.js'}));assert.equal(f.writes,0)});

test('재점검은 저장된 내용과 새 파일을 읽고 제외 폴더에는 진입하지 않는다',async()=>{
 const {readRepairFolder}=await import('./local-repair.mjs');
 const disk=new Map([['settings.py','DEBUG = True']]);
 const root={async *values(){
  yield {kind:'directory',name:'node_modules',values(){throw Error('제외 폴더에 접근함')}};
  for(const [name,text] of disk)yield {kind:'file',name,getFile:async()=>new File([text],name)};
 }};
 const options={includeFile:path=>path.endsWith('.py'),includeDirectory:name=>name!=='node_modules'};
 const before=await readRepairFolder(root,options);
 disk.set('settings.py','DEBUG = False');disk.set('worker.py','# new');
 const after=await readRepairFolder(root,options);
 assert.equal(await before[0].text(),'DEBUG = True');
 assert.deepEqual(after.map(f=>f.scanPath),['settings.py','worker.py']);
 assert.equal(await after[0].text(),'DEBUG = False');
});

test('일괄 적용은 같은 파일의 항목을 묶고 하나라도 지원하지 않으면 차단한다',async()=>{
 const {planLocalRepairs}=await import('./local-repair.mjs');
 const findings=['debug-enabled','hardcoded-credential'].map(id=>({id,path:'a.py',lines:[1]}));
 const snapshot=[{path:'a.py',text:'source'}];
 assert.equal(planLocalRepairs(findings,snapshot).files[0].findings.length,2);
 for(const extra of [{link:true},{path:'missing.py'},{status:'locally_false'}]){
  assert.ok(planLocalRepairs([...findings,{...findings[0],...extra}],snapshot).reason);
 }
 assert.ok(planLocalRepairs(findings,[{path:'a.py',text:'한'.repeat(4001)}]).reason);
});
test('모든 원본을 확인하고 커밋 실패 시 먼저 저장한 파일을 복원한다',async()=>{
 const {applyLocalRepairs}=await import('./local-repair.mjs');
 for(const failure of ['none','stale','commit']){
  const disk=new Map([['a.py','old-a'],['b.py',failure==='stale'?'edited':'old-b']]);
  const root={name:'demo',getFileHandle:async path=>({
   getFile:async()=>new Blob([disk.get(path)]),createWritable:async()=>{
    let text;
    return {write:async x=>{text=x},abort:async()=>{},close:async()=>{
     if(failure==='commit'&&path==='b.py')throw Error('disk full');
     disk.set(path,text);
    }};
   }
  })};
  const changes=['a','b'].map(n=>({path:n+'.py',before:'old-'+n,after:'new-'+n}));
  const operation=applyLocalRepairs({root,projectName:'demo',changes});
  if(failure==='none'){await operation;assert.deepEqual([...disk.values()],['new-a','new-b'])}
  else{await assert.rejects(operation);assert.deepEqual([...disk.values()],['old-a',failure==='stale'?'edited':'old-b'])}
 }
});
