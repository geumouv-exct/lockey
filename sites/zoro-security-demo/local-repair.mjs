export function planLocalRepairs(items,snapshot){
 const byPath=new Map();
 if(!items.length)return {reason:'수정할 항목이 없어요.'};
 for(const f of items){
  const file=snapshot.find(x=>x.path===f.path);
  if(f.link||!f.lines?.length||!file||f.status==='locally_false')return {reason:'요청에 직접 수정할 코드 위치를 확인할 수 없는 항목이 있어요.'};
  if(!/\.(?:[cm]?js|jsx|ts|tsx|py)$/i.test(file.path)||!file.text.trim()||new TextEncoder().encode(file.text).length>12000)
   return {reason:'모든 대상이 12KB 이하의 JavaScript, TypeScript 또는 Python 소스 파일이어야 해요.'};
  if(!byPath.has(file.path))byPath.set(file.path,{path:file.path,before:file.text,findings:[]});
  byPath.get(file.path).findings.push({id:f.id,lines:f.lines});
 }
 return {files:[...byPath.values()]};
}
function checkCurrent(isCurrent){
 if(!isCurrent())throw Error('검사 세션이 바뀌어 적용을 중단했습니다.');
}
async function stageRepair(root,{path,before,after},isCurrent){
 checkCurrent(isCurrent);
 const parts=path.split('/');
 if(parts.some(p=>!p||p==='.'||p==='..'||p.includes('\\')))throw Error('잘못된 파일 경로입니다.');
 let dir=root;
 for(const part of parts.slice(0,-1))dir=await dir.getDirectoryHandle(part);
 const handle=await dir.getFileHandle(parts.at(-1));
 const writer=await handle.createWritable({mode:'exclusive'});
 try{
  const disk=await handle.getFile();
  const bytes=new Uint8Array(await disk.arrayBuffer()),expected=new TextEncoder().encode(before);
  if(bytes.length!==expected.length||bytes.some((v,i)=>v!==expected[i]))throw Error(path+' 파일이 검사 이후 변경되었거나 지원하지 않는 인코딩입니다.');
  checkCurrent(isCurrent);
  await writer.write(after);
  return writer;
 }catch(error){await writer.abort().catch(()=>{});throw error}
}

// Stage every file before committing any of them. If a commit fails, restore
// committed files only while they still contain the exact approved revision.
export async function applyLocalRepairs({root,projectName,changes,isCurrent=()=>true}){
 checkCurrent(isCurrent);
 if(root.name!==projectName)throw Error('검사한 프로젝트와 같은 폴더를 선택해 주세요.');
 if(!changes.length||new Set(changes.map(c=>c.path)).size!==changes.length)throw Error('파일별 수정안을 확인해 주세요.');
 const writers=[];
 let committed=0;
 try{
  for(const change of changes)writers.push(await stageRepair(root,change,isCurrent));
  for(const writer of writers){checkCurrent(isCurrent);await writer.close();committed++}
 }catch(error){
  await Promise.allSettled(writers.slice(committed).map(w=>w.abort()));
  const incomplete=[];
  for(const change of changes.slice(0,committed).reverse()){
   try{
    const restore=await stageRepair(root,{path:change.path,before:change.after,after:change.before},()=>true);
    try{await restore.close()}catch(e){await restore.abort().catch(()=>{});throw e}
   }catch{incomplete.push(change.path)}
  }
  if(incomplete.length)throw Error('일부 파일을 복원하지 못했어요. 변경 내용을 확인하세요. '+incomplete.join(', '));
  throw error;
 }
}
export function applyLocalRepair({path,before,after,...options}){
 return applyLocalRepairs({...options,changes:[{path,before,after}]});
}

// Read directory entries again after writing, including newly created source files.
// The caller supplies the same path rules used for the original upload.
export async function readRepairFolder(root,{includeFile,includeDirectory}) {
 const files=[];
 async function visit(dir,prefix) {
  for await (const entry of dir.values()) {
   const path=prefix+entry.name;
   if(entry.kind==='directory'){
    if(includeDirectory(entry.name))await visit(entry,path+'/');
   }else if(entry.kind==='file'&&includeFile(path)){
    const file=await entry.getFile();
    files.push({scanPath:path,name:file.name,size:file.size,text:()=>file.text()});
   }
  }
 }
 await visit(root,'');
 return files;
}
