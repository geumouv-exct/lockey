import {createHash} from 'node:crypto';
import {mkdtemp,writeFile,rm,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const maxBytes = 24 * 1024 * 1024;
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const sections = ['dependencies','devDependencies','optionalDependencies','peerDependencies'];
function manifest(text) {
  try {
    const value=JSON.parse(text);
    if(value && typeof value==='object' && !Array.isArray(value)) return value;
  } catch {}
  throw Error('npm 매니페스트 JSON 형식을 확인하세요.');
}

export function dependencyPlan(files) {
  const pkgFile=files.find(f=>f.path==='package.json');
  const lockFile=files.find(f=>f.path==='package-lock.json');
  if (!pkgFile && !lockFile) return null;
  if (!pkgFile) throw Error('package-lock.json과 일치하는 package.json이 필요합니다.');
  const pkg=manifest(pkgFile.text);
  if (pkg.workspaces) throw Error('npm workspace 프로젝트는 아직 지원하지 않습니다.');
  if (!lockFile) {
    if (sections.some(k=>Object.keys(pkg[k]??{}).length)) throw Error('외부 패키지 테스트에는 루트 package-lock.json(v2/v3)이 필요합니다.');
    return null;
  }
  const lock=manifest(lockFile.text);
  if (![2,3].includes(lock.lockfileVersion)||!lock.packages?.['']) throw Error('npm lockfileVersion 2 또는 3이 필요합니다.');
  const entries=Object.entries(lock.packages).filter(([key])=>key!=='');
  if (entries.length>128) throw Error('잠금 파일당 설치 항목은 최대 128개입니다.');
  const archives=new Map();
  for(const [path,item] of entries) {
    const parts=path.split('node_modules/');
    if(parts.shift()!=='' || !parts.length || parts.some((p,i)=>!packageName.test(i===parts.length-1?p:p.endsWith('/')?p.slice(0,-1):'')))
      throw Error('잠금 파일에 지원하지 않는 패키지 경로가 있습니다.');
    const name=item?.name??parts.at(-1);
    const version=item?.version;
    if(typeof name!=='string'||!packageName.test(name)||typeof version!=='string'||!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(version)||item.link)
      throw Error('공개 npm 패키지의 고정 버전만 설치할 수 있습니다.');
    const url='https://registry.npmjs.org/'+name+'/-/'+name.split('/').at(-1)+'-'+version+'.tgz';
    if(item.resolved!==url || typeof item.integrity!=='string'||!/^sha512-[A-Za-z0-9+/]{86}==$/.test(item.integrity))
      throw Error('공식 npm 배포 URL과 SHA-512가 있는 잠금 파일이 필요합니다.');
    const filename=Buffer.from(item.integrity.slice(7),'base64').toString('hex')+'.tgz';
    archives.set(filename,{url,filename,integrity:item.integrity});
    item.resolved='file:/bundles/'+filename;
  }
  delete lock.dependencies;
  lock.lockfileVersion=3;
  return {archives:[...archives.values()],lock,count:entries.length,packageText:pkgFile.text};
}

// Only public, canonical tarball URLs are fetched. No project process, credentials
// or npm config participates in this step. Installation happens fully offline.
export async function withDependencies(files,run,fetcher=fetch) {
  const plan=dependencyPlan(files);
  if(!plan) return run(null);
  const parent=await mkdtemp(join(tmpdir(),'trace-npm-'));
  const folder=join(parent,'bundles');
  try {
    await mkdir(folder,{mode:0o755});
    const signal=AbortSignal.timeout(60000);
    let total=0;
    for(const archive of plan.archives) {
      const response=await fetcher(archive.url,{redirect:'error',credentials:'omit',signal});
      if(!response.ok||!response.body)throw Error('잠긴 npm 배포 파일 다운로드 실패 (HTTP '+response.status+').');
      const chunks=[],hash=createHash('sha512');
      for await(const data of response.body) {
        total+=data.length;
        if(total>maxBytes) throw Error('패키지 다운로드 제한(24 MiB)을 초과했습니다.');
        hash.update(data);chunks.push(data);
      }
      if('sha512-'+hash.digest('base64')!==archive.integrity)throw Error('npm 패키지 SHA-512 불일치로 설치를 중단했습니다.');
      await writeFile(join(folder,archive.filename),Buffer.concat(chunks),{flag:'wx',mode:0o644});
    }
    await writeFile(join(folder,'package.json'),plan.packageText,{mode:0o644});
    await writeFile(join(folder,'package-lock.json'),JSON.stringify(plan.lock),{mode:0o644});
    return await run({folder,count:plan.count});
  } finally {await rm(parent,{recursive:true,force:true});}
}
