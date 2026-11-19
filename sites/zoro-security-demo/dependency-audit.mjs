import {advisoryCvss} from './cvss.mjs';
const validName=/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const validVersion=/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
export function extractPackages(text){
 let data;try{data=JSON.parse(text)}catch{throw Error('package-lock.json이 올바른 JSON이 아닙니다.')}
 if(![2,3].includes(data.lockfileVersion)||!data.packages||typeof data.packages!=='object')throw Error('npm lockfileVersion 2 또는 3이 필요합니다.');
 const found=new Map();let omitted=0;
 for(const [path,item] of Object.entries(data.packages)){
  if(!path)continue;
  const name=item?.name||path.split('node_modules/').at(-1);const version=item?.version;
  if(!path.includes('node_modules/')||item?.link||!validName.test(name||'')||!validVersion.test(version||'')){omitted++;continue}
  const key=name+'@'+version;if(!found.has(key))found.set(key,{name,version});
 }
 const entries=[...found.values()];if(entries.length>100)throw Error('최대 100개 패키지까지 대조합니다. 더 작은 잠금 파일을 선택하세요.');
 if(!entries.length)throw Error('대조할 수 있는 고정 패키지 버전이 없습니다.');
 return {entries,omitted};
}
export async function queryOsv(text,{fetcher=fetch,includeDetails=true}={}){
 const {entries,omitted}=extractPackages(text);
 let pending=entries.map((entry,index)=>({entry,index,token:null}));const results=entries.map(e=>({...e,advisories:[]}));let pages=0;
 while(pending.length){
  if(++pages>5)throw Error('OSV 페이지 제한을 초과해 결과를 완료하지 못했습니다.');
  const response=await fetcher('https://api.osv.dev/v1/querybatch',{method:'POST',headers:{'Content-Type':'application/json'},redirect:'error',signal:AbortSignal.timeout(20000),body:JSON.stringify({queries:pending.map(({entry,token})=>({package:{ecosystem:'npm',name:entry.name},version:entry.version,...(token?{page_token:token}:{})}))})});
  if(!response.ok)throw Error(`OSV 조회 실패 (HTTP ${response.status})`);
  const payload=await response.json();if(!Array.isArray(payload.results)||payload.results.length!==pending.length)throw Error('OSV 응답을 확인할 수 없습니다.');
  const next=[];for(let i=0;i<pending.length;i++){
   const r=payload.results[i];if(!r||typeof r!=='object'||(r.vulns&&!Array.isArray(r.vulns)))throw Error('OSV 응답 형식 오류');
   for(const v of r.vulns||[]){if(typeof v.id==='string'&&/^(GHSA-[a-z0-9-]+|CVE-\d{4}-\d{4,}|OSV-\d{4}-\d+)$/i.test(v.id))results[pending[i].index].advisories.push(v.id);else throw Error('OSV 식별자를 확인할 수 없습니다.')}
   if(r.next_page_token){if(typeof r.next_page_token!=='string'||r.next_page_token.length>2000)throw Error('OSV 페이지 토큰 오류');next.push({...pending[i],token:r.next_page_token})}
  }pending=next;
 }
 const matches=results.filter(r=>r.advisories.length);let detailsIncomplete=false;
 if(includeDetails){
  const ids=[...new Set(matches.flatMap(r=>r.advisories))];if(ids.length>20)detailsIncomplete=true;
  const details=new Map();
  await Promise.all(ids.slice(0,20).map(async id=>{try{
   const res=await fetcher('https://api.osv.dev/v1/vulns/'+encodeURIComponent(id),{redirect:'error',signal:AbortSignal.timeout(12000)});
   if(!res.ok)throw Error('detail failed');const data=await res.json();if(data.id!==id)throw Error('ID mismatch');details.set(id,data);
  }catch{detailsIncomplete=true}}));
  for(const item of matches)item.details=item.advisories.map(id=>{
   const data=details.get(id);const fixed=[];
   for(const affected of data?.affected||[])if(affected.package?.ecosystem==='npm'&&affected.package?.name===item.name)
    for(const range of affected.ranges||[])for(const event of range.events||[])if(typeof event.fixed==='string'&&validVersion.test(event.fixed))fixed.push(event.fixed);
   return {id,cvss:advisoryCvss(data),cves:(data?.aliases||[]).filter(a=>typeof a==='string'&&/^CVE-\d{4}-\d{4,}$/.test(a)),fixed:[...new Set(fixed)],available:Boolean(data)};
  });
 }
 return {status:'completed',checked:entries.length,omitted,detailsIncomplete,packages:matches,source:'https://osv.dev/',note:'잠금 파일에 기록된 버전과 공개 권고를 대조했습니다. 실제 설치·호출 여부와 악용 가능성은 별도 확인이 필요합니다.'};
}
