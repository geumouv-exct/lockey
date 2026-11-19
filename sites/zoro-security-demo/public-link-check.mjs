import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import {createHash} from 'node:crypto';
const blocked=new net.BlockList();
for(const [address,prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]])blocked.addSubnet(address,prefix,'ipv4');
export function validatePublicUrl(value){
 if(typeof value!=='string'||value.length>2048)throw Error('점검할 주소를 확인하세요.');let u;try{u=new URL(value)}catch{throw Error('올바른 웹 주소를 입력하세요.')}
 if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search||u.hash||!u.hostname||net.isIP(u.hostname)||u.hostname==='localhost'||!u.hostname.includes('.')||!/^[-a-z0-9.]+$/i.test(u.hostname)||u.port&&!((u.protocol==='http:'&&u.port==='80')||(u.protocol==='https:'&&u.port==='443')))throw Error('공개 웹 도메인의 기본 HTTP(S) 주소만 지원합니다. 로그인 정보, IP 주소, 비표준 포트와 쿼리는 사용할 수 없습니다.');
 return u;
}
export function assessHeaders(protocol,headers){
 const issues=[];
 const add=(key,title,summary)=>issues.push({key,id:'header-review',title,summary,cwe:'CWE-693',cweName:'Protection Mechanism Failure',status:'검토 필요'});
 if(!headers['content-security-policy'])add('csp','콘텐츠 보안 정책 확인','브라우저에서 허용할 콘텐츠 출처 정책이 응답에서 확인되지 않았어요.');
 if(!headers['x-content-type-options']||!/^nosniff\s*$/i.test(headers['x-content-type-options']))add('nosniff','콘텐츠 유형 보호 확인','브라우저가 응답 유형을 추측하지 않도록 설정을 확인해 주세요.');
 if(!headers['x-frame-options']&&!/\bframe-ancestors\b/i.test(headers['content-security-policy']||''))issues.push({key:'frame',id:'header-review',title:'다른 사이트의 화면 삽입 제한 확인',summary:'다른 웹사이트가 이 화면을 포함하지 못하도록 제한하는 설정을 확인해 주세요.',cwe:'CWE-1021',cweName:'Improper Restriction of Rendered UI Layers or Frames',status:'검토 필요'});
 if(protocol==='http:')issues.push({key:'http',id:'header-review',title:'암호화되지 않은 HTTP 연결',summary:'현재 응답은 암호화되지 않은 연결로 받았습니다. HTTPS 제공 여부를 확인해 주세요.',cwe:'CWE-319',cweName:'Cleartext Transmission of Sensitive Information',status:'검토 필요'});
 return issues;
}
export async function checkPublicLink(value,{resolve=dns.resolve4,transport}={}){
 const url=validatePublicUrl(value);const records=await Promise.race([resolve(url.hostname),new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('주소 조회 시간이 초과되었습니다.')),5000);timer.unref?.()})]);
 if(!Array.isArray(records)||!records.length||records.length>32||records.some(ip=>net.isIP(ip)!==4||blocked.check(ip,'ipv4')))throw Error('공개 IPv4 주소로 확인되지 않아 연결을 중단했습니다.');
 const request=transport||(url.protocol==='https:'?https:http).request;
 const response=await new Promise((resolveResult,reject)=>{let settled=false;const req=request(url,{method:'HEAD',headers:{'user-agent':'Trace-Security-Demo/1.0'},family:4,autoSelectFamily:false,lookup:(_hostname,options,callback)=>options?.all?callback(null,[{address:records[0],family:4}]):callback(null,records[0],4),timeout:7000},res=>{if(settled)return;settled=true;const headers=res.headers;res.resume();resolveResult({status:res.statusCode,headers})});req.on('timeout',()=>req.destroy(Error('응답 시간이 초과되었습니다.')));req.on('error',e=>{if(!settled){settled=true;reject(Error('사이트에 연결하지 못했습니다: '+e.message))}});req.end()});
 if(response.status>=300&&response.status<400)return {status:'redirect',httpStatus:response.status,issues:[],note:'리디렉션을 따라가지 않아 최종 페이지를 검사하지 않았습니다.'};
 return {status:'checked',httpStatus:response.status,issues:assessHeaders(url.protocol,response.headers),note:'입력한 주소에 인증 없이 HEAD 요청 한 번을 보낸 결과입니다. 페이지·로그인·코드·취약점 악용 여부는 검사하지 않았습니다.'};
}

// Both readers pin the resolved public address and never follow redirects.
async function readPublicPage(url,{resolve=dns.resolve4,transport}={},htmlOnly=false){
 const records=await Promise.race([resolve(url.hostname),new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('주소 조회 시간이 초과되었습니다.')),5000);timer.unref?.()})]);
 if(!Array.isArray(records)||!records.length||records.length>32||records.some(ip=>net.isIP(ip)!==4||blocked.check(ip,'ipv4')))throw Error('공개 IPv4 주소로 확인되지 않아 연결을 중단했습니다.');
 const request=transport||(url.protocol==='https:'?https:http).request;
 return new Promise((resolveResult,reject)=>{
  const chunks=[];
  let size=0;
  const req=request(url,{method:'GET',headers:{'user-agent':'Trace-Security-Demo/1.0','accept-encoding':'identity'},family:4,autoSelectFamily:false,lookup:(_host,options,cb)=>options?.all?cb(null,[{address:records[0],family:4}]):cb(null,records[0],4),timeout:7000},res=>{
   const fail=reason=>{reject(Error(reason));res.destroy()};
   if(res.statusCode!==200){fail('HTTP 200 응답을 받지 못했어요.');return}
   if(htmlOnly&&!/^text\/html(?:\s*;|$)/i.test(res.headers['content-type']||'')){fail('공개 HTML 페이지를 확인하지 못했어요.');return}
   res.on('data',chunk=>{
    size+=chunk.length;
    if(size>300000){fail('페이지가 300KB를 초과해 확인하지 못했어요.');return}
    chunks.push(Buffer.from(chunk));
   });
   res.on('end',()=>resolveResult(Buffer.concat(chunks)));
   res.on('aborted',()=>reject(Error('페이지 응답이 중단됐어요.')));
   res.on('error',reject);
  });
  const deadline=setTimeout(()=>req.destroy(Error('응답 시간 초과')),8000);
  deadline.unref?.();
  req.on('close',()=>clearTimeout(deadline));
  req.on('timeout',()=>req.destroy(Error('응답 시간 초과')));
  req.on('error',reject);req.end();
 });
}
export async function readPublicIndexHash(value,options){
 const url=validatePublicUrl(value);if(url.protocol!=='https:'||url.pathname!=='/')throw Error('정적 파일 대조는 공개 HTTPS 루트 주소만 지원합니다.');
 const body=await readPublicPage(url,options);
 return {sha256:createHash('sha256').update(body).digest('hex'),bytes:body.length};
}
export async function readPublicHtml(value,options){
 return (await readPublicPage(validatePublicUrl(value),options,true)).toString('utf8');
}

// The caller supplies only generated challenge headers; HTTPS, pinned public IP and no redirects.
export async function requestDeploymentProof(value,route,{method='GET',headers={},resolve=dns.resolve4,transport}={}){
 const root=validatePublicUrl(value);if(root.protocol!=='https:'||root.pathname!=='/')throw Error('배포 검증은 공개 HTTPS 루트 주소만 지원합니다.');
 if(!['GET','HEAD'].includes(method)||!(route==='/.well-known/lockey-attestation'||/^\/(?:[A-Za-z0-9_-]+\/?)*$/.test(route)&&route!=='/'))throw Error('검증 경로가 올바르지 않습니다.');
 const records=await Promise.race([resolve(root.hostname),new Promise((_,reject)=>{const t=setTimeout(()=>reject(Error('주소 조회 시간 초과')),5000);t.unref?.()})]);
 if(!Array.isArray(records)||!records.length||records.length>32||records.some(ip=>net.isIP(ip)!==4||blocked.check(ip,'ipv4')))throw Error('공개 IPv4 주소로 확인되지 않았습니다.');
 const url=new URL(route,root.origin),request=transport||https.request;
 return await new Promise((resolveResult,reject)=>{let done=false,size=0;const parts=[];const fail=()=>{if(!done){done=true;reject(Error('배포 검증 응답을 확인하지 못했습니다.'))}};
  const req=request(url,{method,headers:{'user-agent':'Lockey-Deployment-Proof/1.0','accept-encoding':'identity',...headers},family:4,autoSelectFamily:false,lookup:(_hostname,options,callback)=>options?.all?callback(null,[{address:records[0],family:4}]):callback(null,records[0],4),timeout:7000},res=>{
   res.on('data',chunk=>{size+=chunk.length;if(size>64000){res.destroy();fail();return}parts.push(chunk)});res.on('end',()=>{if(!done){done=true;resolveResult({status:res.statusCode,body:Buffer.concat(parts).toString('utf8'),signature:res.headers['x-lockey-response'],routeSignature:res.headers['x-lockey-route'],instanceId:res.headers['x-lockey-instance']})}});res.on('aborted',fail);res.on('error',fail);
  });req.on('timeout',()=>req.destroy(Error('timeout')));req.on('error',fail);req.end();
 });
}
