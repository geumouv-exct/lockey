// A clean result means only that the selected checks found no candidates.
export function recheckStatus(previous,current){
 const missing=[];
 if(previous?.hasLink){if(!current?.hasLink||previous.url!==current.url)missing.push('이전에 점검한 링크');else if(current.linkStatus!=='checked'||!(current.httpStatus>=200&&current.httpStatus<300))missing.push('링크의 최종 정상 응답');}
 if(previous?.hasCode){if(!current?.hasCode||previous.projectName!==current.projectName)missing.push('이전에 점검한 프로젝트 폴더');else{const paths=new Set(current.paths||[]);if((previous.paths||[]).some(p=>!paths.has(p)))missing.push('이전 작업 사본의 일부 파일');}}
 if(current?.hasCode&&current.audit?.status==='error')missing.push('의존성 대조');
 if(current?.hasCode&&current.audit?.status==='completed'&&(current.audit.omitted>0||current.audit.detailsIncomplete))missing.push('일부 의존성 대조');
 const count=(current?.codeFindings||0)+(current?.linkFindings||0)+(current?.audit?.packages||0);
 if(count>0)return {status:'findings',count,missing};
 if(missing.length)return {status:'incomplete',count,missing};
 return {status:'clear',count:0,missing:[]};
}
