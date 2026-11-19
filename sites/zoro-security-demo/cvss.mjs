// CVSS v3 base equation per FIRST specification; incomplete or malformed vectors are unknown.
export function cvssBase(vector){
 if(typeof vector!=='string')return null;
 const parts=vector.split('/'),version=parts.shift();if(!['CVSS:3.0','CVSS:3.1'].includes(version))return null;
 const metrics={};for(const part of parts){const match=/^([A-Z]{1,3}):([A-Z])$/.exec(part);if(!match||Object.hasOwn(metrics,match[1]))return null;metrics[match[1]]=match[2]}
 const av={N:.85,A:.62,L:.55,P:.2},ac={L:.77,H:.44},ui={N:.85,R:.62},cia={N:0,L:.22,H:.56};
 const required=['AV','AC','PR','UI','S','C','I','A'];
 const optional={E:'XUPFH',RL:'XOTWU',RC:'XURC',CR:'XLMH',IR:'XLMH',AR:'XLMH',MAV:'XNALP',MAC:'XLH',MPR:'XNLH',MUI:'XNR',MS:'XUC',MC:'XNLH',MI:'XNLH',MA:'XNLH'};
 if(Object.keys(metrics).some(k=>!required.includes(k)&&(!Object.hasOwn(optional,k)||!optional[k].includes(metrics[k]))))return null;
 if(required.some(k=>!metrics[k])||!Object.hasOwn(av,metrics.AV)||!Object.hasOwn(ac,metrics.AC)||!Object.hasOwn(ui,metrics.UI)||!['U','C'].includes(metrics.S)||!['N','L','H'].includes(metrics.PR)||['C','I','A'].some(k=>!Object.hasOwn(cia,metrics[k])))return null;
 const pr=metrics.PR==='N'?.85:metrics.PR==='L'?(metrics.S==='U'?.62:.68):(metrics.S==='U'?.27:.5);
 const iss=1-(1-cia[metrics.C])*(1-cia[metrics.I])*(1-cia[metrics.A]);
 const impact=metrics.S==='U'?6.42*iss:7.52*(iss-.029)-3.25*(iss-.02)**15;
 const exploit=8.22*av[metrics.AV]*ac[metrics.AC]*pr*ui[metrics.UI];
 const raw=impact<=0?0:Math.min(metrics.S==='U'?impact+exploit:1.08*(impact+exploit),10);
 const rounded=Math.ceil(Math.round(raw*100000)/10000)/10;
 return {version:version.slice(5),score:rounded,vector};
}
export function advisoryCvss(data){
 if(!Array.isArray(data?.severity))return [];
 return data.severity.filter(x=>x?.type==='CVSS_V3').map(x=>cvssBase(x.score)).filter(Boolean);
}


