import {createHash} from 'node:crypto';
import {SaxesParser} from 'saxes';
import {parseFragment} from 'parse5';
// The publisher's summary feed contains short introductions and article permalinks.
const feedUrl = 'https://thehackernews.com/feeds/posts/summary';
const pageSize = 150;
const koreaDay = new Intl.DateTimeFormat('sv-SE', {timeZone:'Asia/Seoul', year:'numeric', month:'2-digit', day:'2-digit'});
const namedIncidents = new Map([
  ['CVE-2026-109618','CVE-2026-109619'], // The two flaws disclosed together as PHP2Shell in October 2026.
]);
// Reading notes for the incidents that prompted this feed. They enrich matching reports only.
// Weakness identifiers are from the published CVE records, including CISA's enrichment.
const readingNotes = {
  'CVE-2026-114938': {product:'Java', cwes:['CWE-122'], advisoryUrl:'https://www.oracle.com/security-alerts/cspunov2026.html',
    guide:{category:'서버 프로그램', headline:'일부 Java 서버에서 외부인이 프로그램을 실행할 수 있어요',
      cause:'일부 환경에서 Java가 외부 데이터를 읽는 동안 정해진 메모리 공간을 벗어나 다른 값을 덮어쓸 수 있어요.',
      check:'내 서버나 배포 이미지에 설치된 Java와 앱에 포함된 Java의 버전을 확인하세요. 사용 중인 배포판의 보안 업데이트 대상인지 비교해 보세요.'}},
  'CVE-2026-115560': {product:'PHP', cwes:['CWE-20','CWE-502'], advisoryUrl:'https://www.php.net/releases/8_5_13.php',
    guide:{category:'파일 업로드', headline:'일부 PHP 사이트에서 업로드 기록이 서버가 실행할 지시로 해석될 수 있어요',
      cause:'특정 설정에서 PHP가 파일 업로드 상태를 저장할 때와 다시 읽을 때 다른 형식을 써서 기록의 의미가 바뀔 수 있어요.',
      check:'호스팅 관리 화면에서 사이트가 실제로 쓰는 PHP 버전을 확인하세요. 해당 버전 계열의 보안 업데이트가 적용됐는지 살펴보세요.'}}
};
const weaknessTerms = [
  [/\bcross.site scripting\b|\bXSS\b/i,'CWE-79'], [/\bSQL injection\b/i,'CWE-89'],
  [/\b(?:OS |shell )?command injection\b/i,'CWE-78'], [/\b(?:server.side request forgery|SSRF)\b/i,'CWE-918'],
  [/\b(?:path|directory) traversal\b/i,'CWE-22'], [/\bhard.?coded credentials?\b/i,'CWE-798'],
  [/\buse.after.free\b/i,'CWE-416'], [/\bout.of.bounds write\b/i,'CWE-787']
];
function incidentId(cve) { return namedIncidents.get(cve) || cve; }
function plainText(value) {
  if (typeof value !== 'string') return '';
  const nodes = [...parseFragment(value.slice(0,12000)).childNodes];
  let text = '';
  while (nodes.length) {
    const node = nodes.shift();
    if (node.nodeName === '#text') text += node.value + ' ';
    else if (node.childNodes && !['script','style'].includes(node.tagName)) nodes.unshift(...node.childNodes);
  }
  return text.replace(/\s+/g,' ').replace(/\s*\[\.\.\.\]$/,'').trim();
}

function report({title,summary,link,date}, source) {
  const name=plainText(title), description=plainText(summary), published=new Date(date);
  if (!name || !URL.canParse(link) || !date || !Number.isFinite(+published)) return;
  const url=new URL(link);
  if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.port) return;
  const valid=source==='The Hacker News'
    ? url.hostname==='thehackernews.com' && /^\/\d{4}\/\d{2}\/[a-z\d-]+\.html$/.test(url.pathname)
    : url.hostname==='www.bleepingcomputer.com' && /^\/news\/security\/[a-z\d-]+\/$/.test(url.pathname);
  if (!valid || /^(?:(?:weekly|monthly|threats?)\s+(?:roundup|recap|digest)|threats?day bulletin)\b|\b(?:webinar|sponsored (?:post|content))\b/i.test(name)) return;
  const sourceUrl='https://'+url.hostname+url.pathname;
  const extract = text => [...new Set(text.toUpperCase().match(/\bCVE-\d{4}-\d{4,19}\b/g) || [])];
  const titleIds = extract(name);
  const cves = titleIds.length ? titleIds : extract(description);
  // A round-up mentioning unrelated CVEs cannot stand in for any one of them.
  const ids = new Set(cves.map(incidentId));
  const id = ids.size===1 ? [...ids][0] : 'report-'+createHash('sha256').update(sourceUrl).digest('hex').slice(0,20);
  const notes = readingNotes[id];
  const text = name + ' ' + description;
  return {id, cves, date:koreaDay.format(published), published:published.toISOString(), source, sourceUrl, name, description,
    product:notes?.product || '', vendor:'', readingNotes:notes?.guide, advisoryUrl:notes?.advisoryUrl, action:'Check the affected product, release and vendor guidance cited in the report.',
    cwes:notes?.cwes || weaknessTerms.filter(([pattern]) => pattern.test(text)).map(([,cwe]) => cwe)};
}

async function readBleepingComputer(fetcher) {
  const response=await fetcher('https://www.bleepingcomputer.com/feed/',{redirect:'error',signal:AbortSignal.timeout(15000)});
  if (!response.ok) throw Error('BleepingComputer 보도를 불러오지 못했어요.');
  const parser=new SaxesParser(), items=[];
  let item, field, sawChannel=false;
  parser.on('opentag',({name})=>{
    if (name==='channel') sawChannel=true;
    if (name==='item') item={};
    if (item && ['title','link','description','pubDate'].includes(name)) {field=name;item[field]='';}
  });
  const append=text=>{if(field)item[field]+=text;};
  parser.on('text',append);parser.on('cdata',append);
  parser.on('closetag',({name})=>{
    if(name===field)field=undefined;
    if(name==='item'){
      const row=report({title:item.title,summary:item.description,date:item.pubDate,link:item.link?.trim()},'BleepingComputer');
      if(row)items.push(row);
      item=undefined;
    }
  });
  parser.write(await response.text()).close();
  if(!sawChannel)throw Error('보도 피드 형식을 확인할 수 없어요.');
  return {items};
}

export function createReportingFeed(fetcher) {
  let saved, pending;
  async function fetchYear(period) {
    const base = new URL(feedUrl);
    base.searchParams.set('alt','json');
    base.searchParams.set('max-results',String(pageSize));
    base.searchParams.set('published-min',new Date(period.start+'T00:00:00+09:00').toISOString());
    async function page(start) {
      const url = new URL(base);
      url.searchParams.set('start-index',String(start));
      const response = await fetcher(url.href,{redirect:'error',signal:AbortSignal.timeout(15000)});
      if (!response.ok) throw Error('보안 보도를 불러오지 못했어요.');
      const {feed} = await response.json();
      const total = Number(feed?.openSearch$totalResults?.$t);
      if (!Number.isSafeInteger(total) || total < 0 || (total && !Array.isArray(feed.entry))) throw Error('보도 목록 형식을 확인할 수 없어요.');
      return {total, items:(feed.entry || []).map(entry=>report({
        title:entry.title?.$t, summary:entry.summary?.$t, date:entry.published?.$t,
        link:entry.link?.find(l=>l.rel==='alternate')?.href
      },'The Hacker News')).filter(Boolean)};
    }
    const {total, items} = await page(1);
    let partial = false;
    for (let start = pageSize+1; start <= total; start += 3*pageSize) {
      const starts = [start,start+pageSize,start+2*pageSize].filter(i => i <= total);
      const results = await Promise.allSettled(starts.map(page));
      for (const result of results) {
        if (result.status === 'fulfilled') items.push(...result.value.items);
        else partial = true;
      }
    }
    return {items, partial};
  }
  return async period => {
    if (saved?.day === period.end && saved.expires > Date.now()) return saved.feed;
    if (pending?.day === period.end) return pending.request;
    const request = Promise.allSettled([fetchYear(period),readBleepingComputer(fetcher)]).then(results=>{
      const feeds=results.filter(r=>r.status==='fulfilled').map(r=>r.value);
      if(!feeds.length)throw Error('보안 보도를 불러오지 못했어요.');
      return {items:feeds.flatMap(f=>f.items),partial:feeds.length!==results.length || feeds.some(f=>f.partial)};
    }).then(feed => {
      saved = {day:period.end, expires:Date.now() + (feed.partial ? 1 : 15)*60000, feed};
      return feed;
    }).catch(error => {
      if (saved) return {...saved.feed, partial:true};
      throw error;
    }).finally(() => { if (pending?.request === request) pending = undefined; });
    pending = {day:period.end,request};
    return request;
  };
}

// Use a shared CVE first. Without one, require close dates and distinctive headline evidence.
const stopWords=new Set('a an the in of to for by with on as from and or at after over into could can allow allows including that new more hackers hacker attack attacks flaw flaws bug bugs security critical issue issues vulnerability vulnerabilities users researchers report reports warning warns reveals found using via targets hits affected'.split(' '));
function headlineTerms(title){
  const normal=title.toLowerCase().replace(/remote code execution/g,'rce').replace(/data (?:leak|breach)/g,'breach')
    .replace(/\b(?:fix(?:es|ed)?|patch(?:es|ed)?|updates?)\b/g,'patch').replace(/cve-\d{4}-\d+/g,'');
  return new Set((normal.match(/[a-z][a-z0-9]+/g)||[]).filter(w=>!stopWords.has(w)));
}
const genericTerms=new Set('patch rce code execution remote breach breaches leak data leaked exposes exposed million billion accounts customers records stolen steals reports files campaign malware ransomware phishing package service attack network victims credentials targeted targets group companies company update reveals confirmed warns says advisory compromised compromise cloud impact access unauthorized'.split(' '));
function similar(a,b){
  if(a.cves.length && b.cves.length && !a.cves.some(id=>b.cves.includes(id)))return false;
  if(a.name.toLowerCase()===b.name.toLowerCase())return true;
  // Syndicated descriptions may match even when editors rewrite the headlines.
  if(a.summary.size>=9 && b.summary.size>=9){
    const common=[...a.summary].filter(w=>b.summary.has(w));
    if(common.length>=9 && common.length/(a.summary.size+b.summary.size-common.length)>=0.65 &&
       common.some(w=>!genericTerms.has(w)&&(a.terms.has(w)||b.terms.has(w))))return true;
  }
  const left=a.terms,right=b.terms;
  const common=[...left].filter(w=>right.has(w));
  if(common.length<3 || !common.some(w=>!genericTerms.has(w)))return false;
  return common.length/(left.size+right.size-common.length)>=0.55 ||
    (common.length>=3 && common.includes('patch') && common.includes('rce') &&
     common.some(w=>!['patch','rce','code','execution','remote'].includes(w)) &&
     common.length/Math.min(left.size,right.size)>=0.75);
}
function groupReports(advisories,reports,end){
  const groups=new Map(), recent=[];
  function add(id,record){
    if(!groups.has(id))groups.set(id,[]);
    groups.get(id).push(record);
  }
  for(const record of advisories)if(record.date<=end)add(incidentId(record.id),record);
  for(const record of reports.filter(r=>r.date<=end).sort((a,b)=>a.date.localeCompare(b.date)||a.sourceUrl.localeCompare(b.sourceUrl))){
    const candidate={name:record.name,cves:record.cves||[],terms:headlineTerms(record.name),summary:headlineTerms(record.description||''),day:Date.parse(record.date)/86400000};
    while(recent.length && recent[0].day<candidate.day-7)recent.shift();
    let id=incidentId(record.id);
    const known=/^CVE-/.test(id);
    const matches=new Set(recent.filter(r=>(!known||!r.id.startsWith('CVE-')||r.id===id) && similar(candidate,r)).map(r=>r.id));
    if(matches.size===1){
      const other=[...matches][0];
      if(!known)id=other;
      else if(other!==id){
        for(const earlier of groups.get(other))add(id,earlier);
        groups.delete(other);
        for(const entry of recent)if(entry.id===other)entry.id=id;
      }
    }
    add(id,record);
    recent.push({...candidate,id});
  }
  return groups;
}

export function mergeNews(advisories, reports, period) {
  const items=[];
  for(const [id,records] of groupReports(advisories,reports,period.end)){
    const inRange=records.filter(r=>r.date>=period.start);
    if(!inRange.length)continue;
    inRange.sort((a,b)=>b.date.localeCompare(a.date)||Number(!!b.source)-Number(!!a.source)||(b.published||'').localeCompare(a.published||'')||a.sourceUrl.localeCompare(b.sourceUrl));
    const latest=inRange[0],reference=records.find(r=>!r.source),reporting=inRange.find(r=>r.source);
    const row={...latest,id,cwes:[...new Set(records.flatMap(r=>r.cwes))],cves:[...new Set(records.flatMap(r=>r.cves||[r.id]))]};
    if(reporting){
      row.reportUrl=reporting.sourceUrl;
      row.reportTitle=reporting.name;
      if(reference)Object.assign(row,{product:reference.product,vendor:reference.vendor,action:reference.action,advisoryUrl:reference.sourceUrl});
    }
    const unique=new Map();
    for(const r of [...inRange,...(reference?[reference]:[])]){
      if(!unique.has(r.sourceUrl))unique.set(r.sourceUrl,{source:r.source||'CISA',url:r.sourceUrl,date:r.date,title:r.name,summary:r.description});
    }
    row.sources=[...unique.values()];
    items.push(row);
  }
  return items.sort((a,b)=>b.date.localeCompare(a.date)||(b.published||'').localeCompare(a.published||'')||Number(!!b.reportUrl)-Number(!!a.reportUrl)||a.id.localeCompare(b.id));
}
