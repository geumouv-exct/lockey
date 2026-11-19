import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createSecurityNews} from './security-news.mjs';

const now = () => new Date('2026-01-11T00:00:00Z');
const catalog = {
  dateReleased:'2026-01-10T12:00:00Z',
  vulnerabilities:Array.from({length:6}, (_,i) => ({
    cveID:'CVE-2025-100' + i, dateAdded:'2026-01-0' + (i+1),
    vendorProject:'Vendor', product:'Product', vulnerabilityName:'Test advisory',
    shortDescription:'Example issue', requiredAction:'Follow vendor guidance'
  }))
};
const explanation = {category:'접근 권한', headline:'권한 확인이 빠진 제품', cause:'사용자의 권한을 확인하지 않아요.', check:'사용하는 제품인지 확인하세요.'};
const url = 'http://127.0.0.1:30001/v1/systemone';

test('최신 5건을 선별하고, 잘못된 모델 응답만 다시 요청하며, 원문 변경도 반영한다', async () => {
  const feed = structuredClone(catalog);
  const requests = [];
  const fetcher = async (address, options) => {
    if (!options.method) return Response.json(feed);
    const input = JSON.parse(JSON.parse(options.body).messages[1].content);
    requests.push(input.id);
    const model = requests.length === 2 ? 'unexpected' : 'expected';
    return Response.json({model, choices:[{finish_reason:'stop',message:{content:JSON.stringify(explanation)}}]});
  };
  const load = createSecurityNews({now, url, expectedRevision:'expected', fetcher});
  const [first, concurrent] = await Promise.all([load(),load()]);
  assert.deepEqual(first, concurrent);
  assert.equal(first.modelStatus, 'incomplete');
  assert.deepEqual(first.items.map(x=>x.id), feed.vulnerabilities.slice(1).reverse().map(x=>x.cveID));
  assert.equal(first.items.filter(x=>!x.explanation).length, 1);
  assert.equal(requests.length, 5);
  const second = await load();
  assert.equal(second.modelStatus, 'completed');
  assert.equal(requests.length, 6);
  for (const item of second.items) assert.equal(new URL(item.sourceUrl).searchParams.get('id'), item.id);
  feed.vulnerabilities[5].requiredAction = 'Updated guidance';
  await load();
  assert.equal(requests.length, 7);
  assert.equal(requests.at(-1), feed.vulnerabilities[5].cveID);
});

test('모델 연결이 없으면 원문임을 표시하고 수집 실패 시 재시도할 수 있다', async () => {
  let available = false;
  const load = createSecurityNews({now, fetcher:async () => available ? Response.json(catalog) : new Response('',{status:503})});
  await assert.rejects(load, /CISA 최신 목록/);
  available = true;
  const result = await load();
  assert.equal(result.modelStatus, 'unavailable');
  assert.equal(result.items[0].description, 'Example issue');
  assert.equal(result.items[0].explanation, undefined);
});

test('전체 목록 페이지와 관련 기사 범위를 구분하고 공지 번호 또는 약점 유형이 일치한 기사를 최신순으로 표시한다', async () => {
  const feed = structuredClone(catalog);
  feed.vulnerabilities[5].cwes = ['CWE-79'];
  const load = createSecurityNews({now, fetcher:async () => Response.json(feed)});
  const all = await load();
  assert.equal(all.total,6);
  assert.equal(all.pages,2);
  const page2 = await load({page:2});
  const oldest = page2.items[0].id;
  assert.equal(oldest, feed.vulnerabilities[0].cveID);
  const related = await load({scope:'project',cwes:['CWE-79'],cves:[oldest]});
  assert.deepEqual(related.items.map(item=>item.id), [feed.vulnerabilities[5].cveID, oldest]);
  assert.equal((await load({scope:'project'})).total,0);
  assert.equal((await load({scope:'project',cwes:['CWE-89']})).total,0);
  await assert.rejects(load({page:-1}),/조회 조건/);
});

test('프로젝트 유형, 링크 경고, 의존성 공지를 연결하고 오탐은 제외한다', async () => {
  const {projectNewsContext,newsConnection} = await import('./project-news.mjs');
  const context = projectNewsContext([
    {id:'dangerous-html',path:'src/view.js',lines:[9]},
    {id:'sql-interpolation',path:'db.js',lines:[1],status:'locally_false'}
  ],[{cwe:'CWE-319',summary:'주소가 https로 시작하는지 확인하세요.'}],
  [{name:'pkg',version:'1.0',details:[{id:'GHSA-example',cves:['CVE-2025-1000']}]}]);
  assert.deepEqual([...context.types.keys()],['CWE-79','CWE-319']);
  assert.match(newsConnection({id:'CVE-2025-1000',cwes:['CWE-79']},context),/pkg 1.0/);
  assert.match(newsConnection({id:'CVE-2025-1001',cwes:['CWE-79']},context),/src\/view.js 9행/);
});

test('한국 날짜로 최근 1년의 경계일을 포함하고 관련 뉴스에서는 두 달이 지난 공지를 제외한다', async () => {
  const feed = structuredClone(catalog);
  const dates = ['2023-02-27','2023-02-28','2024-02-28','2024-02-29','2024-03-01','2024-03-02'];
  feed.vulnerabilities.forEach((entry,i) => {entry.dateAdded=dates[i]; entry.cwes=['CWE-89'];});
  const load = createSecurityNews({now:() => new Date('2024-02-28T15:01:00Z'), fetcher:async () => Response.json(feed)});
  const all = await load();
  assert.deepEqual(all.period,{start:'2023-02-28',end:'2024-02-29'});
  assert.deepEqual(all.items.map(i=>i.date),dates.slice(1,4).reverse());
  const related = await load({scope:'project',cves:[feed.vulnerabilities[0].cveID]});
  assert.deepEqual(related.items,[]);
});

test('관련 뉴스는 두 달 전 말일부터 한국의 오늘까지 추가된 공지만 최신순으로 페이지에 나눈다', async () => {
  const dates = ['2024-02-28','2024-02-29','2024-03-10','2024-04-01','2024-04-12','2024-04-19','2024-04-30','2024-05-01'];
  const vulnerabilities = dates.map((dateAdded,i) => ({...catalog.vulnerabilities[0],dateAdded,cveID:'CVE-2024-900'+i,cwes:['CWE-79']}));
  const feed = {...catalog,vulnerabilities};
  const load = createSecurityNews({now:() => new Date('2024-04-29T15:00:00Z'),fetcher:async () => Response.json(feed)});
  const query = {scope:'project',cwes:['CWE-79'],cves:[vulnerabilities[0].cveID,vulnerabilities[1].cveID]};
  const first = await load(query), second = await load({...query,page:2});
  assert.deepEqual(first.period,{start:'2024-02-29',end:'2024-04-30'});
  assert.equal(first.total,6);
  assert.deepEqual(first.items.map(item=>item.date),dates.slice(2,7).reverse());
  assert.deepEqual(second.items.map(item=>item.date),['2024-02-29']);
});

test('이슈 카드에는 3개월 이내 같은 유형의 최신 공지 하나만 표시한다', async () => {
  const feed = structuredClone(catalog);
  const dates = ['2025-08-19','2025-08-20','2025-09-10','2025-10-01','2025-11-21','2025-11-20'];
  feed.vulnerabilities.forEach((item,i) => {
    item.dateAdded = dates[i];
    item.cwes = [i === 5 ? 'CWE-89' : 'CWE-79'];
  });
  const load = createSecurityNews({now:() => new Date('2025-11-20T00:00:00Z'),fetcher:async () => Response.json(feed)});
  const result = await load({scope:'issue',cwes:['CWE-79']});
  assert.deepEqual(result.period,{start:'2025-08-20',end:'2025-11-20'});
  assert.deepEqual(result.items.map(item=>item.date),['2025-10-01']);
  assert.equal(result.pages,1);
  const only = index => load({scope:'issue',cves:[feed.vulnerabilities[index].cveID]});
  assert.equal((await only(0)).items.length,0);
  assert.equal((await only(1)).items.length,1);
  assert.equal((await load({scope:'issue',cwes:['CWE-404']})).items.length,0);
});

test('직접 입력한 검색어로 연간 목록을 판정하고 근거가 있는 기사만 최신순으로 페이지에 넣는다', async () => {
  const feed = structuredClone(catalog);
  feed.vulnerabilities = Array.from({length:9}, (_,i) => ({
    ...catalog.vulnerabilities[0], dateAdded:i === 8 ? '2024-01-01' : '2026-01-0' + (i+1),
    cveID:'CVE-2025-900' + i, vulnerabilityName:i < 6 ? 'Missing login check ' + i : 'File permission error ' + i,
    shortDescription:i === 6 ? 'Login is mentioned only in passing.' : 'An issue in a web product.'
  }));
  const keyword = '로그인 없이 들어갈 수 있는 문제';
  const decisions = [];
  const reply = content => Response.json({model:'expected',choices:[{message:{content:JSON.stringify(content)}}]});
  const fetcher = async (address, options) => {
    if (!options.method) return Response.json(feed);
    const input = JSON.parse(JSON.parse(options.body).messages[1].content);
    if (!input.articles) return reply(explanation);
    decisions.push(input);
    const matches = input.articles.filter(a=>a.title.startsWith('Missing')).map(a=>({n:a.n,quote:'Missing login check'}));
    matches.push({n:1,quote:'invented source text'});
    return reply({matches});
  };
  const load = createSecurityNews({now,url,expectedRevision:'expected',fetcher});
  const first = await load({keyword:'  ' + keyword + '  '});
  assert.equal(first.total,6);
  assert.equal(first.items[0].id,'CVE-2025-9005');
  assert.deepEqual((await load({keyword,page:2})).items.map(item=>item.id),['CVE-2025-9000']);
  assert.equal(decisions.length,1);
  assert.equal(decisions[0].keyword,keyword);
  assert.equal(decisions[0].articles.length,8);
  feed.vulnerabilities[0].vulnerabilityName='File access issue';
  assert.equal((await load({keyword})).total,5);
  assert.equal((await load({keyword:'  '})).total,8);
  await assert.rejects(load({scope:'project',keyword}));
  await assert.rejects(load({keyword:'a'.repeat(121)}));
});

test('검색 판정에 실패하면 결과를 섞지 않고 다시 검색할 수 있다', async () => {
  let model='unexpected';
  const fetcher = async (address, options) => !options.method ? Response.json(catalog) :
    Response.json({model,choices:[{message:{content:'{"matches":[]}'}}]});
  const load = createSecurityNews({now,url,expectedRevision:'expected',fetcher});
  await assert.rejects(load({keyword:'비밀키 유출'}),/검색을 마치지/);
  model='expected';
  assert.equal((await load({keyword:'비밀키 유출'})).total,0);
  await assert.rejects(createSecurityNews({now,fetcher})({keyword:'비밀키 유출'}),/연결/);
});

test('선택 기간의 양 끝을 포함하고 모델에는 해당 공지만 전달한다', async () => {
  let articles;
  const fetcher = async (address,options) => {
    if (!options.method) return Response.json(catalog);
    articles = JSON.parse(JSON.parse(options.body).messages[1].content).articles;
    return Response.json({model:'expected',choices:[{message:{content:'{"matches":[]}'}}]});
  };
  const load = createSecurityNews({now,url,expectedRevision:'expected',fetcher});
  const dates = {startDate:'2026-01-02',endDate:'2026-01-04'};
  const plain = createSecurityNews({now,fetcher:async () => Response.json(catalog)});
  const result = await plain(dates);
  assert.deepEqual(result.items.map(item=>item.date),['2026-01-04','2026-01-03','2026-01-02']);
  assert.equal((await plain({...dates,endDate:dates.startDate})).total,1);
  assert.deepEqual((await load({...dates,keyword:'로그인'})).period,{start:dates.startDate,end:dates.endDate});
  assert.deepEqual(articles.map(item=>item.id),result.items.map(item=>item.id));
  for (const invalid of [{startDate:'2025-02-29'}, {endDate:'2026-01-01'}, {startDate:'2024-01-01'}, {endDate:'2026-01-12'}, {scope:'project'}, {scope:'issue'}]) {
    await assert.rejects(plain({...dates,...invalid}),/시작일과 종료일/);
  }
});

test('후속 보도와 CISA 공지를 합치고, 대표 뉴스는 관련 이슈 한 건만 고른다', async () => {
  const article = (slug, day, title, description) => ({title:{$t:title},summary:{$t:description},published:{$t:day+'T12:00:00Z'},
    link:[{rel:'alternate',href:'http://thehackernews.com/2026/01/'+slug+'.html'}]});
  const media = [
    article('first','2026-01-07','Java issue CVE-2025-1000','Cross-site scripting in a Java application.'),
    article('second','2026-01-08','Java patch CVE-2025-1000','An update for the affected Java application.'),
    article('third','2026-01-09','PHP issue CVE-2025-9999','Cross-site scripting in a PHP product.'),
    article('roundup','2026-01-10','Weekly roundup','CVE-2025-1000 and CVE-2025-9999 in different products.'),
    article('future','2026-01-12','Another update CVE-2025-1000','Future story.'),
  ];
  const fetcher = async url => String(url).includes('thehackernews.com') ?
    Response.json({feed:{openSearch$totalResults:{$t:String(media.length)},entry:media}}) : Response.json(catalog);
  const load = createSecurityNews({now,fetcher});
  const all = await load();
  assert.equal(all.total,7);
  assert.deepEqual(all.items.slice(0,2).map(i=>i.id),['CVE-2025-9999','CVE-2025-1000']);
  const issue = await load({scope:'issue',cwes:['CWE-79'],cves:['CVE-2025-1000']});
  assert.equal(issue.total,1);
  assert.match(issue.items[0].sourceUrl,/second\.html$/);
  assert.equal(issue.items[0].advisoryUrl,'https://www.cve.org/CVERecord?id=CVE-2025-1000');
  assert.equal((await load({scope:'issue',cwes:['CWE-79']})).items[0].id,'CVE-2025-9999');
  assert.equal((await load({scope:'project',cwes:['CWE-79']})).total,0);
  assert.equal((await load({startDate:'2026-01-07',endDate:'2026-01-07'})).items[0].date,'2026-01-07');
});

test('프로젝트 점검 프롬프트에는 선택한 뉴스의 근거만 담는다',async()=>{
  const {newsAssessmentPrompt}=await import('./project-news.mjs');
  const item={id:'CVE-2026-114938',cves:['CVE-2026-114938'],name:'Java4Shell',product:'Java',
    explanation:{headline:'일부 Java 서버의 메모리 처리 문제'},sourceUrl:'https://example.com/report',advisoryUrl:'https://example.com/advisory'};
  const prompt=newsAssessmentPrompt(item);
  for(const fact of [item.explanation.headline,item.product,item.sourceUrl,item.advisoryUrl,'판단 보류'])assert.ok(prompt.includes(fact));
  assert.equal(prompt.split(item.id).length,2);
  assert.doesNotMatch(prompt,/PHP/);
});

test('CVE 없는 같은 사건은 한 번 요약하고 두 매체의 근거를 모델에 전달한다',async()=>{
  const title='Acme Vault incident exposes customer records';
  const description='Acme notified affected customers.';
  const article={title:{$t:title},summary:{$t:description},published:{$t:'2026-01-08T12:00:00Z'},link:[{rel:'alternate',href:'https://thehackernews.com/2026/01/acme-vault.html'}]};
  const bc=(slug,name,section='security')=>'<item><title>'+name+'</title><description><![CDATA[The provider revoked affected access keys.]]></description><pubDate>Fri, 09 Jan 2026 10:00:00 GMT</pubDate><link>https://www.bleepingcomputer.com/news/'+section+'/'+slug+'/</link></item>';
  const xml='<rss><channel>'+bc('acme-notice',title)+bc('bravo-notice','Bravo Hub incident exposes customer records')+bc('offer','Weekly deals','deals')+'</channel></rss>';
  const inputs=[];
  const fetcher=async(address,options)=>{
    if(options.method){
      inputs.push(JSON.parse(JSON.parse(options.body).messages[1].content));
      return Response.json({model:'expected',choices:[{message:{content:JSON.stringify(explanation)}}]});
    }
    if(String(address).includes('bleepingcomputer.com'))return new Response(xml);
    if(String(address).includes('thehackernews.com'))return Response.json({feed:{openSearch$totalResults:{$t:'1'},entry:[article]}});
    return new Response('',{status:503});
  };
  const load=createSecurityNews({now,url,expectedRevision:'expected',fetcher});
  const result=await load();assert.equal(result.total,2);assert.equal(inputs.length,2);
  const row=result.items.find(r=>r.name===title);assert.deepEqual(row.cves,[]);assert.equal(row.sources.length,2);
  assert.equal(inputs.find(i=>i.id===row.id).evidence.length,2);
  assert.ok(!result.items.some(r=>r.name==='Weekly deals'));
  const old=await load({startDate:'2026-01-08',endDate:'2026-01-08'});
  assert.equal(old.items[0].sources.length,1);assert.equal(old.items[0].date,'2026-01-08');
  const {newsAssessmentPrompt}=await import('./project-news.mjs');assert.ok(!newsAssessmentPrompt(row).includes(row.id));
});
