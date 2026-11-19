import {surveyTopics,needsDetail,detailOptions} from './service-survey.mjs';
import {newsPresets} from './news-period.mjs';
import {applyLocalRepairs,planLocalRepairs,readRepairFolder} from './local-repair.mjs';
import {projectNewsContext, newsConnection, newsAssessmentPrompt} from './project-news.mjs';
import {classification} from './classifications.mjs';
import {recheckStatus} from './recheck-status.mjs';
import {selectPromptItems,combinePromptItems} from './prompt-bundle.mjs';
import {startGimbal} from './gimbal.mjs';
import {bindSwipeNavigation} from './swipe-navigation.mjs';
import {codeDiff} from './code-diff.mjs';
import {codeViewerEntries} from './code-viewer-selection.mjs';
import {groupFindings, representativeFinding} from './finding-groups.mjs';
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let result=null, filter='all',view='overview';
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stateText={review_code:'코드 흐름 추가 검토',verify_access:'접근 권한 검증',defer:'수동 검토로 보류'};
const dialog=(title,body)=>{$('#modal-content').innerHTML=`<div class="dialog-body"><span class="dialog-tag">TRACE SECURITY</span><h2>${escape(title)}</h2>${body}</div>`;$('#modal').showModal()};
function modelUI(model){const configured=model?.status==='connected';$('#model-state').textContent=configured?'응답 수신':model?.status==='error'?'연결 오류':'연결 필요';$('#model-title').textContent=configured?`다음 단계 제안: ${stateText[model.choice]||model.choice}`:'Zoro-1 연결이 필요합니다';$('#model-description').textContent=configured?`서버 응답: ${Object.entries(model.probabilities).map(([key,value])=>`${stateText[key]||key} ${Math.round(value*100)}%`).join(' · ')}. ${model.model_verified?'설정한 모델 리비전과 서버 응답이 일치합니다.':'모델 신원은 별도 확인이 필요합니다.'}`:model?.message||'로컬 또는 Brev 포워딩 서버를 연결해 주세요.';}
function allItems(){if(!result)return [];let items=[...result.findings];if(result.dynamic&&result.dynamic.status!=='skipped')items.push({key:'dynamic',id:'idor',category:'접근 제어',title:'다른 사용자의 주문을 조회할 수 있어요',path:'로컬 가상 API',lines:[],why:'테스트 사용자 B가 사용자 A의 주문 식별자를 응답받았습니다.',fix:'서버가 각 요청에서 리소스 소유자와 요청자 권한을 검증하도록 수정하세요.',reference:'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',status:result.dynamic.status,owasp:'A01'});return items}
function issueWindowBar(title) {
 return `<header class="news-bar issue-window-bar"><span class="window-lights news-lights" aria-hidden="true"><i></i><i></i><i></i></span><span>${escape(title)}</span></header>`;
}
function issueCard(f,group) {
 const meta = classification(f);
 const status = {flow_verified:'흐름 확인', confirmed:'검증됨', locally_false:'해당 위치 오탐', inconclusive:'판단 보류'}[f.status] || '';
 const key = escape(f.key);
 const type = meta.cwe === '미확인' ? 'CWE 미확인' : meta.cwe;
 return `<article class="issue issue-card news-window">
   ${issueWindowBar(type)}
   <div class="finding-copy">
     <div class="finding-line"><span class="finding-label">약점 유형</span>
       <div class="finding-type">${escape(meta.cweName)}</div></div>
     <div class="finding-line"><span class="finding-label">한줄 분석</span>
       <h4 class="finding-summary">${escape(meta.summary || f.title)}</h4></div>
     ${group.findings.length>1?`<p class="finding-meta">발견 위치 ${group.findings.reduce((count,item)=>count+(item.lines?.length||1),0)}개 · 코드 비교에서 확인</p>`:`<p class="finding-meta"><span>${escape(f.path)}${f.lines?.length ? ' : '+escape(f.lines.join(', ')) : ''}</span></p>`}
     ${status ? `<span class="issue-status">${status}</span>` : ''}
     <div class="issue-actions">
       <button type="button" data-inspect-issue="${key}">코드 비교</button>
       ${groupFindings(allItems()).length>1?`<button type="button" data-issue-prompt="${key}">AI 수정 요청</button>`:''}
     </div>
   </div>
   ${issueNewsSlot(meta.cwe,group.findings)}
 </article>`;
}
function issueNewsSlot(cwe, findings) {
 const candidates = findings.filter(f => f.status !== 'locally_false');
 const cves = [...new Set(candidates.flatMap(f => [f.cve, f.id, ...(f.cves || []), ...(f.advisory?.cves || [])])
   .filter(id => /^CVE-\d{4}-\d{4,19}$/.test(id)))].sort();
 const type = candidates.length && /^CWE-\d+$/.test(cwe) ? cwe : '';
 return `<aside class="finding-rating" aria-label="관련 대표 뉴스"><strong>관련 대표 뉴스</strong>
   <div data-issue-news="${type}" data-cves="${cves.join(' ')}">최근 3개월의 관련 뉴스를 찾고 있어요.</div></aside>`;
}
function newsDateline(item) {
 return (item.source ? item.source+' 보도 ' : 'CISA 목록 추가 ') + item.date;
}
// Filters can redraw the same card while a summary is being generated.
const issueNewsRequests = new Map();
async function renderIssueNews(slot) {
  const cwe = slot.dataset.issueNews;
  const cves = slot.dataset.cves.split(' ').filter(Boolean);
  const key = JSON.stringify([cwe,cves]);
  if (!cwe && !cves.length) {
    slot.textContent = '이 항목과 연결할 뉴스가 없어요.';
    return;
  }
  let cached = issueNewsRequests.get(key);
  if (!cached || Date.now() >= cached.expires) {
    cached = {expires:Date.now() + 5 * 60_000, request:postJson('/api/security-news', {scope:'issue', cwes:cwe ? [cwe] : [], cves})};
    issueNewsRequests.set(key, cached);
  }
  try {
    const data = await cached.request;
    if (!slot.isConnected) return;
    const item = data.items[0];
    if (!item) {
      slot.textContent = data.sourceNotice || '최근 3개월 동안 이 이슈와 연결되는 뉴스가 없어요.';
      return;
    }
    const link = document.createElement('a');
    link.href = item.sourceUrl;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = item.explanation?.headline || item.guide?.headline || item.name;
    const date = document.createElement('small');
    date.textContent = [newsDateline(item),...(item.cves || [])].join(' · ');
    slot.replaceChildren(link, date);
  } catch {
    if (issueNewsRequests.get(key) === cached) issueNewsRequests.delete(key);
    slot.textContent = '관련 뉴스를 불러오지 못했어요. ';
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'text-btn';
    retry.textContent = '다시 시도';
    retry.onclick = () => { retry.disabled = true; renderIssueNews(slot); };
    slot.append(retry);
  }
}
function renderIssues(){
 const items=allItems().filter(x=>filter==='all'||(filter==='dynamic'?x.key==='dynamic':x.owasp===filter));
 const groups=groupFindings(items);
 const cards=groups.map(group=>issueCard(representativeFinding(group),group));
 if(view==='issues' && !$('#link-results').hidden && currentLinkData) cards.push(...currentLinkData.issues.map(linkIssueCard));
 $('#issue-list').innerHTML=cards.length?cards.join(''):`<div class="empty"><span>⌕</span><strong>${result?'표시할 항목이 없습니다':'아직 분석 결과가 없습니다'}</strong><p>${result?'다른 필터를 선택해 보세요.':'샘플 검사를 시작하면 결과가 여기에 표시됩니다.'}</p></div>`;
 bindLinkCode($('#issue-list'));
 $$('#issue-list [data-issue-news]').forEach(renderIssueNews);
 $$('[data-inspect-issue]').forEach(button=>button.addEventListener('click',()=>openCodeViewer(button.dataset.inspectIssue)));
 $$('[data-issue-prompt]').forEach(button=>button.addEventListener('click',()=>{
  setView('overview');
  openPromptPage(true,{type:'code',key:button.dataset.issuePrompt});
 }));
}

function openCodeViewer(key){
 const captured=result, selection=lastScanSelection;
 const entries=codeViewerEntries(allItems(),key,lastScanSnapshot);
 let index=entries.findIndex(e=>e.f.key===key), generation=0;
 if(index<0){dialog('코드 위치 확인 불가','<p>업로드한 코드와 연결된 위치를 확인하지 못했습니다.</p>');return}
 const modal=$('#modal');
 $('#modal-content').innerHTML=`<div class="code-viewer" aria-label="취약점 코드 비교"><div class="code-viewer-window"><div class="code-viewer-title"><span class="window-lights"><button type="button" class="code-viewer-close" aria-label="코드 비교 닫기" title="닫기"></button><i aria-hidden="true"></i><i aria-hidden="true"></i></span><strong data-viewer-file></strong><span data-viewer-count></span></div><div class="code-viewer-stage"><button type="button" class="code-viewer-arrow prev" aria-label="이전 취약점">‹</button><div class="code-viewer-panes"><section><h3>수정 전 · 발견한 코드</h3><pre data-viewer-before></pre></section><section><div class="viewer-after-heading"><h3>수정 후 · 검토 제안</h3><button type="button" class="viewer-refresh" aria-label="수정 코드 다시 검토" title="수정 코드 다시 검토">↻</button></div><pre data-viewer-after></pre></section></div><button type="button" class="code-viewer-arrow next" aria-label="다음 취약점">›</button></div></div><p class="code-viewer-note" aria-live="polite"></p><div data-viewer-repair></div></div>`;
 modal.classList.add('code-viewer-modal');modal.addEventListener('close',()=>modal.classList.remove('code-viewer-modal'),{once:true});modal.showModal();
 modal.querySelector('.code-viewer-close').onclick=()=>modal.close();
 const root=modal.querySelector('.code-viewer'),before=root.querySelector('[data-viewer-before]'),after=root.querySelector('[data-viewer-after]'),note=root.querySelector('.code-viewer-note'),prev=root.querySelector('.prev'),next=root.querySelector('.next'),refresh=root.querySelector('.viewer-refresh');
 const repairBox=root.querySelector('[data-viewer-repair]');

 async function render(force=false){
  const version=++generation,{f,line}=entries[index],file=selection===projectFiles?lastScanSnapshot.find(x=>x.path===f.path):null;
  if(repairBox.dataset.finding!==f.key){
   repairBox.replaceChildren();
   repairBox.dataset.finding=f.key;
   attachAiRepair(f,repairBox);
  }
  const sensitive=/private-key|hardcoded-credential|public-secret|service-role/.test(f.id),secret=/(?:password|secret|token|api[_-]?key|private[_-]?key|bearer|ghp_|sk-proj)/i;
  const text=file?.text.split(/\r?\n/)[line-1];root.querySelector('[data-viewer-file]').textContent=f.path.split('/').pop();root.querySelector('[data-viewer-file]').title=f.path;root.querySelector('[data-viewer-count]').textContent=`${index+1} / ${entries.length}`;
  before.textContent=typeof text==='string'?`${line}  ${sensitive||secret.test(text)?'[민감정보가 포함될 수 있어 숨김]':text}`:'검사한 원본 코드를 확인할 수 없습니다.';
  after.textContent='Zoro-1이 수정 방향을 검토하는 중…';refresh.disabled=true;note.textContent='Zoro-1의 검토 선택에 따라 규칙 기반으로 만든 제안입니다. 프로젝트에 적용되지 않았으며 실제 동작 검증이 필요합니다.';prev.disabled=index===0;next.disabled=index===entries.length-1;
  const viewerKey=codeKey(f)+'|'+line;let review=force?null:reviewedFindings.get(viewerKey)?.review;let item=force?null:review?.items?.find(x=>x.id===f.id&&x.path===f.path&&x.line===line)||captured?.review?.items?.find(x=>x.id===f.id&&x.path===f.path&&x.line===line);
  if(!item&&!review&&file&&captured?.baselineToken){try{const data=await postJson('/api/review-finding',{token:captured.baselineToken,path:f.path,id:f.id,lines:f.lines,line});reviewedFindings.set(viewerKey,data);review=data.review;item=review?.items?.find(x=>x.id===f.id&&x.path===f.path&&x.line===line)}catch(e){if(version===generation)note.textContent='수정 코드 검토 실패: '+e.message}}
  if(version!==generation||result!==captured||!modal.open)return;
  refresh.disabled=false;
  if(item&&!sensitive&&!secret.test(item.after)&&typeof text==='string'&&!secret.test(text)){const diff=codeDiff(text,item.after);showDiff(before,diff.before,'diff-removed',line);showDiff(after,diff.after,'diff-added',item.line)}else after.textContent='이 위치에 대해 확인된 수정 코드가 없습니다. AI 수정 요청에서 수정 방향을 확인해 주세요.';
 }
 const move=delta=>{const n=Math.max(0,Math.min(entries.length-1,index+delta));if(n!==index){index=n;render()}};
 prev.onclick=()=>move(-1);next.onclick=()=>move(1);refresh.onclick=()=>render(true);
 bindSwipeNavigation(root.querySelector('.code-viewer-window'),move);
 render();
}

const reviewedFindings=new Map();
function codeKey(f){return JSON.stringify([result?.baselineToken,f.path,f.id,f.lines])}
function showDiff(element,segments,kind,lineNo){
 element.replaceChildren();
 if(lineNo!==undefined)element.append(document.createTextNode(`${lineNo}  `));
 for(const segment of segments){
  const node=document.createElement(segment.changed?'mark':'span');
  if(segment.changed)node.className=kind;
  node.textContent=segment.text;
  element.append(node);
 }
}
function attachAiRepair(f,box){
 if(result?.kind!=='project')return;
 const button=document.createElement('button');button.type='button';button.className='outline';
 button.textContent='Zoro-1으로 직접 수정';
 const reason=localBlockReason([f],result);button.disabled=!!reason;button.title=reason;
 button.onclick=()=>{$('#modal').close();openLocalRepair([f])};
 box.append(button);
}

async function postJson(url,input){
 const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});
 if (!res.headers.get('Content-Type')?.includes('application/json')) {
   throw Error(res.status === 524 || res.status === 504 ? '서버 응답 시간이 길어졌어요. 잠시 후 다시 시도해 주세요.' : '서버 응답을 확인할 수 없어요. 잠시 후 다시 시도해 주세요.');
 }
 const data=await res.json();
 if(!res.ok)throw Error(data.error||'요청을 완료하지 못했습니다.');
 return data;
}


const isTestFile=path=>/(?:^|\/)(?:tests?|__tests__)\/.*\.[cm]?js$|\.(?:test|spec)\.[cm]?js$|(?:^|\/)test_[^/]+\.py$|(?:^|\/)[^/]+_test\.py$/i.test(path);
function setFilter(value){filter=value;$$('.filter').forEach(b=>b.classList.toggle('selected',b.dataset.filter===filter));renderIssues();if(view!=='overview'&&view!=='issues')setView('issues')}
let newsRequest = 0, newsPage = 1, projectNews = false, newsKeyword = '';
let newsDates = null;

const presetButtons = $$('[data-news-preset]');
function markNewsPreset(presets) {
  const start = $('#news-start').value, end = $('#news-end').value;
  for (const button of presetButtons) {
    const period = presets[button.dataset.newsPreset];
    button.setAttribute('aria-pressed', String(period.start === start && period.end === end));
  }
}

function showNewsDates(preset) {
  const presets = newsPresets(new Date());
  const bounds = presets.year;
  const from = $('#news-start'), to = $('#news-end');
  if (newsDates && newsDates.startDate < bounds.start) newsDates = null;
  from.min = to.min = bounds.start;
  from.max = to.max = bounds.end;
  from.value = preset ? presets[preset].start : newsDates?.startDate || bounds.start;
  to.value = preset ? presets[preset].end : newsDates?.endDate || bounds.end;
  markNewsPreset(presets);
  to.setCustomValidity('');
  $('#news-clear').hidden = !newsDates && !newsKeyword;
}

function openNewsAssessment(item) {
 const opener=document.activeElement,modal=$('#modal');
 $('#modal-content').replaceChildren($('#news-prompt-window').content.cloneNode(true));
 modal.classList.add('window-modal');
 modal.setAttribute('aria-labelledby','news-prompt-title');
 const field=modal.querySelector('.news-prompt-field');
 modal.querySelector('.window-close').onclick=()=>modal.close();
 modal.querySelector('.news-prompt-topic').textContent=item.explanation?.headline || item.guide?.headline || item.name;
 field.value=newsAssessmentPrompt(item);
 modal.querySelector('.news-prompt-actions button').onclick=async()=>{
  const status=modal.querySelector('.news-prompt-actions [role="status"]');
  try{await navigator.clipboard.writeText(field.value);status.textContent='복사했어요.'}
  catch{field.focus();field.select();status.textContent='선택한 프롬프트를 복사해 주세요.'}
 };
 modal.addEventListener('close',()=>{
  modal.classList.remove('window-modal');
  modal.removeAttribute('aria-labelledby');
  if(opener?.isConnected)opener.focus();
 },{once:true});
 modal.showModal();
}

function newsCard(item, open, context) {
  const card = $('#news-card').content.firstElementChild.cloneNode(true);
  const explanation = item.explanation || item.guide;
  card.dataset.id = item.id;
  card.open = open;
  card.querySelector('.news-category').textContent = explanation?.category || (item.source || 'CISA 공지');
  card.querySelector('.news-headline').textContent = explanation?.headline || item.name;
  if (!context && item.date) {
    const date = card.querySelector('.news-headline-date');
    date.dateTime = item.date;
    date.textContent = item.date;
    date.title = newsDateline(item);
    date.hidden = false;
  }
  card.querySelector('.news-cause').textContent = explanation?.cause || item.description;
  card.querySelector('.news-check p').textContent = explanation?.check || item.action;
  if (context) {
    const note = card.querySelector('.news-connection');
    note.textContent = newsConnection(item, context);
    note.hidden = !note.textContent;
  }
  const sources=item.sources || [];
  const cves=item.cves || [item.id];
  card.querySelector('.news-meta').textContent=[...cves,newsDateline(item),item.guide?'원문 읽기 안내':sources.length>1?'Zoro-1 종합 요약':'Zoro-1 요약'].join(' · ');
  if(sources.length>1 || !cves.length)card.querySelector('.news-cause-label').textContent='핵심 내용';
  const original = card.querySelector('a');
  original.href = item.sourceUrl;
  const links=new Map(sources.map(s=>[s.url,s]));
  if(item.reportUrl&&!links.has(item.reportUrl))links.set(item.reportUrl,{source:'보도'});
  if(item.advisoryUrl&&!links.has(item.advisoryUrl))links.set(item.advisoryUrl,{source:'공식 공지'});
  if(sources.length>1){
    const references=document.createElement('details');
    references.className='news-sources';
    const toggle=document.createElement('summary');
    toggle.textContent='출처 '+links.size+'건';
    references.append(toggle);
    for(const [href,source] of links){
      const link=original.cloneNode(false);
      link.href=href;
      link.textContent=[source.source,source.date,source.title].filter(Boolean).join(' · ');
      references.append(link);
    }
    original.replaceWith(references);
  }else{
    for(const [href,source] of links){
      if(href===item.sourceUrl)continue;
      const link=original.cloneNode(false);
      link.href=href;link.textContent=source.source+' ↗';
      original.parentElement.append(link);
    }
  }
  if (context) return card;
  const shell=document.createElement('article');
  shell.className='news-card-shell';
  shell.dataset.id=item.id;
  const prompt=document.createElement('button');
  prompt.type='button';
  prompt.className='news-assess';
  prompt.title='내 프로젝트 점검 프롬프트 만들기';
  prompt.setAttribute('aria-label', (explanation?.headline || item.name)+' 프로젝트 점검 프롬프트 만들기');
  prompt.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4H5v13h3v4l5-4h6v-4"/><path d="m17.5 2 1.2 3.3L22 6.5l-3.3 1.2-1.2 3.3-1.2-3.3L13 6.5l3.3-1.2Z"/></svg>';
  prompt.onclick=()=>openNewsAssessment(item);
  shell.append(card,prompt);
  return shell;
}

async function loadSecurityNews(page = 1, reset = false) {
  const sequence = ++newsRequest;
  const related = projectNews;
  const keyword = related ? '' : newsKeyword;
  const list = $('#news-list'), status = $('#news-status'), pager = $('#news-pager');
  if (reset) {
    list.replaceChildren();
    pager.hidden = true;
    newsPage = 1;
  }
  $('#news-refresh').disabled = $('#news-prev').disabled = $('#news-next').disabled = true;
  list.setAttribute('aria-busy','true');
  status.textContent = keyword ? 'Zoro-1 Arena가 선택한 기간의 뉴스에서 ‘' + keyword + '’을 다룬 기사를 찾고 있어요…' : '기사와 공지를 확인하고 쉬운 말로 요약하고 있어요…';
  try {
    let context;
    if (related) {
      if (result?.kind === 'project') await lastAuditPromise;
      if (sequence !== newsRequest) return;
      context = projectNewsContext(result?.kind === 'project' ? result.findings : [], currentLinkData?.issues || [],
        result?.kind === 'project' ? lastAuditState.data?.packages || [] : []);
      if (!context.types.size && !context.advisories.size) {
        status.textContent = '이번 분석에서 공지와 연결할 수 있는 보안 항목이 없어요. 전체 기사는 메뉴의 보안 뉴스에서 볼 수 있어요.';
        return;
      }
    }
    const query = context ? {scope:'project', cwes:[...context.types.keys()], cves:[...context.advisories.keys()], page} : {scope:'all', page, keyword, ...newsDates};
    if (!related) query.asyncSearch = true;
    let data = await postJson('/api/security-news', query);
    while (data.searchId && sequence === newsRequest) {
      data = await postJson('/api/security-news', {searchId:data.searchId});
    }
    if (sequence !== newsRequest) return;
    const open = new Map([...list.children].map(card => [card.dataset.id, (card.querySelector('details') || card).open]));
    list.replaceChildren(...data.items.map((item,i) => newsCard(item, open.get(item.id) ?? (i === 0), context)));
    status.textContent = data.total ? (keyword ? '‘' + keyword + '’ 검색 결과 ' : related ? '최근 2개월 관련 공지 ' : '최신 보안 이슈 ') + data.total.toLocaleString('ko-KR') + '건' + (data.period ? ' · ' + data.period.start + ' ~ ' + data.period.end : '') + (related && data.released ? ' · CISA 목록 갱신 ' + data.released.slice(0,10) : '') + (data.modelMessage ? ' · ' + data.modelMessage : '')
      : (keyword ? '선택한 기간에 ‘' + keyword + '’을 주로 다룬 뉴스를 찾지 못했어요.' : related ? '최근 2개월 동안 CISA 목록에 추가된 공지 중 이번 분석과 관련된 기사가 없어요.' : '선택한 기간에 표시할 보안 뉴스가 없어요.');
    if (data.sourceNotice) status.textContent += ' · ' + data.sourceNotice;
    newsPage = data.page;
    pager.hidden = data.pages <= 1;
    pager.dataset.pages = data.pages;
    $('#news-page-count').textContent = data.page + ' / ' + data.pages;
  } catch (error) {
    if (sequence === newsRequest) status.textContent = (list.childElementCount ? '이전 목록을 표시합니다. ' : '') + error.message;
  } finally {
    if (sequence === newsRequest) {
      list.removeAttribute('aria-busy');
      $('#news-refresh').disabled = false;
      $('#news-prev').disabled = newsPage <= 1;
      $('#news-next').disabled = newsPage >= Number(pager.dataset.pages || 0);
    }
  }
}
function validateNewsDates() {
  const to = $('#news-end');
  to.setCustomValidity(to.value && $('#news-start').value > to.value ? '종료일은 시작일과 같거나 늦어야 해요.' : '');
}
$('#news-start').oninput = $('#news-end').oninput = () => {
  validateNewsDates();
  markNewsPreset(newsPresets(new Date()));
};
for (const button of presetButtons) {
  button.onclick = () => {
    showNewsDates(button.dataset.newsPreset);
    $('#news-search').requestSubmit();
  };
}
$('#news-search').onsubmit = event => {
  event.preventDefault();
  validateNewsDates();
  if (!$('#news-search').reportValidity()) return;
  const from = $('#news-start'), to = $('#news-end');
  newsDates = from.value === from.min && to.value === to.max ? null : {startDate:from.value, endDate:to.value};
  newsKeyword = $('#news-keyword').value.trim();
  $('#news-clear').hidden = !newsKeyword && !newsDates;
  loadSecurityNews(1, true);
};
$('#news-clear').onclick = () => {
  newsDates = null;
  showNewsDates();
  $('#news-keyword').value = '';
  $('#news-search').requestSubmit();
  $('#news-keyword').focus();
};
$('#news-refresh').onclick = () => loadSecurityNews(newsPage);
$('#news-prev').onclick = () => loadSecurityNews(newsPage - 1);
$('#news-next').onclick = () => loadSecurityNews(newsPage + 1);
$('#news-back').onclick = () => { setView('overview'); setProjectStep('analysis'); $('.nav[data-view="overview"]').focus(); };

function setView(v, relatedNews = false){
  ++newsRequest;
  if (v === 'news') {
    projectNews = relatedNews;
    $('#news-title').textContent = relatedNews ? '내 프로젝트 관련 보안 뉴스' : '전체 보안 뉴스';
    $('#news-description').textContent = relatedNews
      ? '최근 2개월 동안 CISA 목록에 추가된 공지에서 내 프로젝트와 관련된 사례를 최신순으로 보여줘요. 같은 유형이어도 영향을 받는 제품은 다를 수 있어요.'
      : '최신 이슈 10건을 보여줘요. 검색하면 최근 1년의 보안 보도와 CISA 공지에서 찾을 수 있어요.';
    $('#news-back').hidden = !relatedNews;
    $('#news-search').hidden = relatedNews;
    if (!relatedNews) { showNewsDates(); $('#news-keyword').value = newsKeyword; }
    loadSecurityNews(1, true);
  }
  const wasIssues = view === 'issues';
  view = v;
  document.body.dataset.view = v;
  $$('.nav').forEach(button => button.classList.toggle('active',button.dataset.view === v));
  const titles = {overview:['프로젝트 보안 현황','최근 분석 결과를 한눈에 확인하세요.'],issues:['보안 이슈','실제 코드에서 발견한 검토 후보를 확인하세요.'],news:['보안 뉴스','최근 알려진 보안 약점을 쉽게 살펴보세요.'],prompts:['수정 프롬프트','확인된 경고에 대한 AI 수정 요청입니다.']};
  [$('#view-title').textContent,$('#view-subtitle').textContent] = titles[v];
  $('#dashboard').hidden = v === 'prompts' || v === 'news';
  $('#news-page').hidden = v !== 'news';
  $('#prompt-page').hidden = v !== 'prompts' && document.body.dataset.projectStep !== 'prompt';
  if (v === 'issues') setFilter('all');
  else if (wasIssues) renderIssues();
  if (v === 'prompts' && !$('#prompt-list').hasChildNodes()) openPromptPage(false);
}
function showModelHelp(){dialog('Zoro-1 연결 안내','<p>Trida-Stack의 Zoro-1 decision 서버를 실행하고, 이 데모 서버를 시작하기 전에 로컬 주소를 설정하세요.</p><pre>ZORO_DECIDE_URL=http://127.0.0.1:30001/v1/systemone node server.mjs</pre><p>Brev를 사용하는 경우 SSH 포트 포워딩을 먼저 연결하세요. 서버가 응답해도 실제 모델 가중치와 버전은 별도 확인이 필요합니다.</p><a href="https://huggingface.co/trillionlabs/Zoro-1" target="_blank" rel="noopener noreferrer">Zoro-1 모델 카드</a>')}
$('#scan').addEventListener('click',async()=>{$('#five-risks').hidden=true;$('#checklist').hidden=true;$('#project-review').hidden=true;document.querySelector('.topbar b').textContent='sample-store';document.querySelector('.summary-heading h2').textContent='sample-store';document.querySelector('.summary-heading p').textContent='전자상거래 샘플 · JavaScript';document.querySelector('.summary-stats strong').textContent='가상 코드 1개';const btn=$('#scan');btn.disabled=true;btn.textContent='검사 실행 중…';$('#result-label').textContent='분석 중';try{const res=await fetch('/api/scan',{method:'POST'});const data=await res.json();if(!res.ok)throw Error(data.error||'검사를 완료하지 못했습니다.');result=data;$('#total').textContent=groupFindings(result.findings).length;$('#side-count').textContent=groupFindings(allItems()).length;$('#injection').textContent=groupFindings(result.findings.filter(f=>f.owasp==='A05')).length;$('#settings').textContent=groupFindings(result.findings.filter(f=>f.owasp==='A02')).length;$('#dynamic-count').textContent=result.dynamic.status==='skipped'?'—':result.dynamic.status==='confirmed'?'1':'0';$('#gate').textContent='판정 보류';$('#last-run').textContent=new Date(result.scan.at).toLocaleString('ko-KR');$('#result-label').textContent=result.model.status==='connected'?(result.model.model_verified?'모델 응답 확인':'부분 결과 · 모델 확인 필요'):'부분 결과 · 모델 미연결';$('#coverage-flow').textContent=result.flow?.status==='completed'?'완료':result.flow?.status==='error'?'실행 오류':'미실행';$('#coverage-flow').classList.toggle('done',result.flow?.status==='completed');$('#coverage-code').textContent='완료';$('#coverage-code').classList.add('done');$('#coverage-dynamic').textContent=result.dynamic.status==='skipped'?'미실행':'완료';$('#coverage-dynamic').classList.toggle('done',result.dynamic.status!=='skipped');$('#notice').hidden=false;$('#notice').innerHTML=result.model.model_verified?'<span>✦</span><div><strong>Zoro-1 의사결정이 완료되었습니다.</strong><p>모델이 선택한 단계를 실행했습니다. 항목별 검증 범위를 확인하세요.</p></div>':'<span>✦</span><div><strong>로컬 검사 결과를 확인하세요.</strong><p>Zoro-1 모델 신원을 확인하기 전까지 전체 검사는 미완료입니다. 패턴 검사는 취약점 후보입니다.</p></div>'; modelUI(result.model);document.body.dataset.resultMode='code';$('#link-results').hidden=true;setProjectStep('analysis');setView('overview');setFilter('all')}catch(e){$('#result-label').textContent='검사 오류';dialog('검사 오류',`<p>${escape(e.message)}</p>`)}finally{btn.disabled=false;btn.innerHTML='<span>⌁</span> 샘플 다시 검사'}});
$$('.nav').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.view)));$$('[data-filter]').forEach(b=>b.addEventListener('click',()=>setFilter(b.dataset.filter)));$('#notice-close').onclick=()=>$('#notice').hidden=true;$('#model-details').onclick=showModelHelp;$('#help').onclick=()=>dialog('로컬 데모 안내','<p>샘플 또는 선택한 로컬 프로젝트를 검사할 수 있습니다. 사용자가 명시적으로 실행한 프로젝트 테스트는 실제 코드와 스크립트를 실행합니다.</p><p>패턴 결과는 검토 후보입니다. Zoro-1 미연결 시 모델 판단을 표시하지 않습니다.</p>');
let publicDeployment=false;
fetch('/api/status').then(r=>r.json()).then(s=>{
 publicDeployment=s.publicDeployment===true;
 if(publicDeployment)$('.local-badge').lastChild.textContent=' 공개 체험';
 modelUI(s.modelConfigured?{status:'not_connected',message:'서버 주소가 설정되어 있습니다. 검사를 실행해 연결을 확인하세요.'}:{status:'not_connected'});
}).catch(()=>modelUI({status:'error',message:'데모 서버에 연결할 수 없습니다.'}));

// User-selected files stay in browser memory and are sent only to this local server.
let projectFiles=[],projectName='',lastChecklist=[],lastSummary=[],lastScanSnapshot=[],lastScanSelection=null;
const clientDenied=/^(?:\.git|node_modules|vendor|dist|build|coverage|\.next|\.venv|venv|__pycache__)$/i;
const ext=/\.(?:[cm]?[jt]sx?|json|sql|rules|ya?ml|toml|html?|py|go|rb|php)$/i;
function supportedPath(path){const parts=path.split('/');return parts.every(x=>x&&!clientDenied.test(x)&&!/^\.env/i.test(x)&&!/\.(?:pem|key|p12|pfx)$/i.test(x))&&ext.test(path)&&!/(?:^|\/)(?:__tests__|tests?|fixtures?|examples?|samples?)(?:\/|$)|(?:^|\/)[^/]+\.(?:test|spec)\.[^/]+$/i.test(path)}
function relative(file){return file.scanPath || file.webkitRelativePath.split('/').slice(1).join('/')||file.name}
let selectedRoot=null;
const readSourceFolder=root=>readRepairFolder(root,{
 includeDirectory:name=>!clientDenied.test(name)&&(!name.startsWith('.')||name==='.github'),
 includeFile:path=>supportedPath(path)||isTestFile(path)
});
function selectProject(files,name,root){
 selectedRoot=root;initialAssessment=null;projectFiles=files;projectName=name;
 $('#prompt-list').replaceChildren();promptRun++;
 $('#project-review').hidden=$('#five-risks').hidden=true;
 $('#folder-name').textContent=files.length?name+' · '+files.length+'개 파일':'선택된 폴더 없음';$('#clear-folder').hidden=!files.length; resetRecommendation();
 if(files.length)verifySelection();
}
const folderInput=$('#project-folder');
folderInput.addEventListener('change',()=>{
 const files=[...folderInput.files];folderInput.value='';
 if(files.length)selectProject(files,files[0].webkitRelativePath.split('/')[0],null);
});
if(typeof window.showDirectoryPicker==='function' && window.isSecureContext){
 let useUpload=false;
 folderInput.addEventListener('click',async event=>{
  if(useUpload)return;
  event.preventDefault();
  try{
   const root=await window.showDirectoryPicker({mode:'read'});
   selectProject(await readSourceFolder(root),root.name,root);
  }catch(e){
   if(e.name==='SecurityError'||e.name==='NotAllowedError'){
    useUpload=true;$('#wizard-message').textContent='이 환경에서는 폴더 선택을 다시 눌러 읽기 전용으로 점검할 수 있어요.';
   }else if(e.name!=='AbortError')$('#wizard-message').textContent='폴더를 열 수 없어요. '+e.message;
  }
 });
}

$('#clear-folder').onclick=()=>selectProject([],'선택된 폴더 없음',null);
function renderProjectReview(data){
 const area=$('#project-review'),decision=data.reviewDecision||{},review=data.review||{};area.hidden=false;
 const choices={review_sql:'SQL 결합 추가 검토',review_html:'HTML 삽입 추가 검토',review_secrets:'비밀정보 수동 검토',review_session:'인증·세션 수동 검토',review_access:'접근 제어 수동 검토',review_eval:'동적 코드 실행 수동 검토',review_ssrf:'요청 주소 수동 검토',defer:'수동 검토로 보류'};
 const model=decision.status==='connected'?`Zoro-1 선택: ${escape(choices[decision.choice]||decision.choice)}`:`Zoro-1: ${escape(decision.message||'선택 미실행')}`;
 const item=review.items?.[0];
 const body=item?`<div class="review-caption"><b>${escape(item.path)}:${escape(item.line)}</b><span>${review.status==='completed'?'정적 재검사 완료':'판단 보류'}</span></div><div class="review-code"><div><strong>수정 전</strong><pre><i>−</i> ${escape(item.before)}</pre></div><div><strong>수정 제안</strong><pre><i>+</i> ${escape(item.after)}</pre></div></div><p>구문 검사: ${item.checks.syntax?'통과':'실패'} · 기존 줄 탐지: ${item.checks.before_pattern?'확인':'미확인'} · 제안 줄 재탐지: ${item.checks.after_pattern?'있음':'없음'} · 파일 내 동일 규칙: ${item.checks.previous_rule_hits} → ${item.checks.remaining_rule_hits}곳</p><p>${escape(item.limit)} ${escape(item.note)}</p>`:`<p>${escape(review.message||'추가 검토를 실행하지 않았습니다.')}</p>`;
 const actions=review.proposalToken?`<div class="apply-box"><h4>검사한 작업 사본에 적용</h4><p>${escape(data.projectName||projectName)} / ${escape(item.path)}</p><label><input id="apply-confirm" type="checkbox"> 수정 전후와 동작 변화를 확인했습니다.</label><button type="button" id="apply-proposal" class="primary">사본에 적용</button><p id="apply-result" aria-live="polite"></p><div id="test-controls" hidden><button id="patch-download" class="outline">원본 반영용 패치 저장</button><p>프로젝트 루트에서 git apply --check trace.patch로 충돌을 확인하고 git apply trace.patch로 반영하세요.</p><label>테스트 명령 <select id="test-command"><option value="node-test">node --test</option><option value="npm-test">npm test</option></select></label><label>이 항목의 회귀 테스트 <select id="target-test"><option value="">전체 프로젝트 테스트</option></select></label><button id="run-project-tests" class="primary">격리 테스트 실행</button><div id="test-result" aria-live="polite"></div></div></div>`:'';
 area.innerHTML=`<div class="panel-head"><div><h3>추가 검토 · 수정 제안 · 재검증</h3><p>${model}</p></div></div>${body}${actions}`;
 if(!review.proposalToken)return;
 const token=review.proposalToken,apply=$('#apply-proposal'),message=$('#apply-result'),controls=$('#test-controls');
 const select=$('#target-test'),command=$('#test-command'),run=$('#run-project-tests'),out=$('#test-result'),download=$('#patch-download');
 if(publicDeployment){
  for(const item of [command.closest('label'),select.closest('label'),run])item.hidden=true;
  out.textContent='회귀 테스트는 로컬 환경에서 실행할 수 있어요.';
 }
 const confirm=$('#apply-confirm');
 apply.onclick=async()=>{
   if(!confirm.checked){message.textContent='수정안을 먼저 확인하세요.';return}
   apply.disabled=true;
   try{
     const d=await postJson('/api/project-apply',{token});
     message.textContent='작업 사본 적용 완료 · '+d.path+' · '+d.sha256.slice(0,12);
     for(const path of d.tests)select.add(new Option(path,path));
     download.onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([d.patch],{type:'text/plain'}));a.download='trace.patch';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)};
     controls.hidden=false;
   }catch(e){message.textContent=e.message;apply.disabled=false}
 };
 command.onchange=()=>{select.disabled=command.value==='npm-test';if(select.disabled)select.value=''};
 run.onclick=async()=>{
   run.disabled=true;out.textContent='격리 환경에서 테스트 중…';
   try{
     const d=await postJson('/api/project-test',{token,command:command.value,selectedFile:select.value});
     const labels={failed:'테스트 실패',suite_passed:'프로젝트 테스트 통과',count_unknown:'명령 종료 · 테스트 수 미확인',no_tests:'실행된 테스트 없음',regression_passed:'선택한 보안 회귀 테스트 통과'};
     out.innerHTML=`<p><strong>${escape(labels[d.status])}</strong> · ${escape(d.command)} · 잠금 패키지 ${d.dependencyCount}개 · 실행 ${d.testCount??'미확인'} · 동일 규칙 ${d.ruleHits.length}곳</p><p>${d.selectedFile?escape(d.selectedFile)+' · 종료 코드 '+d.baselineExit+' → '+d.exitCode:'종료 코드 '+d.exitCode} ${escape(d.regression.join(', '))}</p><details><summary>테스트 출력</summary><pre>${escape(d.output)}</pre></details>`;
   }catch(e){out.textContent=e.message}finally{run.disabled=false}
 };
}
let lastAuditState={status:'not_available'},lastAuditPromise=Promise.resolve(),auditGeneration=0;
function renderRiskSummary(categories,snapshot){
 const generation=++auditGeneration;lastAuditState={status:'not_available'};
 const area=$('#five-risks');area.hidden=false;
 const cards=categories.map(c=>`<article class="risk-card"><div class="risk-title"><h4>${escape(c.title)}</h4><span>${escape(c.status)}</span></div><p>${c.items.length?`발견 ${c.items.length}건 · `:''}${escape(c.limitation)}</p>${c.items.map(f=>`<button class="risk-finding" data-risk-key="${escape(f.key)}">${escape(f.path)}:${escape(f.lines.join(', '))} · ${escape(f.evidence)}</button>`).join('')}<p><b>검증</b> ${escape(c.check)}</p><p><b>수정</b> ${escape(c.fix)}</p>${c.id==='dependencies'&&c.status==='대조 가능'?'<button id="osv-check" class="outline">OSV 취약점 대조</button><div id="osv-result" aria-live="polite"></div>':''}</article>`).join('');
 area.innerHTML=`<div class="panel-head"><div><h3>핵심 보안 5가지</h3><p>각 항목의 발견 근거와 검증·수정 방법을 확인하세요.</p></div></div><div class="risk-grid">${cards}</div>`;
 area.querySelectorAll('[data-risk-key]').forEach(button=>button.onclick=()=>openCodeViewer(button.dataset.riskKey));
 const button=$('#osv-check');if(button)button.onclick=async()=>{
  const out=$('#osv-result'),lock=snapshot.find(f=>f.path==='package-lock.json');button.disabled=true;if(generation===auditGeneration){lastAuditState={status:'pending'};}out.textContent='패키지 이름과 버전을 OSV로 보내 대조하고 있습니다…';
  try{const data=await postJson('/api/dependency-audit',{lock:lock.text});
   if(generation===auditGeneration){lastAuditState={status:'completed',packages:data.packages.length,omitted:data.omitted,detailsIncomplete:data.detailsIncomplete,data};}
   const detail=data.packages.map(p=>`<li><b>${escape(p.name)} ${escape(p.version)}</b><ul>${(p.details||[]).map(d=>`<li><a href="https://osv.dev/vulnerability/${encodeURIComponent(d.id)}" target="_blank" rel="noopener noreferrer">${escape(d.id)}</a> · 수정 버전 ${d.fixed.length?escape(d.fixed.join(', ')):'미확인'} <button type="button" data-osv-prompt="${escape(p.name+'@'+p.version+'|'+d.id)}">AI 수정 요청</button></li>`).join('')}</ul></li>`).join('');
   out.innerHTML=`<p>대조 ${data.checked}개 · 권고가 있는 패키지 ${data.packages.length}개 · 버전 미확인 ${data.omitted}개</p>${detail?`<ul>${detail}</ul>`:''}<p>${escape(data.note)} ${data.detailsIncomplete?'일부 권고 상세 조회에 실패했거나 표시 한도를 초과했습니다.':''}</p><p>권고의 수정 버전이 프로젝트에 적용되는지 확인하고 잠금 파일을 갱신한 뒤 회귀 테스트를 실행하세요.</p>`;
   out.querySelectorAll('[data-osv-prompt]').forEach(b=>b.onclick=()=>{setView('overview');openPromptPage(true,{type:'dependency',key:b.dataset.osvPrompt})});
  }catch(e){if(generation===auditGeneration){lastAuditState={status:'error'};}out.textContent=e.message}finally{button.disabled=false}
 };
 lastAuditPromise=button?button.onclick():Promise.resolve();
}
function tableData(findings){const rows=findings.map(f=>[f.wstg||'매핑 미확인',f.title,'코드의 보안 관련 패턴을 확인','검토 필요',`${f.path}:${f.lines.join(', ')} · 실제 악용 여부 미검증`]);rows.push(['WSTG-v42-ATHZ-04','객체별 접근 제어','계정 간 자원 접근 권한 확인','미검사','테스트 계정과 기대 정책 필요'],['WSTG-v42-INPV-05','입력값 검증','실제 SQL 인젝션 여부 확인','미검사','정적 패턴만 확인; 실행·악용 검증 없음'],['WSTG-v42-CLNT-01','클라이언트 입력 검증','브라우저 스크립트 실행 여부 확인','미검사','브라우저 동적 검증 미실행']);return rows}
function renderTables(findings){lastChecklist=tableData(findings);lastSummary=findings.map(f=>[f.wstg||'매핑 미확인',f.title,classification(f).cwe,`${f.path}:${f.lines.join(', ')}`,classification(f).summary,classification(f).fix,'정적 패턴 일치; 수동 확인 필요']);const cells=rows=>rows.map(row=>`<tr>${row.map(v=>`<td>${escape(v)}</td>`).join('')}</tr>`).join('');$('#checklist-rows').innerHTML=cells(lastChecklist);$('#finding-rows').innerHTML=lastSummary.length?cells(lastSummary):'<tr><td class="empty-row" colspan="7">정적 패턴 결과가 없습니다. 검사하지 않은 항목은 위에서 확인하세요.</td></tr>';$('#checklist').hidden=false}
function csvDownload(headers,rows,name){const cell=v=>{let t=String(v??'');if(/^\s*[=+\-@\t\r]/.test(t))t="'"+t;return '"'+t.replaceAll('"','""')+'"'};const contents='\ufeff'+[headers,...rows].map(r=>r.map(cell).join(',')).join('\r\n');const url=URL.createObjectURL(new Blob([contents],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('#download-checklist').onclick=()=>csvDownload(['테스트 ID','검사 항목','검사 목적','상태','메모'],lastChecklist,'testing-checklist.csv');
$('#download-findings').onclick=()=>csvDownload(['테스트 ID','취약점 이름','CWE 후보','위치','관찰 / 한계','권장 조치','검증 근거'],lastSummary,'findings-summary.csv');
function projectSources(selection){
 const chosen=selection.map(file=>({file,path:relative(file)})).filter(x=>supportedPath(x.path));
 if(!chosen.length)throw Error('선택한 폴더에 지원되는 파일이 없습니다.');
 if(chosen.length>200||chosen.some(x=>x.file.size>300000)||chosen.reduce((n,x)=>n+x.file.size,0)>3000000)throw Error('최대 200개, 파일당 300KB, 전체 3MB까지 점검할 수 있어요.');
 return chosen;
}
async function runProjectScan(options={}){try{
 const previousSelection=projectFiles,selection=options.files||projectFiles,chosen=projectSources(selection);
 const paths=new Set(chosen.map(x=>x.path));
 const selected=selection.map(file=>({file,path:relative(file)})).filter(({path})=>{
   if(path.split('/').some(p=>(p.startsWith('.')&&p!=='.github')||clientDenied.test(p)))return false;
   return paths.has(path)||path==='package.json'||path==='package-lock.json'||isTestFile(path);
 });
 if(selected.length>200||selected.some(x=>x.file.size>300000)||selected.reduce((n,x)=>n+x.file.size,0)>3000000)throw Error('테스트를 포함해 최대 200개 파일, 3MB까지 지원합니다.');
 const snapshot=await Promise.all(selected.map(async x=>({path:x.path,text:await x.file.text()})));
 const data=await postJson('/api/project-scan',{files:chosen.map(x=>({path:x.path})),snapshot,serviceProfile:options.assessment?.serviceProfile ?? options.serviceProfile ?? readServiceProfile(),projectName});
 if(previousSelection!==projectFiles||(options.assessment && initialAssessment!==options.assessment))throw Error('프로젝트가 바뀌었습니다.');
 projectFiles=selection;
 result=data;promptRun++;$('#prompt-list').replaceChildren();lastScanSnapshot=snapshot;lastScanSelection=selection;
 $('#file-note').textContent=`선택 ${projectFiles.length}개 중 ${data.scan.files}개 분석 · 정적 흐름 ${data.scan.flowCoverage?.analyzed||0}개, 미지원·구문 오류 ${(data.scan.flowCoverage?.unsupported||0)+(data.scan.flowCoverage?.parse_error||0)}개, 한도 초과 ${data.scan.flowCoverage?.limited||0}개`;
 $('#total').textContent=groupFindings(data.findings).length;$('#side-count').textContent=groupFindings(data.findings).length;$('#injection').textContent=groupFindings(data.findings.filter(f=>f.owasp==='A05')).length;$('#settings').textContent=groupFindings(data.findings.filter(f=>f.owasp==='A02')).length;$('#dynamic-count').textContent='—';$('#gate').textContent='판정 보류';$('#last-run').textContent=new Date(data.scan.at).toLocaleString('ko-KR');$('#result-label').textContent='로컬 프로젝트 · 정적 결과';$('#coverage-code').textContent='부분 검사';$('#coverage-flow').textContent=`${data.scan.flowCoverage?.analyzed||0}개 파일 · 정적 흐름`;$('#coverage-flow').classList.remove('done');$('#coverage-dynamic').textContent='미실행';$('#coverage-dynamic').classList.remove('done');
 document.querySelector('.topbar b').textContent=projectName;document.querySelector('.summary-heading h2').textContent=projectName;document.querySelector('.summary-heading p').textContent=`선택한 로컬 프로젝트 · ${data.scan.files}개 파일`;document.querySelector('.summary-stats strong').textContent=`${data.scan.files}개 파일`;
 $('#notice').hidden=false;$('#notice').innerHTML='<span>✦</span><div><strong>정적 검사 결과를 확인하세요.</strong><p>탐지 결과는 검토 후보입니다. 제한된 함수 호출과 분기 흐름을 확인하며 동적 검증은 수행하지 않았습니다.</p></div>';
 const decision=data.reviewDecision;
 $('#model-state').textContent=decision.status==='connected'?'검토 완료':decision.status==='not_needed'?'검토 대상 없음':'연결 확인 필요';
 $('#model-title').textContent='Zoro-1 코드 검토';
 $('#model-description').textContent=decision.message || '탐지 유형과 프로젝트 설문을 바탕으로 검토 항목을 선택했어요.';
 setView('overview');setFilter('all');renderTables(data.findings);renderProjectReview(data);renderRiskSummary(data.riskSummary,snapshot);if(!options.stayOnStep)setProjectStep('analysis');return true;
 }catch(e){if(options.files)throw e;dialog('프로젝트 검사 안내',`<p>${escape(e.message)}</p>`);return false}}


// Project wizard: survey and target selection are separate from analysis results.
function setProjectStep(step){document.body.dataset.projectStep=step;$('#analysis-top').hidden=step!=='analysis';$('#prompt-page').hidden=step!=='prompt';$('#recheck-page').hidden=step!=='recheck';$('#complete-page').hidden=step!=='complete';window.scrollTo({top:0,behavior:'smooth'});}
const detailQuestions=$('#detail-questions');
for(const topic of surveyTopics){
 const label=document.createElement('label');
 label.className='survey-detail';
 const title=document.createElement('strong');
 title.textContent=topic.question;
 const select=document.createElement('select');
 select.name='detail-'+topic.key;
 label.append(title,select);
 detailQuestions.append(label);
}
const setupWindowBar=$('#setup-window-bar');
for(const card of $$('.survey-row, .survey-detail, .wizard-method label, .wizard-url, .project-input')){
 card.classList.add('setup-window');
 card.prepend(setupWindowBar.content.cloneNode(true));
}
function readServiceProfile(){
 return Object.fromEntries(surveyTopics.map(({key})=>{
  const answer=$(`input[name="survey-${key}"]:checked`)?.value || '';
  return [key,needsDetail(answer)?{answer,detail:$(`select[name="detail-${key}"]`).value}:{answer}];
 }));
}
function updateSurvey(){
 const profile=readServiceProfile();
 const hasDetails=surveyTopics.some(t=>needsDetail(profile[t.key].answer));
 for(const topic of surveyTopics){
  const select=$(`select[name="detail-${topic.key}"]`);
  const {answer}=profile[topic.key];
  select.parentElement.hidden=!needsDetail(answer);
  select.disabled=!needsDetail(answer);
  if(select.dataset.answer===answer)continue;
  select.dataset.answer=answer;
  select.replaceChildren(new Option('선택해 주세요',''));
  for(const [value,label] of Object.entries(detailOptions(topic,answer)))select.add(new Option(label,value));
 }
 $('.wizard-progress [data-stage="details"]').hidden=!hasDetails;
 $('.wizard-progress [data-stage="target"] b').textContent=hasDetails?'3':'2';
 $('#survey-next').textContent=hasDetails?'다음 · 추가 정보 →':'다음 · 점검 대상 선택 →';
 return hasDetails;
}
function setWizardStage(stage) {
 document.body.dataset.wizardStage=stage;
 $('#survey-details').hidden=stage!=='details';
 const heading=$('#project-wizard h2');
 heading.textContent={survey:'어떤 웹 서비스를 점검할까요?',details:'서비스 기능 확인',target:'점검 대상을 선택해 주세요'}[stage];
 for(const step of $$('.wizard-progress li')){
  if(step.dataset.stage===stage)step.setAttribute('aria-current','step');
  else step.removeAttribute('aria-current');
 }
 if(stage==='target')verifySelection();
 heading.focus();
 window.scrollTo({top:0,behavior:'smooth'});
}
function continueDetails(){
 const missing=Array.from(detailQuestions.querySelectorAll('select:enabled')).find(select=>!select.value);
 if(missing){
  $('#details-message').textContent='표시된 항목을 모두 선택해 주세요.';
  missing.focus();return false;
 }
 $('#details-message').textContent='';
 setWizardStage('target');return true;
}
let recommendationVersion=0,recommendationRequest=null;
function resetRecommendation(){
 recommendationVersion++;
 recommendationRequest=null;
 $('#verify-status').textContent='';
 $('#verify-report').hidden=true;
 for(const badge of $$('.target-badge'))badge.hidden=true;
}
const checkLabels={login:'로그인',private:'비공개 정보',input:'방문자 입력'};
const checkStates={matched:'답변과 일치하는 단서',partial:'일부 단서 확인',conflict:'답변과 다른 단서',unconfirmed:'미확인'};
function showRecommendation(report){
 const list=$('#verify-report ul');
 list.replaceChildren();
 for(const check of report.checks){
  const row=document.createElement('li');
  const evidence=check.observations.map(e=>e.label+' ('+(e.source==='link'?'공개 페이지':e.path)+(e.line?' '+e.line+'행':'')+')');
  row.textContent=checkLabels[check.feature]+' · '+checkStates[check.status]+(evidence.length?' — '+evidence.join(', '):'');
  list.append(row);
 }
 $('#verify-report').hidden=false;
 const notes=[];
 if(report.linkStatus==='unavailable')notes.push('링크에서 공개 페이지를 읽지 못했어요.');
 if(report.fileCount>report.readableFiles)notes.push('선택한 파일 중 '+report.readableFiles+'개에서 서비스 기능을 대조했어요.');
 if(report.status!=='recommended')notes.push(({offline:'Zoro-1 응답을 확인하지 못했어요.',deferred:'Zoro-1이 추천을 보류했어요.',insufficient:'추천에 필요한 자료를 확인하지 못했어요.'})[report.status]+' 직접 점검 방식을 선택할 수 있어요.');
 $('#verify-status').textContent=notes.join(' ');
 for(const radio of $$('input[name="target-method"]')){
  radio.parentElement.querySelector('.target-badge').hidden=report.status!=='recommended'||report.choice!==radio.value;
 }
}
function verifySelection(){
 if(document.body.dataset.wizardStage!=='target'||document.body.dataset.projectStep!=='setup')return;
 if(recommendationRequest)return recommendationRequest;
 const mode=document.body.dataset.targetMode;
 const url=mode==='folder'?'':$('#target-url').value.trim();
 const files=mode==='link'?[]:projectFiles;
 if(mode!=='folder'&&(!url||!$('#target-url').validity.valid))return;
 if(mode!=='link'&&!files.length)return;
 const version=recommendationVersion,profile=readServiceProfile();
 $('#verify-status').textContent='설문 답변과 점검 자료를 대조하고 있어요…';
 recommendationRequest=(async()=>{
  const sources=files.length?projectSources(files):[];
  const snapshot=await Promise.all(sources.map(async x=>({path:x.path,text:await x.file.text()})));
  if(version!==recommendationVersion)return;
  const report=await postJson('/api/target-recommendation',{url,files:snapshot,serviceProfile:profile});
  if(version===recommendationVersion)showRecommendation(report);
 })().catch(e=>{
  if(version!==recommendationVersion)return;
  recommendationRequest=null;
  $('#verify-status').textContent=e.message;
 });
 return recommendationRequest;
}
$('#target-url').addEventListener('input',resetRecommendation);
$('#target-url').addEventListener('change',verifySelection);
function setTargetMode(){
 document.body.dataset.targetMode=$('input[name="target-method"]:checked').value;
 $('#wizard-message').textContent='';
 resetRecommendation();
 verifySelection();
}
let gateCheckVersion = 0;
async function checkWizardModel(){const version=++gateCheckVersion;const out=$('#wizard-model-status'),gate=$('#gate-model-status');out.textContent=gate.textContent='연결 확인 중…';$('#model-gate').dataset.connection='checking';try{const data=await postJson('/api/model-check',{});if(version!==gateCheckVersion)return;$('#model-gate').dataset.connection=data.status==='connected'?'connected':'error';out.textContent=gate.textContent=data.status==='connected'?(data.model_verified?'응답 수신 · 서버 보고 리비전 일치':'응답 수신 · 리비전 미확인'):'연결 안 됨 · '+(data.message||'설정을 확인하세요');}catch{if(version!==gateCheckVersion)return;$('#model-gate').dataset.connection='error';out.textContent=gate.textContent='연결 확인 실패'}}

let currentLinkData=null,currentLinkUrl='';
let deploymentProofExpiryTimer=null;
async function observeDeploymentForProject(linkData,url){
 const captured=result;if(!linkData||!captured?.baselineToken)return;
 clearTimeout(deploymentProofExpiryTimer);
 for(const finding of captured.findings){finding.deploymentProof=null;finding.deploymentObservations=[];}
 try{
  const observed=await postJson('/api/deployment-observation',{url,token:captured.baselineToken});if(result!==captured)return;linkData.deployment=observed;
  for(const finding of captured.findings){finding.deploymentObservations=observed.findings.filter(x=>x.key===finding.key);finding.deploymentProof=observed.proof?.findings?.find(x=>x.key===finding.key)||null;}
  renderIssues();renderTables(captured.findings);
  if(observed.proof?.findings?.length){const expires=Date.parse(observed.proof.checkedAt)+300001;deploymentProofExpiryTimer=setTimeout(()=>{if(result!==captured)return;for(const finding of captured.findings)finding.deploymentProof=null;linkData.deployment.proof={...linkData.deployment.proof,status:'expired',findings:[],note:'자체 검증이 5분 후 만료되어 검증 결과가 만료되었습니다.'};renderIssues();renderTables(captured.findings);if(currentLinkData===linkData)renderLinkResult(linkData,url);},Math.max(0,expires-Date.now()));}
 }catch(e){linkData.deployment={staticFile:{status:'inconclusive',reason:e.message},checkedRoutes:0,routeCount:0,findings:[],notice:'배포 코드와의 연결을 확인하지 못했습니다.'}}
}

function bindLinkCode(area) {
 area.querySelectorAll('[data-link-code]').forEach(button=>button.onclick=()=>dialog('웹 응답의 코드 위치','<p>링크 응답만으로 이 설정이 어느 파일에 있는지 확인할 수 없습니다. 서버·프록시 설정을 확인해 주세요.</p>'));
}
function linkIssueCard(f,i) { return `<article class="link-finding news-window">${issueWindowBar(f.cwe)}<div class="link-finding-body"><strong>${escape(f.title)}</strong><small>${escape(f.cweName)} · ${escape(f.status)}</small><p>${escape(f.summary)}</p><div class="issue-actions">${document.body.dataset.resultMode==='code'?`<button type="button" data-link-code="${i}">코드 비교</button>`:''}</div></div>${issueNewsSlot(f.cwe,[f])}</article>`; }
function renderLinkResult(data,url=$('#target-url').value.trim()){currentLinkData=data;currentLinkUrl=url;$('#side-count').textContent=(result?.kind==='project'?groupFindings(result.findings).length:0)+data.issues.length;const area=$('#link-results');area.hidden=false;const titles=data.issues.map(linkIssueCard).join('');area.innerHTML=`<div class="panel-head"><div><h3>링크 응답 점검</h3><p>HTTP ${escape(data.httpStatus)} · ${escape(data.note)}</p></div></div>${titles||'<p class="link-empty">응답에서 표시할 헤더 후보가 없습니다. 다른 보안 항목의 안전을 뜻하지 않습니다.</p>'}${data.deployment?`<div class="link-empty"><strong>프로젝트와 배포 관측</strong><p>${escape(data.deployment.staticFile.reason)}</p><p>정적 라우트 응답 ${escape(data.deployment.checkedRoutes)} / ${escape(data.deployment.routeCount)}개 확인</p>${data.deployment.findings.length?`<ul>${data.deployment.findings.map(item=>`<li>${escape(result?.findings?.find(f=>f.key===item.key)?.title||'발견 항목')} · ${escape(item.route)} · HTTP ${escape(item.httpStatus??'미확인')}</li>`).join('')}</ul>`:''}<p>${data.deployment.proof?.status==='self_attested'?`인증된 라우트 ${escape(data.deployment.proof.findings.length)}개. `:''}${escape(data.deployment.proof?.note||'')}</p><p>${escape(data.deployment.notice)}</p></div>`:''}<p class="link-empty">로그인·권한·소스 코드와 실제 악용은 검사하지 않았습니다.</p>`;
 bindLinkCode(area);
 area.querySelectorAll('[data-issue-news]').forEach(renderIssueNews);
 if (view === 'issues') renderIssues();
 area.querySelectorAll('[data-link-prompt]').forEach(button=>button.onclick=()=>{setView('overview');openPromptPage(true,{type:'link',index:Number(button.dataset.linkPrompt)})});}
function confirmedLocalOrigin(value){try{const u=new URL(value);return u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port&&!u.username&&!u.password&&u.pathname==='/'&&!u.search&&!u.hash?u.origin:null}catch{return null}}
let initialAssessment=null;
async function startAssessment(){
 const message=$('#wizard-message'),button=$('#wizard-next'),mode=document.querySelector('input[name="target-method"]:checked').value,link=mode==='folder'?'':$('#target-url').value.trim();
 const serviceProfile=readServiceProfile();
 const answers=Object.values(serviceProfile).map(item=>item.answer);
 if(answers.some(v=>!v)){message.textContent='서비스 기능에 대한 세 가지 질문을 모두 선택해 주세요.';return}
 if(Object.values(serviceProfile).some(item=>needsDetail(item.answer)&&!item.detail)){
  setWizardStage('details');continueDetails();return;
 }
 if((mode==='link'||mode==='code')&&!link){message.textContent='선택한 점검 방식에 웹사이트 주소가 필요합니다.';return}
 if(mode!=='link'&&!projectFiles.length){message.textContent='프로젝트 폴더를 선택해 주세요.';return}
 button.disabled=true;$('#target-configuration').inert=true;$('.project-input').inert=true;$('#survey-back').disabled=true;message.textContent='선택한 대상을 확인하고 있습니다…';let linkData=null;
 try{
  await verifySelection();
  if(link&&!(mode==='code'&&confirmedLocalOrigin(link)))linkData=await postJson('/api/public-link-check',{url:link});
  document.body.dataset.resultMode=mode==='link'?'link':'code';$('#link-results').hidden=true;currentLinkData=null;currentLinkUrl='';
  if(mode!=='link'){const ok=await runProjectScan({serviceProfile});if(!ok)return;if(linkData){await observeDeploymentForProject(linkData,link);renderLinkResult(linkData)}}
  else{result=null;promptRun++;$('#prompt-list').replaceChildren();$('#five-risks').hidden=true;$('#checklist').hidden=true;$('#project-review').hidden=true;$('#side-count').textContent=linkData.issues.length;$('#result-label').textContent='링크 응답 · 제한적 점검';$('#view-title').textContent='링크 점검 결과';$('#view-subtitle').textContent='공개 응답 헤더에서 확인할 항목입니다.';renderLinkResult(linkData);setProjectStep('analysis')}
  initialAssessment={serviceProfile,root:mode==='link'?null:selectedRoot,selection:projectFiles,hasCode:mode!=='link',hasLink:Boolean(linkData),url:linkData?link:'',projectName:mode!=='link'?projectName:'',paths:mode!=='link'?lastScanSnapshot.map(x=>x.path):[]};$('#recheck-summary').hidden=true;message.textContent='';
 }catch(e){message.textContent=e.message}finally{$('#target-configuration').inert=false;$('.project-input').inert=false;$('#survey-back').disabled=false;button.disabled=false}
}
$('#survey-next').onclick=()=>{
 if(Object.values(readServiceProfile()).some(item=>!item.answer)){
  $('#survey-message').textContent='세 가지 질문을 모두 선택해 주세요.';
  return;
 }
 $('#survey-message').textContent='';
 setWizardStage(updateSurvey()?'details':'target');
};
$('#details-back').onclick=()=>setWizardStage('survey');
$('#details-next').onclick=continueDetails;
detailQuestions.onchange=()=>{$('#details-message').textContent='';resetRecommendation()};
$('#survey-back').onclick=()=>setWizardStage(updateSurvey()?'details':'survey');
$('#wizard-next').onclick=startAssessment;
$('#wizard-back').onclick=()=>setProjectStep('setup');
$('#wizard-model-check').onclick=checkWizardModel;
$$('input[name="target-method"]').forEach(input=>input.addEventListener('change',setTargetMode));
$('.wizard-questions').onchange=()=>{
 resetRecommendation();
 $('#survey-message').textContent=$('#details-message').textContent='';
 updateSurvey();
};
document.body.dataset.projectStep='setup';
document.body.dataset.wizardStage='survey';
updateSurvey();setTargetMode();checkWizardModel();
const gate = $('#model-gate');
const gateContinue = $('#gate-continue');
const gateRetry = $('#gate-retry');
let gimbal = startGimbal($('#gimbal'));
$('#gate-back').onclick=()=>{gate.classList.remove('is-revealing');gate.hidden=false;$('.app-window').inert=true;gateContinue.disabled=gateRetry.disabled=false;gimbal=startGimbal($('#gimbal'));checkWizardModel();gateRetry.focus()};
gateRetry.onclick = checkWizardModel;
gateContinue.onclick = async () => {
  if (gateContinue.disabled || gate.hidden) return;
  gateContinue.disabled = gateRetry.disabled = true;
  try {
    if (gate.dataset.connection === 'connected') {
      $('#gate-model-status').textContent = '잠금 여는 중…';
      await gimbal.unlock(() => gate.classList.add('is-revealing'));
    }
  } finally {
    gimbal.stop();
    gate.hidden = true;
    $('.app-window').inert = false;
    ($('input[name="survey-login"]:checked') || $('input[name="survey-login"]')).focus();
  }
};


function localBlockReason(items,captured) {
 if(!initialAssessment?.hasCode || captured?.kind!=='project' || !captured.baselineToken || captured!==result ||
    lastScanSelection!==projectFiles || initialAssessment.selection!==projectFiles)return '분석한 로컬 프로젝트가 필요해요.';
 if(typeof window.showDirectoryPicker!=='function' || !window.isSecureContext || !initialAssessment.root)return '이 브라우저에서 프로젝트 폴더에 직접 쓸 수 없어요.';
 if($('#model-gate').dataset.connection!=='connected')return 'Zoro-1 연결을 확인해 주세요.';
 return planLocalRepairs(items,lastScanSnapshot).reason || '';
}
function openLocalRepair(items) {
 const captured=result,assessment=initialAssessment;
 if(localBlockReason(items,captured))return;
 const {files}=planLocalRepairs(items,lastScanSnapshot);
 const modal=$('#local-repair-window'),body=modal.querySelector('.window-body');
 const close=modal.querySelector('.window-close'),generate=body.querySelector('[data-generate]'),save=body.querySelector('[data-save]');
 const preview=body.querySelector('[data-preview]'),status=body.querySelector('[data-status]');
 body.querySelector('[data-file-count]').textContent=`수정할 파일 ${files.length}개`;
 body.querySelector('[data-files]').replaceChildren(...files.map(file=>{
  const item=document.createElement('li');item.textContent=file.path;return item;
 }));
 preview.replaceChildren();status.textContent='';save.disabled=true;generate.disabled=false;
 generate.textContent='전체 수정안 만들기';
 close.onclick=()=>modal.close();
 modal.showModal();
 let active=true;
 modal.addEventListener('close',()=>{active=false},{once:true});
 const current=()=>active && modal.open && assessment===initialAssessment && captured===result && projectFiles===assessment.selection;
 let changes=[];
 generate.onclick=async()=>{
  if(changes.length===files.length){changes=[];preview.replaceChildren()}
  save.disabled=generate.disabled=true;
  try{
   for(const file of files.slice(changes.length)){
    if(!current())return;
    status.textContent=file.path+' 수정안을 만드는 중…';
    const proposal=await postJson('/api/ai-repair',{token:captured.baselineToken,path:file.path,findings:file.findings});
    if(!current())return;
    if(proposal.status!=='proposed'||proposal.path!==file.path)throw Error(proposal.message||'수정안을 만들지 못했어요.');
    const section=document.createElement('section');
    section.className='ai-repair';
    section.innerHTML='<h3></h3><p></p><div class="code-pair"><div class="mac-code"><div class="mac-code-bar">현재 파일</div><pre></pre></div><div class="mac-code"><div class="mac-code-bar">수정 후</div><pre></pre></div></div>';
    section.querySelector('h3').textContent=file.path;
    section.querySelector('p').textContent=proposal.reason;
    const diff=codeDiff(file.before,proposal.code);
    const [before,after]=section.querySelectorAll('pre');
    showDiff(before,diff.before,'diff-removed');
    showDiff(after,diff.after,'diff-added');
    preview.append(section);
    changes.push({...file,after:proposal.code});
   }
   generate.textContent='전체 수정안 다시 만들기';
   status.textContent='모든 파일의 변경 내용을 확인한 뒤 한 번에 승인해 주세요.';
   save.disabled=false;
  }catch(e){
   if(current()){
    status.textContent=`${files[changes.length].path} · ${e.message} (준비된 파일 ${changes.length}/${files.length}개)`;
    generate.textContent='남은 수정안 다시 만들기';
   }
  }
  finally{if(current())generate.disabled=false}
 };
 save.onclick=async()=>{
  if(save.disabled || !current() || changes.length!==files.length)return;
  const blockCancel=e=>e.preventDefault();
  save.disabled=generate.disabled=close.disabled=true;modal.addEventListener('cancel',blockCancel);
  try{
   if(await assessment.root.requestPermission({mode:'readwrite'})!=='granted'){
    const trigger=$('.prompt-local');if(trigger){trigger.disabled=true;trigger.title='폴더 쓰기 권한이 필요해요.'}
    throw Error('폴더 쓰기 권한이 필요해요.');
   }
   status.textContent='원본을 확인하고 승인한 변경을 저장하고 있어요…';
   await applyLocalRepairs({root:assessment.root,projectName:assessment.projectName,changes,isCurrent:current});
   modal.close();
   enterRecheck(true);
   await performRecheck();
  }catch(e){status.textContent=e.message;save.disabled=false}
  finally{generate.disabled=close.disabled=false;modal.removeEventListener('cancel',blockCancel)}
 };
}

let promptRun=0;
async function openPromptPage(navigate=true,selection=null){
 if(navigate!==false)setProjectStep('prompt');else $('#prompt-page').hidden=false;
 const list=$('#prompt-list'),captured=result,linkData=currentLinkData,linkUrl=currentLinkUrl,run=++promptRun;list.textContent='분석 결과를 모으고 있습니다…';await lastAuditPromise;if(run!==promptRun)return;
 const codeItems=allItems().filter(f=>f.id&&f.path&&(f.lines?.length||f.key==='dynamic')).map(f=>({...f,link:false}));
 const linkItems=(linkData?.issues||[]).map((x,index)=>({id:'link-'+x.key,title:x.title,path:('웹 응답 '+linkUrl).slice(0,500),lines:[],status:'candidate',link:true,index}));
 const audit=captured?.kind==='project'&&lastAuditState.status==='completed'?lastAuditState.data:null;const dependencyItems=(audit?.packages||[]).flatMap(p=>(p.details||[]).map(d=>({id:'dependency-advisory',key:p.name+'@'+p.version+'|'+d.id,title:`${p.name} ${p.version}: ${d.id}`,path:'package-lock.json',lines:[],status:'candidate',link:true,dependency:true,pkg:p.name,version:p.version,advisory:d})));const items=selectPromptItems(codeItems,[...linkItems,...dependencyItems],selection);
 list.replaceChildren();
 if(!items.length){list.textContent=selection?'선택한 경고를 찾을 수 없습니다. 분석 결과에서 다시 선택해 주세요.':'수정 요청을 만들 분석 결과가 없습니다.';return}
 const card=document.createElement('article');
 const copyButton=`<button type="button" class="prompt-copy" aria-label="수정 요청 복사" title="수정 요청 복사" disabled>
   <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
     <rect x="8" y="8" width="11" height="11" rx="2"></rect><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"></path>
   </svg></button>`;
 const promptOutput='<textarea rows="14" readonly aria-label="AI 수정 요청"></textarea><span class="prompt-status" aria-live="polite"></span>';
 if(selection){
  card.className='prompt-card';
  card.innerHTML=copyButton+'<h3>선택한 취약점 수정 요청</h3><p></p>'+promptOutput;
 }else{
  card.className='prompt-card news-window prompt-window';
  card.innerHTML=`<header class="news-bar">
    <span class="window-lights news-lights" aria-hidden="true"><i></i><i></i><i></i></span>
    <h3>전체 취약점 통합 수정 요청</h3>
   </header>
   <div class="prompt-window-body">
    <div class="prompt-window-toolbar"><p></p><div class="prompt-window-actions">${copyButton}</div></div>
    ${promptOutput}
   </div>`;
 }
 list.append(card);
 card.querySelector('p').textContent=selection?`${items[0].title} · ${items[0].path}${items[0].lines.length?':'+items[0].lines.join(', '):' · 파일 위치 미확인'}`:`분석된 ${items.length}개 항목을 하나의 요청으로 구성합니다.`;
 const field=card.querySelector('textarea'),button=card.querySelector('.prompt-copy'),status=card.querySelector('.prompt-status');status.textContent='Zoro-1이 수정 요청을 준비하고 있습니다…';
 if(captured?.kind==='project' && captured.baselineToken && projectFiles.length && projectFiles===lastScanSelection){
  const local=document.createElement('button');
  local.type='button';local.className='prompt-local';local.textContent='로컬에 적용';
  const reason=localBlockReason(items,captured);
  local.disabled=!!reason;
  local.title=reason || '이 요청의 모든 변경을 함께 적용합니다.';
  if(!reason && initialAssessment.root.queryPermission){
   initialAssessment.root.queryPermission({mode:'readwrite'}).then(permission=>{
    if(permission==='denied'){local.disabled=true;local.title='프로젝트 폴더에 쓰기 권한이 없어요.'}
   }).catch(()=>{local.disabled=true;local.title='폴더 쓰기 권한을 확인할 수 없어요.'});
  }
  local.onclick=()=>{if(result===captured && projectFiles===lastScanSelection)openLocalRepair(items);else status.textContent='프로젝트가 바뀌었어요. 분석 결과에서 새 수정 요청을 열어 주세요.'};
  button.before(local);
 }
 try{
  const sections=[];
  for(const f of items){
   let review=reviewedFindings.get(codeKey(f));
   if(!f.link&&!review&&captured?.kind==='project'&&captured.baselineToken&&['dangerous-html','sql-interpolation'].includes(f.id)){review=await postJson('/api/review-finding',{token:captured.baselineToken,path:f.path,id:f.id,lines:f.lines});if(run!==promptRun)return;reviewedFindings.set(codeKey(f),review)}
   const token=f.link?undefined:review?.review?.proposalToken||captured?.review?.proposalToken;
   const answer=await postJson('/api/repair-prompt',{id:f.id,path:f.path,lines:f.lines,status:f.status,baselineToken:f.link?undefined:captured?.baselineToken,token,sample:!f.link&&captured?.kind!=='project'});
   if(run!==promptRun)return;const extra=f.dependency?`\n확인된 의존성: ${f.pkg}@${f.version} · 권고 ${f.advisory.id} · ${f.advisory.cves.length?f.advisory.cves.join(', '):'CVE 미확인'} · 권고의 수정 버전 ${f.advisory.fixed.length?f.advisory.fixed.join(', '):'미확인'}.\n권고와 현재 의존성 경로를 확인하고 적용 가능한 안전 버전을 선택해 package.json과 package-lock.json을 함께 갱신 필요. 다른 권고의 영향과 기존 기능 테스트 필요. 실제 미사용 여부나 전이 의존성 여부는 확인 전 단정 금지.`:'';sections.push(answer.text+extra);
  }
  field.value=combinePromptItems(items,sections,selection);
  button.disabled=false;status.textContent='생성 완료 · 변경 후 테스트와 재검사가 필요합니다.'+(audit?.detailsIncomplete||audit?.omitted?' 의존성 조회에 누락이 있어 일부 권고가 빠질 수 있습니다.':lastAuditState.status==='error'?' 의존성 조회에 실패해 권고는 포함되지 않았습니다.':'');
  button.onclick=async()=>{try{await navigator.clipboard.writeText(field.value);status.textContent='수정 요청을 복사했습니다.'}catch{field.select();status.textContent='선택된 내용을 복사하세요.'}};
 }catch(e){if(run!==promptRun)return;status.textContent='전체 요청을 완성하지 못했습니다: '+e.message;field.value='';button.disabled=false;button.setAttribute('aria-label','수정 요청 다시 생성');button.title='수정 요청 다시 생성';button.textContent='↻';button.onclick=()=>openPromptPage(view==='prompts'?false:true,selection);}
}
$('#to-prompt-page').onclick=()=>openPromptPage();$('#prompts-back').onclick=()=>{promptRun++;setView('overview');setProjectStep('analysis')};

let rechecking=false;
function enterRecheck(saved=false){
 setView('overview');promptRun++;
 $('#recheck-message').textContent='';
 document.querySelectorAll('[name="repair-done"]').forEach(input=>{input.checked=saved && input.value==='yes'});
 $('#recheck-run').disabled=!saved;
 setProjectStep('recheck');
}
function freshUpload(assessment){
 return new Promise((resolve,reject)=>{
  const input=document.createElement('input');input.type='file';input.webkitdirectory=true;input.multiple=true;
  input.oncancel=()=>reject(Error('폴더 읽기를 취소했어요.'));
  input.onchange=()=>{
   const files=[...input.files];
   if(!files.length || files[0].webkitRelativePath.split('/')[0]!==assessment.projectName)reject(Error('처음 점검한 프로젝트 폴더를 열어 주세요.'));
   else resolve(files);
  };
  input.click();
 });
}
async function originalProjectFiles(assessment){
 if(!assessment.root)return freshUpload(assessment);
 if(await assessment.root.requestPermission({mode:'read'})!=='granted')throw Error('처음 선택한 폴더를 다시 읽을 권한이 필요해요.');
 return readSourceFolder(assessment.root);
}
async function performRecheck(){
 const assessment=initialAssessment;
 if(rechecking || !assessment)return;
 const msg=$('#recheck-message'),back=$('#recheck-back'),button=$('#recheck-run');
 rechecking=true;button.disabled=back.disabled=true;
 msg.textContent='처음 선택한 조건으로 다시 점검하고 있어요…';
 try{
  const files=assessment.hasCode?await originalProjectFiles(assessment):null;
  if(initialAssessment!==assessment)return;
  const link=assessment.hasLink?await postJson('/api/public-link-check',{url:assessment.url}):null;
  if(initialAssessment!==assessment)return;
  if(files){
   await runProjectScan({files,assessment,stayOnStep:true});
   assessment.selection=projectFiles;
   await lastAuditPromise;
   if(initialAssessment!==assessment)return;
   if(link)await observeDeploymentForProject(link,assessment.url);
  }
  if(initialAssessment!==assessment)return;
  if(link)renderLinkResult(link,assessment.url);
  const outcome=recheckStatus(assessment,{...assessment,hasLink:!!link,
   paths:files?lastScanSnapshot.map(f=>f.path):[],codeFindings:files?groupFindings(result.findings).length:0,
   linkFindings:link?.issues.length||0,linkStatus:link?.status,httpStatus:link?.httpStatus,
   audit:files?lastAuditState:{status:'not_available'}});
  const note=$('#recheck-summary');
  if(outcome.status==='clear'){
   note.hidden=true;
   $('#complete-summary').textContent='처음 선택한 범위로 다시 점검했어요. 남은 보안 이슈는 0건이에요.';
   setProjectStep('complete');
  }else if(outcome.status==='findings'){
   note.hidden=false;note.textContent='재점검에서 보안 이슈 '+outcome.count+'건이 남았어요.';
   setProjectStep('analysis');
  }else msg.textContent='재점검을 마치지 못했어요. '+outcome.missing.join(', ');
 }catch(e){msg.textContent=e.message}
 finally{rechecking=false;back.disabled=false;button.disabled=!document.querySelector('[name="repair-done"][value="yes"]').checked}
}
$('#to-recheck-page').onclick=()=>enterRecheck();
$('#recheck-back').onclick=()=>setProjectStep('prompt');
document.querySelectorAll('[name="repair-done"]').forEach(input=>input.onchange=()=>{
 $('#recheck-run').disabled=rechecking||input.value!=='yes';
 $('#recheck-message').textContent=input.value==='no'?'수정을 마친 뒤 다시 점검해 주세요.':'';
});
$('#recheck-run').onclick=performRecheck;
$('#complete-results').onclick=()=>setProjectStep('analysis');$('#complete-new').onclick=()=>{selectProject([],'선택된 폴더 없음',null);result=null;lastScanSnapshot=[];lastScanSelection=null;currentLinkData=null;$('#link-results').hidden=true;$('#side-count').textContent='—';renderIssues();document.querySelectorAll('input[name="repair-done"]').forEach(x=>x.checked=false);$$('.wizard-questions input').forEach(input=>{input.checked=false});updateSurvey();$('#survey-message').textContent=$('#details-message').textContent='';setWizardStage('survey');setProjectStep('setup')};
