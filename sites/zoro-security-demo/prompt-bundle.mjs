// Keep selection and aggregation independent of presentation and model calls.
export function selectPromptItems(code, links, selection) {
  const all = [...code, ...links];
  if (!selection) return all;
  return all.filter(f => selection.type === 'dependency' ? f.dependency && f.key === selection.key : selection.type === 'link' ? f.link && !f.dependency && f.index === selection.index : !f.link && f.key === selection.key);
}
export function combinePromptItems(items, sections, selection) {
  if (!items.length || items.length !== sections.length || sections.some(s => typeof s !== 'string' || !s.trim()))
    throw Error('모든 수정 요청을 완성하지 못했습니다.');
  const instruction='아래 항목을 프로젝트에서 직접 확인하고 적용 가능한 보안 수정과 회귀 테스트 작성·실행 필요. 기존 정상 동작 유지 필요. 확인되지 않은 사실 추측 금지. 수정 파일, 실행한 테스트와 결과, 확인하지 못한 사항 보고 필요.\n\n';
  return instruction + (selection ? sections[0] : sections.map((text, i) => `[${i + 1}] ${items[i].title}\n${text}`).join('\n\n'));
}
