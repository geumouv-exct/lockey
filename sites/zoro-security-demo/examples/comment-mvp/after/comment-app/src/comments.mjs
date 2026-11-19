export function showComment(element, message) {
  const label = '댓글';
  // 입력은 HTML이 아니라 텍스트로 표시합니다.
  element.textContent = message;
  return label;
}
