const storageKey = 'garden-journal-entries';
const initialEntries = [
  { bed: '온실', text: '상추 모종을 옮겨 심었어요. 금요일에는 흙부터 만져 보고 물을 주세요.' },
  { bed: '도구 창고', text: '새 장갑 세 켤레를 둘째 칸에 두었어요.' },
  { bed: '허브 화단', text: '로즈메리 옆 빈자리에는 봄까지 씨를 뿌리지 않기로 했어요.' }
];
const entries = JSON.parse(localStorage.getItem(storageKey) || 'null') ?? initialEntries;
function renderEntries() {
  const rows = entries.map(({ bed, text }) => {
    const row = document.createElement('li');
    row.textContent = bed + ' · ' + text;
    return row;
  });
  document.querySelector('#entries').replaceChildren(...rows);
}
const form = document.querySelector('#post-entry');
form.addEventListener('submit', event => {
  event.preventDefault();
  const text = form.elements.post.value.trim();
  if (!text) return;
  entries.unshift({ bed: form.elements.bed.value, text });
  localStorage.setItem(storageKey, JSON.stringify(entries));
  form.reset();
  renderEntries();
});
renderEntries();
