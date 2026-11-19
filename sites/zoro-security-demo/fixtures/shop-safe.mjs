// 비교를 위한 수정된 가상 구현입니다.
export function search(req, db) {
  return db.query('SELECT * FROM products WHERE name = ?', [req.query.name]);
}
export function renderDescription(element, product) {
  element.textContent = product.description;
}
