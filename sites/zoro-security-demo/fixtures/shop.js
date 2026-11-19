// 보안 검사 시연을 위한 의도적으로 취약한 가상 코드입니다.
export function search(req, db) {
  return db.query(`SELECT * FROM products WHERE name = '${req.query.name}'`);
}
export function renderDescription(element, product) {
  element.innerHTML = product.description;
}
export const config = { debug: true, origin: '*' };
export const cookie = { httpOnly: false };
