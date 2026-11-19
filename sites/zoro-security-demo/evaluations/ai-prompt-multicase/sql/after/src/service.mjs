export function findUser(db, req) {
  return db.query('SELECT * FROM users WHERE name = ?', [req.query.name]);
}
