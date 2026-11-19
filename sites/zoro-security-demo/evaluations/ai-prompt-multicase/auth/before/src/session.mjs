import jwt from 'jsonwebtoken';
export const cookieOptions = { httpOnly: false, secure: false, sameSite: 'lax' };
export function authenticate(token, key) {
  try { return jwt.decode(token); } catch { return null; }
}
