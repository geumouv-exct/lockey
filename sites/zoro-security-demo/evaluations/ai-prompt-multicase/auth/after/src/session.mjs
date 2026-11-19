import jwt from 'jsonwebtoken';
export const cookieOptions = { httpOnly: true, secure: true, sameSite: 'lax' };

export function authenticate(token, key) {
  try {
    const claims = jwt.verify(token, key, {
      algorithms: ['HS256'],
      issuer: 'trace-eval',
    });
    return Number.isFinite(claims.exp) ? claims : null;
  } catch {
    return null;
  }
}
