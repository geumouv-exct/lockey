export const sessionCookie = {
  name: 'neuti_session',
  path: '/',
  sameSite: 'Lax',
  secure: true,
  httpOnly: true,
  maxAge: 60 * 60 * 8
};
