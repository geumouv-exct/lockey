export const sessionCookie = {
  name: 'neuti_session',
  path: '/',
  sameSite: 'Lax',
  secure: true,
  httpOnly: false,
  maxAge: 60 * 60 * 8
};
