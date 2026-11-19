export const config = {
  debug: process.env.NODE_ENV === 'development' && process.env.DEBUG === 'true',
  origin: 'https://app.example.test',
  rejectUnauthorized: true,
  verifySignature: true,
};
