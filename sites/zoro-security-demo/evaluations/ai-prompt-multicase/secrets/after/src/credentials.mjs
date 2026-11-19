export function configuredPassword() {
  const password = process.env.TRACE_DEMO_PASSWORD;
  if (!password) {
    throw new Error('TRACE_DEMO_PASSWORD must be set');
  }
  return password;
}
