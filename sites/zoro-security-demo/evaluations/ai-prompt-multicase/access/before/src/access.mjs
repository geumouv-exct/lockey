export function canRead(checkOwner) {
  try { return checkOwner(); } catch (err) { return true; }
}
