export function canRead(checkOwner) {
  try {
    return checkOwner();
  } catch {
    return false;
  }
}
