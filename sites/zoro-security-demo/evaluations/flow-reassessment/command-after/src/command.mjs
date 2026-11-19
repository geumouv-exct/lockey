export function runCommand(req, _exec, execFile) {
  if (req.query?.cmd !== 'status') {
    throw new TypeError('Unsupported command');
  }

  return execFile('/usr/bin/uptime', [], { shell: false });
}
