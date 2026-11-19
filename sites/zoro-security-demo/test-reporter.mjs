// Runs in the container's test-runner process. Child stdout is not an event.
export default async function* report(events) {
  for await (const {type, data} of events) {
    if (!['test:pass', 'test:fail'].includes(type) || data.details?.type === 'suite') continue;
    if (!data.line || data.skip || data.todo || data.name === data.file) continue;
    const cause = data.details?.error?.cause;
    yield JSON.stringify({
      name: data.name, file: data.file, line: data.line, passed: type === 'test:pass',
      assertion: cause?.code === 'ERR_ASSERTION'
    }) + '\n';
  }
}
