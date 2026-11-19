import path from 'node:path';
// HTML script references are only evidence that a file is referenced in this snapshot.
export function attachBrowserContext(files,findings){
 const pages=files.filter(f=>/\.html?$/i.test(f.path));const refs=new Map();
 for(const page of pages){const tags=page.text.matchAll(/<script\b[^>]*\bsrc\s*=\s*(["'])([^"']+)\1[^>]*>/gi);for(const m of tags){const value=m[2];if(/^(?:[a-z][\w+.-]*:|\/\/|\/|#)/i.test(value))continue;const resolved=path.posix.normalize(path.posix.join(path.posix.dirname(page.path),value.split(/[?#]/,1)[0]));if(resolved==='..'||resolved.startsWith('../'))continue;const list=refs.get(resolved)||[];list.push({page:page.path,line:page.text.slice(0,m.index).split('\n').length});refs.set(resolved,list)}}
 for(const finding of findings){if(!/\.[cm]?[jt]sx?$/i.test(finding.path||''))continue;finding.browserContext={directPages:refs.get(finding.path)||[],generated:/(?:\.bundle|\.min)\.[cm]?[jt]sx?$/i.test(finding.path),pageCoverage:pages.length};}
}
