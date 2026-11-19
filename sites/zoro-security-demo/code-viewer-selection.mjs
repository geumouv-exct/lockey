import {groupFindings} from './finding-groups.mjs';
// Navigate every location belonging to the selected weakness type.
export function codeViewerEntries(items,key,snapshot){
 const group=groupFindings(items).find(g=>g.findings.some(f=>f.key===key));
 return (group?.findings||[]).filter(f=>f.path&&f.lines?.length&&snapshot.some(file=>file.path===f.path)).flatMap(f=>f.lines.map(line=>({f,line})));
}
