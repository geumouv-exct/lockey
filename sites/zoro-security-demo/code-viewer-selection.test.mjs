import test from 'node:test';
import assert from 'node:assert/strict';
import {codeViewerEntries} from './code-viewer-selection.mjs';
test('같은 약점 유형의 모든 파일과 줄을 순서대로 탐색하고 다른 약점은 제외',()=>{
 const html={id:'dangerous-html',key:'html',path:'app.js',lines:[2,4]}, other={id:'dangerous-html',key:'other',path:'other.js',lines:[9]},sql={id:'sql-interpolation',key:'sql',path:'app.js',lines:[6]};
 const snapshot=[{path:'app.js'},{path:'other.js'}];
 assert.deepEqual(codeViewerEntries([html,other,sql],'html',snapshot).map(x=>[x.f.path,x.line]),[['app.js',2],['app.js',4],['other.js',9]]);
 assert.deepEqual(codeViewerEntries([html,other,sql],'sql',snapshot).map(x=>x.line),[6]);
 assert.deepEqual(codeViewerEntries([html,other,sql],'html',[]),[]);
});
