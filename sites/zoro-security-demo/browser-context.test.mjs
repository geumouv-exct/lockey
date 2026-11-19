import test from 'node:test';import assert from 'node:assert/strict';import {attachBrowserContext} from './browser-context.mjs';
test('HTML의 직접 스크립트 참조만 기록하고 실제 배포 또는 함수 실행을 단정하지 않는다',()=>{
 const findings=[{path:'js/a.js'},{path:'js/b.bundle.js'},{path:'js/c.js'}];
 const files=[{path:'index.html',text:'<script src="./js/a.js"></script>\n<script src="./js/b.bundle.js?v=2"></script>\n<script src="https://example.com/js/c.js"></script>'}];attachBrowserContext(files,findings);
 assert.deepEqual(findings[0].browserContext.directPages,[{page:'index.html',line:1}]);assert.equal(findings[1].browserContext.generated,true);assert.deepEqual(findings[2].browserContext.directPages,[]);
});
