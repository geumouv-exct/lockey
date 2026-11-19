// 이 프로브는 저장소에 포함된 두 시연용 fixture만 실행한다.
import * as vulnerable from './fixtures/shop.js';
import * as safe from './fixtures/shop-safe.mjs';
const sqlMarker="'TRACE_TEST";
const htmlMarker='<b>TRACE_TEST</b>';
function probe(target){
 let query;
 target.search({query:{name:sqlMarker}}, {query:(...args)=>{query=args;}});
 let inner='',text='';
 const element={set innerHTML(value){inner=value;},set textContent(value){text=value;}};
 target.renderDescription(element,{description:htmlMarker});
 return {sql:{markerInQuery:typeof query?.[0]==='string'&&query[0].includes(sqlMarker),markerInParams:Array.isArray(query?.[1])&&query[1].includes(sqlMarker)},html:{markerInInnerHTML:inner===htmlMarker,markerInTextContent:text===htmlMarker}};
}
console.log(JSON.stringify({vulnerable:probe(vulnerable),safe:probe(safe)}));
