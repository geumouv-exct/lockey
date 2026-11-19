import test from 'node:test';
import assert from 'node:assert/strict';
import {bindSwipeNavigation} from './swipe-navigation.mjs';
function emit(el,type,touches=[],changedTouches=[]){const event=new Event(type);Object.defineProperties(event,{touches:{value:touches},changedTouches:{value:changedTouches}});el.dispatchEvent(event)}
const point=(x,y)=>({clientX:x,clientY:y});
test('터치 이벤트에서 좌우 이동만 실행하고 짧은 이동·세로 스크롤·다중 터치·취소는 무시',()=>{
 const el=new EventTarget(),moves=[];bindSwipeNavigation(el,n=>moves.push(n));
 const swipe=(a,b)=>{emit(el,'touchstart',[a]);emit(el,'touchend',[],[b])};
 swipe(point(200,100),point(100,105));swipe(point(100,100),point(200,105));
 swipe(point(100,100),point(120,100));swipe(point(100,100),point(160,250));
 emit(el,'touchstart',[point(100,100),point(200,100)]);emit(el,'touchend',[],[point(10,100)]);
 emit(el,'touchstart',[point(100,100)]);emit(el,'touchcancel');emit(el,'touchend',[],[point(10,100)]);
 assert.deepEqual(moves,[1,-1]);
});
test('마우스 드래그 및 트랙패드 가로 스크롤로 이동하고 세로 스크롤은 그대로 둔다',()=>{
 const el=new EventTarget(),moves=[];bindSwipeNavigation(el,n=>moves.push(n));
 const event=(type,fields)=>{const e=new Event(type,{cancelable:true});for(const [k,v] of Object.entries(fields))Object.defineProperty(e,k,{value:v});el.dispatchEvent(e);return e};
 const target={closest:()=>null};event('pointerdown',{pointerType:'mouse',button:0,pointerId:1,clientX:200,clientY:100,target});event('pointerup',{pointerId:1,clientX:80,clientY:105});
 const horizontal=event('wheel',{deltaX:-70,deltaY:1,timeStamp:1000});const vertical=event('wheel',{deltaX:1,deltaY:80,timeStamp:2000});
 assert.deepEqual(moves,[1,-1]);assert.equal(horizontal.defaultPrevented,true);assert.equal(vertical.defaultPrevented,false);
});
