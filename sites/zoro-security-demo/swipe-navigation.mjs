// Support single-finger touch, mouse drag, and horizontal trackpad gestures.
export function bindSwipeNavigation(element, move){
 let start=null,mouse=null,wheelDistance=0,wheelTime=0,wheelTrigger=-Infinity;
 const horizontal=(dx,dy)=>Math.abs(dx)>55&&Math.abs(dx)>Math.abs(dy)*1.3;
 const finish=(point,origin)=>{const dx=point.x-origin.x,dy=point.y-origin.y;if(horizontal(dx,dy))move(dx<0?1:-1)};
 element.addEventListener('touchstart',event=>{
  start=event.touches.length===1?{x:event.touches[0].clientX,y:event.touches[0].clientY}:null;
 },{passive:true});
 element.addEventListener('touchcancel',()=>{start=null},{passive:true});
 element.addEventListener('touchend',event=>{
  if(!start||!event.changedTouches.length)return;
  const point={x:event.changedTouches[0].clientX,y:event.changedTouches[0].clientY},origin=start;
  start=null;finish(point,origin);
 },{passive:true});
 element.addEventListener('pointerdown',event=>{
  if(event.pointerType!=='mouse'||event.button!==0||event.target.closest?.('button'))return;
  mouse={x:event.clientX,y:event.clientY,id:event.pointerId};
  element.setPointerCapture?.(event.pointerId);
 });
 element.addEventListener('pointercancel',()=>{mouse=null});
 element.addEventListener('pointerup',event=>{
  if(!mouse||event.pointerId!==mouse.id)return;
  const origin=mouse;mouse=null;finish({x:event.clientX,y:event.clientY},origin);
 });
 element.addEventListener('wheel',event=>{
  if(Math.abs(event.deltaX)<=Math.abs(event.deltaY)*1.3)return;
  if(event.timeStamp-wheelTrigger<400){event.preventDefault();return}
  if(event.timeStamp-wheelTime>300)wheelDistance=0;
  wheelTime=event.timeStamp;wheelDistance+=event.deltaX;
  if(Math.abs(wheelDistance)>55){move(wheelDistance>0?1:-1);wheelDistance=0;wheelTrigger=event.timeStamp}
  event.preventDefault();
 },{passive:false});
}
