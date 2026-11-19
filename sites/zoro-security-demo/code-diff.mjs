// Return literal text segments; the caller inserts text nodes, never HTML.
export function codeDiff(before,after){
 const tokens=text=>text.match(/[\p{L}\p{N}_$]+|\s+|[^\p{L}\p{N}_$\s]/gu)||[];
 const a=tokens(before),b=tokens(after);
 if(a.length*b.length>1000000){
  let start=0,endA=a.length,endB=b.length;
  while(start<endA&&start<endB&&a[start]===b[start])start++;
  while(endA>start&&endB>start&&a[endA-1]===b[endB-1]){endA--;endB--}
  const parts=(tokens,end)=>[[tokens.slice(0,start).join(''),false],[tokens.slice(start,end).join(''),true],[tokens.slice(end).join(''),false]].filter(([text])=>text).map(([text,changed])=>({text,changed}));
  return {before:parts(a,endA),after:parts(b,endB)};
 }
 const width=b.length+1,table=new Uint32Array((a.length+1)*width);
 for(let i=a.length-1;i>=0;i--)for(let j=b.length-1;j>=0;j--)table[i*width+j]=a[i]===b[j]?1+table[(i+1)*width+j+1]:Math.max(table[(i+1)*width+j],table[i*width+j+1]);
 const left=[],right=[];const push=(out,text,changed)=>{const last=out.at(-1);if(last&&last.changed===changed)last.text+=text;else out.push({text,changed})};
 let i=0,j=0;while(i<a.length||j<b.length){if(i<a.length&&j<b.length&&a[i]===b[j]){push(left,a[i++],false);push(right,b[j++],false)}else if(j<b.length&&(i===a.length||table[i*width+j+1]>table[(i+1)*width+j]))push(right,b[j++],true);else push(left,a[i++],true)}
 return {before:left,after:right};
}
