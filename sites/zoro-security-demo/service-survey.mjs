// Project-wide statements from the setup wizard, never evidence about a specific line of code.
export const surveyTopics = [
 {key:'login', question:'어떤 방식으로 로그인하나요?', options:{
  password:'아이디 또는 이메일과 비밀번호', social:'소셜 로그인', both:'두 방식 모두', other:'다른 방식'}},
 {key:'private', question:'비공개 정보는 누가 볼 수 있어야 하나요?', options:{
  owner:'작성자 본인', group:'초대한 사람이나 같은 팀', role:'관리자 등 지정된 역할', varies:'정보마다 달라요'}},
 {key:'input', question:'방문자가 어떤 내용을 올릴 수 있나요?', options:{
  text:'글이나 댓글', file:'파일이나 이미지', both:'글과 파일 모두'}}
];
export function needsDetail(answer){
 return answer==='yes'||answer==='unknown';
}
export function detailOptions(topic,answer){
 return {...topic.options,...(answer==='unknown'?{none:'해당 기능이 없어요'}:{}),unknown:'잘 모르겠어요'};
}
export function surveyContext(profile){
 if(profile===undefined)return []; // Older clients and scans without the setup wizard.
 return surveyTopics.map(topic=>{
  const answer=profile?.[topic.key]?.answer;
  if(!['yes','no','unknown'].includes(answer))throw Error('서비스 기능을 모두 선택해 주세요.');
  if(!needsDetail(answer))return {feature:topic.key,answer};
  const detail=profile[topic.key].detail;
  if(typeof detail!=='string'||!Object.hasOwn(detailOptions(topic,answer),detail))throw Error('추가 정보를 선택해 주세요.');
  return {feature:topic.key,answer,detail};
 });
}
