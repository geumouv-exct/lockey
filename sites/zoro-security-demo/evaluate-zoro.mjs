import {scanProject} from './project-scan.mjs';
import {chooseProjectReview} from './zoro.mjs';
import {reviewProject} from './project-review.mjs';

// Hand-labeled examples: the expected choice has a supported, independently
// inspected change. The baseline always chooses HTML when present, then SQL.
const cases=[
 {name:'html-only',text:'function render(req,el){el.innerHTML = req.query.text;}',expected:'review_html'},
 {name:'sql-only',text:'import pg from "pg"; const db=new pg.Pool(); function find(req){return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)}',expected:'review_sql'},
 {name:'mixed-only-html-patchable',text:'function show(req,db,el){db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);el.innerHTML=req.query.text;}',expected:'review_html'},
 {name:'mixed-only-sql-patchable',text:'import pg from "pg"; const db=new pg.Pool(); function find(req){return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)}\nfunction show(req,el){el.innerHTML=req.query.text;}',expected:'both'}
];
const choices={'review_html':'dangerous-html','review_sql':'sql-interpolation'};
let modelSuccess=0,baselineSuccess=0,connected=0;
for(const c of cases){
 const files=[{path:'src/app.js',text:c.text}];const {findings}=scanProject(files);
 const baseline=findings.some(f=>f.id==='dangerous-html')?'review_html':'review_sql';
 const decision=await chooseProjectReview(findings,{url:process.env.ZORO_DECIDE_URL,expectedRevision:process.env.ZORO_EXPECTED_REVISION});
 function evaluate(choice){if(!choices[choice])return false;const verdict=reviewProject(files,findings,choice);return verdict.status==='completed'&&(c.expected==='both'||c.expected===choice)}
 const b=evaluate(baseline),m=decision.status==='connected'&&evaluate(decision.choice);baselineSuccess+=Number(b);modelSuccess+=Number(m);connected+=Number(decision.status==='connected');
 console.log(JSON.stringify({case:c.name,expected:c.expected,baseline,baseline_supported:b,model_status:decision.status,model_choice:decision.choice||null,model_supported:m,revision:decision.reported_model||null}));
}
console.log(JSON.stringify({cases:cases.length,model_connected:connected,baseline_success:baselineSuccess,model_success:modelSuccess,note:'수정안 생성 가능 여부를 평가한 소규모 합성 사례이며 실제 악용 또는 보안 개선을 입증하지 않습니다.'}));
