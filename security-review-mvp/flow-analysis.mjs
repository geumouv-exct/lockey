import acorn from './vendor/acorn/parser.mjs';
import babel from './vendor/babel-parser/parser.mjs';

// A small, deliberately bounded same-file JS analysis. It does not execute code.
// Express-like route registrations are potential entry points, not proof of exposure.
export function analyzeFlows(path,text){
 if(!/\.[cm]?js$/i.test(path)||text.length>200000)return [];
 let ast;try{ast=acorn.parse(text,{ecmaVersion:'latest',sourceType:'module',locations:true,allowHashBang:true})}catch{return []}
 const functions=new Map(),results=[],seen=new Set();let steps=0;
 for(const node of ast.body){
  if(node.type==='FunctionDeclaration'&&node.id)functions.set(node.id.name,node);
  if(node.type==='VariableDeclaration')for(const d of node.declarations)if(d.id.type==='Identifier'&&['ArrowFunctionExpression','FunctionExpression'].includes(d.init?.type))functions.set(d.id.name,d.init);
 }
 const empty=()=>({tainted:false});
 function analyzeFunction(fn,args,ctx,depth){
  if(!fn||depth>6||steps>50000)return empty();
  const vars=new Map();fn.params.forEach((p,i)=>{if(p.type==='Identifier')vars.set(p.name,args[i]||empty())});
  if(fn.body.type==='BlockStatement')return statements(fn.body.body,vars,ctx,depth);
  return evaluate(fn.body,vars,ctx,depth);
 }
 function report(kind,node,value,ctx){
  if(!value.tainted||results.length>=100||value.sourceKind!==(kind==='request_to_sql'?'request':'location'))return;
  const line=node.loc.start.line,sourceLine=value.sourceLine,routeLine=ctx.routeLine||0;
  const key=`${kind}:${line}:${sourceLine}:${routeLine}`;if(seen.has(key))return;seen.add(key);
  results.push({kind,line,sourceLine,routeLine});
 }
 function evaluate(node,vars,ctx,depth){
  if(!node||++steps>50000)return empty();
  switch(node.type){
   case 'Identifier':return vars.get(node.name)||empty();
   case 'Literal':return empty();
   case 'MemberExpression':{
    if(!node.computed&&node.object.type==='Identifier'&&node.object.name==='window'&&node.property.name==='location')return {browserLocation:true};
    const obj=evaluate(node.object,vars,ctx,depth);const prop=!node.computed?node.property.name:node.property.value;
    if(obj.request&&['query','params','body'].includes(prop))return {tainted:true,sourceKind:'request',sourceLine:node.loc.start.line};
    if(obj.browserLocation&&['hash','search'].includes(prop))return {tainted:true,sourceKind:'location',sourceLine:node.loc.start.line};
    return obj.tainted?obj:empty();
   }
   case 'TemplateLiteral':case 'BinaryExpression':case 'LogicalExpression':{
    const parts=node.type==='TemplateLiteral'?node.expressions:[node.left,node.right];
    for(const part of parts){const val=evaluate(part,vars,ctx,depth);if(val.tainted)return val}return empty();
   }
   case 'AwaitExpression':return evaluate(node.argument,vars,ctx,depth);
   case 'AssignmentExpression':{
    const val=evaluate(node.right,vars,ctx,depth);
    if(node.left.type==='Identifier')vars.set(node.left.name,val);
    if(node.left.type==='MemberExpression'&&!node.left.computed&&node.left.property.name==='innerHTML')report('location_to_html',node,val,ctx);
    return val;
   }
   case 'CallExpression':{
    const vals=node.arguments.map(a=>evaluate(a,vars,ctx,depth));
    if(node.callee.type==='MemberExpression'&&!node.callee.computed&&['query','execute'].includes(node.callee.property.name))report('request_to_sql',node,vals[0]||empty(),ctx);
    if(node.callee.type==='Identifier'&&functions.has(node.callee.name))return analyzeFunction(functions.get(node.callee.name),vals,ctx,depth+1);
    // Unknown functions may sanitize or transform inputs; do not infer through them.
    return empty();
   }
   default:return empty();
  }
 }
 function statements(nodes,vars,ctx,depth){
  let returned=empty();
  for(const n of nodes){if(++steps>50000)break;
   if(n.type==='VariableDeclaration'){for(const d of n.declarations)if(d.id.type==='Identifier')vars.set(d.id.name,evaluate(d.init,vars,ctx,depth));}
   else if(n.type==='ExpressionStatement')evaluate(n.expression,vars,ctx,depth);
   else if(n.type==='ReturnStatement'){returned=evaluate(n.argument,vars,ctx,depth);break;}
   // Branches and loops are intentionally not modeled to avoid inventing a path.
  }return returned;
 }
 for(const n of ast.body){
  if(n.type!=='ExpressionStatement'||n.expression.type!=='CallExpression')continue;
  const call=n.expression,callee=call.callee;
  if(callee.type!=='MemberExpression'||callee.computed||!['get','post','put','patch','delete','all'].includes(callee.property.name)||call.arguments.length<2||call.arguments[0].type!=='Literal'||typeof call.arguments[0].value!=='string')continue;
  // Middleware may enforce access; the analysis intentionally makes no access claim.
  const candidate=call.arguments.at(-1);const fn=candidate.type==='Identifier'?functions.get(candidate.name):candidate;
  if(fn&&['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(fn.type))analyzeFunction(fn,[{request:true},empty()],{routeLine:n.loc.start.line},0);
 }
 // Browser sources at top level, without treating every function as reachable.
 statements(ast.body,new Map(),{},0);
 return results;
}

// Project-level, bounded may-flow analysis for static ESM imports and Express-like
// routes. Results are possibilities, not proof that branches or routes execute.
export function analyzeProjectFlows(files){
 const modules=new Map(),out=[],seen=new Set();let steps=0;
 const valid=files.filter(f=>typeof f.path==='string'&&typeof f.text==='string'&&/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(f.path)&&f.text.length<=200000).slice(0,200);
 for(const file of valid){
  let ast;try{const plugins=['estree'];if(/\.[cm]?tsx?$/i.test(file.path))plugins.push('typescript');if(/\.[jt]sx$/i.test(file.path))plugins.push('jsx');ast=babel.parse(file.text,{sourceType:'unambiguous',plugins,createImportExpressions:true}).program}catch{continue}
  const m={path:file.path,ast,funcs:new Map(),imports:new Map(),namespaces:new Map(),exports:new Map(),listeners:new Map(),middlewareOwners:new Set(),basicFactories:new Set(),staticBasic:new Map()};modules.set(file.path,m);
  for(const raw of ast.body)if(raw.type==='ImportDeclaration'&&raw.source.value==='express-basic-auth')for(const sp of raw.specifiers)if(sp.type==='ImportDefaultSpecifier')m.basicFactories.add(sp.local.name);
  for(const raw of ast.body){const n=raw.type==='ExportNamedDeclaration'||raw.type==='ExportDefaultDeclaration'?raw.declaration:raw;
   if(n?.type==='FunctionDeclaration'&&n.id){m.funcs.set(n.id.name,n);if(raw!==n)m.exports.set(raw.type==='ExportDefaultDeclaration'?'default':n.id.name,n.id.name)}
   if(n?.type==='VariableDeclaration')for(const d of n.declarations)if(d.id.type==='Identifier'&&['ArrowFunctionExpression','FunctionExpression'].includes(d.init?.type)){m.funcs.set(d.id.name,d.init);if(raw!==n)m.exports.set(d.id.name,d.id.name)}
   if(n?.type==='VariableDeclaration')for(const d of n.declarations){const c=d.init;if(c?.type!=='CallExpression'||c.callee.type!=='Identifier'||c.callee.name!=='require'||c.arguments.length!==1||c.arguments[0].type!=='Literal'||typeof c.arguments[0].value!=='string'||!c.arguments[0].value.startsWith('.'))continue;const from=c.arguments[0].value;if(d.id.type==='Identifier')m.namespaces.set(d.id.name,from);else if(d.id.type==='ObjectPattern')for(const p of d.id.properties)if(p.type==='Property'&&!p.computed&&p.value.type==='Identifier')m.imports.set(p.value.name,{from,name:p.key.name||p.key.value})}
   if(n?.type==='VariableDeclaration'&&n.kind==='const')for(const d of n.declarations){const c=d.init;if(d.id.type!=='Identifier'||c?.type!=='CallExpression'||c.callee.type!=='Identifier'||!m.basicFactories.has(c.callee.name))continue;const opt=c.arguments[0];if(opt?.type!=='ObjectExpression'||opt.properties.some(p=>p.type!=='Property'||p.computed||['authorizer','authorizeAsync'].includes(p.key.name||p.key.value)))continue;const users=opt.properties.find(p=>p.type==='Property'&&!p.computed&&(p.key.name||p.key.value)==='users')?.value;if(users?.type==='ObjectExpression'&&users.properties.length>0&&users.properties.every(p=>p.type==='Property'&&!p.computed&&p.value.type==='Literal'&&typeof p.value.value==='string'))m.staticBasic.set(d.id.name,d.loc.start.line)}
   if(raw.type==='ExportNamedDeclaration'&&!raw.source)for(const x of raw.specifiers)m.exports.set(x.exported.name,x.local.name);
   if(raw.type==='ExportDefaultDeclaration'&&n?.type==='Identifier')m.exports.set('default',n.name);
   if(raw.type==='ExpressionStatement'&&raw.expression.type==='AssignmentExpression'){
    const a=raw.expression,l=a.left;
    if(l.type==='MemberExpression'&&!l.computed&&l.object.type==='Identifier'&&l.object.name==='exports'){
     if(a.right.type==='Identifier')m.exports.set(l.property.name,a.right.name);
     else if(['FunctionExpression','ArrowFunctionExpression'].includes(a.right.type)){const name=`#export:${l.property.name}`;m.funcs.set(name,a.right);m.exports.set(l.property.name,name)}
    }
    if(l.type==='MemberExpression'&&!l.computed&&l.object.type==='Identifier'&&l.object.name==='module'&&l.property.name==='exports'){
     if(a.right.type==='Identifier')m.exports.set('default',a.right.name);
     if(['FunctionExpression','ArrowFunctionExpression'].includes(a.right.type)){m.funcs.set('#default',a.right);m.exports.set('default','#default')}
     if(a.right.type==='ObjectExpression')for(const p of a.right.properties)if(p.type==='Property'&&!p.computed&&p.value.type==='Identifier')m.exports.set(p.key.name||p.key.value,p.value.name);
    }
   }
   if(raw.type==='ImportDeclaration'&&typeof raw.source.value==='string'&&raw.source.value.startsWith('.'))for(const spec of raw.specifiers){if(spec.type==='ImportSpecifier')m.imports.set(spec.local.name,{from:raw.source.value,name:spec.imported.name});else if(spec.type==='ImportDefaultSpecifier')m.imports.set(spec.local.name,{from:raw.source.value,name:'default'})}
   if(raw.type==='ExpressionStatement'&&raw.expression.type==='CallExpression'){
    const c=raw.expression, cal=c.callee;if(cal.type==='MemberExpression'&&!cal.computed&&cal.object.type==='Identifier'&&cal.property.name==='use')m.middlewareOwners.add(cal.object.name);
    if(cal.type==='MemberExpression'&&!cal.computed&&cal.object.type==='Identifier'&&cal.property.name==='listen'){
     const host=c.arguments[1];if(host?.type==='Literal'&&typeof host.value==='string'){if(['127.0.0.1','::1','localhost'].includes(host.value))m.listeners.set(cal.object.name,'loopback');else if(['0.0.0.0','::'].includes(host.value))m.listeners.set(cal.object.name,'wildcard')}
    }
   }
  }
 }
 function resolve(from,rel){const parts=from.split('/');parts.pop();for(const p of rel.split('/')){if(p==='.'||!p)continue;if(p==='..'){if(!parts.length)return null;parts.pop()}else parts.push(p)}const base=parts.join('/');for(const p of [base,base+'.js',base+'.mjs',base+'.cjs',base+'.ts',base+'.tsx',base+'.jsx',base+'/index.js',base+'/index.ts'])if(modules.has(p))return modules.get(p);return null}
 function lookup(mod,name){if(mod.funcs.has(name))return {mod,fn:mod.funcs.get(name)};const imp=mod.imports.get(name);if(!imp)return null;const target=resolve(mod.path,imp.from),local=target?.exports.get(imp.name);return local&&target.funcs.has(local)?{mod:target,fn:target.funcs.get(local)}:null}
 const empty=()=>({tainted:false});
 const mergeVal=(a,b)=>a?.tainted?a:b?.tainted?b:(a?.request?a:b?.request?b:empty());
 function mergeEnv(a,b){for(const key of new Set([...a.keys(),...b.keys()]))a.set(key,mergeVal(a.get(key),b.get(key)))}
 function runFunction(ref,args,ctx,depth){if(!ref?.fn||depth>6||steps>100000)return empty();const vars=new Map();for(const [name,from] of ref.mod.namespaces){const target=resolve(ref.mod.path,from);if(target)vars.set(name,{namespace:target.path})}ref.fn.params.forEach((p,i)=>{if(p.type==='Identifier')vars.set(p.name,args[i]||empty())});return ref.fn.body.type==='BlockStatement'?statements(ref.mod,ref.fn.body.body,vars,ctx,depth):evalNode(ref.mod,ref.fn.body,vars,ctx,depth)}
 function report(mod,n,v,ctx){if(!v.tainted||v.kind!=='request'||out.length>=100||!ctx.routePath)return;const e={kind:'request_to_sql_project',line:n.loc.start.line,sourceLine:v.line,sourcePath:v.path,routeLine:ctx.routeLine,routePath:ctx.routePath,sinkPath:mod.path,listener:ctx.listener,middleware:ctx.middleware,auth:ctx.auth,authLine:ctx.authLine,route:ctx.route};const key=JSON.stringify(e);if(!seen.has(key)){seen.add(key);out.push(e)}}
 function evalNode(mod,n,vars,ctx,depth){if(!n||++steps>100000)return empty();switch(n.type){
  case 'Identifier':return vars.get(n.name)||empty();
  case 'ImportExpression':{const src=n.source;if(src?.type==='Literal'&&typeof src.value==='string'&&src.value.startsWith('.')){const target=resolve(mod.path,src.value);if(target)return {namespace:target.path}}return empty()}
  case 'TSAsExpression':case 'TSTypeAssertion':case 'TSNonNullExpression':return evalNode(mod,n.expression,vars,ctx,depth);
  case 'MemberExpression':{const v=evalNode(mod,n.object,vars,ctx,depth),prop=n.computed?n.property.value:n.property.name;if(v.request&&['query','params','body'].includes(prop))return {tainted:true,kind:'request',path:mod.path,line:n.loc.start.line};return v.tainted?v:empty()}
  case 'TemplateLiteral':case 'BinaryExpression':case 'LogicalExpression':case 'ConditionalExpression':{const xs=n.type==='TemplateLiteral'?n.expressions:n.type==='ConditionalExpression'?[n.consequent,n.alternate]:[n.left,n.right];return xs.reduce((acc,x)=>mergeVal(acc,evalNode(mod,x,vars,ctx,depth)),empty())}
  case 'AwaitExpression':return evalNode(mod,n.argument,vars,ctx,depth);
  case 'AssignmentExpression':{const v=evalNode(mod,n.right,vars,ctx,depth);if(n.left.type==='Identifier')vars.set(n.left.name,v);return v}
  case 'CallExpression':{
   if(n.callee.type==='Identifier'&&n.callee.name==='require'&&n.arguments.length===1&&n.arguments[0].type==='Literal'&&typeof n.arguments[0].value==='string'&&n.arguments[0].value.startsWith('.')){const target=resolve(mod.path,n.arguments[0].value);return target?{namespace:target.path}:empty()}
   const args=n.arguments.map(x=>evalNode(mod,x,vars,ctx,depth));if(n.callee.type==='MemberExpression'&&!n.callee.computed&&['query','execute'].includes(n.callee.property.name))report(mod,n,args[0]||empty(),ctx);
   if(n.callee.type==='Identifier'){const v=vars.get(n.callee.name);if(v?.namespace){const target=modules.get(v.namespace),local=target?.exports.get('default');if(local)return runFunction({mod:target,fn:target.funcs.get(local)},args,ctx,depth+1)}if(v?.reference){const target=modules.get(v.reference.path),local=target?.exports.get(v.reference.name);if(local)return runFunction({mod:target,fn:target.funcs.get(local)},args,ctx,depth+1)}return runFunction(lookup(mod,n.callee.name),args,ctx,depth+1)}
   if(n.callee.type==='MemberExpression'&&!n.callee.computed){const v=evalNode(mod,n.callee.object,vars,ctx,depth);if(v.namespace){const target=modules.get(v.namespace),local=target?.exports.get(n.callee.property.name);if(local)return runFunction({mod:target,fn:target.funcs.get(local)},args,ctx,depth+1)}}return empty()}
  default:return empty();
 }}
 function statements(mod,nodes,vars,ctx,depth){let ret=empty();for(const n of nodes){if(++steps>100000)break;switch(n.type){
  case 'VariableDeclaration':for(const d of n.declarations){const value=evalNode(mod,d.init,vars,ctx,depth);if(d.id.type==='Identifier')vars.set(d.id.name,value);else if(d.id.type==='ObjectPattern'&&value.namespace)for(const p of d.id.properties)if(p.type==='Property'&&!p.computed&&p.value.type==='Identifier')vars.set(p.value.name,{reference:{path:value.namespace,name:p.key.name||p.key.value}})}break;
  case 'ExpressionStatement':evalNode(mod,n.expression,vars,ctx,depth);break;
  case 'ReturnStatement':ret=mergeVal(ret,evalNode(mod,n.argument,vars,ctx,depth));return ret;
  case 'BlockStatement':ret=mergeVal(ret,statements(mod,n.body,vars,ctx,depth));break;
  case 'IfStatement':{const yes=new Map(vars),no=new Map(vars);const visit=(node,env)=>node?statements(mod,node.type==='BlockStatement'?node.body:[node],env,ctx,depth):empty();ret=mergeVal(ret,mergeVal(visit(n.consequent,yes),visit(n.alternate,no)));mergeEnv(yes,no);mergeEnv(vars,yes);break}
  case 'ForStatement':case 'ForOfStatement':case 'ForInStatement':case 'WhileStatement':case 'DoWhileStatement':{const before=new Map(vars),loop=new Map(vars);if(n.init?.type==='VariableDeclaration')statements(mod,[n.init],loop,ctx,depth);else if(n.init)evalNode(mod,n.init,loop,ctx,depth);for(let i=0;i<3;i++){statements(mod,n.body.type==='BlockStatement'?n.body.body:[n.body],loop,ctx,depth);if(n.update)evalNode(mod,n.update,loop,ctx,depth)}mergeEnv(before,loop);mergeEnv(vars,before);break}
 }}return ret}
 for(const mod of modules.values())for(const n of mod.ast.body){if(n.type!=='ExpressionStatement'||n.expression.type!=='CallExpression')continue;const call=n.expression,c=call.callee;if(c.type!=='MemberExpression'||c.computed||!['get','post','put','patch','delete','all'].includes(c.property.name)||call.arguments.length<2||call.arguments[0].type!=='Literal'||typeof call.arguments[0].value!=='string')continue;const handler=call.arguments.at(-1),ref=handler.type==='Identifier'?lookup(mod,handler.name):['FunctionExpression','ArrowFunctionExpression'].includes(handler.type)?{mod,fn:handler}:null;const guard=call.arguments.slice(1,-1).find(a=>a.type==='Identifier'&&mod.staticBasic.has(a.name));runFunction(ref,[{request:true},empty()],{routePath:mod.path,routeLine:n.loc.start.line,listener:c.object.type==='Identifier'?(mod.listeners.get(c.object.name)||'unknown'):'unknown',middleware:(c.object.type==='Identifier'&&mod.middlewareOwners.has(c.object.name))||call.arguments.length>2,auth:guard?'static-basic':'unknown',authLine:guard?mod.staticBasic.get(guard.name):0,route:c.property.name==='get'&&/^\/(?:[A-Za-z0-9_-]+\/?)*$/.test(call.arguments[0].value)&&call.arguments[0].value.length<=128?call.arguments[0].value:''},0)}
 return out;
}
