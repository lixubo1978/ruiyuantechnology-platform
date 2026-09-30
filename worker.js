// GitHub 根目录文件名：worker.js
// Secret：RUIYUAN_SUPABASE_URL、RUIYUAN_SUPABASE_SERVICE_ROLE_KEY
// 不把真实密钥写进代码，不把账号密码写入日志。
const COOKIE='__Host-ruiyuan_session';
const BASE='/api/ruiyuan';
const json=(data,status=200,extra={})=>new Response(JSON.stringify(data),{status,headers:{
  'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
  'X-Content-Type-Options':'nosniff',...extra}});
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const sha=async value=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))));
const equal=(a,b)=>{if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0};
const cookie=token=>`${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${token?28800:0}`;
function readToken(req){const raw=req.headers.get('Cookie')||'';for(const item of raw.split(';')){const [k,v]=item.trim().split('=');if(k===COOKIE&&/^[0-9a-f]{64}$/.test(v||''))return v}return ''}
function route(path,method){
  const fixed={
    'POST /employee':'employee','GET /session':'session','POST /login':'login','POST /logout':'logout',
    'GET /users':'users','POST /users':'create','POST /password':'password'
  };
  if(fixed[`${method} ${path}`])return {action:fixed[`${method} ${path}`]};
  const m=path.match(/^\/users\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(\/password)?$/i);
  if(m&&method==='PATCH'&&!m[2])return {action:'update',id:m[1]};
  if(m&&method==='POST'&&m[2])return {action:'reset',id:m[1]};return null;
}
async function readJSON(req,maxBytes=16384){
  if(!req.headers.get('Content-Type')?.toLowerCase().startsWith('application/json'))throw new Error('JSON_REQUIRED');
  if(Number(req.headers.get('Content-Length'))>maxBytes)throw new Error('TOO_LARGE');
  const reader=req.body?.getReader();if(!reader)throw new Error('BAD_JSON');
  const chunks=[];let size=0;
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new Error('TOO_LARGE')}chunks.push(value)}
  const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length}
  let v;try{v=JSON.parse(new TextDecoder().decode(bytes))}catch{throw new Error('BAD_JSON')}
  if(!v||typeof v!=='object'||Array.isArray(v))throw new Error('BAD_JSON');return v;
}
const PUBLIC_PAGES=new Set(['/introduction.html','/introduction','/introduction/','/ruiyuan_namesandpasswords.html','/ruiyuan_namesandpasswords','/ruiyuan_namesandpasswords/']);
function pageRedirect(path,clear=false){return new Response(null,{status:302,headers:{Location:path,'Cache-Control':'private, no-store',...(clear?{'Set-Cookie':cookie('')}:{})}})}
async function servePage(req,env){
 const response=await env.ASSETS.fetch(req);
 const headers=new Headers(response.headers);
 headers.set('Cache-Control','private, no-store');
 headers.set('X-Content-Type-Options','nosniff');
 headers.set('Referrer-Policy','same-origin');
 headers.set('Vary','Cookie');
 return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}
export default {
 async fetch(req,env){
  const url=new URL(req.url);
  // 所有静态访问先经过这里，只有展示页和登录页公开。
  if(url.pathname!==BASE&&!url.pathname.startsWith(BASE+'/')){
   if(url.protocol!=='https:'){url.protocol='https:';return new Response(null,{status:307,headers:{Location:url.href,'Cache-Control':'no-store'}})}
   if(url.pathname.startsWith('/api/'))return json({error:'接口不存在'},404);
   if(!['GET','HEAD'].includes(req.method))return json({error:'请求方法不支持'},405);
   if(PUBLIC_PAGES.has(url.pathname))return servePage(req,env);
   if(!readToken(req))return pageRedirect('/introduction.html');
   // 在当前 Worker 内复用现有会话接口，不通过网站 URL 发起循环请求。
   const session=await this.fetch(new Request(new URL(BASE+'/session',url),{
    headers:{Cookie:req.headers.get('Cookie')||''}
   }),env);
   if(session.status===401)return pageRedirect('/introduction.html',true);
   if(!session.ok)return new Response('暂时无法验证登录，请稍后刷新，或访问 /introduction.html 查看企业介绍。',{
    status:503,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}
   });
   let data;try{data=await session.json()}catch{return json({error:'登录验证暂不可用'},503)}
   if(data.user===null)return pageRedirect('/introduction.html',true);
   if(!data.user||typeof data.user.id!=='string'||typeof data.user.must_change_password!=='boolean')return json({error:'登录验证暂不可用'},503);
   if(data.user.must_change_password)return pageRedirect('/ruiyuan_namesandpasswords.html');
   if(['/ruiyuan_employee.html','/ruiyuan_employee','/ruiyuan_employee/'].includes(url.pathname))return pageRedirect('/employees.html');
   if(data.user.role==='employee'&&!['/employees.html','/employees','/employees/'].includes(url.pathname))return pageRedirect('/employees.html');
   return servePage(req,env);
  }
  try{
   if(url.protocol!=='https:')return json({error:'请使用 HTTPS 地址'},400);
   const match=route(url.pathname.slice(BASE.length),req.method);
   if(!match)return json({error:'瑞渊接口不存在或请求方法不正确'},404);
   if(req.method!=='GET'&&req.headers.get('Origin')!==url.origin)return json({error:'请求来源不匹配，请在当前网站重新打开页面'},403);
   if(!env.RUIYUAN_SUPABASE_URL||!env.RUIYUAN_SUPABASE_SERVICE_ROLE_KEY)
     return json({error:'后台已部署，但尚未配置 Supabase 地址和管理密钥'},503);
   const token=readToken(req);
   if(req.method!=='GET'&&match.action!=='login'){
     if(!token)return json({error:'请先登录'},401,{'Set-Cookie':cookie('')});
     if(!equal(req.headers.get('X-Ruiyuan-CSRF'),await sha('ruiyuan-csrf:'+token)))return json({error:'会话校验失败，请刷新页面后重试'},403);
   }
   const payload=req.method==='GET'?{}:await readJSON(req,match.action==='employee'?3000000:16384);
   if(match.id)payload.id=match.id;
   const loginToken=match.action==='login'?hex(crypto.getRandomValues(new Uint8Array(32))):'';
   const effectiveToken=loginToken||token;
   if(match.action==='login')payload.client_hash=await sha(req.headers.get('CF-Connecting-IP')||'unknown');
   const base=new URL(env.RUIYUAN_SUPABASE_URL.trim());
   if(base.protocol!=='https:'||base.username||base.password)throw new Error('BAD_CONFIG');
   const key=env.RUIYUAN_SUPABASE_SERVICE_ROLE_KEY.trim();
   // 支持服务端 secret key，也支持 legacy service_role JWT。
   const headers={'Content-Type':'application/json',apikey:key};
   if(key.startsWith('eyJ'))headers.Authorization='Bearer '+key;
   let response;
   try{response=await fetch(new URL('/rest/v1/rpc/'+(match.action==='employee'?'ruiyuan_employee_api':'ruiyuan_people_api'),base),{
     method:'POST',headers,body:JSON.stringify({p_action:match.action==='employee'?payload.op:match.action,
       p_token_hash:effectiveToken?await sha(effectiveToken):null,p_payload:payload}),
     signal:AbortSignal.timeout(15000)
   })}catch{ return json({error:'数据库连接超时或不可用；结果未确认，请先刷新核对，避免重复提交'},503)}
   if(!response.ok){
     // 不打印响应正文，数据库错误详情可能包含用户提交的密码。
     if(response.status===404)return json({error:'未找到数据库后台函数，请安装人员接口及员工模块数据库 SQL'},503);
     if(response.status===401||response.status===403)return json({error:'Supabase 服务端密钥或接口权限不正确，请检查 Cloudflare 加密变量'},503);
     return json({error:'数据库接口执行失败，请检查瑞渊表结构和接口 SQL'},503);
   }
   const data=await response.json();
   if(!data||typeof data!=='object'||!Number.isInteger(data.status))return json({error:'后台响应格式不正确'},503);
   const status=data.status;delete data.status;
   const extra={};
   if(status===200&&match.action==='login'){
     extra['Set-Cookie']=cookie(loginToken);data.csrf_token=await sha('ruiyuan-csrf:'+loginToken);
   }else if(status===200&&match.action==='session'&&data.user&&token){data.csrf_token=await sha('ruiyuan-csrf:'+token)}
   if(status===401||data.clear_session||(status===200&&match.action==='logout')||(match.action==='session'&&!data.user))extra['Set-Cookie']=cookie('');
   delete data.clear_session;
   if(status===429)extra['Retry-After']='900';
   return json(data,status,extra);
  }catch(e){
    if(['BAD_JSON','JSON_REQUIRED'].includes(e.message))return json({error:'请求必须是 JSON 数据'},400);
    if(e.message==='TOO_LARGE')return json({error:'提交内容过大'},413);
    return json({error:'瑞渊后台暂不可用，请检查配置后重试'},503);
  }
 }
};
