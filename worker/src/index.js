const cors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
});
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {
  status, headers: {"Content-Type":"application/json; charset=utf-8", ...headers}
});
const uid = () => crypto.randomUUID();
const enc = new TextEncoder();
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const hex = (buf) => [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function digest(value) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(value))); }
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:310000,hash:"SHA-256"},key,256));
}
async function makePassword(password) { const salt=b64(crypto.getRandomValues(new Uint8Array(16))); return {salt,hash:await passwordHash(password,salt)}; }
const clean = (s,max=180) => String(s??"").trim().slice(0,max);
async function body(req) { return await req.json(); }
function validMatric(v) { return /^[0-9]{9}$/.test(String(v||"")); }
function surname(full) { const parts=clean(full,180).split(/\s+/).filter(Boolean); return parts.length ? parts[parts.length-1] : ""; }
async function sessionUser(req,env) {
  const token=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  if(!token) return null;
  const row=await env.DB.prepare("SELECT user_id,user_type,expires_at FROM sessions WHERE token_hash=?").bind(await digest(token)).first();
  if(!row || row.expires_at < Math.floor(Date.now()/1000)) return null;
  const table=row.user_type==="admin"?"admins":"students";
  const user=await env.DB.prepare(`SELECT * FROM ${table} WHERE id=?`).bind(row.user_id).first();
  if(!user || (row.user_type==="admin" && !user.active)) return null;
  return {type:row.user_type,user};
}
async function requireAdmin(req,env) { const s=await sessionUser(req,env); return s?.type==="admin"?s:null; }
async function audit(env,admin,action,target="",details="") {
  await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,target_id,details) VALUES(?,?,?,?,?)")
    .bind(uid(),admin.user.id,action,target,clean(details,500)).run();
}
async function activeElection(env) {
  const setting=await env.DB.prepare("SELECT value FROM settings WHERE key='active_election_id'").first();
  if(setting?.value) return await env.DB.prepare("SELECT * FROM elections WHERE id=?").bind(setting.value).first();
  return await env.DB.prepare("SELECT * FROM elections ORDER BY created_at DESC LIMIT 1").first();
}
async function publicCandidates(env,electionId) {
  const r=await env.DB.prepare(`SELECT c.id,c.full_name,c.political_name,c.department,c.photo_key,c.manifesto,c.manifesto_key,c.position_id,p.title AS position_title
    FROM candidates c JOIN positions p ON p.id=c.position_id
    WHERE c.election_id=? AND c.approval_status='approved' ORDER BY p.display_order,c.full_name`).bind(electionId).all();
  return r.results||[];
}
async function handle(req,env) {
  const url=new URL(req.url), path=url.pathname.replace(/\/+$/,"")||"/", method=req.method;
  if(method==="OPTIONS") return new Response(null,{status:204});
  if(path==="/api/health") return json({ok:true,service:"ECSA election API"});
  if(path==="/api/setup-admin" && method==="POST") {
    if(!env.ADMIN_SETUP_KEY || req.headers.get("X-Setup-Key")!==env.ADMIN_SETUP_KEY) return json({error:"Not authorized."},403);
    const data=await body(req), role=clean(data.role,30);
    if(!["president","election_chairman"].includes(role)) return json({error:"Invalid official role."},400);
    const fullName=clean(data.fullName),email=clean(data.email,180).toLowerCase(),password=String(data.password||"");
    if(!fullName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<12) return json({error:"Provide a name, valid email and password of at least 12 characters."},400);
    const existing=await env.DB.prepare("SELECT id FROM admins WHERE role=?").bind(role).first();
    if(existing) return json({error:"An account for this official role already exists. Use the secure account recovery process."},409);
    const p=await makePassword(password);
    await env.DB.prepare("INSERT INTO admins(id,full_name,email,role,password_hash,password_salt) VALUES(?,?,?,?,?,?)")
      .bind(uid(),fullName,email,role,p.hash,p.salt).run();
    return json({ok:true,message:"Administrator account created."},201);
  }
  if(path==="/api/register" && method==="POST") {
    const d=await body(req), full=clean(d.fullName),matric=clean(d.matric,9),email=clean(d.email,180).toLowerCase(),level=clean(d.level,3);
    if(!full || !validMatric(matric) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !["100","200","300","400","500"].includes(level)) return json({error:"Check all registration fields. Matric number must contain exactly 9 digits."},400);
    const pass=surname(full).toLowerCase(); if(pass.length<2) return json({error:"Enter your complete name, including surname."},400);
    const p=await makePassword(pass);
    try {
      await env.DB.prepare("INSERT INTO students(id,full_name,matric,email,level,password_hash,password_salt) VALUES(?,?,?,?,?,?,?)")
        .bind(uid(),full,matric,email,level,p.hash,p.salt).run();
    } catch { return json({error:"That matriculation number or email address is already registered."},409); }
    return json({ok:true,message:"Registration successful. Your initial password is your surname."},201);
  }
  if(path==="/api/login" && method==="POST") {
    const d=await body(req),matric=clean(d.matric,9),password=String(d.password||"");
    if(!validMatric(matric)||!password) return json({error:"Enter your 9-digit matric number and password."},400);
    const user=await env.DB.prepare("SELECT * FROM students WHERE matric=?").bind(matric).first();
    if(!user || await passwordHash(password.toLowerCase(),user.password_salt)!==user.password_hash) return json({error:"Incorrect matriculation number or password."},401);
    return await issueSession(env,user,"student");
  }
  if(path==="/api/admin/login" && method==="POST") {
    const d=await body(req),email=clean(d.email,180).toLowerCase(),password=String(d.password||"");
    const user=await env.DB.prepare("SELECT * FROM admins WHERE email=? AND active=1").bind(email).first();
    if(!user || await passwordHash(password,user.password_salt)!==user.password_hash) return json({error:"Invalid administrator credentials."},401);
    return await issueSession(env,user,"admin");
  }
  if(path==="/api/logout" && method==="POST") {
    const token=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
    if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ok:true});
  }
  if(path==="/api/public" && method==="GET") {
    const election=await activeElection(env);
    if(!election) return json({election:null,positions:[],candidates:[]});
    const positions=(await env.DB.prepare("SELECT * FROM positions WHERE election_id=? ORDER BY display_order,title").bind(election.id).all()).results||[];
    const candidates=await publicCandidates(env,election.id);
    return json({election:{id:election.id,title:election.title,status:election.status,results_mode:election.results_mode,results_published:election.results_published},positions,candidates});
  }
  if(path==="/api/manifesto" && method==="GET") {
    const id=url.searchParams.get("id");
    const row=await env.DB.prepare("SELECT manifesto_key FROM candidates WHERE id=? AND approval_status='approved'").bind(id).first();
    if(!row?.manifesto_key) return json({error:"No PDF manifesto is available."},404);
    const obj=await env.FILES.get(row.manifesto_key); if(!obj) return json({error:"File not found."},404);
    return new Response(obj.body,{headers:{"Content-Type":"application/pdf","Content-Disposition":"inline","Cache-Control":"public, max-age=300"}});
  }
  if(path==="/api/me" && method==="GET") {
    const s=await sessionUser(req,env); if(!s) return json({error:"Please sign in."},401);
    const u=s.user;
    return json({type:s.type,user:s.type==="student"?{id:u.id,full_name:u.full_name,matric:u.matric,email:u.email,level:u.level}:{id:u.id,full_name:u.full_name,email:u.email,role:u.role}});
  }
  if(path==="/api/votes" && method==="GET") {
    const s=await sessionUser(req,env); if(!s||s.type!=="student") return json({error:"Student sign-in required."},401);
    const e=await activeElection(env); if(!e) return json({voted:[]});
    const rows=await env.DB.prepare("SELECT position_id FROM vote_receipts WHERE election_id=? AND voter_id=?").bind(e.id,s.user.id).all();
    return json({voted:(rows.results||[]).map(x=>x.position_id)});
  }
  if(path==="/api/vote" && method==="POST") {
    const s=await sessionUser(req,env); if(!s||s.type!=="student") return json({error:"Student sign-in required."},401);
    const d=await body(req),e=await activeElection(env);
    if(!e||e.status!=="ongoing") return json({error:"Voting is not currently open."},403);
    const candidate=await env.DB.prepare("SELECT id,position_id,election_id FROM candidates WHERE id=? AND approval_status='approved'").bind(clean(d.candidateId,80)).first();
    if(!candidate||candidate.election_id!==e.id) return json({error:"Invalid candidate."},400);
    const receiptId=uid(),ballotId=uid();
    const results=await env.DB.batch([
      env.DB.prepare("INSERT INTO vote_receipts(id,election_id,voter_id,position_id) VALUES(?,?,?,?) ON CONFLICT(election_id,voter_id,position_id) DO NOTHING")
        .bind(receiptId,e.id,s.user.id,candidate.position_id),
      env.DB.prepare("INSERT INTO ballots(id,election_id,position_id,candidate_id) SELECT ?,?,?,? WHERE changes()=1")
        .bind(ballotId,e.id,candidate.position_id,candidate.id)
    ]);
    if(!results?.[0]?.meta?.changes) return json({error:"You have already voted for this position. Votes cannot be changed."},409);
    return json({ok:true,message:"Your vote has been recorded."});
  }
  if(path==="/api/results" && method==="GET") {
    const e=await activeElection(env); if(!e) return json({error:"No election configured."},404);
    if(e.results_mode==="after_publish" && !e.results_published) return json({hidden:true,message:"Results will be available after the election officials publish them."});
    const rows=await env.DB.prepare(`SELECT c.id,c.full_name,c.political_name,c.photo_key,c.position_id,p.title AS position_title,COUNT(b.id) AS votes
      FROM candidates c JOIN positions p ON p.id=c.position_id LEFT JOIN ballots b ON b.candidate_id=c.id AND b.election_id=c.election_id
      WHERE c.election_id=? AND c.approval_status='approved' GROUP BY c.id ORDER BY p.display_order,votes DESC`).bind(e.id).all();
    const total=await env.DB.prepare("SELECT COUNT(*) AS n FROM ballots WHERE election_id=?").bind(e.id).first();
    const voters=await env.DB.prepare("SELECT COUNT(DISTINCT voter_id) AS n FROM vote_receipts WHERE election_id=?").bind(e.id).first();
    return json({totalVotes:total?.n||0,voters:voters?.n||0,results:rows.results||[]});
  }
  const admin=await requireAdmin(req,env);
  if(path.startsWith("/api/admin/") && !admin) return json({error:"Administrator access required."},403);
  if(path==="/api/admin/positions" && method==="POST") {
    const d=await body(req),e=await activeElection(env); if(!e) return json({error:"Create an election first."},400);
    const title=clean(d.title,100); if(!title) return json({error:"Position title is required."},400);
    const id=uid();
    try { await env.DB.prepare("INSERT INTO positions(id,election_id,title,display_order) VALUES(?,?,?,?)").bind(id,e.id,title,Number(d.order)||0).run(); }
    catch { return json({error:"That position already exists in this election."},409); }
    await audit(env,admin,"position_created",id,title); return json({ok:true,id},201);
  }
  if(path==="/api/admin/candidates" && method==="GET") {
    const e=await activeElection(env); if(!e) return json({candidates:[]});
    const rows=await env.DB.prepare("SELECT c.*,p.title AS position_title FROM candidates c JOIN positions p ON p.id=c.position_id WHERE c.election_id=? ORDER BY p.display_order,c.created_at DESC").bind(e.id).all();
    return json({candidates:rows.results||[]});
  }
  if(path==="/api/admin/candidates" && method==="POST") {
    const d=await body(req),e=await activeElection(env); if(!e||e.status!=="not_started") return json({error:"Candidates can only be added before voting begins."},403);
    const position=await env.DB.prepare("SELECT id FROM positions WHERE id=? AND election_id=?").bind(clean(d.positionId,80),e.id).first();
    if(!position) return json({error:"Select a valid position."},400);
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM candidates WHERE position_id=?").bind(position.id).first();
    if(count.n>=10) return json({error:"This position already has the maximum of 10 aspirants."},409);
    const id=uid();
    await env.DB.prepare(`INSERT INTO candidates(id,election_id,position_id,full_name,political_name,department,manifesto,registered_by,updated_by,approval_status)
      VALUES(?,?,?,?,?,?,?,?,?,'approved')`).bind(id,e.id,position.id,clean(d.fullName),clean(d.politicalName),clean(d.department,120),clean(d.manifesto,12000),admin.user.id,admin.user.id).run();
    await audit(env,admin,"candidate_created",id,clean(d.fullName)); return json({ok:true,id},201);
  }
  if(path.startsWith("/api/admin/candidates/") && method==="POST") {
    const id=path.split("/").pop(),form=await req.formData(),e=await activeElection(env);
    if(!e||e.status!=="not_started") return json({error:"Candidate files can only be changed before voting begins."},403);
    const candidate=await env.DB.prepare("SELECT * FROM candidates WHERE id=? AND election_id=?").bind(id,e.id).first();
    if(!candidate) return json({error:"Candidate not found."},404);
    const photo=form.get("photo"),pdf=form.get("manifestoPdf");
    let photoKey=candidate.photo_key,manifestoKey=candidate.manifesto_key;
    if(photo && typeof photo==="object" && photo.size){
      if(!photo.type.startsWith("image/")||photo.size>3*1024*1024) return json({error:"Photo must be an image under 3 MB."},400);
      photoKey=`candidates/${id}/photo-${Date.now()}`; await env.FILES.put(photoKey,photo.stream(),{httpMetadata:{contentType:photo.type}});
    }
    if(pdf && typeof pdf==="object" && pdf.size){
      if(pdf.type!=="application/pdf"||pdf.size>5*1024*1024) return json({error:"Manifesto must be a PDF under 5 MB."},400);
      manifestoKey=`candidates/${id}/manifesto-${Date.now()}`; await env.FILES.put(manifestoKey,pdf.stream(),{httpMetadata:{contentType:"application/pdf"}});
    }
    await env.DB.prepare("UPDATE candidates SET photo_key=?,manifesto_key=?,updated_by=? WHERE id=?").bind(photoKey,manifestoKey,admin.user.id,id).run();
    await audit(env,admin,"candidate_files_updated",id,"Photo or PDF uploaded"); return json({ok:true,photo_key:photoKey,manifesto_key:manifestoKey});
  }
  if(path.startsWith("/api/admin/candidates/") && method==="PUT") {
    const id=path.split("/").pop(),d=await body(req),e=await activeElection(env);
    if(!e||e.status!=="not_started") return json({error:"Candidates can only be edited before voting begins."},403);
    const c=await env.DB.prepare("SELECT id FROM candidates WHERE id=? AND election_id=?").bind(id,e.id).first();
    if(!c) return json({error:"Candidate not found."},404);
    await env.DB.prepare("UPDATE candidates SET full_name=?,political_name=?,department=?,manifesto=?,updated_by=? WHERE id=?")
      .bind(clean(d.fullName),clean(d.politicalName),clean(d.department,120),clean(d.manifesto,12000),admin.user.id,id).run();
    await audit(env,admin,"candidate_updated",id,clean(d.fullName)); return json({ok:true});
  }
  if(path.startsWith("/api/admin/candidates/") && method==="DELETE") {
    const id=path.split("/").pop(),e=await activeElection(env);
    if(!e||e.status!=="not_started") return json({error:"Candidates cannot be removed after voting starts."},403);
    const c=await env.DB.prepare("SELECT id,photo_key,manifesto_key FROM candidates WHERE id=? AND election_id=?").bind(id,e.id).first();
    if(!c) return json({error:"Candidate not found."},404);
    await env.DB.prepare("DELETE FROM candidates WHERE id=?").bind(id).run();
    if(c.photo_key) await env.FILES.delete(c.photo_key); if(c.manifesto_key) await env.FILES.delete(c.manifesto_key);
    await audit(env,admin,"candidate_deleted",id,"Candidate removed"); return json({ok:true});
  }
  if(path==="/api/admin/election" && method==="POST") {
    const d=await body(req),e=await activeElection(env);
    if(d.action==="create"){
      const id=uid(); await env.DB.prepare("INSERT INTO elections(id,title) VALUES(?,?)").bind(id,clean(d.title,160)||"ECSA Election").run();
      await env.DB.prepare("UPDATE settings SET value=? WHERE key='active_election_id'").bind(id).run();
      await audit(env,admin,"election_created",id,clean(d.title)); return json({ok:true,id});
    }
    if(!e) return json({error:"No election exists."},404);
    if(d.action==="status"){
      if(!["not_started","ongoing","completed"].includes(d.status)) return json({error:"Invalid election status."},400);
      await env.DB.prepare("UPDATE elections SET status=? WHERE id=?").bind(d.status,e.id).run();
    } else if(d.action==="results"){
      if(!["live","after_publish"].includes(d.mode)) return json({error:"Invalid results mode."},400);
      await env.DB.prepare("UPDATE elections SET results_mode=?,results_published=? WHERE id=?").bind(d.mode,d.published?1:0,e.id).run();
    } else return json({error:"Unknown election action."},400);
    await audit(env,admin,"election_settings_updated",e.id,JSON.stringify(d)); return json({ok:true});
  }
  if(path==="/api/admin/stats" && method==="GET") {
    const e=await activeElection(env); if(!e) return json({election:null});
    const students=await env.DB.prepare("SELECT COUNT(*) n FROM students").first();
    const receipts=await env.DB.prepare("SELECT COUNT(*) n FROM vote_receipts WHERE election_id=?").bind(e.id).first();
    const ballots=await env.DB.prepare("SELECT COUNT(*) n FROM ballots WHERE election_id=?").bind(e.id).first();
    const logs=await env.DB.prepare("SELECT action,target_id,details,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 30").all();
    return json({election:e,registeredStudents:students.n,positionReceipts:receipts.n,totalVotes:ballots.n,audit:logs.results||[]});
  }
  return json({error:"Route not found."},404);
}
async function issueSession(env,user,type) {
  const token=b64(crypto.getRandomValues(new Uint8Array(32))),days=Number(env.SESSION_DAYS)||2;
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,user_type,expires_at) VALUES(?,?,?,?)")
    .bind(await digest(token),user.id,type,Math.floor(Date.now()/1000)+days*86400).run();
  return json({ok:true,token,type,user:type==="student"?{full_name:user.full_name,matric:user.matric,level:user.level}:{full_name:user.full_name,role:user.role}});
}
export default {
  async fetch(req,env) {
    const origin=req.headers.get("Origin")||"";
    const allowed=env.ALLOWED_ORIGIN||"*";
    if(allowed!=="*" && origin!==allowed) return json({error:"Origin not allowed."},403);
    try {
      const response=await handle(req,env);
      const headers=new Headers(response.headers);
      Object.entries(cors(allowed==="*"? "*":origin)).forEach(([k,v])=>headers.set(k,v));
      return new Response(response.body,{status:response.status,headers});
    } catch(err) {
      return json({error:"Server error. Please try again.",detail:env.ENVIRONMENT==="development"?String(err):undefined},500,cors(allowed==="*"? "*":origin));
    }
  }
};