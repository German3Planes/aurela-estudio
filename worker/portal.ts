type Bindings={DB:D1Database, BUCKET:R2Bucket, STUDIO_EMAIL?:string};
const now=()=>Date.now();
const hex=(bytes:ArrayBuffer)=>Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,"0")).join("");
const json=(data:unknown,status=200,headers:Record<string,string>={})=>Response.json(data,{status,headers:{"Cache-Control":"no-store",...headers}});
async function hash(password:string,salt:string){
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
 return hex(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:new TextEncoder().encode(salt),iterations:100000},key,256));
}
export async function purge(env:Bindings){
 const db=env.DB;
 const expired=await db.prepare("SELECT media.id FROM media JOIN albums ON media.album=albums.id WHERE expires<=? LIMIT 100").bind(now()).all<{id:string}>();
 if(expired.results.length){
  const ids=expired.results.map(x=>x.id); await env.BUCKET.delete(ids);
  await db.batch(ids.map(id=>db.prepare("DELETE FROM media WHERE id=?").bind(id)));
 }
 await db.batch([db.prepare("DELETE FROM albums WHERE expires<=? AND NOT EXISTS(SELECT 1 FROM media WHERE media.album=albums.id)").bind(now()),db.prepare("DELETE FROM sessions WHERE expires<=?").bind(now()),db.prepare("DELETE FROM attempts WHERE until<=?").bind(now())]);
 return expired.results.length;
}
export async function portal(req:Request,env:Bindings){
 const url=new URL(req.url),path=url.pathname.slice(5),db=env.DB,post=req.method==="POST";
 if(post && req.headers.get("origin") && req.headers.get("origin")!==url.origin)return json({},403);
 const fail=(s:string,n=400)=>json({error:s},n);
 const admin=!!env.STUDIO_EMAIL && req.headers.get("oai-authenticated-user-email")?.toLowerCase()===env.STUDIO_EMAIL.toLowerCase();
 const token=(req.headers.get("cookie")||"").match(/(?:^|; *)aurela_session=([a-f0-9-]+)/)?.[1]||"";
 const cookie=(v:string,age:number)=>({ "Set-Cookie":"aurela_session="+v+"; Path=/; Max-Age="+age+"; HttpOnly; Secure; SameSite=Strict"});
 if(path==="limpieza" && post)return json({eliminados:await purge(env)});
 if(path==="login" && post){
  const b=await req.json() as Record<string,string>,dni=String(b.dni||"").replace(/\./g,"");
  if(!/^\d{7,8}$/.test(dni)||typeof b.password!=="string"||b.password.length>160)return fail("Revisá tu DNI y contraseña.");
  const limitKey=req.headers.get("cf-connecting-ip")||"local";
  const hits=await db.prepare("INSERT INTO attempts(id,count,until) VALUES (?,1,?) ON CONFLICT(id) DO UPDATE SET count=CASE WHEN until<=? THEN 1 ELSE count+1 END,until=CASE WHEN until<=? THEN excluded.until ELSE until END RETURNING count").bind(limitKey,now()+600000,now(),now()).first<{count:number}>();
  if((hits?.count||0)>25)return fail("Hubo varios intentos. Volvé a probar en diez minutos.",429);
  const c=await db.prepare("SELECT * FROM clients WHERE dni=?").bind(dni).first<{salt:string,hash:string}>();
  const check=await hash(b.password,c?.salt||"aurela-inactive-account");
  if(!c||c.hash!==check)return fail("El DNI o la contraseña son incorrectos.",401);
  const id=crypto.randomUUID()+crypto.randomUUID();await db.prepare("INSERT INTO sessions VALUES (?,?,?)").bind(id,dni,now()+86400000).run();
  return json({ok:true},200,cookie(id,86400));
 }
 if(path==="logout" && post){await db.prepare("DELETE FROM sessions WHERE token=?").bind(token).run();return json({},200,cookie("",0))}
 if(path.startsWith("estudio")){
  if(!admin)return fail("Ingresá con la cuenta titular del estudio.",403);
  if(path==="estudio"&&!post)return json((await db.prepare("SELECT a.*, (SELECT count(*) FROM media WHERE album=a.id) AS total FROM albums a WHERE expires>? ORDER BY expires DESC").bind(now()).all()).results);
  if(path==="estudio/nueva"&&post){
   const b=await req.json() as Record<string,string>,dni=String(b.dni||"").replace(/\./g,""), title=String(b.title||"").trim().slice(0,120),months=Number(b.months);
   if(!/^\d{7,8}$/.test(dni)||!title||![1,3].includes(months))return fail("Revisá los datos de la galería.");
   const existing=await db.prepare("SELECT dni FROM clients WHERE dni=?").bind(dni).first();
   if(!existing&&(!b.password||b.password.length<10||b.password.length>160))return fail("Para un cliente nuevo, asigná una contraseña de al menos 10 caracteres.");
   const date=new Date(),day=date.getUTCDate();date.setUTCDate(1);date.setUTCMonth(date.getUTCMonth()+months);const last=new Date(Date.UTC(date.getUTCFullYear(),date.getUTCMonth()+1,0)).getUTCDate();date.setUTCDate(Math.min(day,last));
   const id=crypto.randomUUID(), queries=[];
   if(!existing){const salt=crypto.randomUUID();queries.push(db.prepare("INSERT INTO clients VALUES(?,?,?)").bind(dni,salt,await hash(b.password,salt)))}
   queries.push(db.prepare("INSERT INTO albums VALUES(?,?,?,?)").bind(id,dni,title,date.getTime()));await db.batch(queries);return json({id,existing:!!existing});
  }
  if(path==="estudio/subir"&&post){
   const album=url.searchParams.get("album"),name=(url.searchParams.get("name")||"").slice(0,180),type=req.headers.get("content-type")||"";
   if(!album||!name||!["image/jpeg","image/png","image/webp","video/mp4","video/webm"].includes(type)||!req.body)return fail("Elegí una foto JPG, PNG, WebP o un video MP4 o WebM.");
   if(!await db.prepare("SELECT id FROM albums WHERE id=? AND expires>?").bind(album,now()).first())return fail("La galería ya venció.",410);
   const id=crypto.randomUUID();await env.BUCKET.put(id,req.body,{httpMetadata:{contentType:type}});
   try{const res=await db.prepare("INSERT INTO media SELECT ?,id,?,? FROM albums WHERE id=? AND expires>?").bind(id,name,type,album,now()).run();if(!res.meta.changes)throw Error()}catch(e){await env.BUCKET.delete(id);throw e}return json({ok:true});
  }
 }
 const session=await db.prepare("SELECT dni FROM sessions WHERE token=? AND expires>?").bind(token,now()).first<{dni:string}>();
 if(!session)return fail("Ingresá para abrir tu biblioteca.",401);
 if(path==="biblioteca"&&!post){
 const albums=(await db.prepare("SELECT id,title,expires FROM albums WHERE dni=? AND expires>? ORDER BY expires DESC").bind(session.dni,now()).all()).results;
 const files=(await db.prepare("SELECT m.* FROM media m JOIN albums a ON a.id=m.album WHERE a.dni=? AND a.expires>? ORDER BY m.rowid").bind(session.dni,now()).all()).results;return json({albums,files});
 }
 if(path.startsWith("archivo/")&&!post){
 const id=path.slice(8),file=await db.prepare("SELECT m.* FROM media m JOIN albums a ON a.id=m.album WHERE m.id=? AND a.dni=? AND a.expires>?").bind(id,session.dni,now()).first<{type:string,name:string}>();
 if(!file)return fail("Archivo no disponible.",404);
 const range=req.headers.has("Range");const obj=await env.BUCKET.get(id,range?{range:req.headers}:{});if(!obj)return fail("Archivo no disponible.",404);
 const headers=new Headers({"Content-Type":file.type,"Cache-Control":"private, no-store","Accept-Ranges":"bytes","X-Content-Type-Options":"nosniff","Content-Disposition":(url.searchParams.has("descargar")?"attachment":"inline")+"; filename*=UTF-8''"+encodeURIComponent(file.name).replace(/'/g,"%27")});
 const part=obj.range;if(part&&"offset" in part&&"length" in part){headers.set("Content-Range",`bytes ${part.offset}-${part.offset+part.length-1}/${obj.size}`);return new Response(obj.body,{status:206,headers})}
 return new Response(obj.body,{headers});
 }
 return fail("Página no disponible.",404);
}
