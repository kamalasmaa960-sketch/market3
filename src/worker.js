function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean);
  const headers = {
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
  };
  if (allowed.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}
const json = (data, status=200, req=null, env=null) => new Response(JSON.stringify(data), {
  status, headers: {...(req && env ? corsHeaders(req,env) : {}), "Content-Type":"application/json; charset=utf-8"}
});
const err = (message,status=400,req=null,env=null) => json({error:message},status,req,env);
const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
async function hashPassword(password,salt) {
  const key = await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:180000,hash:"SHA-256"},key,256);
  return b64(bits);
}
async function sign(payload,secret) {
  const body=btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign("HMAC",key,enc.encode(body));
  return body+"."+b64(sig);
}
async function verify(token,secret) {
  try {
    const [body,sig]=token.split(".");
    const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const ok=await crypto.subtle.verify("HMAC",key,unb64(sig),enc.encode(body));
    if(!ok) return null;
    const p=JSON.parse(decodeURIComponent(escape(atob(body))));
    return p.exp>Date.now()?p:null;
  } catch { return null; }
}
async function auth(req,env) {
  const token=(req.headers.get("Authorization")||"").replace(/^Bearer /,"");
  if(!env.AUTH_SECRET) return null;
  return token?verify(token,env.AUTH_SECRET):null;
}
async function body(req){ try{return await req.json()}catch{return {}} }
async function all(db,sql,...args){return (await db.prepare(sql).bind(...args).all()).results||[]}
async function one(db,sql,...args){return db.prepare(sql).bind(...args).first()}
async function setting(db,key, fallback=""){const r=await one(db,"SELECT value FROM settings WHERE key=?",key);return r?.value??fallback}
function cleanImages(images, main="") {
  const list=Array.isArray(images)?images:[];
  const valid=list.filter(x=>typeof x==="string" && /^https:\/\//i.test(x));
  if(main && !valid.includes(main) && /^https:\/\//i.test(main)) valid.unshift(main);
  return [...new Set(valid)].slice(0,12);
}
function safeImages(raw, main="") {
  let parsed=[]; try { parsed=JSON.parse(raw||"[]"); } catch {}
  const list=cleanImages(parsed,main);
  return list.length?list:(/^https:\/\//i.test(main)?[main]:[]);
}
async function route(req,env) {
  const url=new URL(req.url), p=url.pathname, method=req.method;
  if(p==="/api/health") return json({ok:true,service:"luxury-store-api"});
  if(p==="/api/setup" && method==="POST") {
    if(!env.DB) return err("قاعدة البيانات غير مربوطة",500);
    const count=await one(env.DB,"SELECT COUNT(*) n FROM admins");
    if((count?.n||0)>0) return err("تم إعداد حساب الإدارة بالفعل",409);
    const b=await body(req);
    if(!env.SETUP_KEY || !b.setup_key || b.setup_key !== env.SETUP_KEY) return err("مفتاح الإعداد الأولي غير صحيح",403);
    const username=String(b.username||"").trim();
    if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(username) || !b.password || String(b.password).length<12) return err("اسم المستخدم يجب أن يكون 3 إلى 40 حرفًا إنجليزيًا أو أرقامًا، وكلمة المرور 12 حرفًا على الأقل");
    const salt=crypto.randomUUID(), password_hash=await hashPassword(String(b.password),salt);
    try { await env.DB.prepare("INSERT INTO admins(username,password_hash,salt) SELECT ?,?,? WHERE NOT EXISTS (SELECT 1 FROM admins)").bind(username,password_hash,salt).run(); } catch(e) { return err("تعذر إنشاء حساب المدير. قد يكون الحساب أُنشئ بالفعل.",409); }
    const created=await one(env.DB,"SELECT COUNT(*) n FROM admins");
    if(!created || Number(created.n)!==1) return err("تم إعداد حساب الإدارة بالفعل أو تعذر إكمال الإعداد",409);
    return json({ok:true,message:"تم إنشاء المدير. سجّل الدخول الآن."});
  }
  if(p==="/api/login" && method==="POST") {
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    const windowStart = new Date(Date.now()-15*60*1000).toISOString();
    const attempts = await one(env.DB,"SELECT COUNT(*) n FROM login_attempts WHERE ip=? AND attempted_at>?",ip,windowStart);
    if ((attempts?.n || 0) >= 5) return err("محاولات كثيرة. انتظري 15 دقيقة ثم حاولي مجددًا.",429);
    const b=await body(req), admin=await one(env.DB,"SELECT * FROM admins WHERE username=?",b.username||"");
    const valid = !!admin && await hashPassword(String(b.password||""),admin.salt)===admin.password_hash;
    if(!valid) { await env.DB.prepare("INSERT INTO login_attempts(ip,attempted_at) VALUES(?,?)").bind(ip,new Date().toISOString()).run(); return err("بيانات الدخول غير صحيحة",401); }
    if(!env.AUTH_SECRET) return err("يجب ضبط AUTH_SECRET كمتغير سري في Cloudflare",500);
    const token=await sign({sub:admin.id,exp:Date.now()+8*60*60*1000},env.AUTH_SECRET);
    return json({token,expires_in:28800});
  }
  if(p==="/api/public-products" && method==="GET") {
    const rows=await all(env.DB,"SELECT id,name,description,type,price,stock,image_url,image_urls FROM products WHERE active=1 ORDER BY id DESC");
    return json(rows.map(x=>({...x, images: safeImages(x.image_urls,x.image_url)})));
  }
  if(p==="/api/settings" && method==="GET") {
    const rows=await all(env.DB,"SELECT key,value FROM settings WHERE key IN ('store_name','currency','primary_color','announcement','description','shipping_fee','hero_title','about')");
    return json(Object.fromEntries(rows.map(x=>[x.key,x.value])));
  }
  const user=await auth(req,env);
  const adminOnly=["/api/settings","/api/products","/api/orders","/api/returns","/api/losses","/api/expenses","/api/reports"];
  if(adminOnly.some(x=>p===x || p.startsWith(x+"/")) && !user) return err("يلزم تسجيل دخول الإدارة",401);

  if(p==="/api/settings" && method==="PUT") {
    const b=await body(req);
    const allowedSettings=new Set(["store_name","currency","primary_color","announcement","description","shipping_fee","hero_title","about"]);
    for(const [k,v] of Object.entries(b)) { if(!allowedSettings.has(k)) continue; await env.DB.prepare("INSERT INTO settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(k,String(v).slice(0,2000)).run(); }
    return json({ok:true});
  }
  if(p==="/api/products" && method==="GET") {
    const rows=await all(env.DB,"SELECT * FROM products ORDER BY id DESC");
    return json(rows.map(x=>({...x, images:safeImages(x.image_urls,x.image_url)})));
  }
  if(p==="/api/products" && method==="POST") {
    const b=await body(req);
    if(!String(b.name||"").trim() || String(b.name).length>180 || !["physical","digital"].includes(b.type)) return err("اسم المنتج ونوعه مطلوبان");
    if(!Number.isFinite(Number(b.price)) || Number(b.price)<0 || !Number.isFinite(Number(b.cost||0)) || Number(b.cost||0)<0 || !Number.isInteger(Number(b.stock||0)) || Number(b.stock||0)<0) return err("تحققي من السعر والتكلفة والمخزون");
    const r=await env.DB.prepare("INSERT INTO products(name,description,type,price,cost,stock,image_url,image_urls,active) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(b.name,b.description||"",b.type,Number(b.price)||0,Number(b.cost)||0,Number(b.stock)||0,b.image_url||"",JSON.stringify(cleanImages(b.images,b.image_url)),b.active===false?0:1).run();
    return json({id:r.meta.last_row_id},201);
  }
  const prod=p.match(/^\/api\/products\/(\d+)$/);
  if(prod && method==="PUT") {
    const b=await body(req);
    if(!String(b.name||"").trim() || String(b.name).length>180 || !["physical","digital"].includes(b.type) || !Number.isFinite(Number(b.price)) || Number(b.price)<0 || !Number.isFinite(Number(b.cost||0)) || Number(b.cost||0)<0 || !Number.isInteger(Number(b.stock||0)) || Number(b.stock||0)<0) return err("بيانات المنتج غير صالحة");
    await env.DB.prepare("UPDATE products SET name=?,description=?,type=?,price=?,cost=?,stock=?,image_url=?,image_urls=?,active=? WHERE id=?")
      .bind(b.name,b.description||"",b.type,Number(b.price)||0,Number(b.cost)||0,Number(b.stock)||0,b.image_url||"",JSON.stringify(cleanImages(b.images,b.image_url)),b.active===false?0:1,prod[1]).run();
    return json({ok:true});
  }
  if(prod && method==="DELETE") { await env.DB.prepare("DELETE FROM products WHERE id=?").bind(prod[1]).run(); return json({ok:true}); }

  if(p==="/api/orders" && method==="GET") return json(await all(env.DB,"SELECT * FROM orders ORDER BY id DESC"));
  if(p==="/api/orders" && method==="POST") {
    const b=await body(req);
    if(!b.customer_name||!b.phone||!Array.isArray(b.items)||!b.items.length) return err("بيانات العميل والمنتجات مطلوبة");
    let subtotal=0, normalized=[];
    for(const item of b.items) {
      const product=await one(env.DB,"SELECT * FROM products WHERE id=? AND active=1",Number(item.product_id));
      const qty=Math.max(1,Math.floor(Number(item.quantity)||1));
      if(!product) return err("يوجد منتج غير متاح");
      if(product.type==="physical" && product.stock<qty) return err("الكمية المطلوبة غير متاحة للمخزون");
      subtotal+=product.price*qty; normalized.push({product,qty});
    }
    const shipping=Number(await setting(env.DB,"shipping_fee","0"))||0, total=subtotal+shipping;
    const r=await env.DB.prepare("INSERT INTO orders(customer_name,phone,address,items_json,subtotal,shipping,total,payment_method) VALUES(?,?,?,?,?,?,?,?)")
      .bind(b.customer_name,b.phone,b.address||"",JSON.stringify(normalized.map(x=>({product_id:x.product.id,name:x.product.name,quantity:x.qty,price:x.product.price,type:x.product.type}))),subtotal,shipping,total,b.payment_method||"cash").run();
    for(const x of normalized) {
      await env.DB.prepare("INSERT INTO order_items(order_id,product_id,quantity,unit_price,unit_cost) VALUES(?,?,?,?,?)").bind(r.meta.last_row_id,x.product.id,x.qty,x.product.price,x.product.cost).run();
      if(x.product.type==="physical") await env.DB.prepare("UPDATE products SET stock=stock-? WHERE id=?").bind(x.qty,x.product.id).run();
    }
    return json({id:r.meta.last_row_id,total,status:"new"},201);
  }
  const order=p.match(/^\/api\/orders\/(\d+)$/);
  if(order && method==="PUT") {const b=await body(req);const states=["new","processing","shipped","completed","cancelled"],payments=["pending","paid","failed"];if(!states.includes(b.status)||!payments.includes(b.payment_status))return err("حالة الطلب أو الدفع غير صالحة");const r=await env.DB.prepare("UPDATE orders SET status=?,payment_status=? WHERE id=?").bind(b.status,b.payment_status,order[1]).run();if(!r.meta.changes)return err("الطلب غير موجود",404);return json({ok:true});}

  if(p==="/api/returns" && method==="GET") return json(await all(env.DB,"SELECT r.*,o.customer_name,p.name product_name FROM returns r JOIN orders o ON o.id=r.order_id JOIN products p ON p.id=r.product_id ORDER BY r.id DESC"));
  if(p==="/api/returns" && method==="POST") {
    const b=await body(req), q=Math.max(1,Math.floor(Number(b.quantity)||1));
    const oi=await one(env.DB,"SELECT oi.*,o.status FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE oi.order_id=? AND oi.product_id=?",Number(b.order_id),Number(b.product_id));
    if(!oi) return err("لا توجد كمية مطابقة في الطلب");
    const already=await one(env.DB,"SELECT COALESCE(SUM(quantity),0) q FROM returns WHERE order_id=? AND product_id=? AND status!='rejected'",Number(b.order_id),Number(b.product_id));
    if(Number(already.q)+q>Number(oi.quantity)) return err("الكمية المرتجعة تتجاوز الكمية الموجودة في الطلب");
    if(oi.status==="cancelled") return err("لا يمكن تسجيل مرتجع لطلب ملغي");
    const product=await one(env.DB,"SELECT * FROM products WHERE id=?",Number(b.product_id));
    const refund=Math.max(0,Number(b.refund_amount)||0);
    const maxRefund=Number(oi.unit_price)*q;
    if(refund>maxRefund) return err("قيمة الاسترداد تتجاوز قيمة المنتجات المرتجعة");
    await env.DB.prepare("INSERT INTO returns(order_id,product_id,quantity,reason,condition_status,refund_amount,status) VALUES(?,?,?,?,?,?,?)")
      .bind(b.order_id,b.product_id,q,b.reason||"غير محدد",b.condition_status||"resellable",refund,b.status||"received").run();
    if((b.condition_status||"resellable")==="resellable") await env.DB.prepare("UPDATE products SET stock=stock+? WHERE id=?").bind(q,product.id).run();
    return json({ok:true,refund_amount:refund},201);
  }

  if(p==="/api/losses" && method==="GET") return json(await all(env.DB,"SELECT l.*,p.name product_name FROM losses l LEFT JOIN products p ON p.id=l.product_id ORDER BY l.id DESC"));
  if(p==="/api/losses" && method==="POST") {
    const b=await body(req);
    const amount=Math.max(0,Number(b.amount)||0), qty=Math.max(0,Math.floor(Number(b.quantity)||0));
    if(!b.title) return err("وصف الخسارة مطلوب");
    if(b.product_id && qty>0) {
      const product=await one(env.DB,"SELECT * FROM products WHERE id=?",Number(b.product_id));
      if(!product || product.stock<qty) return err("المخزون غير كافٍ لتسجيل التالف أو الفاقد");
      await env.DB.prepare("UPDATE products SET stock=stock-? WHERE id=?").bind(qty,product.id).run();
    }
    await env.DB.prepare("INSERT INTO losses(product_id,title,category,quantity,amount,notes) VALUES(?,?,?,?,?,?)").bind(b.product_id||null,b.title,b.category||"other",qty,amount,b.notes||"").run();
    return json({ok:true},201);
  }
  if(p==="/api/expenses" && method==="GET") return json(await all(env.DB,"SELECT * FROM expenses ORDER BY id DESC"));
  if(p==="/api/expenses" && method==="POST") {
    const b=await body(req); if(!b.title||!(Number(b.amount)>0)) return err("الوصف والمبلغ مطلوبان");
    await env.DB.prepare("INSERT INTO expenses(title,category,amount,notes) VALUES(?,?,?,?)").bind(b.title,b.category||"general",Number(b.amount),b.notes||"").run();return json({ok:true},201);
  }
  if(p==="/api/reports" && method==="GET") {
    const sales=await one(env.DB,"SELECT COALESCE(SUM(total),0) total,COUNT(*) count FROM orders WHERE status!='cancelled' AND payment_status='paid'");
    const cogs=await one(env.DB,"SELECT COALESCE(SUM(quantity*unit_cost),0) total FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.status!='cancelled' AND o.payment_status='paid'");
    const refunds=await one(env.DB,"SELECT COALESCE(SUM(refund_amount),0) total FROM returns WHERE status!='rejected'");
    const losses=await one(env.DB,"SELECT COALESCE(SUM(amount),0) total FROM losses");
    const expenses=await one(env.DB,"SELECT COALESCE(SUM(amount),0) total FROM expenses");
    return json({sales:sales.total,orders:sales.count,cost_of_goods:cogs.total,refunds:refunds.total,losses:losses.total,expenses:expenses.total,estimated_net:Number(sales.total)-Number(cogs.total)-Number(refunds.total)-Number(losses.total)-Number(expenses.total)});
  }
  return env.ASSETS.fetch(req);
}
export default {
  async fetch(req, env, ctx) {
    let response;
    if (req.method === "OPTIONS") {
      const h = corsHeaders(req, env);
      if (!h["Access-Control-Allow-Origin"]) return new Response(null, {status: 403, headers: h});
      return new Response(null, {headers: h});
    }
    try { response = await route(req, env, ctx); } catch (e) { response = json({error:"حدث خطأ داخلي في الخادم. راجعي إعدادات D1 والترحيلات."},500); }
    const headers = new Headers(response.headers);
    for (const [k,v] of Object.entries(corsHeaders(req,env))) {
      if (k.toLowerCase() !== "access-control-allow-origin" || v) headers.set(k,v);
    }
    return new Response(response.body, {status: response.status, statusText: response.statusText, headers});
  }
};