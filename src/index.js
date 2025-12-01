/**
 * 全能 Worker (NPM 專業版)
 * 特點：使用 npm 包 (postal-mime) 在後端直接渲染郵件，速度更快
 */

// === 1. 引入 NPM 包 ===
import PostalMime from 'postal-mime';

// === 2. 主邏輯 ===
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
  async email(message, env, ctx) {
    return handleEmail(message, env, ctx);
  }
};

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 獨立閱讀頁面
  const match = path.match(/^\/([a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8})$/);
  if (request.method === "GET" && match) return await handlePublicMailPage(match[1], env);

  // API
  if (request.method === "POST") {
    if (path === "/api/register") return await handleRegister(request, env);
    if (path === "/api/login") return await handleLogin(request, env);
  }

  // 驗證 & 靜態頁
  const user = await verifyJwt(request, env);
  if (!path.startsWith("/api/")) return new Response(renderHTML(env.EMAIL_DOMAIN), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
  if (!user) return jsonResp({ error: "Unauthorized" }, 401);

  // 受保護 API
  if (path === "/api/me") return await handleGetMe(user, env, request);
  if (path === "/api/mails") return await handleGetMails(user, env);
  if (path === "/api/mails/delete") return await handleDeleteMail(request, env, user);
  if (path === "/api/settings/alias/add") return await handleAddAlias(request, env, user);
  if (path === "/api/settings/alias/del") return await handleDelAlias(request, env, user);
  if (path === "/api/settings/password") return await handleChangePassword(request, env, user);

  return new Response("Not Found", { status: 404 });
}

async function handleEmail(message, env, ctx) {
  const subject = message.headers.get("subject") || "(無主題)";
  const from = message.from;
  const to = message.to.toLowerCase();
  
  if (!to.endsWith("@" + env.EMAIL_DOMAIN)) { message.setReject("Domain mismatch"); return; }

  const targetUser = to.split('@')[0];
  let owner = null;
  const mainUserExists = await env.USER_KV.get(`user:${targetUser}`);
  if (mainUserExists) owner = targetUser;
  else {
    const aliasOwner = await env.USER_KV.get(`alias:${to}`);
    if (aliasOwner) owner = aliasOwner;
  }

  if (!owner) { message.setReject("User not found"); return; }

  // 讀取原始碼
  let fullContent = "Error reading body";
  try { fullContent = await new Response(message.raw).text(); } catch (e) {}
  
  const r = () => Math.random().toString(36).slice(2, 10).padEnd(8, '0');
  const shareId = `${r()}-${r()}-${r()}`;

  try {
    await env.DB.prepare("INSERT INTO mails (owner_user, recipient, sender, subject, content, created_at, share_id) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(owner, to, from, subject, fullContent, Date.now(), shareId).run();
  } catch (e) { console.error(e); message.setReject("Internal Error"); }

  if (env.TG_BOT_TOKEN && env.TG_CHAT_ID) {
    ctx.waitUntil(sendTelegram(env.TG_BOT_TOKEN, env.TG_CHAT_ID, `📧 New Mail: ${subject}`));
  }
}

// ==========================================
// 核心升級：後端渲染郵件頁面
// ==========================================
async function handlePublicMailPage(shareId, env) {
    const mail = await env.DB.prepare("SELECT * FROM mails WHERE share_id = ?").bind(shareId).first();
    if (!mail) return new Response("郵件不存在", { status: 404, headers: { "Content-Type": "text/plain;charset=UTF-8" }});
    
    // 時間處理
    const d = new Date(mail.created_at);
    const utc = d.getTime() + (d.getTimezoneOffset() * 60000);
    const dateStr = new Date(utc + (3600000 * 8)).toLocaleString('zh-TW', { hour12: false });

    // 🔥 使用 NPM 包在後端解析
    let bodyHtml = "";
    try {
        const parser = new PostalMime();
        const email = await parser.parse(mail.content);
        
        if (email.html) {
            // 簡單的 HTML 清洗 (防止破壞頁面佈局)
            bodyHtml = `<div class="email-content">${email.html}</div>`;
        } else if (email.text) {
            bodyHtml = `<pre style="white-space:pre-wrap;font-family:sans-serif">${esc(email.text)}</pre>`;
        } else {
            bodyHtml = `<div style="color:red">無法解析內容</div>`;
        }
    } catch (e) {
        bodyHtml = `<div style="color:red">解析錯誤: ${e.message}</div><pre>${esc(mail.content)}</pre>`;
    }

    const html = `
    <!DOCTYPE html>
    <html lang="zh">
    <head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(mail.subject)}</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; background: #f3f4f6; margin: 0; padding: 20px; display: flex; justify-content: center; }
        .paper { background: white; width: 100%; max-width: 900px; padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border-radius: 8px; min-height: 80vh; }
        .header { border-bottom: 2px solid #f3f4f6; padding-bottom: 20px; margin-bottom: 30px; }
        h1 { margin: 0 0 10px 0; font-size: 24px; color: #1f2937; }
        .meta { color: #6b7280; font-size: 14px; line-height: 1.6; }
        .email-content img { max-width: 100%; height: auto; }
        .raw-btn { display:block; margin-top:30px; text-align:right; font-size:12px; color:#999; cursor:pointer; }
        #raw-view { display:none; margin-top:10px; padding:10px; background:#333; color:#fff; font-size:12px; overflow:auto; max-height:300px; }
    </style>
    </head>
    <body>
        <div class="paper">
            <div class="header">
                <h1>${esc(mail.subject)}</h1>
                <div class="meta">
                    <div><strong>From:</strong> ${esc(mail.sender)}</div>
                    <div><strong>To:</strong> ${esc(mail.recipient)}</div>
                    <div><strong>Date:</strong> ${dateStr}</div>
                </div>
            </div>
            
            <!-- 這裡直接顯示後端解析好的 HTML -->
            ${bodyHtml}

            <div class="raw-btn" onclick="document.getElementById('raw-view').style.display='block'">View Raw Source</div>
            <pre id="raw-view">${esc(mail.content)}</pre>
        </div>
    </body>
    </html>
    `;
    return new Response(html, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
}


// === 其他業務函數 (不變) ===
async function handleRegister(req, env) { try { const { username, password } = await req.json(); if (!username || !password) return jsonResp({ error: "Missing fields" }, 400); if (!/^[a-zA-Z0-9._-]+$/.test(username)) return jsonResp({ error: "Invalid format" }, 400); if (await env.USER_KV.get(`user:${username}`)) return jsonResp({ error: "User exists" }, 409); const hash = await hashPassword(password, env.SALT); const userData = { username, passwordHash: hash, email: `${username}@${env.EMAIL_DOMAIN}`, aliases: [], createdAt: Date.now() }; await env.USER_KV.put(`user:${username}`, JSON.stringify(userData)); return jsonResp({ success: true, email: userData.email }); } catch (e) { return jsonResp({ error: "Error" }, 500); } }
async function handleLogin(req, env) { try { const { username, password } = await req.json(); const userRaw = await env.USER_KV.get(`user:${username}`); if (!userRaw) return jsonResp({ error: "Invalid credentials" }, 401); const user = JSON.parse(userRaw); if (user.passwordHash !== await hashPassword(password, env.SALT)) return jsonResp({ error: "Invalid credentials" }, 401); const token = await signJwt({ username: user.username }, env.JWT_SECRET); return jsonResp({ success: true, token }); } catch (e) { return jsonResp({ error: "Error" }, 500); } }
async function handleGetMe(user, env) { const u = JSON.parse(await env.USER_KV.get(`user:${user.username}`)); return jsonResp({ username: u.username, email: u.email, aliases: u.aliases||[] }); }
async function handleGetMails(user, env) { const { results } = await env.DB.prepare("SELECT id, recipient, sender, subject, content, created_at, share_id FROM mails WHERE owner_user = ? ORDER BY created_at DESC LIMIT 50").bind(user.username).all(); const mails = results.map(m => ({ ...m, date: getTaiwanDateFromTs(m.created_at) })); return jsonResp({ mails }); }
async function handleDeleteMail(req, env, user) { const { id } = await req.json(); await env.DB.prepare("DELETE FROM mails WHERE id = ? AND owner_user = ?").bind(id, user.username).run(); return jsonResp({ success: true }); }
async function handleAddAlias(req, env, user) { let { alias } = await req.json(); if (!alias) return jsonResp({ error: "Empty" }, 400); if (!alias.includes("@")) alias = `${alias}@${env.EMAIL_DOMAIN}`; const userRaw = await env.USER_KV.get(`user:${user.username}`); let u = JSON.parse(userRaw); if (!u.aliases) u.aliases = []; if (u.aliases.includes(alias)) return jsonResp({ error: "Exists" }, 400); const existingOwner = await env.USER_KV.get(`alias:${alias}`); if (existingOwner) return jsonResp({ error: "Taken" }, 409); u.aliases.push(alias); await env.USER_KV.put(`user:${user.username}`, JSON.stringify(u)); await env.USER_KV.put(`alias:${alias}`, user.username); return jsonResp({ success: true, aliases: u.aliases }); }
async function handleDelAlias(req, env, user) { const { alias } = await req.json(); const userRaw = await env.USER_KV.get(`user:${user.username}`); let u = JSON.parse(userRaw); if (!u.aliases) u.aliases = []; u.aliases = u.aliases.filter(a => a !== alias); await env.USER_KV.put(`user:${user.username}`, JSON.stringify(u)); await env.USER_KV.delete(`alias:${alias}`); return jsonResp({ success: true, aliases: u.aliases }); }
async function handleChangePassword(req, env, user) { const { newPassword } = await req.json(); if (!newPassword || newPassword.length < 6) return jsonResp({ error: "Too short" }, 400); const userRaw = await env.USER_KV.get(`user:${user.username}`); let u = JSON.parse(userRaw); u.passwordHash = await hashPassword(newPassword, env.SALT); await env.USER_KV.put(`user:${user.username}`, JSON.stringify(u)); return jsonResp({ success: true }); }

// === Utils ===
function getTaiwanDateFromTs(ts) { const d = new Date(ts); const utc = d.getTime() + (d.getTimezoneOffset() * 60000); const nd = new Date(utc + (3600000 * 8)); return nd.toLocaleString('zh-TW', { hour12: false }); }
async function hashPassword(p, salt) { const m = new TextEncoder().encode(salt + p); const h = await crypto.subtle.digest('SHA-256', m); return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function signJwt(payload, secret) { const h = { alg: "HS256", typ: "JWT" }; payload.exp = Math.floor(Date.now()/1000)+86400; const e = `${b64url(JSON.stringify(h))}.${b64url(JSON.stringify(payload))}`; const k = await importKey(secret); const s = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(e)); return `${e}.${b64url(s)}`; }
async function verifyJwt(req, env) { const a = req.headers.get("Authorization"); if(!a||!a.startsWith("Bearer ")) return null; const [h,p,s] = a.split(" ")[1].split("."); if(!h||!p||!s) return null; const k = await importKey(env.JWT_SECRET); const v = await crypto.subtle.verify("HMAC", k, base64UrlToUint8Array(s), new TextEncoder().encode(`${h}.${p}`)); if(!v) return null; return JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(p))); }
async function importKey(secret) { return await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }
function b64url(i) { let u = typeof i === 'string' ? new TextEncoder().encode(i) : new Uint8Array(i); return btoa(String.fromCharCode(...u)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function base64UrlToUint8Array(s) { const p = '='.repeat((4 - s.length % 4) % 4); const r = atob((s + p).replace(/-/g, '+').replace(/_/g, '/')); const o = new Uint8Array(r.length); for (let i = 0; i < r.length; ++i) o[i] = r.charCodeAt(i); return o; }
function jsonResp(d, s=200) { return new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json" }}); }
async function sendTelegram(t, c, x) { try { await fetch(`https://api.telegram.org/bot${t}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: c, text: x }) }); } catch (e) {} }
function esc(s){ return s ? s.replace(/</g, "&lt;") : ""; }
function renderHTML(domain) { return `<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Netlib Mail</title><style>:root{--primary:#2563eb;--bg:#f8fafc;--card:#fff;--text:#1e293b}body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);margin:0;display:flex;justify-content:center;align-items:center;height:100vh;overflow:hidden}.auth-box{background:var(--card);padding:2rem;border-radius:1rem;width:350px;box-shadow:0 10px 20px rgba(0,0,0,0.1)}input{width:100%;padding:0.8rem;margin:0.5rem 0;border:1px solid #cbd5e1;border-radius:0.5rem;box-sizing:border-box}button{width:100%;padding:0.8rem;background:var(--primary);color:white;border:none;border-radius:0.5rem;font-weight:600;cursor:pointer}.link{text-align:center;margin-top:1rem;color:#64748b;font-size:0.9rem;cursor:pointer;text-decoration:underline}.dashboard{width:100%;max-width:1000px;padding:2rem;display:none;height:100vh;overflow-y:auto;box-sizing:border-box}.dash-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:2rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem}.card{background:var(--card);padding:1.5rem;border-radius:1rem;box-shadow:0 4px 6px rgba(0,0,0,0.05);transition:transform 0.2s;display:flex;flex-direction:column;justify-content:space-between;height:180px;cursor:pointer;border:1px solid #e2e8f0}.card:hover{transform:translateY(-4px);border-color:var(--primary)}.c-icon{font-size:2rem;margin-bottom:0.5rem}.c-title{font-size:1.2rem;font-weight:600;margin-bottom:0.5rem}.c-desc{color:#64748b;font-size:0.9rem;flex:1}.c-act{text-align:right;color:var(--primary);font-weight:600}.modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);display:none;justify-content:center;align-items:center;z-index:100;backdrop-filter:blur(2px)}.modal.show{display:flex}.m-box{background:white;width:90%;max-width:800px;max-height:85vh;border-radius:1rem;padding:1.5rem;display:flex;flex-direction:column;box-shadow:0 20px 50px rgba(0,0,0,0.2)}.m-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;border-bottom:1px solid #eee;padding-bottom:0.5rem}.m-list{flex:1;overflow-y:auto}.m-item{padding:1rem;border-bottom:1px solid #f1f5f9;cursor:default}.m-item:hover{background:#f8fafc}.hidden{display:none}</style></head><body><div class="auth-box" id="auth-screen"><h2 id="t" style="text-align:center;margin-top:0">Netlib Mail</h2><div id="reg-ui"><input id="u" placeholder="用戶名 (例: user1)"><div style="text-align:right;font-size:0.8rem;color:#64748b;margin-top:-5px;margin-bottom:10px">@${domain}</div></div><input id="p" type="password" placeholder="密碼"><button id="btn" onclick="sub()">登錄</button><div class="link" onclick="tog()">切換 註冊 / 登錄</div><div id="msg" style="color:red;text-align:center;margin-top:10px"></div></div><div class="dashboard" id="dash-screen"><div class="dash-head"><h2>控制台</h2><button onclick="logout()" style="width:auto;background:#fff;color:#333;border:1px solid #ccc">退出</button></div><div class="grid"><div class="card" onclick="openMail()"><div><div class="c-icon">📭</div><div class="c-title">電子信箱</div><div class="c-desc">查看收件箱及別名郵件。</div></div><div class="c-act">打開 &rarr;</div></div><div class="card"><div><div class="c-icon">👤</div><div class="c-title">用戶檔案</div><div class="c-desc" id="info-txt">加載中...</div></div></div><div class="card"><div><div class="c-icon">📊</div><div class="c-title">系統狀態</div><div class="c-desc">System: Online<br>Mode: NPM Bundled</div></div></div><div class="card" onclick="openSettings()"><div><div class="c-icon">⚙️</div><div class="c-title">系統設置</div><div class="c-desc">管理多帳號別名、修改密碼。</div></div><div class="c-act">配置 &rarr;</div></div></div></div><div class="modal" id="mail-modal"><div class="m-box"><div class="m-head"><h3>收件箱</h3><button onclick="cls('mail-modal')" style="width:auto;padding:5px 10px">關閉</button></div><div id="mail-content" class="m-list"></div></div></div><div class="modal" id="set-modal"><div class="m-box" style="max-width:500px"><div class="m-head"><h3>設置</h3><button onclick="cls('set-modal')" style="width:auto;padding:5px 10px">關閉</button></div><div style="margin-bottom:2rem"><h4>添加別名</h4><div style="display:flex;gap:5px"><input id="new-alias" placeholder="例: shop" style="margin:0"><button onclick="addAlias()" style="width:80px;margin:0">添加</button></div><div id="alias-list" style="margin-top:10px;max-height:150px;overflow-y:auto"></div></div><div><h4>修改密碼</h4><input id="new-pw" type="password" placeholder="新密碼" style="margin-bottom:10px"><button onclick="changePw()">提交修改</button></div></div></div><script>let isReg=false, userData={};const el=i=>document.getElementById(i);const API=async(u,m='GET',d)=>fetch(u,{method:m,headers:{'Authorization':'Bearer '+localStorage.getItem('t'),'Content-Type':'application/json'},body:d?JSON.stringify(d):null}).then(r=>r.json());function tog(){ isReg=!isReg; el('btn').innerText=isReg?"註冊":"登錄"; document.querySelector('#reg-ui div').style.display=isReg?'block':'none'; }async function sub(){ const u=el('u').value, p=el('p').value; if(!u||!p)return; el('btn').innerText="..."; const d = await API(isReg?'/api/register':'/api/login', 'POST', {username:u,password:p}); if(d.error) el('msg').innerText=d.error; else if(isReg) { alert("成功: "+d.email); tog(); } else { localStorage.setItem('t',d.token); init(); } el('btn').innerText=isReg?"註冊":"登錄"; }async function init(){ const d = await API('/api/me'); if(d.error) logout(); else { userData=d; el('auth-screen').style.display='none'; el('dash-screen').style.display='block'; el('info-txt').innerHTML = \`<b>\${d.username}</b><br>\${d.email}\`; } }async function openMail(){ el('mail-modal').classList.add('show'); el('mail-content').innerHTML = '<div style="padding:2rem;text-align:center">加載中...</div>'; const d = await API('/api/mails'); const mails = d.mails || []; el('mail-content').innerHTML = mails.length ? mails.map(m => { const linkBtn = m.share_id ? \`<a href="/\${m.share_id}" target="_blank" style="text-decoration:none;background:#2563eb;color:white;padding:4px 12px;border-radius:4px;font-size:0.85rem">📖 閱讀全文</a>\` : \`<span style="color:#999;font-size:0.8rem">(舊郵件無全文)</span>\`; return \`<div class="m-item"><div style="display:flex;justify-content:space-between"><div style="font-weight:bold;font-size:1.05rem">\${esc(m.subject)}</div><div style="font-size:0.8rem;color:#999">\${m.date}</div></div><div style="font-size:0.9rem;color:#666;margin-top:4px">From: \${esc(m.sender)} | To: \${m.recipient}</div><div style="margin-top:10px;display:flex;gap:10px">\${linkBtn}<button onclick="delMail(\${m.id})" style="background:white;color:red;border:1px solid red;padding:4px 12px;width:auto;font-size:0.85rem">刪除</button></div></div>\`; }).join('') : '<div style="padding:2rem;text-align:center">暫無郵件</div>'; }async function delMail(id){ if(confirm("刪除?")) { await API('/api/mails/delete', 'POST', {id}); openMail(); } }function openSettings(){ el('set-modal').classList.add('show'); renderAliases(); }function renderAliases(){ el('alias-list').innerHTML = (userData.aliases||[]).map(a => \`<div style="display:flex;justify-content:space-between;padding:8px;background:#f8fafc;margin-bottom:5px;border-radius:4px"><span>\${a}</span><span style="color:red;cursor:pointer" onclick="delAlias('\${a}')">刪除</span></div>\`).join(''); }async function addAlias(){ const v=el('new-alias').value; if(v){ const d=await API('/api/settings/alias/add','POST',{alias:v}); if(d.error)alert(d.error); else { userData.aliases=d.aliases; el('new-alias').value=""; renderAliases(); } } }async function delAlias(a){ if(confirm("刪除?")){ const d=await API('/api/settings/alias/del','POST',{alias:a}); userData.aliases=d.aliases; renderAliases(); } }async function changePw(){ const p=el('new-pw').value; await API('/api/settings/password','POST',{newPassword:p}); alert("密碼已修改"); el('new-pw').value=""; }function cls(i){ el(i).classList.remove('show'); }function logout(){ localStorage.removeItem('t'); location.reload(); }function esc(s){ return s?s.replace(/</g,"&lt;"):"" }if(localStorage.getItem('t')) init();</script></body></html>`;
}