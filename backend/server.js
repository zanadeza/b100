require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto    = require("crypto");
const path      = require("path");
const fs        = require("fs");
const fetch     = (...a) => import("node-fetch").then(({ default: f }) => f(...a));

const app  = express();
const PORT = process.env.PORT || 3000;
const DB_FILE   = path.join(__dirname, "medterm_db.json");
const SESS_FILE = path.join(__dirname, "sessions.json");
const APP_VERSION = "1.22.8";

// ── DB ────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE))
    fs.writeFileSync(DB_FILE, JSON.stringify({ users:{}, training:[], events:[] }));
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return { users:{}, training:[], events:[] }; }
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function loadSess() {
  if (!fs.existsSync(SESS_FILE)) fs.writeFileSync(SESS_FILE, JSON.stringify({}));
  try { return JSON.parse(fs.readFileSync(SESS_FILE, "utf8")); }
  catch { return {}; }
}
function saveSess(s) { fs.writeFileSync(SESS_FILE, JSON.stringify(s)); }

const now    = () => new Date().toISOString();
const today  = () => new Date().toISOString().slice(0, 10);
const hash   = (t) => crypto.createHash("sha256").update(t + (process.env.SECRET || "mt_secret")).digest("hex");
const randId = (n=16) => crypto.randomBytes(n).toString("hex");

// ── LIMITS ────────────────────────────────────────────────────
const LIMITS = {
  user:  { daily_msgs:30,  max_words:400,  max_tokens:1200, max_img_size_mb:5  },
  admin: { daily_msgs:999, max_words:4000, max_tokens:4000, max_img_size_mb:20 }
};

// ── SECURITY MIDDLEWARE ───────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"]
    }
  },
  xFrameOptions: { action: "deny" },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "25mb" }));

// Global rate limit
app.use("/api/", rateLimit({
  windowMs: 60000, max: 100,
  message: { error: "Too many requests. Please wait." },
  standardHeaders: true, legacyHeaders: false
}));

// Login rate limit — strict
const loginLim = rateLimit({ windowMs: 60000, max: 5, message: { error: "Too many login attempts. Wait 1 minute." } });
// Register rate limit
const regLim = rateLimit({ windowMs: 300000, max: 3, message: { error: "Too many registrations from this IP." } });

app.use(express.static(path.join(__dirname, "../frontend")));

// ── INPUT SANITIZATION ────────────────────────────────────────
function sanitize(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/[<>]/g, "") // prevent XSS
    .replace(/javascript:/gi, "")
    .replace(/on\w+=/gi, "")
    .trim()
    .slice(0, 10000);
}

function validateUsername(u) {
  return typeof u === "string" && /^[A-Za-z0-9_]{4,30}$/.test(u);
}

// ── CSRF ──────────────────────────────────────────────────────
// We use HttpOnly session cookies + custom x-csrf-token header
// Since API requests need both session cookie AND csrf header,
// CSRF attacks from other origins cannot include the custom header
function csrfCheck(req, res, next) {
  const origin = req.headers.origin || req.headers.referer || "";
  const host   = req.headers.host || "";
  // Allow same-origin requests (no origin header or matching host)
  if (!origin || origin.includes(host.split(":")[0])) return next();
  // For cross-origin, require x-requested-with header
  if (!req.headers["x-requested-with"]) {
    return res.status(403).json({ error: "CSRF check failed." });
  }
  next();
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function auth(req, res, next) {
  // Read token from HttpOnly cookie
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/mt_sess=([^;]+)/);
  const token = match ? match[1] : null;

  if (!token) return res.status(401).json({ error: "Not authenticated" });

  const sess = loadSess();
  const s = sess[token];
  if (!s) return res.status(401).json({ error: "Session expired. Please login." });

  // 24h expiry
  if (Date.now() - s.created > 86400000) {
    delete sess[token]; saveSess(sess);
    res.setHeader("Set-Cookie", "mt_sess=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/");
    return res.status(401).json({ error: "Session expired. Please login." });
  }

  req.user = s;
  req.sessionToken = token;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required." });
  next();
}

// ── HELPERS ───────────────────────────────────────────────────
const ADJ  = ["Smart","Swift","Prime","Elite","Agile","Bold","Clear","Sharp","Bright","Quick"];
const NOUN = ["Mind","Core","Wave","Peak","Flow","Link","Star","Pulse","Edge","Base"];
function genCreds() {
  const u = ADJ[Math.floor(Math.random()*10)] + NOUN[Math.floor(Math.random()*10)] + (Math.floor(Math.random()*9000)+1000);
  const p = randId(4).toUpperCase().replace(/[^A-Z0-9]/g,"X") + Math.floor(Math.random()*900+100);
  return { username: u, password: p };
}

function wordCount(t) { return t.trim().split(/\s+/).filter(Boolean).length; }

function checkLimit(user) {
  const lim = LIMITS[user.role] || LIMITS.user;
  const used = user.usage_date === today() ? (user.daily_used || 0) : 0;
  return { ok: used < lim.daily_msgs, used, limit: lim.daily_msgs };
}

function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie",
    `mt_sess=${token}; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/`
  );
}

function logEvent(db, type, data) {
  if (!db.events) db.events = [];
  db.events.push({ type, data, ts: now() });
  // keep last 500 events
  if (db.events.length > 500) db.events = db.events.slice(-500);
}

// ── AUTH ROUTES ───────────────────────────────────────────────
app.post("/api/auth/register", regLim, (req, res) => {
  const db = loadDB();

  // Login with existing credentials
  const { username, password } = req.body;
  if (username && password) {
    if (!validateUsername(username))
      return res.status(400).json({ error: "Invalid username format." });
    const u = Object.values(db.users).find(x => x.username === username);
    if (!u || u.password_hash !== hash(password)) {
      logEvent(db, "failed_login", { username, ip: req.ip });
      saveDB(db);
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const token = randId(32);
    const sess = loadSess();
    sess[token] = { user_id:u.id, username:u.username, role:u.role, created:Date.now(), ip:req.ip };
    saveSess(sess);
    setSessionCookie(res, token);
    u.last_active = now();
    logEvent(db, "login", { username: u.username });
    saveDB(db);
    return res.json({ username:u.username, role:u.role, new_user:false, version:APP_VERSION });
  }

  // Auto-create new account
  const { username: un, password: pw } = genCreds();
  const id = randId(16);
  db.users[id] = {
    id, username:un, password_hash:hash(pw), role:"user",
    created:now(), last_active:now(), daily_used:0, usage_date:today(),
    total_msgs:0, total_tokens:0, theme:"dark", personality:"precise",
    conversations:{}, memory:{}, ip_registered: req.ip
  };
  const token = randId(32);
  const sess = loadSess();
  sess[token] = { user_id:id, username:un, role:"user", created:Date.now(), ip:req.ip };
  saveSess(sess);
  setSessionCookie(res, token);
  logEvent(db, "register", { username: un });
  saveDB(db);

  // Return password ONCE — client must show it then discard
  res.json({ username:un, password:pw, role:"user", new_user:true, version:APP_VERSION });
});

app.post("/api/auth/login", loginLim, csrfCheck, (req, res) => {
  const db = loadDB();
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: "Username and password required." });
  if (!validateUsername(username))
    return res.status(400).json({ error: "Invalid username format." });

  const u = Object.values(db.users).find(x => x.username === username);
  if (!u || u.password_hash !== hash(password)) {
    logEvent(db, "failed_login", { username, ip: req.ip });
    saveDB(db);
    return res.status(401).json({ error: "Invalid username or password." });
  }

  const token = randId(32);
  const sess = loadSess();
  sess[token] = { user_id:u.id, username:u.username, role:u.role, created:Date.now(), ip:req.ip };
  saveSess(sess);
  setSessionCookie(res, token);
  u.last_active = now();
  logEvent(db, "login", { username: u.username });
  saveDB(db);
  res.json({ username:u.username, role:u.role, version:APP_VERSION });
});

app.post("/api/auth/logout", auth, (req, res) => {
  // Invalidate server-side session
  const sess = loadSess();
  delete sess[req.sessionToken];
  saveSess(sess);
  // Clear cookie
  res.setHeader("Set-Cookie", "mt_sess=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error: "User not found" });
  const lim = checkLimit(u);
  res.json({
    username:u.username, role:u.role, theme:u.theme,
    personality:u.personality, version:APP_VERSION,
    total_msgs:u.total_msgs||0, daily_used:lim.used, daily_limit:lim.limit,
    created:u.created
  });
});

// ── SETTINGS ─────────────────────────────────────────────────
app.post("/api/settings", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error: "Not found" });
  const theme       = sanitize(req.body.theme || "");
  const personality = sanitize(req.body.personality || "");
  const allowed_themes = ["dark","ocean","midnight","light"];
  const allowed_pers   = ["precise","friendly","concise"];
  if (theme && allowed_themes.includes(theme))             u.theme       = theme;
  if (personality && allowed_pers.includes(personality))   u.personality = personality;
  u.last_active = now();
  saveDB(db);
  res.json({ ok: true });
});

// ── CONVERSATIONS ─────────────────────────────────────────────
app.get("/api/conversations", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error: "Not found" });
  const list = Object.values(u.conversations || {})
    .filter(c => !c.archived)
    .sort((a,b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 50);
  res.json({ conversations: list });
});

app.post("/api/conversations", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error: "Not found" });
  const id = randId(12);
  if (!u.conversations) u.conversations = {};
  u.conversations[id] = { id, title:"New Chat", created:now(), last_msg:now(), messages:[], archived:false };
  saveDB(db);
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  const cid = sanitize(req.params.id);
  if (u && u.conversations && u.conversations[cid])
    u.conversations[cid].archived = true;
  saveDB(db);
  res.json({ ok: true });
});

app.get("/api/history/:id", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  const cid = sanitize(req.params.id);
  const c  = u && u.conversations && u.conversations[cid];
  // Never expose image data in history to save bandwidth
  const msgs = (c ? c.messages : []).map(m => ({
    role: m.role, content: m.content, ts: m.ts,
    has_image: m.has_image || false
  }));
  res.json({ messages: msgs });
});

// ── CHAT ─────────────────────────────────────────────────────
app.post("/api/chat/stream", auth, async (req, res) => {
  const { conv_id, message, images } = req.body;
  const msg = sanitize(message || "");
  const cid = sanitize(conv_id || "");

  if (!cid || !msg)
    return res.status(400).json({ error: "Missing fields." });

  const db  = loadDB();
  const u   = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error: "Not found" });

  const lim = LIMITS[u.role] || LIMITS.user;

  // Guards
  if (msg.length > 8000)
    return res.status(400).json({ error: "Message too long." });

  const wc = wordCount(msg);
  if (wc > lim.max_words)
    return res.status(429).json({ error: "Exceeds " + lim.max_words + " words limit." });

  const limitCheck = checkLimit(u);
  if (!limitCheck.ok)
    return res.status(429).json({ error: "Daily limit of " + lim.daily_msgs + " messages reached. Try again tomorrow." });

  // Anti-spam
  if (u.last_msg_ts && Date.now() - u.last_msg_ts < 2000)
    return res.status(429).json({ error: "Please wait before sending another message." });

  // Validate images
  let safeImages = [];
  if (images && Array.isArray(images)) {
    for (const img of images.slice(0, 3)) {
      if (typeof img !== "string") continue;
      if (!img.startsWith("data:image/")) continue; // only real images
      const sizeBytes = img.length * 0.75;
      if (sizeBytes > lim.max_img_size_mb * 1024 * 1024) continue; // size check
      safeImages.push(img);
    }
  }

  const conv = u.conversations && u.conversations[cid];
  if (!conv) return res.status(404).json({ error: "Conversation not found." });

  // Save user message
  conv.messages.push({ role:"user", content:msg, has_image:safeImages.length>0, ts:now() });
  if (conv.messages.filter(m=>m.role==="user").length === 1) conv.title = msg.slice(0, 45);
  conv.last_msg = now();
  u.last_msg_ts = Date.now();
  if (u.usage_date !== today()) { u.daily_used = 0; u.usage_date = today(); }
  u.daily_used++;
  saveDB(db);

  // Build memory
  const memLines = Object.entries(u.memory || {}).map(([k,v]) => k+": "+v).join("\n");
  const memBlock = memLines ? "\n\n[User Memory]\n" + memLines : "";

  const SYSTEM = {
    precise:  "You are MedTerm v"+APP_VERSION+", a highly advanced AI assistant. Provide accurate, well-structured, and COMPLETE answers. Use clear formatting with headers, bullet points, numbered lists, and code blocks when appropriate. Never give incomplete answers. Reply in the same language the user writes in."+memBlock,
    friendly: "You are MedTerm v"+APP_VERSION+", a friendly and advanced AI assistant. Be warm, thorough, and precise. Use good formatting. Reply in the same language the user writes in."+memBlock,
    concise:  "You are MedTerm v"+APP_VERSION+", a concise AI assistant. Be direct but always complete. Reply in the same language the user writes in."+memBlock
  };

  const sysPrompt = SYSTEM[u.personality] || SYSTEM.precise;
  const history   = conv.messages.slice(-13, -1);

  const mistralMsgs = [{ role:"system", content:sysPrompt }];
  for (const m of history) {
    mistralMsgs.push({ role:m.role, content:m.content });
  }

  // Current message with optional images
  if (safeImages.length > 0) {
    const parts = [{ type:"text", text:msg }];
    for (const img of safeImages) parts.push({ type:"image_url", image_url:{ url:img } });
    mistralMsgs.push({ role:"user", content:parts });
  } else {
    mistralMsgs.push({ role:"user", content:msg });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  try {
    const model = safeImages.length > 0 ? "pixtral-12b-2409" : "mistral-large-latest";

    const apiRes = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": "Bearer " + process.env.MISTRAL_API_KEY
      },
      body: JSON.stringify({
        model, messages:mistralMsgs, temperature:0.3,
        max_tokens:lim.max_tokens, stream:true
      }),
      signal: AbortSignal.timeout(60000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(() => ({}));
      res.write("data: " + JSON.stringify({ error: e.message || e.error || "Mistral API error" }) + "\n\n");
      return res.end();
    }

    let fullReply = "";
    for await (const chunk of apiRes.body) {
      const lines = chunk.toString().split("\n").filter(l => l.startsWith("data: "));
      for (const line of lines) {
        const raw = line.slice(6).trim();
        if (raw === "[DONE]") continue;
        try {
          const j = JSON.parse(raw);
          const delta = (j.choices&&j.choices[0]&&j.choices[0].delta&&j.choices[0].delta.content) || "";
          if (delta) { fullReply += delta; res.write("data: " + JSON.stringify({ delta }) + "\n\n"); }
        } catch {}
      }
    }

    const tokens = Math.ceil((msg.length + fullReply.length) / 3);
    const db2 = loadDB();
    const u2  = db2.users[req.user.user_id];
    const c2  = u2 && u2.conversations && u2.conversations[cid];
    if (c2) {
      c2.messages.push({ role:"assistant", content:fullReply, tokens, ts:now() });
      u2.total_msgs = (u2.total_msgs||0) + 1;
      u2.total_tokens = (u2.total_tokens||0) + tokens;
    }

    // Extract memory
    if (!u2.memory) u2.memory = {};
    const memP = [
      {r:/my name is (\w+)/i,k:"name"},{r:/i am from ([\w\s]+)/i,k:"country"},
      {r:/i am (\d+) years/i,k:"age"},{r:/i work as ([\w\s]+)/i,k:"job"},
      {r:/اسمي\s+([\u0600-\u06FF\w]+)/,k:"name"},{r:/انا من\s+([\u0600-\u06FF\w]+)/,k:"country"},
      {r:/عمري\s+(\d+)/,k:"age"},{r:/اشتغل\s+([\u0600-\u06FF\w\s]+)/,k:"job"}
    ];
    for (const {r,k} of memP) { const m=msg.match(r); if(m) u2.memory[k]=sanitize(m[1]); }

    // Save training data
    db2.training.push({
      user_id:req.user.user_id, username:req.user.username,
      user_msg:msg, assistant_msg:fullReply,
      has_image:safeImages.length>0, model, tokens, ts:now()
    });

    logEvent(db2, "chat", { username:req.user.username, tokens, words:wc });
    saveDB(db2);

    const remaining = lim.daily_msgs - (u2 ? u2.daily_used : 0);
    res.write("data: " + JSON.stringify({ done:true, tokens, remaining }) + "\n\n");
    res.end();

  } catch (e) {
    const errMsg = e.name==="TimeoutError" ? "Request timed out." : "Connection error.";
    res.write("data: " + JSON.stringify({ error:errMsg }) + "\n\n");
    res.end();
  }
});

// ── STATS ─────────────────────────────────────────────────────
app.get("/api/stats", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error: "Not found" });
  const lim   = checkLimit(u);
  const convs = Object.values(u.conversations||{}).filter(c=>!c.archived).length;
  const train = db.training.filter(t=>t.user_id===req.user.user_id).length;

  // Activity last 7 days
  const act = {};
  const allMsgs = Object.values(u.conversations||{})
    .flatMap(c => c.messages||[])
    .filter(m => m.role==="user");
  allMsgs.forEach(m => { const d=m.ts?.slice(0,10); if(d) act[d]=(act[d]||0)+1; });

  res.json({
    total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0,
    conversations:convs, daily_used:lim.used, daily_limit:lim.limit,
    training_pairs:train, version:APP_VERSION,
    activity: Object.entries(act).sort().slice(-7).map(([day,count])=>({day,count}))
  });
});

// ── ADMIN DASHBOARD ───────────────────────────────────────────
app.get("/api/admin/dashboard", auth, adminOnly, (req, res) => {
  const db = loadDB();
  const users = Object.values(db.users);

  // Users stats
  const totalUsers   = users.length;
  const adminUsers   = users.filter(u=>u.role==="admin").length;
  const activeToday  = users.filter(u=>u.last_active?.slice(0,10)===today()).length;
  const activeWeek   = users.filter(u=>{
    const d=new Date(u.last_active||0);
    return Date.now()-d.getTime() < 7*86400000;
  }).length;

  // Messages stats
  const totalMsgs    = users.reduce((s,u)=>s+(u.total_msgs||0),0);
  const totalTokens  = users.reduce((s,u)=>s+(u.total_tokens||0),0);
  const totalTraining= db.training.length;

  // Activity last 14 days
  const activity = {};
  db.training.forEach(t => {
    const d = t.ts?.slice(0,10);
    if (d) activity[d] = (activity[d]||0)+1;
  });

  // Top users
  const topUsers = users
    .sort((a,b)=>(b.total_msgs||0)-(a.total_msgs||0))
    .slice(0,10)
    .map(u=>({ username:u.username, role:u.role, total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0, created:u.created, last_active:u.last_active }));

  // Recent events
  const recentEvents = (db.events||[]).slice(-50).reverse();

  // Models used
  const modelUsage = {};
  db.training.forEach(t => { modelUsage[t.model] = (modelUsage[t.model]||0)+1; });

  // Daily usage today
  const todayUsage = users.reduce((s,u)=>{
    return s + (u.usage_date===today() ? (u.daily_used||0) : 0);
  }, 0);

  res.json({
    overview: { totalUsers, adminUsers, activeToday, activeWeek, totalMsgs, totalTokens, totalTraining, todayUsage },
    topUsers,
    activity: Object.entries(activity).sort().slice(-14).map(([day,count])=>({day,count})),
    recentEvents,
    modelUsage,
    version: APP_VERSION
  });
});

app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  const db = loadDB();
  const users = Object.values(db.users).map(u => ({
    id:u.id, username:u.username, role:u.role,
    total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0,
    daily_used: u.usage_date===today() ? (u.daily_used||0) : 0,
    created:u.created, last_active:u.last_active,
    convs: Object.keys(u.conversations||{}).length,
    memory_keys: Object.keys(u.memory||{}).length
  }));
  res.json({ users, total:users.length });
});

app.post("/api/admin/set-role", auth, adminOnly, (req, res) => {
  const db = loadDB();
  const { username, role } = req.body;
  if (!["user","admin"].includes(role)) return res.status(400).json({ error:"Invalid role" });
  if (!validateUsername(username)) return res.status(400).json({ error:"Invalid username" });
  const u = Object.values(db.users).find(x=>x.username===username);
  if (!u) return res.status(404).json({ error:"User not found" });
  u.role=role;
  logEvent(db, "role_change", { by:req.user.username, target:username, role });
  saveDB(db);
  res.json({ ok:true });
});

app.post("/api/admin/reset-limit", auth, adminOnly, (req, res) => {
  const db = loadDB();
  const { username } = req.body;
  const u = Object.values(db.users).find(x=>x.username===username);
  if (!u) return res.status(404).json({ error:"User not found" });
  u.daily_used=0; u.usage_date=today();
  logEvent(db, "limit_reset", { by:req.user.username, target:username });
  saveDB(db);
  res.json({ ok:true });
});

app.delete("/api/admin/user/:username", auth, adminOnly, (req, res) => {
  const db = loadDB();
  const u = Object.values(db.users).find(x=>x.username===req.params.username);
  if (!u) return res.status(404).json({ error:"Not found" });
  if (u.username === req.user.username) return res.status(400).json({ error:"Cannot delete yourself" });
  delete db.users[u.id];
  logEvent(db, "user_deleted", { by:req.user.username, target:u.username });
  saveDB(db);
  res.json({ ok:true });
});

app.get("/api/admin/export", auth, adminOnly, (req, res) => {
  const db   = loadDB();
  const jsonl = db.training.map(r => JSON.stringify({
    messages:[
      { role:"system",    content:"You are MedTerm, an advanced AI assistant." },
      { role:"user",      content:r.user_msg },
      { role:"assistant", content:r.assistant_msg }
    ]
  })).join("\n");
  res.setHeader("Content-Type","application/jsonl");
  res.setHeader("Content-Disposition","attachment; filename=medterm_training.jsonl");
  res.send(jsonl);
});

app.get("*", (_, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));
app.listen(PORT, () => console.log("\nMedTerm v"+APP_VERSION+" → http://localhost:"+PORT+"\n"));
