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

// ── DB ────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE))
    fs.writeFileSync(DB_FILE, JSON.stringify({ users:{}, training:[] }));
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function loadSess() {
  if (!fs.existsSync(SESS_FILE)) fs.writeFileSync(SESS_FILE, JSON.stringify({}));
  return JSON.parse(fs.readFileSync(SESS_FILE, "utf8"));
}
function saveSess(s) { fs.writeFileSync(SESS_FILE, JSON.stringify(s)); }

const now    = () => new Date().toISOString();
const today  = () => new Date().toISOString().slice(0, 10);
const hash   = (t) => crypto.createHash("sha256").update(t + (process.env.SECRET || "mt")).digest("hex");
const randId = (n=8) => crypto.randomBytes(n).toString("hex");

// ── LIMITS ────────────────────────────────────────────────────
const LIMITS = {
  user:  { daily_msgs:30,  max_words:400,  max_tokens:1200 },
  admin: { daily_msgs:999, max_words:4000, max_tokens:4000 }
};

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "25mb" })); // support base64 images
app.use("/api/", rateLimit({ windowMs:60000, max:120, message:{ error:"Too many requests." } }));
const loginLim = rateLimit({ windowMs:60000, max:5, message:{ error:"Too many login attempts." } });
app.use(express.static(path.join(__dirname, "../frontend")));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers["x-session-token"];
  if (!token) return res.status(401).json({ error:"Not authenticated" });
  const sess = loadSess();
  const s = sess[token];
  if (!s || Date.now() - s.created > 86400000) {
    if (s) { delete sess[token]; saveSess(sess); }
    return res.status(401).json({ error:"Session expired. Please login again." });
  }
  req.user = s;
  next();
}
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error:"Admin only." });
  next();
}

// ── HELPERS ───────────────────────────────────────────────────
const ADJ  = ["Smart","Swift","Prime","Elite","Agile","Bold","Clear","Sharp","Bright","Quick"];
const NOUN = ["Mind","Core","Wave","Peak","Flow","Link","Star","Pulse","Edge","Base"];
function genCreds() {
  const u = ADJ[Math.floor(Math.random()*10)] + NOUN[Math.floor(Math.random()*10)] + (Math.floor(Math.random()*9000)+1000);
  const p = randId(4).toUpperCase() + Math.floor(Math.random()*900+100);
  return { username: u, password: p };
}
function wordCount(t) { return t.trim().split(/\s+/).filter(Boolean).length; }
function checkLimit(user) {
  const lim = LIMITS[user.role] || LIMITS.user;
  const used = user.usage_date === today() ? (user.daily_used || 0) : 0;
  return { ok: used < lim.daily_msgs, used, limit: lim.daily_msgs };
}
function getUser(db, id) { return db.users[id]; }

// ── AUTH ROUTES ───────────────────────────────────────────────
app.post("/api/auth/register", (req, res) => {
  const db = loadDB();
  const { username, password } = req.body;

  if (username && password) {
    const u = Object.values(db.users).find(x => x.username === username);
    if (!u || u.password_hash !== hash(password))
      return res.status(401).json({ error:"Invalid username or password." });
    const token = randId(32);
    const sess = loadSess();
    sess[token] = { user_id:u.id, username:u.username, role:u.role, created:Date.now() };
    saveSess(sess);
    return res.json({ token, username:u.username, role:u.role, new_user:false });
  }

  const { username: un, password: pw } = genCreds();
  const id = randId(16);
  db.users[id] = {
    id, username:un, password_hash:hash(pw), role:"user",
    created:now(), last_active:now(), daily_used:0, usage_date:today(),
    total_msgs:0, total_tokens:0, theme:"dark", personality:"precise",
    conversations:{}, memory:{}
  };
  saveDB(db);
  const token = randId(32);
  const sess = loadSess();
  sess[token] = { user_id:id, username:un, role:"user", created:Date.now() };
  saveSess(sess);
  res.json({ token, username:un, password:pw, role:"user", new_user:true });
});

app.post("/api/auth/login", loginLim, (req, res) => {
  const db = loadDB();
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error:"Missing fields." });
  const u = Object.values(db.users).find(x => x.username === username);
  if (!u || u.password_hash !== hash(password))
    return res.status(401).json({ error:"Invalid username or password." });
  const token = randId(32);
  const sess = loadSess();
  sess[token] = { user_id:u.id, username:u.username, role:u.role, created:Date.now() };
  saveSess(sess);
  res.json({ token, username:u.username, role:u.role });
});

app.post("/api/auth/logout", auth, (req, res) => {
  const token = req.headers["x-session-token"];
  const sess = loadSess(); delete sess[token]; saveSess(sess);
  res.json({ ok:true });
});

app.get("/api/me", auth, (req, res) => {
  const db = loadDB();
  const u  = getUser(db, req.user.user_id);
  if (!u) return res.status(404).json({ error:"Not found" });
  const lim = checkLimit(u);
  res.json({
    username:u.username, role:u.role, theme:u.theme, personality:u.personality,
    total_msgs:u.total_msgs, daily_used:lim.used, daily_limit:lim.limit, created:u.created
  });
});

// ── SETTINGS ─────────────────────────────────────────────────
app.post("/api/settings", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error:"Not found" });
  const { theme, personality } = req.body;
  if (theme)       u.theme       = theme;
  if (personality) u.personality = personality;
  u.last_active = now();
  saveDB(db);
  res.json({ ok:true });
});

// ── CONVERSATIONS ─────────────────────────────────────────────
app.get("/api/conversations", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error:"Not found" });
  const list = Object.values(u.conversations || {})
    .filter(c => !c.archived)
    .sort((a,b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 50);
  res.json({ conversations: list });
});

app.post("/api/conversations", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error:"Not found" });
  const id = randId(16);
  if (!u.conversations) u.conversations = {};
  u.conversations[id] = { id, title:"New Chat", created:now(), last_msg:now(), messages:[], archived:false };
  saveDB(db);
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (u && u.conversations && u.conversations[req.params.id])
    u.conversations[req.params.id].archived = true;
  saveDB(db);
  res.json({ ok:true });
});

app.get("/api/history/:id", auth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  const c  = u && u.conversations && u.conversations[req.params.id];
  res.json({ messages: c ? c.messages : [] });
});

// ── CHAT WITH MISTRAL ─────────────────────────────────────────
app.post("/api/chat/stream", auth, async (req, res) => {
  const { conv_id, message, images } = req.body; // images = array of base64
  if (!conv_id || !message)
    return res.status(400).json({ error:"Missing fields." });

  const db  = loadDB();
  const u   = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error:"Not found" });

  const lim = LIMITS[u.role] || LIMITS.user;

  // Guards
  if (message.length > 8000)
    return res.status(400).json({ error:"Message too long." });
  if (wordCount(message) > lim.max_words)
    return res.status(429).json({ error:"Exceeds " + lim.max_words + " words limit." });

  const limitCheck = checkLimit(u);
  if (!limitCheck.ok)
    return res.status(429).json({ error:"Daily limit of " + lim.daily_msgs + " messages reached. Try tomorrow." });

  if (u.last_msg_ts && Date.now() - u.last_msg_ts < 2000)
    return res.status(429).json({ error:"Please wait before sending another message." });

  const conv = u.conversations && u.conversations[conv_id];
  if (!conv) return res.status(404).json({ error:"Conversation not found." });

  // Save user message
  const userMsgObj = { role:"user", content:message, has_image: !!(images && images.length), ts:now() };
  conv.messages.push(userMsgObj);
  if (conv.messages.length === 1) conv.title = message.slice(0, 45);
  conv.last_msg = now();
  u.last_msg_ts = Date.now();
  if (u.usage_date !== today()) { u.daily_used = 0; u.usage_date = today(); }
  u.daily_used++;
  saveDB(db);

  // Build memory context
  const memLines = Object.entries(u.memory || {}).map(([k,v]) => k + ": " + v).join("\n");
  const memBlock = memLines ? "\n\n[User Memory]\n" + memLines : "";

  const SYSTEM = {
    precise: "You are MedTerm, a highly advanced AI assistant. Provide accurate, well-structured, and complete answers. Use clear formatting with headers, bullet points, and code blocks when appropriate. Never give incomplete answers. Reply in the same language the user writes in." + memBlock,
    friendly: "You are MedTerm, a friendly and advanced AI assistant. Be warm, thorough, and precise. Use good formatting. Reply in the same language the user writes in." + memBlock,
    concise: "You are MedTerm, a concise AI assistant. Be direct but complete. Use minimal formatting. Reply in the same language the user writes in." + memBlock
  };

  const sysPrompt = SYSTEM[u.personality] || SYSTEM.precise;
  const history   = conv.messages.slice(-13, -1);

  // Build Mistral messages
  const mistralMsgs = [{ role:"system", content: sysPrompt }];

  for (const m of history) {
    mistralMsgs.push({ role: m.role, content: m.content });
  }

  // Current message — with optional images
  if (images && images.length > 0) {
    const contentParts = [{ type:"text", text: message }];
    for (const img of images.slice(0, 3)) {
      contentParts.push({ type:"image_url", image_url: { url: img } });
    }
    mistralMsgs.push({ role:"user", content: contentParts });
  } else {
    mistralMsgs.push({ role:"user", content: message });
  }

  // SSE
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  try {
    const model = (images && images.length > 0) ? "pixtral-12b-2409" : "mistral-large-latest";

    const apiRes = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": "Bearer " + process.env.MISTRAL_API_KEY
      },
      body: JSON.stringify({
        model,
        messages:    mistralMsgs,
        temperature: 0.3,
        max_tokens:  lim.max_tokens,
        stream:      true
      }),
      signal: AbortSignal.timeout(60000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(() => ({}));
      res.write("data: " + JSON.stringify({ error:(e.message || e.error || "Mistral API error") }) + "\n\n");
      return res.end();
    }

    let fullReply = "";
    for await (const chunk of apiRes.body) {
      const lines = chunk.toString().split("\n").filter(l => l.startsWith("data: "));
      for (const line of lines) {
        const raw = line.slice(6).trim();
        if (raw === "[DONE]") continue;
        try {
          const j     = JSON.parse(raw);
          const delta = (j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content) || "";
          if (delta) { fullReply += delta; res.write("data: " + JSON.stringify({ delta }) + "\n\n"); }
        } catch {}
      }
    }

    const tokens = Math.ceil((message.length + fullReply.length) / 3);

    // Save assistant reply
    const db2 = loadDB();
    const u2  = db2.users[req.user.user_id];
    const c2  = u2 && u2.conversations && u2.conversations[conv_id];
    if (c2) {
      c2.messages.push({ role:"assistant", content:fullReply, tokens, model, ts:now() });
      u2.total_msgs++;
      u2.total_tokens = (u2.total_tokens || 0) + tokens;
    }

    // Extract memory
    if (!u2.memory) u2.memory = {};
    const memP = [
      { r:/my name is (\w+)/i,           k:"name" },
      { r:/i am from ([\w\s]+)/i,         k:"country" },
      { r:/i am (\d+) years/i,            k:"age" },
      { r:/i work as ([\w\s]+)/i,         k:"job" },
      { r:/اسمي\s+([\u0600-\u06FF\w]+)/,  k:"name" },
      { r:/انا من\s+([\u0600-\u06FF\w]+)/,k:"country" },
      { r:/عمري\s+(\d+)/,                 k:"age" },
      { r:/اشتغل\s+([\u0600-\u06FF\w]+)/, k:"job" }
    ];
    for (const { r, k } of memP) {
      const m = message.match(r);
      if (m) u2.memory[k] = m[1];
    }

    // Save training data
    db2.training.push({
      user_id:  req.user.user_id,
      username: req.user.username,
      user_msg: message,
      assistant_msg: fullReply,
      has_image: !!(images && images.length),
      model, tokens, ts: now()
    });

    saveDB(db2);

    const remaining = lim.daily_msgs - (u2 ? u2.daily_used : 0);
    res.write("data: " + JSON.stringify({ done:true, tokens, remaining, model }) + "\n\n");
    res.end();

  } catch (e) {
    const msg = e.name === "TimeoutError" ? "Request timed out." : "Connection error: " + e.message;
    res.write("data: " + JSON.stringify({ error: msg }) + "\n\n");
    res.end();
  }
});

// ── STATS ─────────────────────────────────────────────────────
app.get("/api/stats", auth, (req, res) => {
  const db  = loadDB();
  const u   = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error:"Not found" });
  const lim  = checkLimit(u);
  const convs = Object.values(u.conversations || {}).filter(c => !c.archived).length;
  const train = db.training.filter(t => t.user_id === req.user.user_id).length;
  res.json({
    total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0,
    conversations:convs, daily_used:lim.used, daily_limit:lim.limit, training_pairs:train
  });
});

// ── ADMIN ─────────────────────────────────────────────────────
app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  const db = loadDB();
  res.json({
    users: Object.values(db.users).map(u => ({
      id:u.id, username:u.username, role:u.role,
      total_msgs:u.total_msgs||0, created:u.created
    })),
    total: Object.keys(db.users).length,
    training_pairs: db.training.length
  });
});

app.post("/api/admin/set-role", auth, adminOnly, (req, res) => {
  const db = loadDB();
  const { username, role } = req.body;
  if (!["user","admin"].includes(role)) return res.status(400).json({ error:"Invalid role" });
  const u = Object.values(db.users).find(x => x.username === username);
  if (!u) return res.status(404).json({ error:"User not found" });
  u.role = role; saveDB(db);
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
app.listen(PORT, () => console.log("\nMedTerm v2 running on http://localhost:" + PORT + "\n"));
