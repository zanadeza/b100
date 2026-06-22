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
const DB_FILE      = path.join(__dirname, "medterm_db.json");
const SESSION_FILE = path.join(__dirname, "sessions.json");

// ── DB ────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE))
    fs.writeFileSync(DB_FILE, JSON.stringify({ users:{}, training:[], messages:[] }));
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

function loadSessions() {
  if (!fs.existsSync(SESSION_FILE)) fs.writeFileSync(SESSION_FILE, JSON.stringify({}));
  return JSON.parse(fs.readFileSync(SESSION_FILE, "utf8"));
}
function saveSessions(s) { fs.writeFileSync(SESSION_FILE, JSON.stringify(s)); }

const now    = () => new Date().toISOString();
const today  = () => new Date().toISOString().slice(0, 10);
const hash   = (t) => crypto.createHash("sha256").update(t + process.env.SECRET).digest("hex");
const randId = (n=8) => crypto.randomBytes(n).toString("hex");

// ── LIMITS ────────────────────────────────────────────────────
const LIMITS = {
  user:  { daily_msgs: 30, max_input_words: 300,  max_output_tokens: 800  },
  admin: { daily_msgs: 999, max_input_words: 2000, max_output_tokens: 2000 }
};

// ── SECURITY ──────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "15kb" }));

// IP rate limit — max 100 req/min
app.use("/api/", rateLimit({
  windowMs: 60000, max: 100,
  message: { error: "Too many requests. Please wait." },
  keyGenerator: (req) => req.ip || "unknown"
}));

// Login rate limit — max 5 attempts/min
const loginLimiter = rateLimit({
  windowMs: 60000, max: 5,
  message: { error: "Too many login attempts. Wait 1 minute." }
});

app.use(express.static(path.join(__dirname, "../frontend")));

// ── SESSION MIDDLEWARE ─────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers["x-session-token"];
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  const sessions = loadSessions();
  const sess = sessions[token];
  if (!sess) return res.status(401).json({ error: "Session expired. Please login again." });
  // check expiry (24h)
  if (Date.now() - sess.created > 86400000) {
    delete sessions[token];
    saveSessions(sessions);
    return res.status(401).json({ error: "Session expired. Please login again." });
  }
  req.user = sess;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required." });
  next();
}

// ── WORD COUNT ────────────────────────────────────────────────
function wordCount(text) {
  return text.trim().split(/\s+/).filter(Boolean).length;
}

function checkDailyLimit(user) {
  const lim = LIMITS[user.role] || LIMITS.user;
  const usageDate = user.usage_date;
  const usedToday = usageDate === today() ? (user.daily_msgs_used || 0) : 0;
  return { allowed: usedToday < lim.daily_msgs, used: usedToday, limit: lim.daily_msgs };
}

// ── GENERATE USERNAME/PASSWORD ────────────────────────────────
const ADJECTIVES = ["Smart","Quick","Bright","Swift","Clear","Sharp","Bold","Prime","Elite","Agile"];
const NOUNS      = ["Mind","Star","Wave","Pulse","Core","Edge","Peak","Flow","Link","Base"];

function generateCredentials() {
  const adj  = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  const num  = Math.floor(Math.random() * 9000) + 1000;
  const username = adj + noun + num;
  const password = randId(5).toUpperCase().replace(/[^A-Z0-9]/g,"") + Math.floor(Math.random()*900+100);
  return { username, password };
}

// ── ROUTES ────────────────────────────────────────────────────

// Auto-register: new visitor → get credentials
app.post("/api/auth/register", (req, res) => {
  const db = loadDB();
  const { username: reqUser, password: reqPass } = req.body;

  // If credentials provided, try login instead
  if (reqUser && reqPass) {
    const user = Object.values(db.users).find(u => u.username === reqUser);
    if (!user || user.password_hash !== hash(reqPass))
      return res.status(401).json({ error: "Invalid username or password." });
    // create session
    const token = randId(32);
    const sessions = loadSessions();
    sessions[token] = { user_id: user.id, username: user.username, role: user.role, created: Date.now() };
    saveSessions(sessions);
    return res.json({ token, username: user.username, role: user.role, new_user: false });
  }

  // Auto-create new account
  const { username, password } = generateCredentials();
  const id = randId(16);
  db.users[id] = {
    id, username, password_hash: hash(password),
    role: "user", created: now(), last_active: now(),
    daily_msgs_used: 0, usage_date: today(),
    total_msgs: 0, total_tokens: 0,
    theme: "dark", personality: "friendly", model_pref: "gpt-3.5-turbo",
    conversations: {}, memory: {}
  };
  saveDB(db);

  const token = randId(32);
  const sessions = loadSessions();
  sessions[token] = { user_id: id, username, role: "user", created: Date.now() };
  saveSessions(sessions);

  res.json({ token, username, password, role: "user", new_user: true });
});

// Login
app.post("/api/auth/login", loginLimiter, (req, res) => {
  const db = loadDB();
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required." });

  const user = Object.values(db.users).find(u => u.username === username);
  if (!user || user.password_hash !== hash(password))
    return res.status(401).json({ error: "Invalid username or password." });

  const token = randId(32);
  const sessions = loadSessions();
  sessions[token] = { user_id: user.id, username: user.username, role: user.role, created: Date.now() };
  saveSessions(sessions);
  res.json({ token, username: user.username, role: user.role });
});

// Logout
app.post("/api/auth/logout", requireAuth, (req, res) => {
  const token = req.headers["x-session-token"];
  const sessions = loadSessions();
  delete sessions[token];
  saveSessions(sessions);
  res.json({ ok: true });
});

// Get profile
app.get("/api/me", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (!user) return res.status(404).json({ error: "User not found" });
  const limit = checkDailyLimit(user);
  res.json({
    username: user.username, role: user.role, theme: user.theme,
    personality: user.personality, model_pref: user.model_pref,
    total_msgs: user.total_msgs, daily_used: limit.used, daily_limit: limit.limit,
    created: user.created
  });
});

// Update settings
app.post("/api/settings", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (!user) return res.status(404).json({ error: "User not found" });
  const { theme, personality, model_pref } = req.body;
  if (theme)       user.theme       = theme;
  if (personality) user.personality = personality;
  if (model_pref && req.user.role === "admin") user.model_pref = model_pref;
  user.last_active = now();
  saveDB(db);
  res.json({ ok: true });
});

// Conversations
app.get("/api/conversations", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (!user) return res.status(404).json({ error: "not found" });
  const convs = Object.values(user.conversations || {})
    .filter(c => !c.archived)
    .sort((a, b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 40);
  res.json({ conversations: convs });
});

app.post("/api/conversations", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (!user) return res.status(404).json({ error: "not found" });
  const id = randId(16);
  if (!user.conversations) user.conversations = {};
  user.conversations[id] = { id, title: "New Chat", created: now(), last_msg: now(), messages: [], archived: false };
  saveDB(db);
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (user && user.conversations && user.conversations[req.params.id])
    user.conversations[req.params.id].archived = true;
  saveDB(db);
  res.json({ ok: true });
});

app.get("/api/history/:conv_id", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  const conv = user && user.conversations && user.conversations[req.params.conv_id];
  res.json({ messages: conv ? conv.messages : [] });
});

// ── CHAT (STREAMING) ──────────────────────────────────────────
app.post("/api/chat/stream", requireAuth, async (req, res) => {
  const { conv_id, message } = req.body;
  if (!conv_id || !message)
    return res.status(400).json({ error: "Missing fields." });

  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (!user) return res.status(404).json({ error: "User not found" });

  const lim = LIMITS[user.role] || LIMITS.user;

  // ── GUARDS ──
  // 1. message length
  if (message.length > 3000)
    return res.status(400).json({ error: "Message too long. Max 3000 characters." });

  // 2. word count
  const words = wordCount(message);
  if (words > lim.max_input_words)
    return res.status(429).json({ error: "Message exceeds " + lim.max_input_words + " words limit." });

  // 3. daily limit
  const limitCheck = checkDailyLimit(user);
  if (!limitCheck.allowed)
    return res.status(429).json({ error: "Daily limit of " + lim.daily_msgs + " messages reached. Try again tomorrow." });

  // 4. spam detection — reject if last message was < 2 seconds ago
  if (user.last_msg_time && Date.now() - user.last_msg_time < 2000)
    return res.status(429).json({ error: "Slow down! Please wait before sending another message." });

  const conv = user.conversations && user.conversations[conv_id];
  if (!conv) return res.status(404).json({ error: "Conversation not found." });

  // save user message
  conv.messages.push({ role: "user", content: message, ts: now() });
  if (conv.messages.length === 1) conv.title = message.slice(0, 40);
  conv.last_msg = now();
  user.last_msg_time = Date.now();

  // update daily usage
  if (user.usage_date !== today()) { user.daily_msgs_used = 0; user.usage_date = today(); }
  user.daily_msgs_used++;
  saveDB(db);

  // build context (last 12 messages)
  const history = conv.messages.slice(-13, -1);

  // memory
  const memLines = Object.entries(user.memory || {}).map(([k,v]) => k + ": " + v).join("\n");
  const memBlock = memLines ? "\n\n[User Memory]\n" + memLines : "";

  const PERSONALITIES = {
    friendly: "You are MedTerm, an advanced AI assistant. You are helpful, warm, and thorough. Always reply in the same language the user writes in. Give complete, well-structured answers.",
    formal:   "You are MedTerm, a professional AI assistant. Be precise, formal, and comprehensive. Always reply in the same language the user writes in.",
    concise:  "You are MedTerm, an AI assistant. Be direct and concise but complete. Always reply in the same language the user writes in."
  };

  const sysPrompt = (PERSONALITIES[user.personality] || PERSONALITIES.friendly) + memBlock;
  const model     = user.role === "admin" ? (user.model_pref || "gpt-3.5-turbo") : "gpt-3.5-turbo";

  const messages = [
    { role: "system", content: sysPrompt },
    ...history.map(m => ({ role: m.role, content: m.content })),
    { role: "user", content: message }
  ];

  // SSE
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  try {
    const apiRes = await fetch(process.env.API_BASE + "/chat/completions", {
      method:  "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.API_KEY },
      body: JSON.stringify({ model, messages, temperature: 0.7, max_tokens: lim.max_output_tokens, stream: true }),
      signal: AbortSignal.timeout(45000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(() => ({}));
      res.write("data: " + JSON.stringify({ error: (e.error && e.error.message) || "AI error" }) + "\n\n");
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
        } catch (e2) {}
      }
    }

    const tokens = Math.ceil((message.length + fullReply.length) / 3);

    // save assistant reply + training data
    const db2 = loadDB();
    const u2  = db2.users[req.user.user_id];
    const c2  = u2 && u2.conversations && u2.conversations[conv_id];
    if (c2) {
      c2.messages.push({ role: "assistant", content: fullReply, tokens, ts: now() });
      u2.total_msgs++;
      u2.total_tokens = (u2.total_tokens || 0) + tokens;
    }

    // extract memory
    const memPatterns = [
      { r: /my name is (\w+)/i,   k: "name" },
      { r: /i am from (\w+)/i,    k: "country" },
      { r: /i am (\d+) years/i,   k: "age" },
      { r: /اسمي\s+([\u0600-\u06FF\w]+)/,   k: "name" },
      { r: /انا من\s+([\u0600-\u06FF\w]+)/, k: "country" },
      { r: /عمري\s+(\d+)/,                  k: "age" }
    ];
    if (!u2.memory) u2.memory = {};
    for (const { r, k } of memPatterns) {
      const m = message.match(r);
      if (m) u2.memory[k] = m[1];
    }

    // save training pair
    db2.training.push({
      user_id: req.user.user_id, username: req.user.username,
      user_msg: message, assistant_msg: fullReply, model, tokens, ts: now()
    });

    saveDB(db2);

    const remaining = (LIMITS[req.user.role].daily_msgs) - (u2 ? u2.daily_msgs_used : 0);
    res.write("data: " + JSON.stringify({ done: true, tokens, remaining }) + "\n\n");
    res.end();

  } catch (e) {
    const msg = e.name === "TimeoutError" ? "Request timed out." : "Connection error.";
    res.write("data: " + JSON.stringify({ error: msg }) + "\n\n");
    res.end();
  }
});

// ── STATS ────────────────────────────────────────────────────
app.get("/api/stats", requireAuth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.user_id];
  if (!user) return res.status(404).json({ error: "not found" });
  const limit = checkDailyLimit(user);
  const convCount = Object.values(user.conversations || {}).filter(c => !c.archived).length;
  res.json({
    total_msgs: user.total_msgs || 0, total_tokens: user.total_tokens || 0,
    conversations: convCount, daily_used: limit.used, daily_limit: limit.limit,
    training_pairs: db.training.filter(t => t.user_id === req.user.user_id).length
  });
});

// ── ADMIN ────────────────────────────────────────────────────
app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const users = Object.values(db.users).map(u => ({
    id: u.id, username: u.username, role: u.role,
    total_msgs: u.total_msgs || 0, created: u.created, last_active: u.last_active
  }));
  res.json({ users, total: users.length, training_pairs: db.training.length });
});

app.post("/api/admin/set-role", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const { username, role } = req.body;
  if (!["user","admin"].includes(role)) return res.status(400).json({ error: "Invalid role" });
  const user = Object.values(db.users).find(u => u.username === username);
  if (!user) return res.status(404).json({ error: "User not found" });
  user.role = role;
  saveDB(db);
  res.json({ ok: true });
});

app.get("/api/admin/export-training", requireAuth, requireAdmin, (req, res) => {
  const db   = loadDB();
  const jsonl = db.training.map(r => JSON.stringify({
    messages: [
      { role: "system",    content: "You are MedTerm, an advanced AI assistant." },
      { role: "user",      content: r.user_msg },
      { role: "assistant", content: r.assistant_msg }
    ]
  })).join("\n");
  res.setHeader("Content-Type", "application/jsonl");
  res.setHeader("Content-Disposition", "attachment; filename=medterm_training.jsonl");
  res.send(jsonl);
});

// catch-all
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));

app.listen(PORT, () => console.log("\nMedTerm running on http://localhost:" + PORT + "\n"));
