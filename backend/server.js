require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const { v4: uuidv4 } = require("uuid");
const Database  = require("better-sqlite3");
const path      = require("path");
const fetch     = (...a) => import("node-fetch").then(({ default: f }) => f(...a));

const app = express();
const PORT = process.env.PORT || 3000;
const DB   = new Database("zaka.db");

// ── قاعدة البيانات الكاملة ────────────────────────────────────
DB.exec(`
  CREATE TABLE IF NOT EXISTS users (
    session_id  TEXT PRIMARY KEY,
    name        TEXT DEFAULT 'صديقي',
    personality TEXT DEFAULT 'friendly',
    model_pref  TEXT DEFAULT 'gpt-3.5-turbo',
    font_size   TEXT DEFAULT 'medium',
    theme       TEXT DEFAULT 'dark',
    created     TEXT,
    last_active TEXT,
    total_msgs  INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    session_id TEXT,
    title      TEXT DEFAULT 'محادثة جديدة',
    created    TEXT,
    last_msg   TEXT,
    msg_count  INTEGER DEFAULT 0,
    archived   INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    conv_id     TEXT,
    session_id  TEXT,
    role        TEXT,
    content     TEXT,
    tokens      INTEGER DEFAULT 0,
    model       TEXT,
    ts          TEXT
  );

  CREATE TABLE IF NOT EXISTS user_memory (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    key        TEXT,
    value      TEXT,
    ts         TEXT
  );

  CREATE TABLE IF NOT EXISTS training_data (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT,
    conv_id       TEXT,
    user_msg      TEXT,
    assistant_msg TEXT,
    context       TEXT,
    model         TEXT,
    tokens        INTEGER DEFAULT 0,
    ts            TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_msgs_conv ON messages(conv_id);
  CREATE INDEX IF NOT EXISTS idx_msgs_session ON messages(session_id);
  CREATE INDEX IF NOT EXISTS idx_training_session ON training_data(session_id);
`);

// ── أمان ──────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "20kb" }));
app.use("/api/", rateLimit({ windowMs: 60_000, max: 80,
  message: { error: "طلبات كثيرة جداً، انتظر دقيقة." }
}));
app.use(express.static(path.join(__dirname, "../frontend")));

// ── مساعدات ───────────────────────────────────────────────────
const now = () => new Date().toISOString();

const SYSTEM_PROMPTS = {
  friendly: "أنت مساعد ذكي ودود اسمك ذكاء. تتكلم العربية بطلاقة وتجيب بأسلوب دافئ ومبسط. تتذكر تفضيلات المستخدم وتبني على السياق.",
  formal:   "أنت مساعد ذكاء اصطناعي متخصص اسمك ذكاء. تجيب بأسلوب رسمي ودقيق ومهني. تستشهد بالمعلومات بوضوح.",
  concise:  "أنت مساعد ذكي اسمك ذكاء. إجاباتك مختصرة ومباشرة. لا تطول إلا عند الضرورة."
};

function getUser(sid) {
  let u = DB.prepare("SELECT * FROM users WHERE session_id=?").get(sid);
  if (!u) {
    DB.prepare("INSERT INTO users (session_id,created,last_active) VALUES (?,?,?)").run(sid, now(), now());
    u = DB.prepare("SELECT * FROM users WHERE session_id=?").get(sid);
  }
  return u;
}

function getMemory(sid) {
  const rows = DB.prepare("SELECT key,value FROM user_memory WHERE session_id=? ORDER BY id DESC LIMIT 20").all(sid);
  if (!rows.length) return "";
  return "\n\n[ذاكرة المستخدم]\n" + rows.map(r => `${r.key}: ${r.value}`).join("\n");
}

function extractMemory(sid, userMsg, aiReply) {
  const patterns = [
    { r: /اسمي\s+([\u0600-\u06FF\w]+)/,    k: "اسم المستخدم" },
    { r: /أنا\s+من\s+([\u0600-\u06FF\w]+)/, k: "بلد المستخدم" },
    { r: /عمري\s+(\d+)/,                     k: "عمر المستخدم" },
    { r: /أعمل\s+(?:في|ك)\s*([\u0600-\u06FF\w\s]+)/, k: "عمل المستخدم" }
  ];
  for (const { r, k } of patterns) {
    const m = userMsg.match(r);
    if (m) {
      const exists = DB.prepare("SELECT id FROM user_memory WHERE session_id=? AND key=?").get(sid, k);
      if (exists) DB.prepare("UPDATE user_memory SET value=?,ts=? WHERE session_id=? AND key=?").run(m[1], now(), sid, k);
      else DB.prepare("INSERT INTO user_memory (session_id,key,value,ts) VALUES (?,?,?,?)").run(sid, k, m[1], now());
    }
  }
}

function autoTitle(text) {
  const clean = text.replace(/[^\u0600-\u06FF\w\s]/g, "").trim();
  return clean.slice(0, 35) + (clean.length > 35 ? "..." : "");
}

function getConvHistory(convId, limit = 14) {
  return DB.prepare(
    "SELECT role,content FROM messages WHERE conv_id=? ORDER BY id DESC LIMIT ?"
  ).all(convId, limit).reverse();
}

// ── API Routes ─────────────────────────────────────────────────

// الجلسة
app.post("/api/session", (req, res) => {
  const sid = req.body.session_id || uuidv4();
  const user = getUser(sid);
  DB.prepare("UPDATE users SET last_active=? WHERE session_id=?").run(now(), sid);
  res.json({ session_id: sid, name: user.name, theme: user.theme,
    font_size: user.font_size, personality: user.personality, model_pref: user.model_pref });
});

// تحديث إعدادات المستخدم
app.post("/api/settings", (req, res) => {
  const { session_id, name, personality, model_pref, font_size, theme } = req.body;
  if (!session_id) return res.status(400).json({ error: "no session" });
  getUser(session_id);
  DB.prepare(`UPDATE users SET
    name=COALESCE(?,name), personality=COALESCE(?,personality),
    model_pref=COALESCE(?,model_pref), font_size=COALESCE(?,font_size),
    theme=COALESCE(?,theme) WHERE session_id=?`
  ).run(name||null, personality||null, model_pref||null, font_size||null, theme||null, session_id);
  res.json({ ok: true });
});

// المحادثات
app.get("/api/conversations/:sid", (req, res) => {
  const convs = DB.prepare(
    "SELECT * FROM conversations WHERE session_id=? AND archived=0 ORDER BY last_msg DESC LIMIT 50"
  ).all(req.params.sid);
  res.json({ conversations: convs });
});

app.post("/api/conversations", (req, res) => {
  const { session_id } = req.body;
  if (!session_id) return res.status(400).json({ error: "no session" });
  getUser(session_id);
  const id = uuidv4();
  DB.prepare("INSERT INTO conversations (id,session_id,created,last_msg) VALUES (?,?,?,?)").run(id, session_id, now(), now());
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", (req, res) => {
  DB.prepare("UPDATE conversations SET archived=1 WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// سجل المحادثة
app.get("/api/history/:conv_id", (req, res) => {
  const msgs = DB.prepare(
    "SELECT role,content,tokens,ts FROM messages WHERE conv_id=? ORDER BY id"
  ).all(req.params.conv_id);
  res.json({ messages: msgs });
});

// البحث
app.get("/api/search", (req, res) => {
  const { session_id, q } = req.query;
  if (!q || q.length < 2) return res.json({ results: [] });
  const results = DB.prepare(`
    SELECT m.content, m.role, m.ts, c.id as conv_id, c.title
    FROM messages m JOIN conversations c ON m.conv_id=c.id
    WHERE m.session_id=? AND m.content LIKE ? AND c.archived=0
    ORDER BY m.id DESC LIMIT 20
  `).all(session_id, `%${q}%`);
  res.json({ results });
});

// الذاكرة
app.get("/api/memory/:sid", (req, res) => {
  const mem = DB.prepare("SELECT key,value,ts FROM user_memory WHERE session_id=? ORDER BY id DESC").all(req.params.sid);
  res.json({ memory: mem });
});

// الإرسال مع Streaming
app.post("/api/chat/stream", async (req, res) => {
  const { session_id, conv_id, message } = req.body;
  if (!session_id || !conv_id || !message || message.length > 3000)
    return res.status(400).json({ error: "طلب غير صحيح" });

  const user = getUser(session_id);
  const conv = DB.prepare("SELECT * FROM conversations WHERE id=?").get(conv_id);
  if (!conv) return res.status(404).json({ error: "محادثة غير موجودة" });

  // حفظ رسالة المستخدم
  DB.prepare("INSERT INTO messages (conv_id,session_id,role,content,ts) VALUES (?,?,?,?,?)")
    .run(conv_id, session_id, "user", message, now());

  // تحديث عنوان المحادثة
  if (conv.msg_count === 0) {
    DB.prepare("UPDATE conversations SET title=? WHERE id=?").run(autoTitle(message), conv_id);
  }
  DB.prepare("UPDATE conversations SET last_msg=?, msg_count=msg_count+1 WHERE id=?").run(now(), conv_id);

  const history = getConvHistory(conv_id, 14);
  const memory  = getMemory(session_id);
  const sysPrompt = (SYSTEM_PROMPTS[user.personality] || SYSTEM_PROMPTS.friendly) + memory;
  const model = user.model_pref || "gpt-3.5-turbo";

  const messages = [
    { role: "system", content: sysPrompt },
    ...history,
    { role: "user", content: message }
  ];

  // SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  try {
    const apiRes = await fetch(`${process.env.API_BASE}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.API_KEY}`
      },
      body: JSON.stringify({ model, messages, temperature: 0.7, max_tokens: 1500, stream: true }),
      signal: AbortSignal.timeout(45_000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(() => ({}));
      res.write(`data: ${JSON.stringify({ error: e.error?.message || "خطأ في الـ AI" })}\n\n`);
      return res.end();
    }

    let fullReply = "";
    let tokens = 0;

    for await (const chunk of apiRes.body) {
      const lines = chunk.toString().split("\n").filter(l => l.startsWith("data: "));
      for (const line of lines) {
        const raw = line.slice(6).trim();
        if (raw === "[DONE]") continue;
        try {
          const j = JSON.parse(raw);
          const delta = j.choices?.[0]?.delta?.content || "";
          if (delta) {
            fullReply += delta;
            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
          }
        } catch {}
      }
    }

    // تقدير الـ tokens
    tokens = Math.ceil((message.length + fullReply.length) / 3);

    // حفظ رد الـ AI
    DB.prepare("INSERT INTO messages (conv_id,session_id,role,content,tokens,model,ts) VALUES (?,?,?,?,?,?,?)")
      .run(conv_id, session_id, "assistant", fullReply, tokens, model, now());

    // حفظ بيانات التدريب
    DB.prepare("INSERT INTO training_data (session_id,conv_id,user_msg,assistant_msg,context,model,tokens,ts) VALUES (?,?,?,?,?,?,?,?)")
      .run(session_id, conv_id, message, fullReply,
        JSON.stringify(history.slice(-6)), model, tokens, now());

    // تحديث إحصائيات المستخدم
    DB.prepare("UPDATE users SET total_msgs=total_msgs+1, total_tokens=total_tokens+?, last_active=? WHERE session_id=?")
      .run(tokens, now(), session_id);

    // استخراج ذاكرة
    extractMemory(session_id, message, fullReply);

    res.write(`data: ${JSON.stringify({ done: true, tokens, conv_id })}\n\n`);
    res.end();

  } catch (e) {
    const msg = e.name === "TimeoutError" ? "انتهت المهلة" : "خطأ في الاتصال";
    res.write(`data: ${JSON.stringify({ error: msg })}\n\n`);
    res.end();
  }
});

// إحصائيات
app.get("/api/stats/:sid", (req, res) => {
  const user  = DB.prepare("SELECT * FROM users WHERE session_id=?").get(req.params.sid);
  const convs = DB.prepare("SELECT COUNT(*) as c FROM conversations WHERE session_id=? AND archived=0").get(req.params.sid);
  const train = DB.prepare("SELECT COUNT(*) as c FROM training_data WHERE session_id=?").get(req.params.sid);

  // نشاط آخر 7 أيام
  const activity = DB.prepare(`
    SELECT DATE(ts) as day, COUNT(*) as count
    FROM messages WHERE session_id=? AND role='user'
    AND ts >= datetime('now','-7 days')
    GROUP BY DATE(ts) ORDER BY day
  `).all(req.params.sid);

  res.json({
    total_msgs:    user?.total_msgs || 0,
    total_tokens:  user?.total_tokens || 0,
    conversations: convs?.c || 0,
    training_pairs: train?.c || 0,
    activity
  });
});

// تصدير بيانات التدريب JSONL
app.get("/api/export/training/:sid", (req, res) => {
  const rows = DB.prepare(
    "SELECT user_msg, assistant_msg FROM training_data WHERE session_id=? ORDER BY id"
  ).all(req.params.sid);

  const jsonl = rows.map(r => JSON.stringify({
    messages: [
      { role: "system",    content: "أنت مساعد ذكي اسمك ذكاء، تتحدث العربية بطلاقة." },
      { role: "user",      content: r.user_msg },
      { role: "assistant", content: r.assistant_msg }
    ]
  })).join("\n");

  res.setHeader("Content-Type", "application/jsonl");
  res.setHeader("Content-Disposition", `attachment; filename="training_${req.params.sid.slice(0,8)}.jsonl"`);
  res.send(jsonl);
});

// تصدير JSON كامل
app.get("/api/export/full/:sid", (req, res) => {
  const convs = DB.prepare("SELECT * FROM conversations WHERE session_id=?").all(req.params.sid);
  const msgs  = DB.prepare("SELECT * FROM messages WHERE session_id=?").all(req.params.sid);
  const train = DB.prepare("SELECT * FROM training_data WHERE session_id=?").all(req.params.sid);
  const mem   = DB.prepare("SELECT * FROM user_memory WHERE session_id=?").all(req.params.sid);
  res.json({ exported_at: now(), conversations: convs, messages: msgs, training_data: train, memory: mem });
});

// catch-all
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));

app.listen(PORT, () => {
  console.log(`\n✦ ذكاء v2 يعمل → http://localhost:${PORT}\n`);
});
