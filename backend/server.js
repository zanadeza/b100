require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const { v4: uuidv4 } = require("uuid");
const path      = require("path");
const fs        = require("fs");
const fetch     = (...a) => import("node-fetch").then(({ default: f }) => f(...a));

const app  = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, "zaka_db.json");

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users:{}, conversations:{}, messages:[], training:[], memory:{} }));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db)); }
const now = () => new Date().toISOString();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "20kb" }));
app.use("/api/", rateLimit({ windowMs: 60000, max: 80, message: { error: "rate limit" } }));
app.use(express.static(path.join(__dirname, "../frontend")));

const PROMPTS = {
  friendly: "You are a smart friendly Arabic AI assistant named Zaka. Always reply in Arabic.",
  formal:   "You are a professional Arabic AI assistant named Zaka. Always reply in Arabic formally.",
  concise:  "You are a concise Arabic AI assistant named Zaka. Keep replies short. Always reply in Arabic."
};

function getUser(db, sid) {
  if (!db.users[sid]) {
    db.users[sid] = {
      session_id: sid, name: "friend", personality: "friendly",
      model_pref: "gpt-3.5-turbo", font_size: "medium", theme: "dark",
      created: now(), last_active: now(), total_msgs: 0, total_tokens: 0
    };
    saveDB(db);
  }
  return db.users[sid];
}

function getMemory(db, sid) {
  const mem = db.memory && db.memory[sid];
  if (!mem || !Object.keys(mem).length) return "";
  return "\n\n[User Memory]\n" + Object.entries(mem).map(([k,v]) => k + ": " + v).join("\n");
}

function extractMemory(db, sid, msg) {
  if (!db.memory[sid]) db.memory[sid] = {};
  const patterns = [
    { r: /my name is (\w+)/i,      k: "user_name" },
    { r: /i am from (\w+)/i,       k: "user_country" },
    { r: /i am (\d+) years/i,      k: "user_age" },
    { r: /اسمي\s+([\u0600-\u06FF\w]+)/,      k: "user_name" },
    { r: /انا من\s+([\u0600-\u06FF\w]+)/,    k: "user_country" },
    { r: /عمري\s+(\d+)/,                     k: "user_age" }
  ];
  for (const { r, k } of patterns) {
    const m = msg.match(r);
    if (m) db.memory[sid][k] = m[1];
  }
}

// Routes

app.post("/api/session", (req, res) => {
  const db  = loadDB();
  const sid = req.body.session_id || uuidv4();
  const u   = getUser(db, sid);
  u.last_active = now();
  saveDB(db);
  res.json({ session_id: sid, name: u.name, theme: u.theme, font_size: u.font_size, personality: u.personality, model_pref: u.model_pref });
});

app.post("/api/settings", (req, res) => {
  const db = loadDB();
  const { session_id, name, personality, model_pref, font_size, theme } = req.body;
  if (!session_id) return res.status(400).json({ error: "no session" });
  const u = getUser(db, session_id);
  if (name)        u.name        = name;
  if (personality) u.personality = personality;
  if (model_pref)  u.model_pref  = model_pref;
  if (font_size)   u.font_size   = font_size;
  if (theme)       u.theme       = theme;
  saveDB(db);
  res.json({ ok: true });
});

app.get("/api/conversations/:sid", (req, res) => {
  const db = loadDB();
  const convs = Object.values(db.conversations)
    .filter(c => c.session_id === req.params.sid && !c.archived)
    .sort((a, b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 50);
  res.json({ conversations: convs });
});

app.post("/api/conversations", (req, res) => {
  const db = loadDB();
  const { session_id } = req.body;
  if (!session_id) return res.status(400).json({ error: "no session" });
  getUser(db, session_id);
  const id = uuidv4();
  db.conversations[id] = { id, session_id, title: "New Chat", created: now(), last_msg: now(), msg_count: 0, archived: false };
  saveDB(db);
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", (req, res) => {
  const db = loadDB();
  if (db.conversations[req.params.id]) db.conversations[req.params.id].archived = true;
  saveDB(db);
  res.json({ ok: true });
});

app.get("/api/history/:conv_id", (req, res) => {
  const db = loadDB();
  res.json({ messages: db.messages.filter(m => m.conv_id === req.params.conv_id) });
});

app.get("/api/search", (req, res) => {
  const db = loadDB();
  const { session_id, q } = req.query;
  if (!q || q.length < 2) return res.json({ results: [] });
  const results = db.messages
    .filter(m => m.session_id === session_id && m.content && m.content.includes(q))
    .slice(-20)
    .map(m => ({ ...m, title: (db.conversations[m.conv_id] && db.conversations[m.conv_id].title) || "Chat" }));
  res.json({ results });
});

app.get("/api/memory/:sid", (req, res) => {
  const db  = loadDB();
  const mem = (db.memory && db.memory[req.params.sid]) || {};
  res.json({ memory: Object.entries(mem).map(([key, value]) => ({ key, value })) });
});

app.post("/api/chat/stream", async (req, res) => {
  const { session_id, conv_id, message } = req.body;
  if (!session_id || !conv_id || !message || message.length > 3000)
    return res.status(400).json({ error: "bad request" });

  const db   = loadDB();
  const user = getUser(db, session_id);
  const conv = db.conversations[conv_id];
  if (!conv) return res.status(404).json({ error: "conversation not found" });

  db.messages.push({ conv_id, session_id, role: "user", content: message, ts: now() });
  if (conv.msg_count === 0) conv.title = message.slice(0, 35);
  conv.last_msg = now();
  conv.msg_count++;
  saveDB(db);

  const history    = db.messages.filter(m => m.conv_id === conv_id).slice(-14);
  const sysPrompt  = (PROMPTS[user.personality] || PROMPTS.friendly) + getMemory(db, session_id);
  const model      = user.model_pref || "gpt-3.5-turbo";
  const messages   = [
    { role: "system", content: sysPrompt },
    ...history.map(m => ({ role: m.role, content: m.content })),
    { role: "user", content: message }
  ];

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  try {
    const apiRes = await fetch(process.env.API_BASE + "/chat/completions", {
      method:  "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.API_KEY },
      body:    JSON.stringify({ model, messages, temperature: 0.7, max_tokens: 1500, stream: true }),
      signal:  AbortSignal.timeout(45000)
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
          const delta = j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content || "";
          if (delta) {
            fullReply += delta;
            res.write("data: " + JSON.stringify({ delta }) + "\n\n");
          }
        } catch (e2) {}
      }
    }

    const tokens = Math.ceil((message.length + fullReply.length) / 3);
    const db2    = loadDB();
    db2.messages.push({ conv_id, session_id, role: "assistant", content: fullReply, tokens, model, ts: now() });
    db2.training.push({ session_id, conv_id, user_msg: message, assistant_msg: fullReply, model, tokens, ts: now() });
    db2.users[session_id].total_msgs++;
    db2.users[session_id].total_tokens += tokens;
    extractMemory(db2, session_id, message);
    saveDB(db2);

    res.write("data: " + JSON.stringify({ done: true, tokens, conv_id }) + "\n\n");
    res.end();

  } catch (e) {
    const msg = e.name === "TimeoutError" ? "timeout" : "connection error";
    res.write("data: " + JSON.stringify({ error: msg }) + "\n\n");
    res.end();
  }
});

app.get("/api/stats/:sid", (req, res) => {
  const db    = loadDB();
  const u     = db.users[req.params.sid] || {};
  const convs = Object.values(db.conversations).filter(c => c.session_id === req.params.sid && !c.archived).length;
  const train = db.training.filter(t => t.session_id === req.params.sid).length;
  const act   = {};
  db.messages
    .filter(m => m.session_id === req.params.sid && m.role === "user")
    .forEach(m => { const d = m.ts && m.ts.slice(0, 10); if (d) act[d] = (act[d] || 0) + 1; });
  res.json({
    total_msgs: u.total_msgs || 0, total_tokens: u.total_tokens || 0,
    conversations: convs, training_pairs: train,
    activity: Object.entries(act).map(([day, count]) => ({ day, count })).slice(-7)
  });
});

app.get("/api/export/training/:sid", (req, res) => {
  const db   = loadDB();
  const jsonl = db.training
    .filter(t => t.session_id === req.params.sid)
    .map(r => JSON.stringify({
      messages: [
        { role: "system",    content: "You are a smart Arabic AI assistant named Zaka." },
        { role: "user",      content: r.user_msg },
        { role: "assistant", content: r.assistant_msg }
      ]
    })).join("\n");
  res.setHeader("Content-Type", "application/jsonl");
  res.setHeader("Content-Disposition", "attachment; filename=training_" + req.params.sid.slice(0, 8) + ".jsonl");
  res.send(jsonl);
});

app.get("*", (_, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));

app.listen(PORT, () => console.log("\n Zaka running on http://localhost:" + PORT + "\n"));
