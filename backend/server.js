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

// ── قاعدة بيانات JSON بسيطة تشتغل على أي نظام ──
const DB_FILE = path.join(__dirname, "zaka_db.json");

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const empty = { users:{}, conversations:{}, messages:[], training:[] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty));
    return empty;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

const now = () => new Date().toISOString();

// ── أمان ──
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "20kb" }));
app.use("/api/", rateLimit({ windowMs: 60_000, max: 80,
  message: { error: "طلبات كثيرة جداً، انتظر دقيقة." }
}));
app.use(express.static(path.join(__dirname, "../frontend")));

const SYSTEM_PROMPTS = {
  friendly: "أنت مساعد ذكي ودود اسمك ذكاء. تتكلم العربية بطلاقة وتجيب بأسلوب دافئ ومبسط.",
  formal:   "أنت مساعد ذكاء اصطناعي متخصص اسمك ذكاء. تجيب بأسلوب رسمي ودقيق.",
  concise:  "أنت مساعد ذكي اسمك ذكاء. إجاباتك مختصرة ومباشرة."
};

function getUser(db, sid) {
  if (!db.users[sid]) {
    db.users[sid] = { session_id:sid, name:"صديقي", personality:"friendly",
      model_pref:"gpt-3.5-turbo", font_size:"medium", theme:"dark",
      created:now(), last_active:now(), total_msgs:0, total_tokens:0 };
    saveDB(db);
  }
  return db.users[sid];
}

function getMemory(db, sid) {
  const mem = db.memory?.[sid];
  if (!mem || !Object.keys(mem).length) return "";
  return "\n\n[ذاكرة المستخدم]\n" + Object.entries(mem).map(([k,v])=>`${k}: ${v}`).join("\n");
}

function extractMemory(db, sid, userMsg) {
  if (!db.memory) db.memory = {};
  if (!db.memory[sid]) db.memory[sid] = {};
  const patterns = [
    { r:/اسمي\s+([\u0600-\u06FF\w]+)/, k:"اسم المستخدم" },
    { r:/أنا\s+من\s+([\u0600-\u06FF\w]+)/, k:"بلد المستخدم" },
    { r:/عمري\s+(\d+)/, k:"عمر المستخدم" }
  ];
  for (const { r, k } of patterns) {
    const m = userMsg.match(r);
    if (m) db.memory[sid][k] = m[1];
  }
}

function getConvHistory(db, convId, limit=14) {
  return db.messages.filter(m=>m.conv_id===convId).slice(-limit);
}

// ── Routes ──

app.post("/api/session", (req, res) => {
  const db  = loadDB();
  const sid = req.body.session_id || uuidv4();
  const user = getUser(db, sid);
  user.last_active = now();
  saveDB(db);
  res.json({ session_id:sid, name:user.name, theme:user.theme,
    font_size:user.font_size, personality:user.personality, model_pref:user.model_pref });
});

app.post("/api/settings", (req, res) => {
  const db = loadDB();
  const { session_id, name, personality, model_pref, font_size, theme } = req.body;
  if (!session_id) return res.status(400).json({ error:"no session" });
  const u = getUser(db, session_id);
  if (name)        u.name        = name;
  if (personality) u.personality = personality;
  if (model_pref)  u.model_pref  = model_pref;
  if (font_size)   u.font_size   = font_size;
  if (theme)       u.theme       = theme;
  saveDB(db);
  res.json({ ok:true });
});

app.get("/api/conversations/:sid", (req, res) => {
  const db = loadDB();
  const convs = Object.values(db.conversations)
    .filter(c => c.session_id===req.params.sid && !c.archived)
    .sort((a,b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 50);
  res.json({ conversations: convs });
});

app.post("/api/conversations", (req, res) => {
  const db = loadDB();
  const { session_id } = req.body;
  if (!session_id) return res.status(400).json({ error:"no session" });
  getUser(db, session_id);
  const id = uuidv4();
  db.conversations[id] = { id, session_id, title:"محادثة جديدة", created:now(), last_msg:now(), msg_count:0, archived:false };
  saveDB(db);
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", (req, res) => {
  const db = loadDB();
  if (db.conversations[req.params.id]) db.conversations[req.params.id].archived = true;
  saveDB(db);
  res.json({ ok:true });
});

app.get("/api/history/:conv_id", (req, res) => {
  const db = loadDB();
  const msgs = db.messages.filter(m => m.conv_id===req.params.conv_id);
  res.json({ messages: msgs });
});

app.get("/api/search", (req, res) => {
  const db = loadDB();
  const { session_id, q } = req.query;
  if (!q || q.length < 2) return res.json({ results:[] });
  const results = db.messages
    .filter(m => m.session_id===session_id && m.content?.includes(q))
    .slice(-20)
    .map(m => ({ ...m, title: db.conversations[m.conv_id]?.title || "محادثة" }));
  res.json({ results });
});

app.get("/api/memory/:sid", (req, res) => {
  const db = loadDB();
  const mem = db.memory?.[req.params.sid] || {};
  const memory = Object.entries(mem).map(([key,value])=>({ key, value }));
  res.json({ memory });
});

app.post("/api/chat/stream", async (req, res) => {
  const { session_id, conv_id, message } = req.body;
  if (!session_id || !conv_id || !message || message.length > 3000)
    return res.status(400).json({ error:"طلب غير صحيح" });

  const db   = loadDB();
  const user = getUser(db, session_id);
  const conv = db.conversations[conv_id];
  if (!conv) return res.status(404).json({ error:"محادثة غير موجودة" });

  // حفظ رسالة المستخدم
  db.messages.push({ conv_id, session_id, role:"user", content:message, ts:now() });
  if (conv.msg_count === 0) conv.title = message.slice(0,35);
  conv.last_msg = now();
  conv.msg_count++;
  saveDB(db);

  const history = getConvHistory(db, conv_id, 14);
  const memory  = getMemory(db, session_id);
  const sysPrompt = (SYSTEM_PROMPTS[user.personality] || SYSTEM_PROMPTS.friendly) + memory;
  const model = user.model_pref || "gpt-3.5-turbo";

  const messages = [
    { role:"system", content:sysPrompt },
    ...history.map(m=>({ role:m.role, content:m.content })),
    { role:"user", content:message }
  ];

  res.setHeader("Content-Type","text/event-stream");
  res.setHeader("Cache-Control","no-cache");
  res.setHeader("X-Accel-Buffering","no");

  try {
    const apiRes = await fetch(`${process.env.API_BASE}/chat/completions`, {
      method:"POST",
      headers:{ "Content-Type":"application/json", "Authorization":`Bearer ${process.env.API_KEY}` },
      body: JSON.stringify({ model, messages, temperature:0.7, max_tokens:1500, stream:true }),
      signal: AbortSignal.timeout(45_000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(()=>({}));
      res.write(`data: ${JSON.stringify({ error: e.error?.message || "خطأ في الـ AI" })}\n\n`);
      return res.end();
    }

    let fullReply = "";
    for await (const chunk of apiRes.body) {
      const lines = chunk.toString().split("\n").filter(l=>l.startsWith("data: "));
      for (const line of lines) {
        const raw = line.slice(6).trim();
        if (raw === "[DONE]") continue;
        try {
          const j = JSON.parse(raw);
          const delta = j.choices?.[0]?.delta?.content || "";
          if (delta) { fullReply += delta; res.write(`data: ${JSON.stringify({ delta })}\n\n`); }
        } catch {}
      }
    }

    const tokens = Math.ceil((message.length + fullReply.length) / 3);

    // حفظ رد المساعد
    const db2 = loadDB();
    db2.messages.push({ conv_id, session_id, role:"assistant", content:fullReply, tokens, model, ts:now() });

    // حفظ بيانات التدريب تلقائياً
    db2.training.push({ session_id, conv_id, user_msg:message, assistant_msg:fullReply, model, tokens, ts:now() });

    // تحديث الإحصائيات
    db2.users[session_id].total_msgs++;
    db2.users[session_id].total_tokens += tokens;

    // استخراج الذاكرة
    extractMemory(db2, session_id, message);
    saveDB(db2);

    res.write(`data: ${JSON.stringify({ done:true, tokens, conv_id })}\n\n`);
    res.end();

  } catch(e) {
    const msg = e.name==="TimeoutError" ? "انتهت المهلة" : "خطأ في الاتصال";
    res.write(`data: ${JSON.stringify({ error:msg })}\n\n`);
    res.end();
  }
});

app.get("/api/stats/:sid", (req, res) => {
  const db   = loadDB();
  const user = db.users[req.params.sid] || {};
  const convs = Object.values(db.conversations).filter(c=>c.session_id===req.params.sid&&!c.archived).length;
  const train = db.training.filter(t=>t.session_id===req.params.sid).length;

  const activity = {};
  db.messages.filter(m=>m.session_id===req.params.sid&&m.role==="user").forEach(m=>{
    const day = m.ts?.slice(0,10);
    if (day) activity[day] = (activity[day]||0)+1;
  });
  const actArr = Object.entries(activity).map(([day,count])=>({ day, count })).slice(-7);

  res.json({ total_msgs:user.total_msgs||0, total_tokens:user.total_tokens||0,
    conversations:convs, training_pairs:train, activity:actArr });
});

app.get("/api/export/training/:sid", (req, res) => {
  const db = loadDB();
  const rows = db.training.filter(t=>t.session_id===req.params.sid);
  const jsonl = rows.map(r=>JSON.stringify({
    messages:[
      { role:"system", content:"أنت مساعد ذكي اسمك ذكاء، تتحدث العربية بطلاقة." },
      { role:"user", content:r.user_msg },
      { role:"assistant", content:r.assistant_msg }
    ]
  })).join("\n");
  res.setHeader("Content-Type","application/jsonl");
  res.setHeader("Content-Disposition",`attachment; filename="training_${req.params.sid.slice(0,8)}.jsonl"`);
  res.send(jsonl);
});

app.get("/api/export/full/:sid", (req, res) => {
  const db = loadDB();
  res.json({
    exported_at: now(),
    conversations: Object.values(db.conversations).filter(c=>c.session_id===req.params.sid),
    messages: db.messages.filter(m=>m.session_id===req.params.sid),
    training_data: db.training.filter(t=>t.session_id===req.params.sid),
    memory: db.memory?.[req.params.sid] || {}
  });
});

app.get("*", (_,res) => res.sendFile(path.join(__dirname,"../frontend/index.html")));

app.listen(PORT, () => console.log(`\n✦ ذكاء يعمل → http://localhost:${PORT}\n`));
