import {
  PERSONA, CLONES, GOLDEN, FUNNEL,
  buildDraft, classifyStage, routeClone, faqRepeat,
} from "./engine.js";

const now = Date.now();
const HOUR = 3600000;

function seed() {
  return [
    {
      id: "s1",
      customer: "陈小舟",
      stage: "意向",
      dayHint: "分手第 3 天",
      lastIn: "语音：我想复合，昨晚又哭了，睡不着。",
      lastText: "我想复合，昨晚又哭了，睡不着。",
      voice: true,
      asrConf: 0.93,
      unread: true,
      lastActive: now - 2 * HOUR,
      history: [
        { role: "in", kind: "voice", text: "我想复合，昨晚又哭了，睡不着。", asr: true },
      ],
      takeover: false,
    },
    {
      id: "s2",
      customer: "阿宁",
      stage: "交付",
      dayHint: "已购第 2 课",
      lastIn: "第2课作业不会做",
      lastText: "第2课作业不会做",
      voice: false,
      asrConf: 1,
      unread: true,
      lastActive: now - 1 * HOUR,
      history: [
        { role: "in", kind: "text", text: "第2课作业不会做" },
      ],
      takeover: false,
    },
    {
      id: "s3",
      customer: "周叔",
      stage: "异议",
      dayHint: "",
      lastIn: "太贵了，我再想想",
      lastText: "太贵了，我再想想",
      voice: false,
      asrConf: 1,
      unread: true,
      lastActive: now - 26 * HOUR,
      history: [
        { role: "in", kind: "text", text: "太贵了，我再想想" },
      ],
      takeover: false,
      alarm: "24h 未回复",
    },
    {
      id: "s4",
      customer: "米米",
      stage: "咨询",
      dayHint: "",
      lastIn: "多少钱啊多少钱到底多少钱",
      lastText: "多少钱",
      voice: false,
      asrConf: 1,
      unread: true,
      lastActive: now - 0.2 * HOUR,
      history: [
        { role: "in", kind: "text", text: "多少钱" },
        { role: "in", kind: "text", text: "多少钱啊" },
        { role: "in", kind: "text", text: "到底多少钱" },
      ],
      merge: true,
      takeover: false,
    },
  ];
}

const state = {
  sessions: seed(),
  current: "s1",
  filter: "all",
  drafts: {},
  audit: [],
  faqCorpus: ["多少钱", "价格", "收费", "多少钱啊"],
};

function el(id) { return document.getElementById(id); }

function session() {
  return state.sessions.find((s) => s.id === state.current);
}

function refreshDraft(opts = {}) {
  const s = session();
  s.cloneId = routeClone(s);
  const d = buildDraft(s, { tone: Number(el("tone").value) / 100, ...opts });
  state.drafts[s.id] = d;
  /* 接管后禁止 AI 盖掉人手写 */
  if (!s.takeover) el("draft").value = d.text;
  el("draft").readOnly = false;
  el("ime-clone").textContent = `${d.cloneName} · ${s.takeover ? "已接管" : "人在环"}`;
  const pill = el("conf-pill");
  pill.textContent = `置信 ${(d.confidence * 100).toFixed(0)}%`;
  pill.className = "conf " + d.band;
  el("cite").textContent = d.cites.length
    ? `引用 ${d.cites.join("、")} · ${d.ms}ms（生产走模型流式）`
    : `库弱命中 · ${d.ms}ms`;
  const faq = faqRepeat(s.lastText || s.lastIn, state.faqCorpus);
  const hint = el("faq-hint");
  if (faq.hot) {
    hint.hidden = false;
    hint.textContent = "高频问题：收费口径已按成功回复生成，扫一眼再发。";
  } else if (s.merge) {
    hint.hidden = false;
    hint.textContent = "同一客户连续多条，已合并起草。仍需你点发送。";
  } else if (s.alarm) {
    hint.hidden = false;
    hint.textContent = `干预：${s.alarm}。意向漏跟进风险。`;
  } else {
    hint.hidden = true;
  }
  if (d.bansHit.length) {
    hint.hidden = false;
    hint.textContent = "禁说词命中，已改写。禁止保证复合/疗效。";
  }
  return d;
}

function renderWho() {
  el("who").innerHTML = state.sessions.map((s) =>
    `<button type="button" data-sid="${s.id}" class="${s.id === state.current ? "on" : ""}">${s.customer}${s.unread ? " ·未" : ""}</button>`
  ).join("");
}

function renderThread() {
  const s = session();
  renderWho();
  el("wx-name").textContent = s.customer;
  el("wx-meta").textContent = `外部客户 · 存档开启 · ${s.dayHint || "进行中"}`;
  el("wx-stage").textContent = s.stage;
  const box = el("thread");
  box.innerHTML = "";
  for (const m of s.history) {
    const b = document.createElement("div");
    b.className = "bubble " + (m.role === "out" ? "out" : "in") + (m.kind === "voice" ? " voice" : "");
    if (m.kind === "voice") {
      b.innerHTML = `<span class="wave"></span><span>${m.text}</span>`;
    } else b.textContent = m.text;
    box.appendChild(b);
    if (m.asr) {
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = "ASR 转写 · 腾讯云口径（演示）· 标点已补";
      box.appendChild(meta);
    }
    if (m.audit) {
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = m.audit;
      box.appendChild(meta);
    }
  }
  box.scrollTop = box.scrollHeight;
}

function audit(action, extra) {
  const s = session();
  state.audit.unshift({
    t: new Date().toLocaleTimeString(),
    who: s.customer,
    action,
    human: "是",
    extra,
  });
  renderAudit();
}

function renderAudit() {
  el("audit").innerHTML = state.audit.map((a) =>
    `<tr><td>${a.t}</td><td>${a.who}</td><td>${a.action}</td><td>${a.human}</td></tr>`
  ).join("") || `<tr><td colspan="4">还没有发送。点侧边栏「发送」才会有记录。</td></tr>`;
}

function humanSend(fromQueueId) {
  if (fromQueueId) state.current = fromQueueId;
  const s = session();
  const d = state.drafts[s.id];
  const text = (fromQueueId ? (d?.text || "") : el("draft").value).trim();
  if (!text) return;
  if (d && d.band === "red" && text === d.text && !s.takeover) {
    alert("红条必须改写后再发。这是风控，不是礼貌。");
    return;
  }
  s.history.push({
    role: "out",
    kind: "text",
    text,
    audit: "员工点击发送 · 非自动外发",
  });
  s.unread = false;
  audit(`发送给 ${s.customer}`, text.slice(0, 40));
  renderThread();
  renderQueue();
  bumpDot();
}

function bumpDot() {
  const n = state.sessions.filter((s) => s.unread).length;
  el("qdot").classList.toggle("show", n > 0);
}

function renderQueue() {
  const hot = state.filter === "hot";
  const rows = state.sessions.filter((s) => {
    if (!s.unread) return false;
    if (hot && !["意向", "异议", "待付"].includes(s.stage)) return false;
    return true;
  });
  el("queue").innerHTML = rows.map((s) => {
    const snap = { ...s, cloneId: routeClone(s) };
    const d = buildDraft(snap, { tone: PERSONA.tone });
    state.drafts[s.id] = d;
    return `<article class="qcard ${d.band}">
      <div><b>${s.customer}</b><small>${s.stage} · ${d.cloneName}${s.alarm ? " · " + s.alarm : ""}</small></div>
      <button class="sendq" data-send="${s.id}" type="button">发送</button>
      <div class="preview">${d.text}</div>
    </article>`;
  }).join("") || "<p class='empty'>队列清空。</p>";
}

function renderAdmin() {
  el("kb-close").innerHTML = CLONES.close.docs.map((d) => `<div class="doc"><b>${d.t}</b>${d.x}</div>`).join("");
  el("kb-deliver").innerHTML = CLONES.deliver.docs.map((d) => `<div class="doc"><b>${d.t}</b>${d.x}</div>`).join("");
  el("persona-box").textContent = `${PERSONA.name} · 口头禅：${PERSONA.quirks.join(" / ")} · 禁说：${PERSONA.bans.join("、")}`;
}

function renderDebug() {
  const q = el("dbg-q").value.trim() || "我想复合";
  const a = buildDraft({
    customer: "陈小舟", stage: "意向", dayHint: "分手第 3 天", lastIn: q, lastText: q,
    voice: false, asrConf: 1, takeover: false, history: [],
  });
  const b = buildDraft({
    customer: "陈小舟", stage: "意向", dayHint: "分手第 30 天", lastIn: q, lastText: q,
    voice: false, asrConf: 1, takeover: false, history: [],
  });
  el("dbg-a").innerHTML = `<h2>第 3 天</h2><p>${a.text}</p><p class="muted">${a.cloneName} · ${(a.confidence * 100).toFixed(0)}%</p>`;
  el("dbg-b").innerHTML = `<h2>第 30 天</h2><p>${b.text}</p><p class="muted">${b.cloneName} · ${(b.confidence * 100).toFixed(0)}%</p>`;
}

function show(view) {
  document.querySelectorAll(".view").forEach((v) => {
    const on = v.id === "view-" + view;
    v.classList.toggle("is-on", on);
    v.hidden = !on;
  });
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  if (view === "queue") renderQueue();
  if (view === "admin") renderAdmin();
  if (view === "debug") renderDebug();
  if (view === "risk") renderAudit();
}

function goldSearch(q) {
  const box = el("gold-list");
  if (!q) { box.innerHTML = ""; return; }
  box.innerHTML = GOLDEN.filter((g) => g.includes(q)).map((g) =>
    `<button type="button" data-gold="${g}">${g}</button>`
  ).join("");
}

window.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".navbtn").forEach((b) => {
    b.addEventListener("click", () => show(b.dataset.view));
  });
  document.querySelectorAll(".chip").forEach((c) => {
    c.addEventListener("click", () => {
      document.querySelectorAll(".chip").forEach((x) => x.classList.remove("on"));
      c.classList.add("on");
      state.filter = c.dataset.filter;
      renderQueue();
    });
  });
  el("queue").addEventListener("click", (e) => {
    const id = e.target.dataset.send;
    if (!id) return;
    humanSend(id);
    renderThread();
    if (!session().takeover) refreshDraft();
  });
  el("gold-list").addEventListener("click", (e) => {
    const g = e.target.dataset.gold;
    if (!g) return;
    el("draft").value = (el("draft").value + "\n" + g).trim();
  });
  el("gold").addEventListener("input", () => goldSearch(el("gold").value.trim()));
  el("tone").addEventListener("input", () => {
    const v = Number(el("tone").value);
    el("tone-lab").textContent = v < 35 ? "更软" : v > 75 ? "更硬" : "稳";
    refreshDraft();
  });
  el("btn-rewrite").addEventListener("click", () => {
    refreshDraft({ rewrite: true });
    audit("重写草稿");
  });
  el("btn-take").addEventListener("click", () => {
    const s = session();
    s.takeover = !s.takeover;
    if (s.takeover) {
      refreshDraft({ keepEdit: true });
    } else {
      refreshDraft();
    }
    audit(s.takeover ? "接管（停 AI）" : "恢复 AI 起草");
  });
  el("btn-send").addEventListener("click", () => humanSend());
  el("sim-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const s = session();
    const q = el("sim-in").value.trim();
    if (!q) return;
    s.lastIn = q;
    s.lastText = q;
    s.voice = false;
    s.unread = true;
    s.stage = classifyStage(q, s.stage);
    s.history.push({ role: "in", kind: "text", text: q });
    el("sim-in").value = "";
    refreshDraft();
    renderThread();
    bumpDot();
  });
  el("btn-voice").addEventListener("click", () => {
    const s = session();
    const t = "语音转写：我真的好想他，你帮我看看还能不能回头。";
    s.lastIn = t;
    s.lastText = t;
    s.voice = true;
    s.asrConf = 0.91;
    s.unread = true;
    s.stage = classifyStage(t, s.stage);
    s.history.push({ role: "in", kind: "voice", text: t.replace("语音转写：", ""), asr: true });
    refreshDraft();
    renderThread();
    bumpDot();
  });
  el("btn-pay").addEventListener("click", () => {
    const s = session();
    s.stage = "已购";
    s.lastIn = "付了，我从哪开始看课";
    s.lastText = s.lastIn;
    s.unread = true;
    s.history.push({ role: "in", kind: "text", text: s.lastIn });
    refreshDraft();
    renderThread();
    audit("付款事件：标签已购，分身切到交付，历史延续");
    bumpDot();
  });
  el("dbg-q").addEventListener("input", renderDebug);
  el("who").addEventListener("click", (e) => {
    const id = e.target.dataset.sid;
    if (!id) return;
    state.current = id;
    renderThread();
    refreshDraft();
  });

  renderThread();
  refreshDraft();
  renderAdmin();
  renderAudit();
  bumpDot();
});

window.__siyu = { state, buildDraft, humanSend, FUNNEL };
