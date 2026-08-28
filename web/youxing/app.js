const TENANTS = {
  lin: {
    id: "lin",
    name: "林晚",
    title: "留学规划",
    tag: "文书 / 选校 / 套磁",
    price: "¥29.9 / 10次",
    credits: 10,
    exclusive: ["斯坦福", "文书", "套磁", "托福", "Common App", "选校", "WES", "CS硕士", "推荐信", "ED"],
    docs: [
      { t: "选校定位-CS硕士", k: ["斯坦福", "卡内基梅隆", "CMU", "CS", "选校", "排名", "研究组"], x: "冲刺档：斯坦福CS、CMU SCS需顶会/强科研；匹配档：UCSD、UCLA、UIUC；保底档：NEU、NYU Tandon。林晚只按「科研匹配度>综合排名」排表，不卖排名焦虑。" },
      { t: "文书结构-SOP", k: ["文书", "SOP", "个人陈述", "故事", "科研"], x: "林晚模板四段：钩子场景（实验室一次失败）→ 能力证据（方法/指标）→ Why this lab（点名教授论文）→ 三年贡献。禁止空话「从小热爱计算机」。" },
      { t: "套磁节奏", k: ["套磁", "教授", "邮件", "CV"], x: "套磁窗口：网申前6-10周。第一封≤120词，只提对方最近一篇论文的一个具体实验设置。附件CV一页。林晚禁止群发同一封。" },
      { t: "标化与材料", k: ["托福", "GRE", "WES", "成绩单", "推荐信"], x: "CS申请托福建议100+；GRE多数CS已optional。成绩单做WES course-by-course。推荐信至少一封来自带你发过论文或做过工程的导师。" },
      { t: "ED/RD策略", k: ["ED", "RD", "早申", "奖学金"], x: "ED只绑「去了不后悔」的一所。用ED冲排名而不匹配研究方向，是林晚明确反对的。奖学金故事写清楚：你能给实验室省哪笔标注/算力成本。" }
    ]
  },
  chen: {
    id: "chen",
    name: "陈衡",
    title: "个体财税",
    tag: "对公 / 发票 / 汇算",
    price: "¥39.9 / 10次",
    credits: 10,
    exclusive: ["个体户", "对公", "专票", "汇算清缴", "核定征收", "个税", "W-2", "社保", "公户", "普票"],
    docs: [
      { t: "个体户开公户", k: ["个体户", "对公", "公户", "银行", "开户"], x: "个体户可开对公账户。陈衡流程：营业执照+法人身份证+公章/财务章，预约开户。公户用于收平台货款、发工资、缴税，避免公私混同被税局盯资金流。" },
      { t: "工资与个税", k: ["工资", "个税", "代扣", "工资表"], x: "用对公发工资：做工资表→个税扣缴客户端申报→公户代发。陈衡禁止「公户提现再发红包当工资」。员工应发、专项扣除、实发三列必须对齐。" },
      { t: "发票与专票", k: ["专票", "普票", "进项", "销项", "发票"], x: "一般纳税人可抵进项专票；小规模主要普票。陈衡口径：没有真实交易不开票。平台服务费专票进项要和合同、流水三单匹配。" },
      { t: "汇算清缴", k: ["汇算清缴", "年报", "所得税", "核定征收"], x: "查账征收按利润；核定征收按税务局核定应税所得率。汇算前先对银行流水与发票。陈衡不建议为了「少交」改核定，被查成本更高。" },
      { t: "境外收入W-2", k: ["W-2", "境外", "美国", "报税", "税收协定"], x: "美国W-2工资在中国居民纳税人下需申报境外所得，可按中美税收协定抵免已缴美国税款。陈衡要求先备W-2、1040、完税证明再谈抵免，不口述数字。" }
    ]
  }
};

const state = {
  credits: { lin: 10, chen: 10 },
  streaming: { lin: false, chen: false }
};

function grams(s) {
  const t = String(s || "").toLowerCase().replace(/\s+/g, "");
  const out = [];
  for (let i = 0; i < t.length - 1; i++) out.push(t.slice(i, i + 2));
  return out;
}

function score(query, doc) {
  let s = 0;
  for (const k of doc.k) {
    if (query.includes(k)) s += 14;
  }
  const qg = grams(query);
  const hg = new Set(grams(doc.t + doc.k.join("") + doc.x));
  let overlap = 0;
  for (const g of qg) if (hg.has(g)) overlap += 1;
  return s + Math.min(overlap, 16);
}

function signals(tid, query) {
  const other = tid === "lin" ? "chen" : "lin";
  const own = TENANTS[tid].exclusive.filter((w) => query.includes(w)).length;
  const foreign = TENANTS[other].exclusive.filter((w) => query.includes(w)).length;
  return { own, foreign };
}

function retrieve(tid, query) {
  const ranked = TENANTS[tid].docs
    .map((d) => ({ ...d, s: score(query, d) }))
    .sort((a, b) => b.s - a.s);
  const { own, foreign } = signals(tid, query);
  if (foreign > own && (ranked[0]?.s || 0) < 20) return [];
  return ranked.filter((d) => d.s >= 12).slice(0, 3);
}

function leakScan(text, tid) {
  const other = tid === "lin" ? "chen" : "lin";
  const hits = TENANTS[other].exclusive.filter((w) => text.includes(w));
  return hits;
}

function refuse(tid) {
  const t = TENANTS[tid];
  return [
    "这题不在我的知识库里。",
    `我是${t.name}，只根据自己的私有库回答「${t.title}」。`,
    "跨博主的问题请切换对应博主。我不会去读别人的文档——这是租户隔离，不是我不会装懂。"
  ].join("\n");
}

function compose(tid, query, hits) {
  const t = TENANTS[tid];
  const cites = hits.map((h) => h.t).join("、");
  const body = hits.map((h, i) => `${i + 1}. ${h.x}`).join("\n");
  return `按我知识库里的「${cites}」直接答，不编库外细节。\n\n${body}\n\n——${t.name}｜仅使用本博主私有库｜引用 ${hits.length} 条`;
}

function answer(tid, query) {
  const hits = retrieve(tid, query);
  const text = hits.length ? compose(tid, query, hits) : refuse(tid);
  const leaked = leakScan(text, tid);
  return { text, hits, leaked, isolated: leaked.length === 0 };
}

function el(id) { return document.getElementById(id); }

function addBubble(tid, role, text, extra) {
  const box = el("chat-" + tid);
  const b = document.createElement("div");
  b.className = "bubble " + (role === "me" ? "me" : "bot");
  b.textContent = text;
  box.appendChild(b);
  if (extra) {
    const m = document.createElement("div");
    m.className = "meta";
    m.textContent = extra;
    box.appendChild(m);
  }
  box.scrollTop = box.scrollHeight;
  return b;
}

function setCredits(tid) {
  el("credit-" + tid).textContent = state.credits[tid] + " 次";
}

function logLine(html) {
  const log = el("lab-log");
  const d = document.createElement("div");
  d.innerHTML = html;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

async function streamInto(node, text, fast, ms) {
  node.textContent = "";
  const caret = document.createElement("span");
  caret.className = "caret";
  node.appendChild(caret);
  const delay = ms == null ? 8 : ms;
  for (const ch of text) {
    caret.insertAdjacentText("beforebegin", ch);
    const box = node.parentElement;
    if (box) box.scrollTop = box.scrollHeight;
    if (!fast) await new Promise((r) => setTimeout(r, ch === "\n" ? delay * 2 : delay));
  }
  caret.remove();
}

async function ask(tid, query, opts = {}) {
  query = String(query || "").trim();
  if (!query || state.streaming[tid]) return null;
  if (state.credits[tid] <= 0) {
    addBubble(tid, "bot", "次数已用完。开通会员套餐后继续（生产接微信支付 JSAPI；本验收件点右侧「补 10 次」）。");
    return { blocked: "no-credit" };
  }
  state.streaming[tid] = true;
  if (!opts.silentUser) addBubble(tid, "me", query);
  state.credits[tid] -= 1;
  setCredits(tid);
  const res = answer(tid, query);
  if (opts.short) {
    res.text = res.hits.length
      ? `命中「${res.hits[0].t}」。\n${res.hits[0].x.slice(0, 72)}${res.hits[0].x.length > 72 ? "…" : ""}`
      : refuse(tid);
  }
  const node = addBubble(tid, "bot", "");
  await streamInto(node, res.text, !!opts.fast, opts.streamMs);
  const extra = res.hits.length
    ? `扣 1 次 · 命中 ${res.hits.length} 条私有文档 · 泄漏雷达 ${res.isolated ? "未检出对方库" : "异常"}`
    : `扣 1 次 · 库内无命中 · 已拒绝越权作答 · 泄漏雷达 ${res.isolated ? "干净" : "异常"}`;
  const m = document.createElement("div");
  m.className = "meta";
  m.textContent = extra;
  node.after(m);
  state.streaming[tid] = false;
  return res;
}

const PRESETS = [
  { id: "t1", q: "个体户怎么用对公账户发工资？", expect: { lin: "refuse", chen: "hit" }, title: "财税题打两边", desc: "林晚应拒绝；陈衡应引用对公/工资文档。" },
  { id: "t2", q: "斯坦福CS硕士文书怎么写？", expect: { lin: "hit", chen: "refuse" }, title: "留学题打两边", desc: "陈衡应拒绝；林晚应引用SOP/选校。" },
  { id: "t3", q: "美国W-2收入在中国怎么报？", expect: { lin: "refuse", chen: "hit" }, title: "W-2跨境所得", desc: "只允许出现在陈衡库。林晚不得提到汇算/专票。" }
];

function judge(tid, expect, res) {
  if (!res || res.blocked) return false;
  if (expect === "hit") return res.hits.length > 0 && res.isolated;
  return res.hits.length === 0 && res.isolated;
}

function setBadge(id, pass) {
  const b = el("badge-" + id);
  b.className = "badge " + (pass ? "pass" : "fail");
  b.textContent = pass ? "通过" : "失败";
}

async function runLab(customQ) {
  el("lab-log").textContent = "";
  const suite = customQ
    ? [{ id: "tx", q: customQ, expect: { lin: "any", chen: "any" }, title: "自定义同一句", desc: "只验泄漏：两边答案都不得出现对方独占术语。" }]
    : PRESETS;

  logLine(`<span class="dim">开始验收 · 同一句分别打入两个租户 · 中间层先扣次再检索</span>`);
  for (const t of suite) {
    logLine(`<span class="dim">▶ ${t.title}｜「${t.q}」</span>`);
    const a = await ask("lin", t.q, { fast: true });
    const b = await ask("chen", t.q, { fast: true });
    let pass;
    if (t.expect.lin === "any") {
      pass = a && b && a.isolated && b.isolated;
    } else {
      pass = judge("lin", t.expect.lin, a) && judge("chen", t.expect.chen, b);
    }
    if (t.id !== "tx") setBadge(t.id, pass);
    logLine(pass
      ? `<span class="ok">通过 · 林晚 ${a.hits.length ? "命中" : "拒绝"} · 陈衡 ${b.hits.length ? "命中" : "拒绝"} · 双边泄漏雷达干净</span>`
      : `<span class="bad">失败 · 请看对话气泡。隔离或命中方向不符合预期。</span>`);
  }
  if (!customQ) {
    const all = PRESETS.every((t) => el("badge-" + t.id).classList.contains("pass"));
    el("hero-stamp").textContent = all ? "三项隔离验收已全部通过" : "还有未通过项，先看右侧日志";
    el("hero-stamp").style.color = all ? "#3ee08a" : "#e2b57a";
  }
}

function renderDocs() {
  for (const tid of ["lin", "chen"]) {
    const box = el("docs-" + tid);
    box.innerHTML = TENANTS[tid].docs.map((d) => `<div class="doc"><b>${d.t}</b>${d.x}</div>`).join("");
  }
}

function bindPhone(tid) {
  el("form-" + tid).addEventListener("submit", (e) => {
    e.preventDefault();
    const input = el("input-" + tid);
    const q = input.value;
    input.value = "";
    ask(tid, q);
  });
}

function greet() {
  addBubble("lin", "bot", "我是林晚。只根据我的留学知识库回答。你可以把同一句话丢给隔壁陈衡，看我们会不会串库。");
  addBubble("chen", "bot", "我是陈衡。只根据我的财税知识库回答。库外的问题我会明确拒绝，不会去「帮忙编」。");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function say(text) {
  const c = el("caption");
  if (c) c.textContent = text;
}

function resetDemo() {
  state.credits.lin = 10;
  state.credits.chen = 10;
  state.streaming.lin = false;
  state.streaming.chen = false;
  setCredits("lin");
  setCredits("chen");
  el("chat-lin").innerHTML = "";
  el("chat-chen").innerHTML = "";
  greet();
  PRESETS.forEach((t) => {
    const b = el("badge-" + t.id);
    b.className = "badge wait";
    b.textContent = "待测";
  });
  el("lab-log").textContent = "";
  el("hero-stamp").textContent = "正在自动演示隔离。";
  el("hero-stamp").style.color = "#e2b57a";
}

function focusPhone(tid) {
  const lin = el("col-lin");
  const chen = el("col-chen");
  if (lin) lin.classList.toggle("focus", tid === "lin");
  if (chen) chen.classList.toggle("focus", tid === "chen");
  const col = el("col-" + tid);
  if (col && window.innerWidth < 1180) {
    col.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

let autoRunning = false;

async function runAuto() {
  if (autoRunning) return;
  autoRunning = true;
  document.body.classList.add("autoplaying");
  const play = el("btn-play");
  if (play) play.hidden = true;
  resetDemo();
  say("同一句话，先打进林晚，再打进陈衡。看会不会串库。");
  focusPhone("lin");
  await sleep(900);

  for (const t of PRESETS) {
    say(t.title + "：「" + t.q + "」");
    logLine(`<span class="dim">▶ ${t.title}｜「${t.q}」</span>`);
    await sleep(500);
    focusPhone("lin");
    const a = await ask("lin", t.q, { short: true, streamMs: 16 });
    await sleep(420);
    focusPhone("chen");
    const b = await ask("chen", t.q, { short: true, streamMs: 16 });
    const pass = judge("lin", t.expect.lin, a) && judge("chen", t.expect.chen, b);
    setBadge(t.id, pass);
    logLine(pass
      ? `<span class="ok">通过 · 林晚 ${a.hits.length ? "命中自己的库" : "拒绝"} · 陈衡 ${b.hits.length ? "命中自己的库" : "拒绝"}</span>`
      : `<span class="bad">失败 · 看两边气泡</span>`);
    say(pass
      ? `这项过了：林晚${a.hits.length ? "只引用留学库" : "拒绝越权"}，陈衡${b.hits.length ? "只引用财税库" : "拒绝越权"}。`
      : "这项没对上，看气泡。");
    await sleep(800);
  }

  const lin = el("col-lin");
  const chen = el("col-chen");
  if (lin) lin.classList.remove("focus");
  if (chen) chen.classList.remove("focus");
  const all = PRESETS.every((t) => el("badge-" + t.id).classList.contains("pass"));
  el("hero-stamp").textContent = all ? "三项隔离验收已全部通过" : "还有未通过项，先看气泡";
  el("hero-stamp").style.color = all ? "#3ee08a" : "#e2b57a";
  say(all ? "播完了。点「再播一遍」可重来。" : "播完了，有失败项。");
  document.body.classList.remove("autoplaying");
  autoRunning = false;
  if (play) {
    play.hidden = false;
    play.textContent = "再播一遍";
  }
}

window.addEventListener("DOMContentLoaded", () => {
  if (/MicroMessenger/i.test(navigator.userAgent)) {
    document.body.classList.add("wx");
  }
  renderDocs();
  bindPhone("lin");
  bindPhone("chen");
  setCredits("lin");
  setCredits("chen");
  greet();
  el("btn-lab").addEventListener("click", () => runLab());
  el("btn-custom").addEventListener("click", () => {
    const q = el("probe").value.trim();
    if (!q) return;
    runLab(q);
  });
  el("btn-refill-lin").addEventListener("click", () => { state.credits.lin += 10; setCredits("lin"); });
  el("btn-refill-chen").addEventListener("click", () => { state.credits.chen += 10; setCredits("chen"); });
  el("btn-play").addEventListener("click", () => { runAuto(); });
  PRESETS.forEach((t) => {
    el("q-" + t.id).textContent = t.q;
  });
  setTimeout(() => { runAuto(); }, 280);
});
