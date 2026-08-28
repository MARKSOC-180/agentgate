/** 私域分身工作台 · 草稿核（浏览器内可跑，生产换 Dify/企微存档 SDK） */
export const FUNNEL = ["陌生", "了解", "咨询", "意向", "异议", "待付", "已购", "交付", "续费"];

export const PERSONA = {
  name: "苏晚",
  tone: 0.62,
  quirks: ["先接住情绪", "少讲大道理", "一句落地动作", "偶尔用「嗯。」收"],
  length: "短",
  emoji: "极少，最多一个",
  bans: ["一定复合", "保证挽回", "包过", "疗效", "诊断", "自动发送", "无人值守"],
};

export const CLONES = {
  close: {
    id: "close",
    name: "成交分身",
    strategy: "售前：接住情绪 → 澄清阶段 → 轻邀约咨询/课，不逼单砸价",
    exclusive: ["逼单", "定金", "名额", "体验课", "挽回方案价"],
    docs: [
      { t: "接住-失恋前三天", k: ["复合", "分手", "想他", "哭", "失眠"], x: "前三天只稳住，不卖课。先承认疼，再问「现在最怕的是再也联系不上，还是怕自己先软」。禁止承诺复合。" },
      { t: "异议-太贵", k: ["贵", "没钱", "再想想", "便宜"], x: "不降价。把价换成一次说清：咨询是把「反复拉扯」变成「一次判断」。给两个选项：先预约15分钟或先看免费边界说明。" },
      { t: "FAQ-怎么收费", k: ["多少钱", "价格", "收费", "套餐"], x: "一对一咨询 1280/次，四次深聊 4580。不谈疗效，只谈边界：不代替心理治疗，不做宗教承诺。" },
      { t: "SOP-意向邀约", k: ["想试试", "怎么开始", "约"], x: "邀约只给一个具体时段+一个准备问题。不要连发三条催。" },
      { t: "禁-医疗宗教", k: ["抑郁症", "吃药", "算命必准"], x: "出现医疗诉求：建议线下专业帮助，不诊断。塔罗只当隐喻工具，不说「必准」「改命」。" },
    ],
  },
  deliver: {
    id: "deliver",
    name: "交付分身",
    strategy: "售后：履约、答疑、点评作业、续费只在交付完成后提",
    exclusive: ["作业点评", "课程回放", "第几课", "打卡", "续费"],
    docs: [
      { t: "课-边界练习", k: ["作业", "练习", "不会做", "第2课"], x: "第2课作业：写出三次「想发又停住」的瞬间。点评只标一个可执行改法，不翻旧账。" },
      { t: "答疑-回放", k: ["回放", "链接", "没听到", "看课", "从哪", "开始看"], x: "回放在「交付」知识库卡片，有效期 14 天。过期走补发申请，不在私聊丢网盘。" },
      { t: "SOP-退费苗头", k: ["退费", "没用", "不想学"], x: "先问卡在哪一课。能补一次直播就补，不争对错。退费走助理工单，分身不承诺退款到账时间。" },
      { t: "续费-四次后", k: ["还想聊", "续", "下一期"], x: "仅当四次已完成再提续。话术：要不要把下一段目标写进新协议，而不是「再买更便宜」。" },
    ],
  },
};

function grams(s) {
  const t = String(s || "").toLowerCase().replace(/\s+/g, "");
  const out = [];
  for (let i = 0; i < t.length - 1; i++) out.push(t.slice(i, i + 2));
  return out;
}

export function scoreDoc(query, doc) {
  let s = 0;
  for (const k of doc.k) if (query.includes(k)) s += 14;
  const qg = grams(query);
  const hg = new Set(grams(doc.t + doc.k.join("") + doc.x));
  let o = 0;
  for (const g of qg) if (hg.has(g)) o += 1;
  return s + Math.min(o, 16);
}

export function retrieve(cloneId, query) {
  const ranked = CLONES[cloneId].docs
    .map((d) => ({ ...d, s: scoreDoc(query, d) }))
    .sort((a, b) => b.s - a.s);
  return ranked.filter((d) => d.s >= 10).slice(0, 2);
}

export function leakScan(text, cloneId) {
  const other = cloneId === "close" ? "deliver" : "close";
  return CLONES[other].exclusive.filter((w) => text.includes(w));
}

export function routeClone(session) {
  const bought = ["已购", "交付", "续费"].includes(session.stage);
  return bought ? "deliver" : "close";
}

export function classifyStage(text, current) {
  if (/退费|没用|不想学/.test(text)) return current === "已购" || current === "交付" ? "交付" : current;
  if (/已付|付了|买了|报名成功/.test(text)) return "已购";
  if (/贵|没钱|再想想/.test(text)) return "异议";
  if (/多少钱|价格|收费/.test(text)) return current === "陌生" ? "咨询" : current;
  if (/想复合|分手|失眠|哭/.test(text)) return current === "陌生" ? "意向" : current;
  return current;
}

export function faqRepeat(query, corpus) {
  const hits = corpus.filter((q) => scoreDoc(query, { t: "", k: [q], x: q }) >= 14);
  return { n: hits.length, hot: hits.length >= 2 || /多少钱|价格/.test(query) };
}

export function confidence({ hits, leaked, bansHit, voicePoor, takeover }) {
  if (takeover) return 0.2;
  let c = 0.55;
  if (hits.length) c += 0.22;
  if (hits[0]?.s >= 20) c += 0.12;
  if (leaked.length) c -= 0.45;
  if (bansHit.length) c -= 0.35;
  if (voicePoor) c -= 0.12;
  return Math.max(0.18, Math.min(0.97, c));
}

export function bannedHits(text) {
  return PERSONA.bans.filter((w) => text.includes(w));
}

function toneWord(t) {
  if (t < 0.35) return "更软，短，先陪一会儿";
  if (t > 0.75) return "更清楚边界，不绕";
  return "稳，像她本人打字";
}

export function composeDraft(session, hits, opts = {}) {
  const clone = CLONES[session.cloneId];
  const q = session.lastIn;
  const tone = opts.tone == null ? PERSONA.tone : opts.tone;
  const facts = [
    session.customer,
    `阶段 ${session.stage}`,
    session.dayHint || "",
    session.voice ? "对方发了语音，按转写回" : "",
  ].filter(Boolean).join(" · ");
  const know = hits.length
    ? hits.map((h) => h.x).join(" ")
    : "库内无强命中，只接住情绪，不编产品细节，不承诺结果。";
  const body = [
    `（${facts}）`,
    toneWord(tone) + "。",
    know,
    PERSONA.quirks[0] + "，" + PERSONA.quirks[2] + "。",
  ].join("");
  // 口语压缩：生产换 LLM。这里用规则压成短草稿，避免模板腔。
  const spoken = speak(session, hits, tone, q);
  return { text: spoken, raw: body, cites: hits.map((h) => h.t) };
}

function speak(session, hits, tone, q) {
  const name = session.customer;
  const soft = tone < 0.45;
  if (/退费|没用/.test(q) && session.cloneId === "deliver") {
    return `${name}，我先问卡在第几课，不跟你争对错。能补一次我补；退费走助理工单，我这边不口头承诺到账时间。`;
  }
  if (/贵|没钱|再想想/.test(q)) {
    return soft
      ? `${name}，贵不贵你说了算。我只把一件事说清：咨询是把反复拉扯收成一次判断。你可以先约 15 分钟，或先看边界说明。`
      : `${name}，这个价不砍。你选：约 15 分钟，或先看我们不做什么。`;
  }
  if (/多少钱|价格|收费/.test(q)) {
    return `${name}，一对一 1280/次，四次 4580。不保证复合，不代替心理治疗。要数字就这些。`;
  }
  if (/看课|从哪|回放|链接|没听到/.test(q) && session.cloneId === "deliver") {
    return `${name}，回放在交付卡里，14 天有效。从第一课开始看。过期走补发，我不在聊天里丢网盘。`;
  }
  if (/作业|第2课|不会做/.test(q) && session.cloneId === "deliver") {
    return `${name}，第 2 课就写三次「想发又停住」。你先丢一条过来，我只改一个动作。`;
  }
  if (/复合|分手|想他|哭|失眠/.test(q)) {
    const dayNum = Number(String(session.dayHint || "").match(/(\d+)/)?.[1] || 0);
    if (dayNum >= 21) {
      return soft
        ? `${name}，已经 ${dayNum} 天了。疼还在，但可以问清楚：你要的是复合，还是先从反复拉扯里出来。要不要约 15 分钟把这件事说死。`
        : `${name}，${dayNum} 天了。先定目标：复合还是停拉扯。约 15 分钟，不保证结果。`;
    }
    const day = session.dayHint || "这几天";
    return soft
      ? `${name}，${day}先别逼自己想通。你现在更怕再也联系不上，还是怕自己先软？跟我说这一个就行。`
      : `${name}，${day}不谈课。先回答：你更怕断联，还是怕自己先回头？`;
  }
  if (/想试试|怎么开始|约/.test(q)) {
    return `${name}，明天下午 3 点或晚上 8 点，你回一个。来之前想好：你最想停掉的一个重复动作是什么。`;
  }
  if (hits.length) {
    return `${name}，${hits[0].x.slice(0, 72)}${hits[0].x.length > 72 ? "…" : ""}`;
  }
  return `${name}，我在。你把最难受的那一句发我，我按你的情况回，不套模板。`;
}

export function buildDraft(session, opts = {}) {
  const cloneId = routeClone(session);
  session.cloneId = cloneId;
  const q = String(session.lastIn || "");
  const hits = retrieve(cloneId, q);
  const { text, cites } = composeDraft(session, hits, opts);
  const leaked = leakScan(text, cloneId);
  const bansHit = bannedHits(text);
  const conf = confidence({
    hits,
    leaked,
    bansHit,
    voicePoor: !!(session.voice && session.asrConf < 0.85),
    takeover: !!session.takeover,
  });
  return {
    text,
    cites,
    hits,
    leaked,
    bansHit,
    cloneId,
    cloneName: CLONES[cloneId].name,
    confidence: conf,
    band: conf >= 0.9 ? "green" : conf >= 0.7 ? "yellow" : "red",
    ms: 380 + Math.round(Math.random() * 420),
  };
}

export const GOLDEN = [
  "先接住，再问一个问题",
  "不保证复合",
  "15分钟边界说明",
  "回放 14 天",
  "退费走工单",
];
