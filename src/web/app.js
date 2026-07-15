"use strict";
const $ = (id) => document.getElementById(id);
const LS = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k)    { try { localStorage.removeItem(k); } catch {} },
};
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function trunc(s, n) {
  s = String(s);
  if (s.length <= n) return s;
  const head = Math.ceil((n - 1) * 0.6);
  return s.slice(0, head) + "…" + s.slice(-(n - 1 - head));
}

/* ---------- token premium : capturé une fois depuis ?token=…, puis retiré de l'URL ---------- */
(() => {
  const u = new URL(location.href);
  const t = u.searchParams.get("token");
  if (t) { LS.set("indic_token", t); u.searchParams.delete("token"); history.replaceState(null, "", u); }
})();
const token = () => LS.get("indic_token", "");

/* ---------- thème ---------- */
let GRAPH = null;   // instance du graphe de pivots (déclarée tôt : applyTheme la référence)
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("mTheme").content = t === "dark" ? "#0a0e13" : "#f3f5f8";
  $("icoMoon").style.display = t === "dark" ? "" : "none";
  $("icoSun").style.display  = t === "dark" ? "none" : "";
  const tb = $("themeBtn");
  const lbl = t === "dark" ? "Passer au thème clair" : "Passer au thème sombre";
  tb.setAttribute("aria-pressed", t === "dark" ? "true" : "false");
  tb.setAttribute("aria-label", lbl);
  tb.title = lbl;
  GRAPH?.redraw();   // le Canvas doit re-résoudre ses couleurs
}
applyTheme(LS.get("indic_theme", "dark"));
$("themeBtn").onclick = () => {
  const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  LS.set("indic_theme", t); applyTheme(t);
};

/* ---------- sémantique couleurs ---------- */
const SIG_HUE = {
  malicious: "red", infostealer: "red", abuse: "red", spam: "red", attack: "red", compromised: "red", bot: "red",
  vpn: "orange", proxy: "orange", anonymous: "orange",
  tor: "purple", relay: "purple",
  scanner: "amber", noise: "amber", honeypot: "amber", bruteforce: "amber",
  datacenter: "blue", hosting: "blue", cloud: "blue", cdn: "blue",
  residential: "green", benign: "green", clean: "green",
  infra: "slate",
};
const SEVERITY = { red: 0, orange: 1, purple: 2, amber: 3, blue: 4, magenta: 5, cyan: 6, green: 7, slate: 8 };
const hueOf = (cat) => SIG_HUE[String(cat || "").toLowerCase()] || "slate";
const KIND_HUE = { ip: "blue", domain: "blue", url: "purple", email: "magenta", hash: "amber", cve: "red", cidr: "green", asn: "orange", phone: "green", onion: "purple", package: "cyan" };
const kindHue = (k) => KIND_HUE[k] || "slate";
const INFRA_LABEL = { datacenter: "Datacenter", isp: "FAI", mobile: "Mobile", education: "Éducation", government: "Gouvernement", unknown: "Inconnu" };
const ANON_LABEL  = { tor: "Tor", vpn: "VPN", proxy: "Proxy", relay: "Relay", datacenter: "Datacenter", residential: "Résidentiel", unknown: "Inconnu" };
const ANON_HUE    = { tor: "purple", vpn: "orange", proxy: "orange", relay: "purple", datacenter: "blue", residential: "green", unknown: "slate" };

/* glossaire des clés de facts (lookup insensible à la casse) — explication FR ~1 phrase */
const GLOSSARY = {
  type: "Catégorie de l'objet ou de l'allocation, selon la source.",
  rdap_name: "Nom de l'objet réseau enregistré au RIR (RDAP).",
  handle: "Identifiant unique de l'objet dans la base du RIR (RDAP).",
  registrant: "Entité déclarée propriétaire de la ressource (RDAP / WHOIS).",
  range: "Plage d'adresses IP couverte par l'allocation.",
  cidr: "Bloc d'adresses (notation CIDR) couvert par l'allocation.",
  reports: "Nombre de signalements d'activité malveillante reçus (DShield / AbuseIPDB).",
  targets: "Nombre de cibles distinctes attaquées par cette IP (DShield).",
  detections: "Nombre de moteurs antivirus ayant flaggé l'objet (VirusTotal).",
  reputation: "Score de réputation communautaire ; négatif = mauvaise réputation (VirusTotal).",
  as_owner: "Opérateur du système autonome qui annonce l'IP (VirusTotal).",
  fraud_score: "Score de fraude estimé, 0–100 (IPQualityScore).",
  abuse_score: "Taux de confiance d'abus, 0–100 % (AbuseIPDB).",
  score: "Score de risque propre à la source (échelle variable).",
  risk: "Niveau de risque évalué par la source.",
  usage: "Usage déclaré de l'IP (hébergement, résidentiel, mobile…).",
  usage_type: "Usage déclaré de l'IP (hébergement, résidentiel, mobile…).",
  asn: "Numéro de système autonome (AS) qui annonce l'IP.",
  isp: "Fournisseur d'accès / opérateur de l'IP.",
  org: "Organisation propriétaire ou gestionnaire de l'IP.",
  location: "Localisation géographique estimée de l'IP.",
  coords: "Coordonnées (latitude, longitude) approximatives.",
  timezone: "Fuseau horaire associé à la géolocalisation.",
  country: "Pays de géolocalisation de l'IP.",
  city: "Ville de géolocalisation estimée.",
  domain: "Nom de domaine associé à l'objet.",
  hostname: "Nom d'hôte inverse (PTR) résolu pour l'IP.",
  rdns: "Résolution DNS inverse (PTR) de l'IP.",
  appears: "Présence de l'IP / e-mail dans la base (StopForumSpam).",
  frequency: "Nombre d'apparitions dans les signalements (StopForumSpam).",
  created: "Date de création / enregistrement de l'objet.",
  registered: "Date d'enregistrement de la ressource au RIR.",
  updated: "Date de dernière mise à jour de l'objet.",
  last_seen: "Dernière fois que la source a observé cette activité.",
};
const glossaryFor = (k) => GLOSSARY[String(k || "").toLowerCase().trim()];

/* ---------- toast + copie ---------- */
let toastT;
function toast(msg) {
  const t = $("toast"); t.textContent = msg; t.classList.add("on");
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("on"), 1400);
}
async function copyText(s) {
  try { await navigator.clipboard.writeText(s); }
  catch {
    const ta = el("textarea"); ta.value = s;
    ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch {}
    ta.remove();
  }
  toast("copié ✓");
}

/* ---------- historique ---------- */
const HKEY = "indic_history";
function getHist() { try { return JSON.parse(LS.get(HKEY, "[]")) || []; } catch { return []; } }
function pushHist(q, kind) {
  if (!q) return;
  let h = getHist().filter((e) => e.q !== q);
  h.unshift({ q, kind, ts: Date.now() });
  LS.set(HKEY, JSON.stringify(h.slice(0, 12)));
  renderHist();
}
function renderHist() {
  const w = $("histRow"); w.replaceChildren();
  const h = getHist();
  if (!h.length) { w.hidden = true; return; }
  w.hidden = false;
  w.append(el("span", "hl", "récents"));
  for (const e of h) {
    const b = el("a", "chip pchip");
    b.href = "?q=" + encodeURIComponent(e.q);
    b.target = "_blank"; b.rel = "noopener";
    const d = el("i", "kdot"); d.style.background = `var(--h-${kindHue(e.kind)})`;
    b.append(d, el("span", "ctxt", trunc(e.q, 30)));
    b.title = `ouvrir « ${e.q} » dans un nouvel onglet`;
    w.append(b);
  }
  const c = el("button", "hclear", "effacer ×");
  c.onclick = () => { LS.del(HKEY); renderHist(); };
  w.append(c);
}

/* ---------- agrégation signaux & pivots ---------- */
function collectSignals(data) {
  const seen = new Set(); const out = [];
  const add = (s) => {
    if (!s || !s.category) return;
    const k = `${s.source}|${s.category}|${s.detail || ""}`;
    if (seen.has(k)) return;
    seen.add(k); out.push(s);
  };
  (data.ip?.signals || []).forEach(add);
  (data.enrichments || []).forEach((e) => (e.signals || []).forEach(add));
  out.sort((a, b) => (SEVERITY[hueOf(a.category)] ?? 9) - (SEVERITY[hueOf(b.category)] ?? 9));
  return out;
}
function collectPivots(data) {
  const seen = new Set(); const out = [];
  const add = (p) => {
    if (!p || !p.value || p.value === data.query) return;
    const k = `${p.kind}|${p.value}`;
    if (seen.has(k)) return;
    seen.add(k); out.push(p);
  };
  (data.pivots || []).forEach(add);
  (data.enrichments || []).forEach((e) => (e.pivots || []).forEach(add));
  return out;
}

/* ---------- chips ---------- */
function sigChip(s, withSource) {
  const c = el("span", "chip c-" + hueOf(s.category));
  c.append(el("i", "cdot"), el("span", null, s.category));
  if (s.detail) c.append(el("span", "cdet", "· " + s.detail));
  if (withSource && s.source) c.append(el("span", "csrc", s.source));
  return c;
}
function pivotChip(p) {
  const b = el("button", "chip pchip");
  const d = el("i", "kdot"); d.style.background = `var(--h-${kindHue(p.kind)})`;
  b.append(d, el("span", "crel", p.relation), el("span", "ctxt", trunc(p.value, 48)));
  b.title = `${p.kind} · ${p.value}`;
  b.onclick = () => go(p.value);
  return b;
}
/* liste de chips avec repli au-delà de `cap` */
function chipList(container, items, build, cap) {
  container.replaceChildren();
  container.classList.remove("expanded");
  items.forEach((it, i) => {
    const c = build(it);
    if (i >= cap) c.classList.add("xtra");
    container.append(c);
  });
  if (items.length > cap) {
    const label = `+ ${items.length - cap} de plus`;
    const more = el("button", "chip pchip", label);
    more.onclick = () => {
      const exp = container.classList.toggle("expanded");
      more.textContent = exp ? "réduire" : label;
    };
    container.append(more);
  }
}

/* ---------- verdict ---------- */
function vline(hue, html) {
  const l = el("div", "vline");
  const d = el("i", "cdot"); d.style.color = `var(--h-${hue})`;
  l.append(d);
  const s = el("span");
  html.forEach((part) => s.append(typeof part === "string" ? part : part));
  l.append(s);
  return l;
}
/* arbitrage backend : label pondéré + raison (corrige les faux « malveillant » sur domaines majeurs) */
const VERDICT_META = {
  clean:     { hue: "green", label: "Propre" },
  suspect:   { hue: "amber", label: "Suspect" },
  malicious: { hue: "red",   label: "Malveillant" },
};
function verdictBanner(V) {
  const meta = VERDICT_META[V.label] || { hue: "slate", label: V.label || "—" };
  const box = el("div", "verdictbox v-" + meta.hue);
  const head = el("div", "vbhead");
  head.append(el("i", "vbdot"), el("span", "vblabel", meta.label));
  if (Number.isFinite(V.score)) {
    const sc = el("span", "vbscore", "score " + V.score);
    sc.title = "score pondéré (poids des signaux − prior de popularité)"
      + (Number.isFinite(V.raw) ? ` · poids brut : ${V.raw}` : "");
    head.append(sc);
  }
  box.append(head);
  if (V.rationale) box.append(el("div", "vbwhy", V.rationale));
  return box;
}
function renderVerdict(data, sigs) {
  const v = $("verdict"); v.replaceChildren();
  if (data.verdict) v.append(verdictBanner(data.verdict));

  // détail brut des signaux : dé-emphasize s'il est coiffé par un verdict
  const detail = el("div", "vdetail" + (data.verdict ? " secondary" : ""));
  const threats = sigs.filter((s) => hueOf(s.category) === "red");
  if (threats.length) {
    const srcs = [...new Set(threats.map((t) => t.source))];
    const label = srcs.slice(0, 3).join(", ") + (srcs.length > 3 ? ` +${srcs.length - 3}` : "");
    detail.append(vline("red", [el("b", null, "Signaux malveillants"), ` — ${label}`]));
  }
  if (data.ip) {
    const ip = data.ip;
    if (ip.anonymous) {
      const hue = ANON_HUE[ip.anon_type] || "orange";
      const prov = ip.provider ? ` (${ip.provider})` : "";
      detail.append(vline(hue, [el("b", null, "Anonymisation détectée"), ` — ${ANON_LABEL[ip.anon_type] || ip.anon_type}${prov}`]));
    } else {
      detail.append(vline("green", ["Aucun signal d'anonymisation"]));
    }
  } else if (!threats.length) {
    detail.append(sigs.length
      ? vline("slate", [`${sigs.length} signau${sigs.length > 1 ? "x" : "l"} — aucun malveillant`])
      : vline("green", ["Aucun signal négatif"]));
  }
  if (detail.childElementCount) v.append(detail);
}

/* ---------- stat tiles (IP) ---------- */
function flagEmoji(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
function tile(label, value, opts = {}) {
  const t = el("div", "tile");
  const lab = el("div", "tl", label);
  if (opts.help) {
    const q = el("span", "thelp", "?");
    q.setAttribute("role", "button");
    q.setAttribute("aria-label", opts.help);
    q.tabIndex = 0;
    const tip = el("span", "tip", opts.help);
    tip.setAttribute("aria-hidden", "true");   // aria-label porte déjà le texte, évite la double lecture SR
    q.append(tip);
    const toggle = (e) => { e.preventDefault(); e.stopPropagation(); q.classList.toggle("open"); };
    q.onclick = toggle;
    q.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") toggle(e); };
    lab.append(" ", q);
  }
  t.append(lab);
  const tv = el("div", "tv" + (opts.mono ? " mono" : ""));
  if (opts.dotHue) { const d = el("i", "cdot"); d.style.color = `var(--h-${opts.dotHue})`; tv.append(d); }
  tv.append(el("span", null, value));
  tv.title = value;
  t.append(tv);
  if (opts.sub) { const s = el("div", "ts", opts.sub); s.title = opts.sub; t.append(s); }
  if (opts.meter != null) {
    const m = el("div", "meter"); const i = el("i");
    i.style.width = Math.round(opts.meter * 100) + "%";
    m.append(i); t.append(m);
  }
  return t;
}
function renderTiles(ip) {
  const w = $("tiles"); w.replaceChildren();
  if (!ip) { w.hidden = true; return; }
  w.hidden = false;
  w.append(tile("Infrastructure", INFRA_LABEL[ip.infra_type] || ip.infra_type, {
    help: "Type d'infrastructure hébergeant l'IP (datacenter, FAI résidentiel, mobile…).",
  }));
  w.append(tile("Anonymat", ip.anonymous ? (ANON_LABEL[ip.anon_type] || ip.anon_type) : "Non", {
    dotHue: ip.anonymous ? (ANON_HUE[ip.anon_type] || "orange") : "green",
    sub: ip.anonymous && ip.provider ? ip.provider : undefined,
    help: "Indique si l'IP masque l'utilisateur réel (Tor, VPN, proxy) et via quel service.",
  }));
  if (Number.isFinite(ip.confidence)) w.append(tile("Confiance", Math.round(ip.confidence * 100) + " %", {
    meter: ip.confidence,
    help: "Certitude de l'évaluation, dérivée du nombre et de la qualité des signaux — pas un score de risque ni la fiabilité des données.",
  }));
  if (ip.asn) w.append(tile("Réseau", "AS" + ip.asn, {
    mono: true, sub: ip.as_name || undefined,
    help: "Système autonome (ASN) qui annonce l'IP, et son opérateur.",
  }));
  if (ip.country) {
    const f = flagEmoji(ip.country);
    w.append(tile("Pays", (f ? f + "  " : "") + ip.country.toUpperCase(), {
      help: "Pays de géolocalisation de l'IP (approximatif, selon les bases publiques).",
    }));
  }
  if (ip.provider && !ip.anonymous) w.append(tile("Provider", ip.provider, {
    help: "Fournisseur / organisation propriétaire de l'IP.",
  }));
  // dernière tuile : ancre son tooltip à droite pour éviter tout débordement au bord
  const badges = w.querySelectorAll(".thelp");
  if (badges.length) badges[badges.length - 1].classList.add("right");
}

/* ---------- graphe de pivots récursif (Canvas, force-directed) ----------
   Cliquer un nœud le déplie sur place (fetch de SES pivots → nouveaux enfants).
   ⌘/Ctrl/Maj-clic = lookup complet (navigation). Dédup stricte par valeur.
   La chip-list sous le graphe reste le chemin accessible clavier / lecteur d'écran. */
const G_MAX_NODES = 60;        // plafond dur : au-delà, on ne déplie plus
const G_INIT_CHILDREN = 24;    // pivots initiaux disposés autour du central

// résout les tokens CSS en couleurs concrètes (le Canvas ne comprend pas var(--x))
function graphPalette() {
  const cs = getComputedStyle(document.documentElement);
  const v = (nm) => cs.getPropertyValue(nm).trim();
  const hues = ["red", "orange", "amber", "green", "blue", "purple", "cyan", "magenta", "slate"];
  const mark = {}; for (const h of hues) mark[h] = v(`--m-${h}`) || "#888";
  return { mark, edge: v("--line2"), ink: v("--ink"), ink2: v("--ink2"), ink3: v("--ink3"),
           card: v("--card"), card2: v("--card2"), accent: v("--accent") };
}

function renderGraph(query, centralKind, pivots) {
  GRAPH?.destroy();
  GRAPH = null;
  const card = $("graphCard");
  $("glegend").replaceChildren();
  if (pivots.length < 3) { card.hidden = true; return; }
  card.hidden = false;
  GRAPH = createPivotGraph(card, $("glegend"), query, centralKind, pivots);
}

function createPivotGraph(card, leg, query, centralKind, initialPivots) {
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const nodes = [];
  const nodeById = new Map();
  const edges = [];
  const edgeSet = new Set();
  let hovered = null, capped = false;

  let W = Math.max(320, Math.round(card.clientWidth || 760));
  const H = 440;
  let cx = W / 2, cy = H / 2;
  const PAD = 26;

  const canvas = el("canvas", "gcanvas");
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", "Graphe interactif des pivots (exploration à la souris ; liste des pivots ci-dessous pour le clavier)");
  const ctx = canvas.getContext("2d");
  const tip = el("div", "gtip"); tip.hidden = true;
  const hint = el("div", "ghint", "clic : déplier · ⌘/Ctrl-clic : rapport complet");
  card.append(canvas, tip, hint);

  let dpr = 1;
  function fit() {
    W = Math.max(320, Math.round(card.clientWidth || 760));
    cx = W / 2; cy = H / 2;
    dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = W + "px";
    canvas.style.height = H + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  let palTheme = null, pal = null;
  function palette() {
    const th = document.documentElement.dataset.theme;
    if (th !== palTheme) { pal = graphPalette(); palTheme = th; }
    return pal;
  }

  function makeNode(value, kind, level, relation) {
    return { id: value, value, kind, level, relation: relation || "",
             x: cx, y: cy, dx: 0, dy: 0, expanded: false, loading: false, central: false };
  }
  function addEdge(a, b) {
    if (a === b) return;
    const key = a.id < b.id ? a.id + " " + b.id : b.id + " " + a.id;
    if (edgeSet.has(key)) return;
    edgeSet.add(key); edges.push({ s: a, t: b });
  }
  function addChildren(parent, kids) {
    for (const p of kids) {
      if (p.value === parent.id) continue;
      let child = nodeById.get(p.value);
      if (!child) {
        if (nodes.length >= G_MAX_NODES) { capped = true; break; }
        child = makeNode(p.value, p.kind, parent.level + 1, p.relation);
        child.x = parent.x + (Math.random() - 0.5) * 60;
        child.y = parent.y + (Math.random() - 0.5) * 60;
        nodes.push(child); nodeById.set(child.id, child);
      }
      addEdge(parent, child);
    }
  }

  const central = makeNode(query, centralKind || "", 0, "");
  central.central = true; central.expanded = true;
  central.x = cx; central.y = cy; central.fx = cx; central.fy = cy;
  nodes.push(central); nodeById.set(central.id, central);

  const init = initialPivots.slice(0, G_INIT_CHILDREN);
  init.forEach((p, i) => {
    if (p.value === central.id) return;
    const ang = -Math.PI / 2 + (2 * Math.PI * i) / init.length;
    let nd = nodeById.get(p.value);
    if (!nd) {
      nd = makeNode(p.value, p.kind, 1, p.relation);
      nd.x = cx + Math.cos(ang) * 130; nd.y = cy + Math.sin(ang) * 130;
      nodes.push(nd); nodeById.set(nd.id, nd);
    }
    addEdge(central, nd);
  });

  /* --- simulation Fruchterman–Reingold --- */
  let temp = W / 8;
  function frStep() {
    const k = 0.85 * Math.sqrt((W * H) / Math.max(1, nodes.length));
    const k2 = k * k;
    for (const nd of nodes) { nd.dx = 0; nd.dy = 0; }
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let ex = a.x - b.x, ey = a.y - b.y;
        const dist = Math.hypot(ex, ey) || 0.01;
        const f = k2 / dist, ux = ex / dist, uy = ey / dist;
        a.dx += ux * f; a.dy += uy * f; b.dx -= ux * f; b.dy -= uy * f;
      }
    }
    for (const e of edges) {
      const a = e.s, b = e.t;
      let ex = a.x - b.x, ey = a.y - b.y;
      const dist = Math.hypot(ex, ey) || 0.01;
      const f = (dist * dist) / k, ux = ex / dist, uy = ey / dist;
      a.dx -= ux * f; a.dy -= uy * f; b.dx += ux * f; b.dy += uy * f;
    }
    for (const nd of nodes) {
      if (nd.fx != null) { nd.x = nd.fx; nd.y = nd.fy; continue; }
      nd.dx += (cx - nd.x) * 0.015; nd.dy += (cy - nd.y) * 0.015;   // gravité douce
      const d = Math.hypot(nd.dx, nd.dy) || 0.01;
      nd.x += (nd.dx / d) * Math.min(d, temp);
      nd.y += (nd.dy / d) * Math.min(d, temp);
      nd.x = Math.max(PAD, Math.min(W - PAD, nd.x));
      nd.y = Math.max(PAD, Math.min(H - PAD, nd.y));
    }
    temp *= 0.965;
  }
  function solveStatic(iters) { temp = W / 8; for (let i = 0; i < iters; i++) frStep(); }

  /* --- rendu Canvas --- */
  function labelShown(nd) { return nodes.length <= 22 || nd.central || nd.expanded || nd === hovered; }
  function draw() {
    const p = palette();
    ctx.clearRect(0, 0, W, H);
    ctx.lineWidth = 1;
    for (const e of edges) {
      const hl = hovered && (e.s === hovered || e.t === hovered);
      const other = e.s.central ? e.t : e.s;
      ctx.strokeStyle = hl ? (p.mark[kindHue(other.kind)] || p.edge) : p.edge;
      ctx.globalAlpha = hl ? 0.9 : 0.5;
      ctx.beginPath(); ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); ctx.stroke();
    }
    ctx.globalAlpha = 1;
    for (const nd of nodes) {
      const r = nd.central ? 11 : (nd === hovered ? 8 : 6);
      ctx.beginPath(); ctx.arc(nd.x, nd.y, r, 0, Math.PI * 2);
      ctx.fillStyle = nd.central ? p.card2 : (p.mark[kindHue(nd.kind)] || p.mark.slate);
      ctx.fill();
      ctx.lineWidth = 2; ctx.strokeStyle = nd.central ? p.edge : (nd === hovered ? p.ink : p.card); ctx.stroke();
      if (nd.expanded && !nd.central) {
        ctx.beginPath(); ctx.arc(nd.x, nd.y, r + 3, 0, Math.PI * 2);
        ctx.globalAlpha = 0.55; ctx.lineWidth = 1; ctx.strokeStyle = p.ink3; ctx.stroke(); ctx.globalAlpha = 1;
      }
      if (nd.loading) {
        const t = reduce ? 0.6 : (performance.now() / 260);
        ctx.beginPath(); ctx.arc(nd.x, nd.y, r + 4, t, t + Math.PI * 1.4);
        ctx.lineWidth = 2; ctx.strokeStyle = p.accent; ctx.stroke();
      }
    }
    ctx.font = "500 10.5px ui-monospace, Menlo, monospace";
    ctx.textAlign = "center"; ctx.textBaseline = "top";
    for (const nd of nodes) {
      if (!labelShown(nd)) continue;
      const r = nd.central ? 11 : 6;
      ctx.fillStyle = nd.central ? p.ink : (nd === hovered ? p.ink : p.ink2);
      ctx.fillText(trunc(nd.value, nd.central ? 24 : 16), nd.x, nd.y + r + 4);
    }
  }

  /* --- boucle d'animation (aucune si reduced-motion) --- */
  let raf = null, running = false;
  const anyLoading = () => nodes.some((n) => n.loading);
  function frame() {
    if (running) { frStep(); frStep(); if (temp < 0.6) running = false; }
    draw();
    raf = (running || anyLoading()) ? requestAnimationFrame(frame) : null;
  }
  function startLoop() { if (!raf) raf = requestAnimationFrame(frame); }
  function reheat() {
    if (reduce) { solveStatic(220); draw(); return; }
    temp = Math.max(temp, W / 12); running = true; startLoop();
  }

  /* --- hit-test + interactions --- */
  function nodeAt(mx, my) {
    let best = null, bd = Infinity;
    for (const nd of nodes) {
      const dx = nd.x - mx, dy = nd.y - my, d2 = dx * dx + dy * dy;
      const rr = nd.central ? 14 : 11;
      if (d2 <= rr * rr && d2 < bd) { best = nd; bd = d2; }
    }
    return best;
  }
  function rel(ev) { const b = canvas.getBoundingClientRect(); return { x: ev.clientX - b.left, y: ev.clientY - b.top }; }
  function onMove(ev) {
    const { x, y } = rel(ev);
    const nd = nodeAt(x, y);
    if (nd !== hovered) { hovered = nd; canvas.style.cursor = nd ? "pointer" : "default"; if (!raf) draw(); }
    if (nd) {
      tip.replaceChildren();
      tip.append(el("div", "gtv", nd.value));
      tip.append(el("div", "gtm", nd.central ? "observable central"
        : `${nd.relation ? nd.relation + " · " : ""}${nd.kind}${nd.expanded ? " · déplié" : ""}`));
      if (!nd.central) tip.append(el("div", "gth", nd.expanded ? "⌘/Ctrl-clic : rapport complet" : "clic : déplier · ⌘/Ctrl-clic : rapport"));
      tip.hidden = false;
      tip.style.left = Math.max(6, Math.min(x + 14, W - 232)) + "px";
      tip.style.top = Math.max(6, Math.min(y + 14, H - 64)) + "px";
    } else tip.hidden = true;
  }
  function onLeave() { if (hovered) { hovered = null; if (!raf) draw(); } tip.hidden = true; canvas.style.cursor = "default"; }
  function onClick(ev) {
    const { x, y } = rel(ev);
    const nd = nodeAt(x, y);
    if (!nd || nd.central) return;
    if (ev.metaKey || ev.ctrlKey || ev.shiftKey) { go(nd.value); return; }
    expandNode(nd);
  }

  /* --- expansion récursive (réutilise l'endpoint + le token) --- */
  const gctrl = new AbortController();
  async function expandNode(nd) {
    if (nd.central || nd.expanded || nd.loading) return;
    if (nodes.length >= G_MAX_NODES) { toast("graphe plafonné (60 nœuds)"); return; }
    nd.loading = true;
    if (reduce) draw(); else startLoop();
    try {
      const opts = { signal: gctrl.signal };
      if (token()) opts.headers = { "x-indic-token": token() };
      const res = await fetch("/lookup?q=" + encodeURIComponent(nd.value), opts);
      const data = await res.json().catch(() => null);
      nd.loading = false; nd.expanded = true;
      if (!res.ok || !data || data.error) { toast(data?.error || "expansion impossible"); if (reduce) draw(); return; }
      const before = nodes.length;
      addChildren(nd, collectPivots(data));
      updateLegend();
      if (capped) { toast("graphe plafonné (60 nœuds)"); capped = false; }
      if (nodes.length !== before) reheat(); else if (reduce) draw();
    } catch (err) {
      if (err.name === "AbortError") return;
      nd.loading = false; toast("expansion impossible"); if (reduce) draw();
    }
  }

  function updateLegend() {
    leg.replaceChildren();
    for (const k of [...new Set(nodes.filter((n) => !n.central).map((n) => n.kind))]) {
      const s = el("span");
      const d = el("i"); d.style.background = `var(--h-${kindHue(k)})`;
      s.append(d, k);
      leg.append(s);
    }
  }

  let rTimer = null;
  function onResize() {
    clearTimeout(rTimer);
    rTimer = setTimeout(() => { fit(); reduce ? draw() : reheat(); }, 160);
  }

  fit();
  updateLegend();
  canvas.addEventListener("mousemove", onMove);
  canvas.addEventListener("mouseleave", onLeave);
  canvas.addEventListener("click", onClick);
  window.addEventListener("resize", onResize);
  if (reduce) { solveStatic(320); draw(); } else { running = true; startLoop(); }

  return {
    redraw() { palTheme = null; if (raf) return; draw(); },   // ex. changement de thème
    destroy() {
      gctrl.abort();
      if (raf) cancelAnimationFrame(raf);
      canvas.removeEventListener("mousemove", onMove);
      canvas.removeEventListener("mouseleave", onLeave);
      canvas.removeEventListener("click", onClick);
      window.removeEventListener("resize", onResize);
      clearTimeout(rTimer);
      canvas.remove(); tip.remove(); hint.remove();
    },
  };
}

/* ---------- sources ---------- */
function srcCard(e) {
  const hasContent = (e.facts?.length || 0) + (e.signals?.length || 0) + (e.pivots?.length || 0) > 0;
  const card = el("div", "src");
  const head = el("div", "srchead");
  const dot = el("i", "sdot");
  dot.style.background = e.error ? "var(--h-red)" : hasContent ? "var(--h-green)" : "var(--ink3)";
  head.append(dot, el("span", "sname", e.source));
  head.append(el("span", "scnt", e.error ? "erreur" : `${e.facts?.length || 0} fait${(e.facts?.length || 0) > 1 ? "s" : ""}`));
  card.append(head);

  if (e.error) {
    card.append(el("div", "srcerr", e.error));
    return card;
  }
  if (!hasContent) {
    card.append(el("div", "srcempty", "aucune donnée"));
    return card;
  }
  if (e.facts?.length) {
    const facts = el("div", "facts");
    for (const f of e.facts) {
      const row = el("div", "fact");
      const fk = el("div", "fk", f.key);
      const help = glossaryFor(f.key);
      if (help) { fk.title = help; fk.classList.add("has-help"); }
      const fv = el("button", "fv", f.value);
      fv.title = "cliquer pour copier";
      fv.setAttribute("aria-label", `copier ${f.key}`);
      fv.onclick = () => copyText(f.value);
      row.append(fk, fv);
      facts.append(row);
    }
    card.append(facts);
  }
  if (e.signals?.length || e.pivots?.length) {
    const zone = el("div", "srcchips chips");
    (e.signals || []).forEach((s) => zone.append(sigChip(s, false)));
    (e.pivots || []).slice(0, 12).forEach((p) => zone.append(pivotChip(p)));
    if ((e.pivots?.length || 0) > 12) zone.append(el("span", "chip", `+ ${e.pivots.length - 12} pivots`));
    card.append(zone);
  }
  return card;
}
function renderSources(data) {
  const w = $("sources"); w.replaceChildren();
  const all = [...(data.enrichments || [])];
  const errs = all.filter((e) => e.error);
  const oks = all.filter((e) => !e.error);
  const rank = (e) => ((e.facts?.length || 0) + (e.signals?.length || 0) + (e.pivots?.length || 0) ? 0 : 1);
  oks.sort((a, b) => rank(a) - rank(b));
  $("cntSources").textContent = oks.length;          // le compteur ne reflète que les sources exploitables
  $("secSources").hidden = !all.length;
  oks.forEach((e) => w.append(srcCard(e)));

  // sources en erreur : repliées, discrètes, sous la grille
  const wrap = $("srcErrWrap");
  const listEl = $("srcErrList"); listEl.replaceChildren();
  if (errs.length) {
    wrap.hidden = false;
    wrap.open = false;
    const plur = errs.length > 1 ? "s" : "";
    $("srcErrSummary").textContent = `${errs.length} source${plur} indisponible${plur} (clé · quota · non supporté)`;
    for (const e of errs) {
      const msg = String(e.error || "").trim();
      const short = msg.length > 80 ? msg.slice(0, 79) + "…" : msg;
      const row = el("div", "srcerrrow");
      row.append(el("span", "sen", e.source), el("span", "ser", short || "indisponible"));
      listEl.append(row);
    }
  } else {
    wrap.hidden = true;
  }
}

/* ---------- landing (accueil sans requête) ---------- */
const LANDING = [
  { kind: "ip",       label: "IP",       ex: [
    { v: "8.8.8.8", d: "Google DNS, propre" },
    { v: "185.220.101.1", d: "nœud de sortie Tor" },
  ]},
  { kind: "cidr",     label: "CIDR",     ex: [
    { v: "104.16.0.0/13", d: "plage Cloudflare" },
    { v: "8.8.8.0/24", d: "plage Google" },
  ]},
  { kind: "domain",   label: "Domaine",  ex: [
    { v: "google.com", d: "domaine de référence" },
    { v: "github.com", d: "plateforme dev" },
  ]},
  { kind: "url",      label: "URL",      ex: [
    { v: "http://testphp.vulnweb.com/", d: "site de test" },
    { v: "https://example.com/", d: "URL neutre" },
  ]},
  { kind: "hash",     label: "Hash",     ex: [
    { v: "4e768038d00b2db2bd80dd53f790e8f0c9aaa4be34ee9d6bc820f77688500db7", d: "Emotet (SHA-256)" },
    { v: "44d88612fea8a8f36de82e1278abb02f", d: "EICAR test (MD5)" },
  ]},
  { kind: "cve",      label: "CVE",      ex: [
    { v: "CVE-2021-44228", d: "Log4Shell" },
    { v: "CVE-2014-0160", d: "Heartbleed" },
  ]},
  { kind: "email",    label: "E-mail",   ex: [
    { v: "test@example.com", d: "adresse de test" },
    { v: "admin@github.com", d: "email pro" },
  ]},
  { kind: "asn",      label: "ASN",      ex: [
    { v: "AS15169", d: "Google" },
    { v: "AS13335", d: "Cloudflare" },
  ]},
  { kind: "crypto",   label: "Crypto",   ex: [
    { v: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", d: "genesis de Satoshi" },
    { v: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", d: "adresse ETH" },
  ]},
  { kind: "username", label: "Username", ex: [
    { v: "torvalds", d: "Linus Torvalds" },
    { v: "octocat", d: "mascotte GitHub" },
  ]},
  { kind: "phone",    label: "Téléphone", ex: [
    { v: "+33612345678", d: "mobile France" },
    { v: "+14155552671", d: "US" },
  ]},
  { kind: "onion",    label: "Onion",     ex: [
    { v: "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion", d: "Facebook sur Tor (v3)" },
    { v: "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", d: "DuckDuckGo sur Tor" },
  ]},
  { kind: "package",  label: "Package",   ex: [
    { v: "pkg:pypi/requests", d: "package Python" },
    { v: "pkg:npm/express", d: "package Node" },
  ]},
];
function buildLanding(root) {
  root.replaceChildren();
  root.append(el("p", "lintro", "Analysez n'importe quel observable, ou partez d'un exemple :"));
  const grid = el("div", "lgrid");
  for (const cat of LANDING) {
    const card = el("div", "lcard");
    const head = el("div", "lhead");
    const dot = el("i", "kdot"); dot.style.background = `var(--h-${kindHue(cat.kind)})`;
    head.append(dot, el("span", "ltype", cat.label));
    card.append(head);
    const list = el("div", "lex");
    for (const e of cat.ex) {
      const b = el("button", "chip pchip lchip");
      b.append(el("span", "ctxt", trunc(e.v, 28)));
      if (e.d) b.append(el("span", "ldesc", e.d));
      b.title = e.v;
      b.onclick = () => go(e.v);
      list.append(b);
    }
    card.append(list);
    grid.append(card);
  }
  root.append(grid);
}
function showLanding() {
  const l = $("landing");
  if (!l.dataset.built) { buildLanding(l); l.dataset.built = "1"; }
  l.hidden = false;
}

/* ---------- rendu global ---------- */
let CUR = null;
let FROM_PIVOT = false;   // true seulement quand le rendu suit une navigation via go() (pivot/graphe/historique)
function render(data, info) {
  CUR = data;
  $("err").hidden = true;
  $("skeleton").hidden = true;
  $("landing").hidden = true;

  const rep = $("report");
  rep.hidden = false;
  rep.classList.remove("stale");

  const kb = $("kindBadge");
  kb.className = "chip badge c-" + kindHue(data.kind);
  kb.textContent = data.kind;
  $("selfNote").textContent = info.self ? "· votre adresse IP" : "";
  $("obsText").textContent = data.ip?.ip || data.query;

  const sigs = collectSignals(data);
  const pivs = collectPivots(data);
  renderVerdict(data, sigs);
  renderTiles(data.ip);

  $("secSignals").hidden = !sigs.length;
  const cntSig = $("cntSignals");
  const reds = sigs.filter((s) => hueOf(s.category) === "red").length;
  // ton du compteur : suit le verdict quand il existe et n'est pas "malicious"
  // (évite un « N critique » rouge sous un bandeau « Propre »). Sinon : rouge si signaux critiques.
  const vlabel = data.verdict?.label;
  let tone = null;                                  // neutre
  if (data.verdict && vlabel !== "malicious") tone = vlabel === "suspect" ? "amber" : null; // clean → neutre
  else if (reds > 0) tone = "red";                  // malicious ou type sans verdict
  cntSig.classList.toggle("c-red", tone === "red");
  cntSig.classList.toggle("c-amber", tone === "amber");
  cntSig.textContent = reds > 0 ? `${sigs.length} dont ${reds} critique${reds > 1 ? "s" : ""}` : sigs.length;
  cntSig.title = data.verdict
    ? `arbitrage : ${VERDICT_META[vlabel]?.label || vlabel} — ${sigs.length} signal(aux), dont ${reds} classé(s) critique`
    : "signaux de menace détectés (critique = malicious/C2/blocklist… en rouge)";
  chipList($("signals"), sigs, (s) => sigChip(s, true), 30);

  $("secPivots").hidden = !pivs.length;
  $("cntPivots").textContent = pivs.length;
  renderGraph(data.ip?.ip || data.query, data.kind, pivs);
  chipList($("pivots"), pivs, pivotChip, 40);

  renderSources(data);

  const nSrc = (data.enrichments || []).length;
  $("elapsed").textContent = `${(info.ms / 1000).toFixed(2)} s · ${nSrc} source${nSrc > 1 ? "s" : ""}`;
  $("rawWrap").open = false;
  $("raw").textContent = JSON.stringify(data, null, 2);

  rep.classList.remove("enter"); void rep.offsetWidth; rep.classList.add("enter");

  const obs = $("obsText");
  obs.tabIndex = -1;
  if (FROM_PIVOT) { obs.focus({ preventScroll: true }); FROM_PIVOT = false; }
}

/* ---------- lookup ---------- */
let ctrl = null;
function setLoading(on) {
  $("progress").classList.toggle("on", on);
  const wrap = document.querySelector("main.wrap");
  if (on) { wrap.setAttribute("aria-busy", "true"); $("landing").hidden = true; }
  else wrap.removeAttribute("aria-busy");
  const rep = $("report");
  if (on) {
    if (rep.hidden) { $("skeleton").hidden = false; $("err").hidden = true; }
    else rep.classList.add("stale");
  } else {
    $("skeleton").hidden = true;
    rep.classList.remove("stale");
  }
}
let LASTQ = "";
function showErr(msg) {
  $("skeleton").hidden = true;
  $("report").hidden = true;
  const e = $("err"); e.hidden = false; e.replaceChildren();
  e.append(el("span", null, LASTQ ? `« ${LASTQ} » — ${msg}` : msg));
  const retry = el("button", "ghost", "réessayer");
  retry.style.marginLeft = "12px";
  retry.onclick = () => lookup(LASTQ, !LASTQ);
  e.append(retry);
}
/* erreur : préserve un rapport déjà affiché (toast) sinon panneau plein */
function failLookup(msg) {
  FROM_PIVOT = false;   // un pivot qui échoue ne doit pas voler le focus au rendu suivant
  const rep = $("report");
  if (CUR && !rep.hidden) { rep.classList.remove("stale"); toast(msg); }
  else showErr(msg);
}
async function lookup(raw, self = false) {
  LASTQ = raw;
  if (ctrl) ctrl.abort();
  const my = (ctrl = new AbortController());
  const started = performance.now();
  setLoading(true);
  const url = raw ? "/lookup?q=" + encodeURIComponent(raw) : "/lookup";
  const opts = { signal: my.signal };
  if (token()) opts.headers = { "x-indic-token": token() };
  try {
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok || !data || data.error) {
      failLookup(data?.error || `erreur ${res.status}`);
      return;
    }
    render(data, { ms: performance.now() - started, self });
    if (!self) pushHist(data.query, data.kind);
    const u = new URL(location.href);
    if (self) u.searchParams.delete("q"); else u.searchParams.set("q", data.query);
    history.replaceState(null, "", u);
  } catch (err) {
    if (err.name === "AbortError") return;
    failLookup("erreur réseau — API injoignable ?");
  } finally {
    if (my === ctrl) setLoading(false);
  }
}
function go(q) {
  $("q").value = q;
  FROM_PIVOT = true;
  window.scrollTo({ top: 0, behavior: "smooth" });
  lookup(q);
}

/* ---------- interactions ---------- */
$("goBtn").onclick = () => { const v = $("q").value.trim(); v ? lookup(v) : lookup("", true); };
$("q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { const v = $("q").value.trim(); v ? lookup(v) : lookup("", true); }
  if (e.key === "Escape") { $("q").blur(); if (ctrl) { ctrl.abort(); setLoading(false); } }
});
/* clic sur le logo : retour accueil sans recharger (garde clic-milieu / cmd-clic natifs) */
document.querySelector(".brand").addEventListener("click", (e) => {
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
  e.preventDefault();
  if (ctrl) ctrl.abort();
  setLoading(false);
  $("report").hidden = true;
  $("err").hidden = true;
  $("q").value = "";
  const u = new URL(location.href); u.searchParams.delete("q"); history.replaceState(null, "", u);
  showLanding();
  window.scrollTo({ top: 0, behavior: "smooth" });
});
$("obsCopy").onclick = () => copyText($("obsText").textContent);
$("rawCopy").onclick = () => { if (CUR) copyText(JSON.stringify(CUR, null, 2)); };
$("jsonBtn").onclick = () => {
  const d = $("rawWrap"); d.open = true;
  d.scrollIntoView({ behavior: "smooth", block: "start" });
};
function refreshTokenBtn() {
  const has = !!token();
  $("tokenBtn").classList.toggle("on", has);
  const lbl = has ? "Token premium actif — cliquer pour modifier" : "Aucun token — enrichers premium désactivés";
  $("tokenBtn").title = lbl;
  $("tokenBtn").setAttribute("aria-label", lbl);
}
$("tokenBtn").onclick = () => {
  const v = prompt("Token indic (vide pour effacer) :", token());
  if (v === null) return;
  if (v.trim()) { LS.set("indic_token", v.trim()); toast("token enregistré"); }
  else { LS.del("indic_token"); toast("token effacé"); }
  refreshTokenBtn();
};

/* ---------- réglages (overlay token + statut clés API) ---------- */
let SET_RETURN = null;   // élément à re-focus à la fermeture
function setMsg(text, kind) {
  const m = $("setMsg");
  if (!text) { m.hidden = true; m.textContent = ""; return; }
  m.hidden = false; m.textContent = text;
  m.className = "setmsg" + (kind ? " " + kind : "");
}
function keyGroup(title, count, names, keys) {
  const g = el("div", "keygrp");
  const h = el("h4"); h.append(title + " ", el("span", "kn", "(" + count + ")"));
  g.append(h);
  if (!names.length) { g.append(el("div", "keyempty", "—")); return g; }
  const list = el("div", "keylist");
  for (const k of names) {
    const it = el("div", "keyitem " + (keys[k] ? "ok" : "no"));
    it.append(el("span", "kmark", keys[k] ? "✓" : "✗"), el("span", "kname", k));
    it.title = k + (keys[k] ? " — configurée" : " — manquante");
    list.append(it);
  }
  g.append(list);
  return g;
}
function renderKeys(data) {
  const box = $("setKeys"); box.replaceChildren();
  const n = Number(data.keys_configured) || 0, tot = Number(data.keys_total) || 0;
  const sum = el("div", "setsum");
  sum.append(el("span", "setbig", `${n} / ${tot}`));
  sum.append(el("span", "setsub", "clés configurées" + (data.feed_version ? ` · feed v${data.feed_version}` : "")));
  box.append(sum);
  if (tot > 0) {
    const m = el("div", "setmeter"); const i = el("i");
    i.style.width = Math.round((n / tot) * 100) + "%"; m.append(i); box.append(m);
  }
  const keys = data.keys || {};
  const names = Object.keys(keys).sort();
  const ok = names.filter((k) => keys[k]);
  const no = names.filter((k) => !keys[k]);
  box.append(keyGroup("Configurées", ok.length, ok, keys));
  box.append(keyGroup("Manquantes", no.length, no, keys));
}
async function loadSettings() {
  const box = $("setKeys"); box.replaceChildren(el("div", "keyempty", "Chargement…"));
  try {
    const res = await fetch("/settings?token=" + encodeURIComponent(token()));
    if (res.status === 403) {
      box.replaceChildren(el("div", "keyempty", "Token requis pour afficher le statut des clés."));
      setMsg("Token invalide ou manquant.", "err");
      return;
    }
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) { box.replaceChildren(el("div", "keyempty", "Impossible de charger les réglages.")); return; }
    renderKeys(data);
  } catch {
    box.replaceChildren(el("div", "keyempty", "Réglages injoignables (réseau)."));
  }
}
function openSettings() {
  SET_RETURN = document.activeElement;
  $("settings").hidden = false;
  const inp = $("setToken");
  inp.value = token(); inp.type = "password";
  $("setEye").classList.remove("on");
  $("setEye").setAttribute("aria-pressed", "false");
  $("setEye").setAttribute("aria-label", "Afficher le token");
  setMsg("");
  loadSettings();
  requestAnimationFrame(() => inp.focus());
}
function closeSettings() {
  $("settings").hidden = true;
  if (SET_RETURN && SET_RETURN.focus) SET_RETURN.focus();
  else $("settingsBtn").focus();
}
$("settingsBtn").onclick = openSettings;
$("setClose").onclick = closeSettings;
$("settings").addEventListener("click", (e) => { if (e.target === $("settings")) closeSettings(); });
$("setEye").onclick = () => {
  const inp = $("setToken"), show = inp.type === "password";
  inp.type = show ? "text" : "password";
  $("setEye").classList.toggle("on", show);
  $("setEye").setAttribute("aria-pressed", show ? "true" : "false");
  $("setEye").setAttribute("aria-label", show ? "Masquer le token" : "Afficher le token");
  inp.focus();
};
$("setSave").onclick = () => {
  const v = $("setToken").value.trim();
  if (v) { LS.set("indic_token", v); setMsg("Token enregistré.", "ok"); }
  else { LS.del("indic_token"); setMsg("Token effacé.", ""); }
  refreshTokenBtn();
  loadSettings();
};
$("setToken").addEventListener("keydown", (e) => { if (e.key === "Enter") $("setSave").click(); });
/* focus trap léger : Tab cycle dans l'overlay */
$("settings").addEventListener("keydown", (e) => {
  if (e.key !== "Tab") return;
  const f = [...$("settings").querySelectorAll('button, input, [href], [tabindex]:not([tabindex="-1"])')]
    .filter((x) => !x.disabled && x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});



function openComparator() {
  CMP_RETURN = document.activeElement;
  $("comparator").hidden = false;
  $("cmpA").value = "";
  $("cmpB").value = "";
  $("cmpResults").hidden = true;
  requestAnimationFrame(() => $("cmpA").focus());
}
function closeComparator() {
  $("comparator").hidden = true;
  if (CMP_RETURN && CMP_RETURN.focus) CMP_RETURN.focus();
  else $("cmpBtn").focus();
}
function renderCmpCol(col, label, data) {
  col.replaceChildren();
  const h = el("h3", null, label);
  h.title = label;
  col.append(h);

  if (!data) {
    col.append(el("div", "cmpErr", "Aucune donn\u00e9e re\u00e7ue"));
    return;
  }
  h.title = data.query || label;

  if (data.error) {
    col.append(el("div", "cmpErr", data.error));
    return;
  }

  const sigs = collectSignals(data);
  const pivs = collectPivots(data);
  const nSrc = (data.enrichments || []).length;

  // verdict banner (compact)
  if (data.verdict) {
    const vw = el("div", "cmpVerdict");
    vw.append(verdictBanner(data.verdict));
    col.append(vw);
  }

  // key info line
  const meta = el("div", "cmpMeta");
  meta.textContent = `${data.kind}` + (data.ip ? ` \u00b7 ${data.ip.country || ""} ${data.ip.asn ? "AS" + data.ip.asn : ""}` : "") + ` \u00b7 ${nSrc} source${nSrc > 1 ? "s" : ""}`;
  col.append(meta);

  // top signals (max 8)
  if (sigs.length) {
    const sw = el("div", "cmpSigs");
    sigs.slice(0, 8).forEach((s) => sw.append(sigChip(s, false)));
    if (sigs.length > 8) sw.append(el("span", "chip", `+ ${sigs.length - 8}`));
    col.append(sw);
  }

  // top pivots (max 6)
  if (pivs.length) {
    const pw = el("div", "cmpSrcs", `${pivs.length} pivot${pivs.length > 1 ? "s" : ""}`);
    pivs.slice(0, 6).forEach((p) => {
      const b = el("button", "chip pchip");
      const d = el("i", "kdot"); d.style.background = `var(--h-${kindHue(p.kind)})`;
      b.append(d, el("span", "ctxt", trunc(p.value, 28)));
      b.title = `${p.kind} \u00b7 ${p.value}`;
      b.onclick = () => { closeComparator(); go(p.value); };
      pw.append(b);
    }

function renderCmpCol(col, label, data) {
  col.replaceChildren();
  const h = el("h3", null, label);
  h.title = label;
  col.append(h);

  if (!data) {
    col.append(el("div", "cmpErr", "Aucune donn\u00e9e re\u00e7ue"));
    return;
  }
  h.title = data.query || label;

  if (data.error) {
    col.append(el("div", "cmpErr", data.error));
    return;
  }

  const sigs = collectSignals(data);
  const pivs = collectPivots(data);
  const nSrc = (data.enrichments || []).length;

  // verdict banner (compact)
  if (data.verdict) {
    const vw = el("div", "cmpVerdict");
    vw.append(verdictBanner(data.verdict));
    col.append(vw);
  }

  // key info line
  const meta = el("div", "cmpMeta");
  meta.textContent = `${data.kind}` + (data.ip ? ` \u00b7 ${data.ip.country || ""} ${data.ip.asn ? "AS" + data.ip.asn : ""}` : "") + ` \u00b7 ${nSrc} source${nSrc > 1 ? "s" : ""}`;
  col.append(meta);

  // top signals (max 8)
  if (sigs.length) {
    const sw = el("div", "cmpSigs");
    sigs.slice(0, 8).forEach((s) => sw.append(sigChip(s, false)));
    if (sigs.length > 8) sw.append(el("span", "chip", `+ ${sigs.length - 8}`));
    col.append(sw);
  }

  // top pivots (max 6)
  if (pivs.length) {
    const pw = el("div", "cmpSrcs", `${pivs.length} pivot${pivs.length > 1 ? "s" : ""}`);
    pivs.slice(0, 6).forEach((p) => {
      const b = el("button", "chip pchip");
      const d = el("i", "kdot"); d.style.background = `var(--h-${kindHue(p.kind)})`;
      b.append(d, el("span", "ctxt", trunc(p.value, 28)));
      b.title = `${p.kind} \u00b7 ${p.value}`;
      b.onclick = () => { closeComparator(); go(p.value); };
      pw.append(b);
    }

/* ── V_CACHE (mutualisé entre instances du graphe) ── */
const V_CACHE = new Map();

/* ── wiring comparateur ── */
$("cmpBtn").onclick = openComparator;
$("cmpGo").onclick = async () => {
  const a = $("cmpA").value.trim();
  const b = $("cmpB").value.trim();
  if (!a || !b) return;
  $("cmpResults").hidden = false;
  $("cmpResults").innerHTML = '<div class="cmpWait">Recherche…</div>';
  const t = token();
  const body = JSON.stringify({ a, b, token: t || undefined });
  try {
    const res = await fetch("/compare", { method: "POST", headers: { "content-type": "application/json" }, body });
    const data = await res.json();
    $("cmpResults").replaceChildren();
    const wrap = el("div", "cmpCols");
    wrap.append(renderCmpCol("A", a, data.a));
    wrap.append(renderCmpCol("B", b, data.b));
    $("cmpResults").append(wrap);
  } catch (err) {
    $("cmpResults").innerHTML = '<div class="errmsg">Erreur lors de la comparaison.</div>';
  }
};
$("cmpA").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("cmpB").focus(); }
});
$("cmpB").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("cmpGo").click(); }
});


document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("settings").hidden) { e.preventDefault(); closeSettings(); return; }
  if (e.key === "Escape" && !$("comparator").hidden) { e.preventDefault(); closeComparator(); return; }
  if (e.key === "c" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName || "")) {
    e.preventDefault();
    if ($("comparator").hidden) openComparator(); else closeComparator();
    return;
  }
  if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName || "")) {
    e.preventDefault(); $("q").focus(); $("q").select();
  }
});
/* ── init ── */