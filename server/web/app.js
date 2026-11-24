/* VIGIL - painel de monitoramento distribuido (sem dependencias externas) */
"use strict";

const S = {
  me: null, csrf: "", groups: [], info: null, timer: null, lastAlerts: 0,
  f: { status: "", os: "", group: "", location: "", q: "" }, selected: new Set(), range: "1h", alertState: "open", evKind: "",
};
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const LOGO = `<svg viewBox="0 0 64 64"><defs><linearGradient id="lg" x1="0" x2="1"><stop offset="0" stop-color="#38bdf8"/><stop offset="1" stop-color="#6366f1"/></linearGradient></defs><path d="M4 32C12 18 22 12 32 12s20 6 28 20c-8 14-18 20-28 20S12 46 4 32z" fill="url(#lg)"/><circle cx="32" cy="32" r="11" fill="#07122a"/><circle cx="32" cy="32" r="5" fill="#38bdf8"/></svg>`;

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const can = role => S.me && ({ viewer: 1, operator: 2, admin: 3 }[S.me.role] >= { viewer: 1, operator: 2, admin: 3 }[role]);

async function api(method, url, body) {
  const opt = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  if (method !== "GET") opt.headers["X-Vigil-CSRF"] = S.csrf;
  const r = await fetch(url, opt);
  let data = {};
  try { data = await r.json(); } catch (e) { /* sem corpo */ }
  if (r.status === 401 && !url.startsWith("/api/login")) { S.me = null; renderLogin(); throw new Error(data.error || "Sessão expirada"); }
  if (!r.ok) throw new Error(data.error || `Erro HTTP ${r.status}`);
  return data;
}

function toast(msg, err) {
  const el = document.createElement("div");
  el.className = "toast" + (err ? " err" : "");
  el.textContent = msg;
  $("#toast-root").appendChild(el);
  setTimeout(() => el.remove(), err ? 6000 : 3500);
}

/* ------------------------------------------------------------------ formatacao */
const pct = v => v == null ? "—" : `${Math.round(v)}%`;
function bytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i ? 1 : 0)} ${u[i]}`;
}
function bps(n) {
  if (n == null) return "—";
  const b = n * 8, u = ["bps", "Kbps", "Mbps", "Gbps"]; let i = 0, v = b;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
}
function ago(ts) {
  if (!ts) return "nunca";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 10) return "agora"; if (s < 60) return `há ${s} s`; if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`; return `há ${Math.floor(s / 86400)} d`;
}
const dt = ts => ts ? new Date(ts * 1000).toLocaleString("pt-BR") : "—";
function dur(s) {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}min` : `${m} min`;
}
const STATUS = { online: "Online", offline: "Offline", pending: "Aguardando", expired: "Expirado", revoked: "Revogado" };
const HEALTH = { ok: "Normal", attention: "Atenção", critical: "Crítico", unknown: "—" };
const OSL = { windows: "Windows", linux: "Linux", macos: "macOS", other: "Outro", "": "—" };
const EVK = {
  connect: "Reconectado", disconnect: "Desconectado", enrolled: "Primeira conexão", auth_fail: "Falha de autenticação",
  device_created: "Dispositivo cadastrado", device_deleted: "Dispositivo excluído", token_rotated: "Token rotacionado",
  token_rotation_requested: "Rotação solicitada", token_revoked: "Token revogado", token_reissued: "Token reemitido",
  login: "Login no painel", login_fail: "Falha de login",
};
const stBadge = s => `<span class="st st-${esc(s)}"><span class="dot"></span>${esc(STATUS[s] || s)}</span>`;
const hl = (d) => d.status !== "online" ? `<span class="dim">—</span>` : `<span class="hl-${esc(d.health)}">${esc(HEALTH[d.health] || "—")}</span>`;
function mbar(v, warn = 75, crit = 90) {
  if (v == null) return `<span class="dim">—</span>`;
  const c = v >= crit ? "crit" : v >= warn ? "warn" : "";
  return `<div class="mbar"><div class="bar ${c}" style="flex:1"><i style="width:${Math.min(100, v)}%"></i></div><b>${pct(v)}</b></div>`;
}
const osName = d => esc(d.os_name || d.os_declared || OSL[d.os_family] || "—");
const ipOf = d => esc(d.ip_local || d.ip_declared || "—");
// versao curta para tabelas: "Windows 10 Professional (build 19045)" -> "Windows 10"
function osShort(d) {
  const n = (d.os_name || d.os_declared || OSL[d.os_family] || "—").replace(/\s*\(.*\)$/, "");
  const m = n.match(/^(Windows(?: Server)? \S+|Ubuntu \S+|Debian\S* \S+|[A-Za-z]+ Linux \S+)/);
  return m ? m[1] : n.split(" ").slice(0, 3).join(" ");
}

/* ------------------------------------------------------------------ login / setup */
async function boot() {
  try {
    const st = await api("GET", "/api/setup-status");
    if (st.needs_setup) return renderSetup();
    S.me = await api("GET", "/api/me");
    S.csrf = S.me.csrf;
    await loadCommon();
    renderShell();
    window.addEventListener("hashchange", route);
    route();
  } catch (e) { if (!S.me) renderLogin(); }
}
async function loadCommon() {
  [S.groups, S.info] = await Promise.all([api("GET", "/api/groups"), api("GET", "/api/server-info")]);
}
function renderLogin() {
  clearInterval(S.timer);
  $("#app").innerHTML = `<div class="login"><form class="card" id="login-form">
    <div class="brand">${LOGO}<div><b>VIGIL</b><small>Monitoramento de infraestrutura</small></div></div>
    <p>Entre para acessar a central</p>
    <label class="f"><span>Usuário</span><input name="username" autocomplete="username" required autofocus></label>
    <label class="f"><span>Senha</span><input name="password" type="password" autocomplete="current-password" required></label>
    <div class="err" id="login-err"></div>
    <button class="btn pri" style="width:100%">Entrar</button></form></div>`;
  $("#login-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { const r = await api("POST", "/api/login", fd); S.csrf = r.csrf; location.hash = location.hash || "#/dashboard"; location.reload(); }
    catch (e) { $("#login-err").textContent = e.message; }
  });
}
function renderSetup() {
  $("#app").innerHTML = `<div class="login"><form class="card" id="setup-form">
    <div class="brand">${LOGO}<div><b>VIGIL</b><small>Configuração inicial</small></div></div>
    <p>Crie o administrador da central. (Somente neste computador.)</p>
    <label class="f"><span>Nome da organização</span><input name="org_name" placeholder="Ex.: Minha Empresa"></label>
    <label class="f"><span>Usuário administrador</span><input name="username" required minlength="3" value="admin"></label>
    <label class="f"><span>Senha (mín. 10 caracteres)</span><input name="password" type="password" required minlength="10"></label>
    <label class="f"><span>Confirme a senha</span><input name="password2" type="password" required minlength="10"></label>
    <div class="err" id="setup-err"></div>
    <button class="btn pri" style="width:100%">Criar e entrar</button></form></div>`;
  $("#setup-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    if (fd.password !== fd.password2) return $("#setup-err").textContent = "As senhas não conferem";
    try {
      await api("POST", "/api/setup", fd);
      const r = await api("POST", "/api/login", { username: fd.username, password: fd.password });
      S.csrf = r.csrf; location.hash = "#/dashboard"; location.reload();
    } catch (e) { $("#setup-err").textContent = e.message; }
  });
}

/* ------------------------------------------------------------------ casca */
const NAV = [
  ["dashboard", "Dashboard", "◉"], ["devices", "Dispositivos", "▤"], ["infra", "Infraestrutura", "▦"],
  ["groups", "Grupos", "◫"], ["alerts", "Alertas", "⚠"], ["events", "Conexões", "⇄"], ["settings", "Configurações", "⚙"],
];
function renderShell() {
  $("#app").innerHTML = `<div class="shell"><aside class="side">
    <div class="brand">${LOGO}<div><b>VIGIL</b><small>${esc(S.me.org || "Central")}</small></div></div>
    <nav class="nav">${NAV.map(([k, l, i]) => `<a href="#/${k}" data-nav="${k}"><span>${i}</span>${l}${k === "alerts" ? `<span class="badge" id="nav-alerts" hidden></span>` : ""}</a>`).join("")}</nav>
    <div class="foot">${esc(S.me.username)} · ${esc({ admin: "Administrador", operator: "Operador", viewer: "Leitura" }[S.me.role])}<br>VIGIL ${esc(S.me.version)}
      <button class="btn sm" data-act="logout">Sair</button></div>
  </aside><main class="main" id="view"></main></div>`;
}
function setTop(title, actions = "", crumb = "") {
  return `<div class="top"><div>${crumb ? `<div class="crumb">${crumb}</div>` : ""}<h1>${title}</h1></div><div class="sp"></div>${actions}</div>`;
}

async function route() {
  if (!S.me) return;
  clearInterval(S.timer);
  const [, page = "dashboard", arg] = (location.hash || "#/dashboard").split("/");
  $$(".nav a").forEach(a => a.classList.toggle("on", a.dataset.nav === (page === "device" ? "devices" : page)));
  const fn = { dashboard: viewDashboard, devices: viewDevices, device: () => viewDevice(arg), infra: viewInfra, groups: viewGroups, alerts: viewAlerts, events: viewEvents, settings: viewSettings }[page] || viewDashboard;
  const refresh = async (first) => {
    if (!first && (document.activeElement?.matches("#view input, #view select, #view textarea") || $(".modal-bg"))) return;
    try { await fn(first); } catch (e) { if (first) $("#view").innerHTML = `<div class="card empty">${esc(e.message)}</div>`; }
  };
  await refresh(true);
  if (["dashboard", "devices", "device", "infra", "alerts", "events"].includes(page)) S.timer = setInterval(() => refresh(false), 5000);
}
function navBadge(n) {
  const b = $("#nav-alerts"); if (!b) return;
  b.hidden = !n; b.textContent = n;
}

/* ------------------------------------------------------------------ dashboard */
async function viewDashboard() {
  const s = await api("GET", "/api/summary");
  navBadge(s.alerts_critical + s.alerts_warning);
  const k = (cls, l, v, sub = "") => `<div class="card kpi ${cls}"><div class="l">${l}</div><div class="v">${v}</div><div class="s">${sub}</div></div>`;
  const evList = (arr, empty) => arr.length ? `<ul class="list">${arr.map(e => `<li><span class="dot" style="background:${e.kind === "disconnect" ? "var(--off)" : "var(--ok)"}"></span>
     <div class="grow"><a href="#/device/${esc(e.device_id)}" class="name">${esc(e.device_name || "—")}</a><div class="sub">${esc(EVK[e.kind] || e.kind)} · ${esc(e.ip || "")}</div></div>
     <span class="dim" title="${esc(dt(e.ts))}">${ago(e.ts)}</span></li>`).join("")}</ul>` : `<div class="empty">${empty}</div>`;
  const devs = s.devices.slice().sort((a, b) => ({ critical: 0, attention: 1 }[a.health] ?? 2) - ({ critical: 0, attention: 1 }[b.health] ?? 2));
  $("#view").innerHTML = setTop("Visão geral da infraestrutura",
    can("admin") ? `<button class="btn pri" data-act="add-device">+ Adicionar dispositivo</button>` : "") + `
    <div class="grid kpis">
      ${k("acc", "Cadastrados", s.total, `${s.pending} aguardando agente`)}
      ${k("ok", "Online", s.online, s.total ? `${Math.round(100 * s.online / Math.max(1, s.total - s.pending - s.revoked))}% dos ativos` : "")}
      ${k("off", "Offline", s.offline, "sem comunicação")}
      ${k("crit", "Críticos", s.critical, `${s.attention} em atenção`)}
      ${k("", "CPU média", pct(s.avg_cpu), "dispositivos online")}
      ${k("", "RAM média", pct(s.avg_ram), "dispositivos online")}
      ${k("ok", "Disponibilidade", s.availability == null ? "—" : s.availability + "%", "últimas 24 h")}
      ${k(s.alerts_critical ? "crit" : "warn", "Alertas abertos", s.alerts_critical + s.alerts_warning, `${s.alerts_critical} críticos`)}
    </div>
    <div class="grid cols3" style="margin-bottom:14px">
      <div class="card"><h3>Últimos dispositivos conectados</h3>${evList(s.last_connects, "Nenhuma conexão ainda")}</div>
      <div class="card"><h3>Últimas desconexões</h3>${evList(s.last_disconnects, "Nenhuma desconexão registrada")}</div>
      <div class="card"><h3>Alertas ativos</h3>${s.recent_alerts.length ? `<ul class="list">${s.recent_alerts.map(a => `<li><span class="sev sev-${esc(a.severity)}">${a.severity === "critical" ? "Crítico" : "Atenção"}</span>
        <div class="grow"><a class="name" href="#/device/${esc(a.device_id)}">${esc(a.device_name)}</a><div class="sub">${esc(a.message)}</div></div><span class="dim">${ago(a.opened_at)}</span></li>`).join("")}</ul>` : `<div class="empty">Tudo em ordem ✓</div>`}</div>
    </div>
    <div class="card"><h3>Infraestrutura conectada</h3>${devs.length ? `<div class="tiles">${devs.map(tile).join("")}</div>` : emptyDevices()}</div>`;
}
function emptyDevices() {
  return `<div class="empty">Nenhum computador cadastrado ainda.${can("admin") ? ` <a href="#" data-act="add-device">Adicionar o primeiro dispositivo</a>` : ""}</div>`;
}
function tile(d) {
  const t = d.status === "online" ? d.health : d.status === "offline" ? "off" : d.status;
  const tb = (l, v) => `<span>${l}</span><div class="bar ${v >= 90 ? "crit" : v >= 75 ? "warn" : ""}"><i style="width:${Math.min(100, v || 0)}%"></i></div><span class="right">${pct(v)}</span>`;
  return `<div class="tile t-${esc(t)}" data-open="${esc(d.id)}" title="${esc(d.name)}">
    <div class="row" style="gap:6px"><div class="tn" style="flex:1">${esc(d.name)}</div>${d.open_alerts ? `<span class="badge">${d.open_alerts}</span>` : ""}</div>
    <div class="sub">${stBadge(d.status)} <span style="margin-left:4px">${esc(OSL[d.os_family] || "")}</span></div>
    ${d.status === "online" ? `<div class="tm">${tb("CPU", d.cpu)}${tb("RAM", d.ram)}${tb("Disco", d.disk)}</div>` : `<div class="sub" style="margin-top:8px">Última comunicação: ${ago(d.last_seen)}</div>`}</div>`;
}

/* ------------------------------------------------------------------ dispositivos */
async function viewDevices() {
  const all = await api("GET", "/api/devices");
  const f = S.f;
  const counts = {
    "": all.length, online: all.filter(d => d.status === "online").length, offline: all.filter(d => d.status === "offline").length,
    critical: all.filter(d => d.status === "online" && d.health === "critical").length,
    attention: all.filter(d => d.status === "online" && d.health === "attention").length,
    pending: all.filter(d => d.status === "pending" || d.status === "expired").length,
  };
  const locs = [...new Set(all.map(d => d.location).filter(Boolean))].sort();
  const list = all.filter(d => {
    if (f.status === "critical" && !(d.status === "online" && d.health === "critical")) return false;
    if (f.status === "attention" && !(d.status === "online" && d.health === "attention")) return false;
    if (f.status === "pending" && !["pending", "expired"].includes(d.status)) return false;
    if (["online", "offline"].includes(f.status) && d.status !== f.status) return false;
    if (f.os && d.os_family !== f.os) return false;
    if (f.group && String(d.group_id) !== f.group) return false;
    if (f.location && d.location !== f.location) return false;
    if (f.q && !`${d.name} ${d.hostname} ${d.ip_local} ${d.ip_remote} ${d.ip_declared} ${d.description}`.toLowerCase().includes(f.q.toLowerCase())) return false;
    return true;
  });
  [...S.selected].forEach(id => { if (!all.some(d => d.id === id)) S.selected.delete(id); });
  const chip = (k, l) => `<span class="chip ${f.status === k ? "on" : ""}" data-fstatus="${k}">${l}<span class="n">${counts[k]}</span></span>`;
  $("#view").innerHTML = setTop("Dispositivos", can("admin") ? `<button class="btn pri" data-act="add-device">+ Adicionar dispositivo</button>` : "") + `
    <div class="card" style="margin-bottom:14px">
      <div class="row" style="margin-bottom:10px">${chip("", "Todos")}${chip("online", "Online")}${chip("offline", "Offline")}${chip("critical", "Crítico")}${chip("attention", "Atenção")}${chip("pending", "Aguardando")}</div>
      <div class="row">
        <input id="f-q" placeholder="Buscar nome, IP, descrição…" value="${esc(f.q)}" style="flex:1;min-width:200px">
        <select id="f-os"><option value="">Sistema: todos</option>${["windows", "linux", "macos", "other"].map(o => `<option value="${o}" ${f.os === o ? "selected" : ""}>${OSL[o]}</option>`).join("")}</select>
        <select id="f-group"><option value="">Grupo: todos</option>${S.groups.map(g => `<option value="${g.id}" ${f.group === String(g.id) ? "selected" : ""}>${esc(g.name)}</option>`).join("")}</select>
        <select id="f-loc"><option value="">Localização: todas</option>${locs.map(l => `<option ${f.location === l ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
      </div>
      ${can("operator") ? `<div class="row" style="margin-top:10px" ${S.selected.size ? "" : "hidden"} id="bulk">
        <span class="muted">${S.selected.size} selecionado(s) →</span>
        <select id="bulk-group">${S.groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join("")}</select>
        <button class="btn sm" data-act="bulk-move">Mover para o grupo</button><button class="btn sm" data-act="bulk-clear">Limpar seleção</button></div>` : ""}
    </div>
    <div class="card tbl-wrap">${list.length ? `<table><thead><tr>${can("operator") ? `<th><input type="checkbox" id="sel-all"></th>` : ""}
      <th>Computador</th><th>IP</th><th>Sistema</th><th>Status</th><th>Saúde</th><th>CPU</th><th>RAM</th><th>Disco</th><th>Rede</th><th>Contato</th></tr></thead><tbody>
      ${list.map(d => `<tr class="click" data-open="${esc(d.id)}">
        ${can("operator") ? `<td><input type="checkbox" data-sel="${esc(d.id)}" ${S.selected.has(d.id) ? "checked" : ""}></td>` : ""}
        <td><div class="name">${esc(d.name)} ${d.open_alerts ? `<span class="badge">${d.open_alerts}</span>` : ""}</div><div class="sub">${esc(d.group_name)}${d.location ? " · " + esc(d.location) : ""}</div></td>
        <td class="mono">${ipOf(d)}${d.ip_remote && d.ip_remote !== d.ip_local ? `<div class="sub">via ${esc(d.ip_remote)}</div>` : ""}</td>
        <td class="nw" title="${osName(d)}">${esc(osShort(d))}</td><td>${stBadge(d.status)}</td><td>${hl(d)}</td>
        <td>${d.status === "online" ? mbar(d.cpu) : "—"}</td><td>${d.status === "online" ? mbar(d.ram, 75, 85) : "—"}</td><td>${d.status === "online" ? mbar(d.disk, 80, 90) : "—"}</td>
        <td class="sub nw">${d.status === "online" ? `↓ ${bps(d.net_rx)}<br>↑ ${bps(d.net_tx)}` : "—"}</td>
        <td class="sub" title="${esc(dt(d.last_seen))}">${ago(d.last_seen)}</td></tr>`).join("")}
      </tbody></table>` : (all.length ? `<div class="empty">Nenhum dispositivo com esses filtros.</div>` : emptyDevices())}</div>`;
  $("#f-q").addEventListener("input", debounce(e => { f.q = e.target.value; viewDevices().then(() => { const i = $("#f-q"); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }); }, 250));
  $("#f-os").addEventListener("change", e => { f.os = e.target.value; viewDevices(); });
  $("#f-group").addEventListener("change", e => { f.group = e.target.value; viewDevices(); });
  $("#f-loc").addEventListener("change", e => { f.location = e.target.value; viewDevices(); });
  $("#sel-all")?.addEventListener("change", e => { list.forEach(d => e.target.checked ? S.selected.add(d.id) : S.selected.delete(d.id)); viewDevices(); });
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

/* ------------------------------------------------------------------ adicionar dispositivo */
function groupOptions(sel) {
  return S.groups.map(g => `<option value="${g.id}" ${String(sel) === String(g.id) ? "selected" : ""}>${esc(g.name)}</option>`).join("");
}
function addDeviceModal() {
  const outros = S.groups.find(g => g.name === "Outros");
  modal("Adicionar dispositivo", `<form id="add-form">
    <div class="grid cols2" style="gap:0 14px">
      <label class="f"><span>Nome do dispositivo *</span><input name="name" required maxlength="80" placeholder="Ex.: SRV-ARQUIVOS"></label>
      <label class="f"><span>Sistema operacional</span><select name="os"><option>Windows</option><option>Linux</option><option>Outro</option></select></label>
      <label class="f"><span>Endereço IP (opcional)</span><input name="ip" placeholder="Ex.: 192.168.0.20"></label>
      <label class="f"><span>Grupo</span><select name="group_id">${groupOptions(outros?.id)}</select></label>
      <label class="f"><span>Localização</span><input name="location" maxlength="80" placeholder="Ex.: Matriz · Sala TI"></label>
    </div>
    <label class="f"><span>Descrição</span><textarea name="description" rows="2" maxlength="500"></textarea></label>
    <div class="err" id="add-err"></div></form>`,
    `<button class="btn" data-act="close">Cancelar</button><button class="btn pri" id="add-go">Gerar token e instruções</button>`);
  $("#add-go").addEventListener("click", async () => {
    const fd = Object.fromEntries(new FormData($("#add-form")));
    if (!fd.name.trim()) return $("#add-err").textContent = "Informe o nome do dispositivo";
    try {
      const r = await api("POST", "/api/devices", fd);
      S.groups = await api("GET", "/api/groups");
      installModal(r.device, r.token, r.token_expires_at, fd.os);
      route();
    } catch (e) { $("#add-err").textContent = e.message; }
  });
}
function installCommands(token) {
  const i = S.info, url = i.public_url, fp = i.fingerprint, pin = i.spki_pin;
  const selfSigned = !!(i.pin && fp);
  const win = [
    `# Execute no PowerShell como ADMINISTRADOR no computador a ser monitorado`,
    `$srv='${url}'; $tok='${token}'${selfSigned ? `; $fp='${fp}'` : ""}`,
    `[Net.ServicePointManager]::SecurityProtocol='Tls12'`,
    // validacao compilada (scriptblock nao funciona: roda em thread sem runspace no PowerShell 5.1)
    selfSigned ? `Add-Type -TypeDefinition 'using System.Net;using System.Security.Cryptography;public static class VigilPin{public static void On(string f){ServicePointManager.ServerCertificateValidationCallback=(s,c,h,e)=>System.BitConverter.ToString(SHA256.Create().ComputeHash(c.GetRawCertData())).Replace("-","")==f.ToUpper();}}'; [VigilPin]::On($fp)` : null,
    `$d="$env:TEMP\\vigil-agent"; New-Item -ItemType Directory -Force $d | Out-Null`,
    `'vigil_agent.py','vigil_service.py','install.ps1','uninstall.ps1' | ForEach-Object { Invoke-WebRequest -UseBasicParsing "$srv/download/windows/$_" -OutFile "$d\\$_" }`,
    `powershell -ExecutionPolicy Bypass -File "$d\\install.ps1" -Server $srv -Token $tok${selfSigned ? " -Fingerprint $fp" : ""}`,
  ].filter(Boolean).join("\n");
  const curlTls = selfSigned && pin ? `-k --pinnedpubkey 'sha256//${pin}' ` : "";
  const lin = [
    `# Execute no terminal do computador Linux a ser monitorado`,
    `d=$(mktemp -d) && curl -fsSL ${curlTls}'${url}/download/linux/install.sh' -o "$d/install.sh" && \\`,
    `sudo bash "$d/install.sh" --server '${url}' --token '${token}'${selfSigned ? ` --fingerprint '${fp}'${pin ? ` --pin 'sha256//${pin}'` : ""}` : ""}`,
  ].join("\n");
  return { win, lin, selfSigned };
}
function installModal(dev, token, exp, os) {
  const c = installCommands(token);
  const isLin = (os || dev.os_declared) === "Linux";
  modal(`Instalar o VIGIL Agent em “${esc(dev.name)}”`, `
    <div class="tokenbox"><span>🔑</span><code id="tok">${esc(token)}</code></div>
    <p class="muted" style="margin-top:-6px">Este token é individual e aparece <b>somente agora</b>. Válido para o 1º acesso até ${esc(dt(exp))}. Depois de conectado, ele é rotacionado automaticamente.</p>
    <ol class="steps">
      <li>Clique em <b>Copiar comando</b> (no quadro preto abaixo) e cole num PowerShell aberto <b>como Administrador</b> no computador que será monitorado — o comando já inclui o token.</li>
      <li>O instalador baixa o agente, grava o endereço <span class="mono">${esc(S.info.public_url)}</span> e o token, e cria o serviço.</li>
      <li>O agente se autentica e o computador aparece sozinho no dashboard.</li>
    </ol>
    <div class="tabs"><span class="chip ${isLin ? "" : "on"}" data-tab="win">Windows</span><span class="chip ${isLin ? "on" : ""}" data-tab="lin">Linux</span></div>
    <div class="code" data-pane="win" ${isLin ? "hidden" : ""}><button class="btn sm pri" data-copy="#cmd-win">Copiar comando</button><span id="cmd-win">${esc(c.win)}</span></div>
    <div class="code" data-pane="lin" ${isLin ? "" : "hidden"}><button class="btn sm pri" data-copy="#cmd-lin">Copiar comando</button><span id="cmd-lin">${esc(c.lin)}</span></div>
    <p class="sub" style="margin-top:12px">Sem acesso à rede do servidor durante a instalação? Baixe o pacote
      <a href="/download/vigil-agent-windows.zip">Windows (.zip)</a> ou <a href="/download/vigil-agent-linux.zip">Linux (.zip)</a>,
      copie para o computador e rode o instalador com os mesmos parâmetros.
      ${c.selfSigned ? `<br>Certificado do servidor (SHA-256): <span class="mono">${esc(S.info.fingerprint)}</span>` : ""}</p>
    <p class="sub"><b>Aguardando conexão:</b> <span id="wait-st">${stBadge("pending")}</span></p>`,
    `<a class="btn" href="#/device/${esc(dev.id)}" data-act="close">Abrir dispositivo</a><button class="btn pri" data-act="close">Concluir</button>`);
  const poll = setInterval(async () => {
    if (!$("#wait-st")) return clearInterval(poll);
    try {
      const d = await api("GET", `/api/devices/${dev.id}`);
      $("#wait-st").innerHTML = stBadge(d.status) + (d.status === "online" ? ` <b class="hl-ok">Conectado! ${esc(d.hostname || "")}</b>` : "");
      if (d.status === "online") clearInterval(poll);
    } catch (e) { clearInterval(poll); }
  }, 3000);
}

/* ------------------------------------------------------------------ detalhe */
async function viewDevice(id, first) {
  const [d, m] = await Promise.all([api("GET", `/api/devices/${id}`), api("GET", `/api/devices/${id}/metrics?range=${S.range}`)]);
  const s = d.last_sample || {}, info = d.info || {}, r = d.effective_rules;
  const admin = can("admin"), op = can("operator");
  const actions = `${op ? `<button class="btn" data-act="edit-device" data-id="${esc(d.id)}">Editar</button>` : ""}
    ${admin && d.status !== "revoked" && d.enrolled_at ? `<button class="btn" data-act="rotate" data-id="${esc(d.id)}">Rotacionar token</button>` : ""}
    ${admin ? `<button class="btn" data-act="reissue" data-id="${esc(d.id)}">Reemitir token</button>` : ""}
    ${admin && d.status !== "revoked" ? `<button class="btn danger" data-act="revoke" data-id="${esc(d.id)}">Revogar</button>` : ""}
    ${admin ? `<button class="btn danger" data-act="delete" data-id="${esc(d.id)}">Excluir</button>` : ""}`;
  const disks = (s.disks || []).map(x => `<tr><td class="mono">${esc(x.mount)}</td><td class="sub">${esc(x.fs)}</td><td>${mbar(x.pct, r.disk.warn, r.disk.crit)}</td><td class="sub">${bytes(x.used)} de ${bytes(x.total)}</td></tr>`).join("");
  const procs = (s.processes || []).map(p => `<tr><td>${esc(p.name)}</td><td class="mono sub">${esc(p.pid)}</td><td>${pct(p.cpu)}</td><td>${p.mem == null ? "—" : p.mem.toFixed(1) + "%"}</td><td class="sub">${p.mem_mb == null ? "—" : p.mem_mb + " MB"}</td></tr>`).join("");
  const ifs = (s.interfaces || []).map(i => `<tr><td>${esc(i.name)}</td><td class="mono sub">${esc((i.ips || []).join(", "))}</td><td class="sub">${bps(i.rx_bps)}</td><td class="sub">${bps(i.tx_bps)}</td></tr>`).join("");
  const temps = (s.temps || []).map(t => `<span class="chip">${esc(t.label)}: <b style="margin-left:4px">${esc(t.c)} °C</b></span>`).join(" ");
  $("#view").innerHTML = setTop(`${esc(d.name)} ${stBadge(d.status)}`, actions, `<a href="#/devices">Dispositivos</a> / ${esc(d.group_name || "")}`) + `
    ${d.status === "pending" || d.status === "expired" ? `<div class="card" style="margin-bottom:14px;border-color:rgba(167,139,250,.4)">
      <b>Aguardando o agente.</b> <span class="muted">${d.status === "expired" ? "O token de cadastro expirou — use “Reemitir token”." : "Instale o VIGIL Agent com o token gerado no cadastro. Perdeu o token? Use “Reemitir token”."}</span></div>` : ""}
    ${d.status === "revoked" ? `<div class="card" style="margin-bottom:14px;border-color:rgba(239,68,68,.4)"><b>Token revogado.</b> <span class="muted">Este computador não consegue mais enviar dados. “Reemitir token” gera um novo para reinstalação.</span></div>` : ""}
    <div class="grid kpis">
      <div class="card kpi"><div class="l">CPU</div><div class="v">${pct(d.cpu)}</div><div class="s">${esc(info.cpu_threads || "?")} núcleos lógicos</div></div>
      <div class="card kpi"><div class="l">RAM</div><div class="v">${pct(d.ram)}</div><div class="s">${bytes(s.ram_used)} de ${bytes(s.ram_total)}</div></div>
      <div class="card kpi"><div class="l">Disco (maior uso)</div><div class="v">${pct(d.disk)}</div><div class="s">${(s.disks || []).length} volume(s)</div></div>
      <div class="card kpi"><div class="l">Rede ↓ / ↑</div><div class="v" style="font-size:18px;margin-top:8px">${bps(d.net_rx)}<br>${bps(d.net_tx)}</div></div>
      <div class="card kpi"><div class="l">Temperatura</div><div class="v">${d.temp == null ? "—" : Math.round(d.temp) + "°"}</div><div class="s">${d.temp == null ? "não suportada pelo hardware" : "maior sensor"}</div></div>
      <div class="card kpi"><div class="l">Ligado há</div><div class="v" style="font-size:22px;margin-top:6px">${dur(d.uptime)}</div><div class="s">${s.proc_count ? s.proc_count + " processos" : ""}</div></div>
    </div>
    <div class="card" style="margin-bottom:14px"><div class="row"><h3 style="margin:0;flex:1">Histórico</h3>
      ${["1h", "6h", "24h", "7d"].map(x => `<span class="chip ${S.range === x ? "on" : ""}" data-range="${x}">${x}</span>`).join("")}</div>
      <div class="grid cols2" style="margin-top:10px">
        <div><canvas class="chart" id="ch-res"></canvas><div class="legend"><span><i style="background:#38bdf8"></i>CPU</span><span><i style="background:#a78bfa"></i>RAM</span><span><i style="background:#f59e0b"></i>Disco</span>${m.points.some(p => p.temp != null) ? `<span><i style="background:#ef4444"></i>Temp °C</span>` : ""}</div></div>
        <div><canvas class="chart" id="ch-net"></canvas><div class="legend"><span><i style="background:#22c55e"></i>Download</span><span><i style="background:#f472b6"></i>Upload</span></div></div>
      </div></div>
    <div class="grid cols2" style="margin-bottom:14px">
      <div class="card"><h3>Identificação</h3><dl class="kv">
        <dt>Computador</dt><dd>${esc(d.hostname || "—")}</dd>
        <dt>Sistema</dt><dd>${osName(d)} ${esc(info.os?.arch || "")}</dd>
        <dt>IP local</dt><dd class="mono">${esc(d.ip_local || d.ip_declared || "—")}</dd>
        <dt>IP de origem</dt><dd class="mono">${esc(d.ip_remote || "—")} <span class="sub">(visto pelo servidor)</span></dd>
        <dt>Outros IPs</dt><dd class="mono sub">${esc((info.ips || []).join(", ") || "—")}</dd>
        <dt>Processador</dt><dd>${esc(info.cpu_model || "—")}</dd>
        <dt>Grupo</dt><dd>${esc(d.group_name || "—")}</dd>
        <dt>Localização</dt><dd>${esc(d.location || "—")}</dd>
        <dt>Descrição</dt><dd>${esc(d.description || "—")}</dd>
        <dt>Agente</dt><dd>${esc(d.agent_version ? "v" + d.agent_version : "—")} · envio a cada ${esc(d.interval)} s</dd>
        <dt>Última comunicação</dt><dd>${esc(dt(d.last_seen))} (${ago(d.last_seen)})</dd>
        <dt>Token</dt><dd>${d.token_created_at ? "emitido " + esc(dt(d.token_created_at)) : "—"}${d.token_rotation_pending ? ' · <span class="hl-attention">rotação pendente</span>' : ""}</dd>
      </dl></div>
      <div class="card"><h3>Alertas deste computador</h3>${d.alerts.length ? `<ul class="list">${d.alerts.map(a => `<li><span class="sev sev-${esc(a.severity)}">${a.severity === "critical" ? "Crítico" : "Atenção"}</span>
        <div class="grow"><div>${esc(a.message)}</div><div class="sub">${a.closed_at ? "Resolvido " + ago(a.closed_at) : "Aberto " + ago(a.opened_at)}${a.acked_by ? " · ciente: " + esc(a.acked_by) : ""}</div></div>
        ${!a.closed_at && !a.acked_by && op ? `<button class="btn sm" data-act="ack" data-id="${a.id}">Ciente</button>` : ""}</li>`).join("")}</ul>` : `<div class="empty">Nenhum alerta</div>`}
        <h3 style="margin-top:16px">Limites de alerta</h3><div class="sub">CPU ${r.cpu.warn}% / ${r.cpu.crit}% · RAM ${r.ram.warn}% / ${r.ram.crit}% · Disco ${r.disk.warn}% / ${r.disk.crit}% · Temp ${r.temp.warn} / ${r.temp.crit} °C
        ${admin ? ` · <a href="#" data-act="rules" data-id="${esc(d.id)}">personalizar para este computador</a>` : ""}</div></div>
    </div>
    <div class="grid cols2" style="margin-bottom:14px">
      <div class="card tbl-wrap"><h3>Armazenamento</h3>${disks ? `<table><tbody>${disks}</tbody></table>` : `<div class="empty">Sem dados</div>`}</div>
      <div class="card tbl-wrap"><h3>Rede</h3>${ifs ? `<table><thead><tr><th>Interface</th><th>IPs</th><th>↓</th><th>↑</th></tr></thead><tbody>${ifs}</tbody></table>` : `<div class="empty">Sem dados</div>`}
        ${temps ? `<h3 style="margin-top:14px">Sensores de temperatura</h3><div class="row">${temps}</div>` : ""}</div>
    </div>
    <div class="grid cols2">
      <div class="card tbl-wrap"><h3>Processos em execução (maior consumo)</h3>${procs ? `<table><thead><tr><th>Processo</th><th>PID</th><th>CPU</th><th>RAM</th><th>Memória</th></tr></thead><tbody>${procs}</tbody></table>` : `<div class="empty">Sem dados</div>`}</div>
      <div class="card"><h3>Registro de conexões</h3>${d.events.length ? `<ul class="list">${d.events.map(e => `<li><div class="grow">${esc(EVK[e.kind] || e.kind)}<div class="sub">${esc(e.detail || "")} ${e.ip ? "· " + esc(e.ip) : ""}</div></div><span class="dim" title="${esc(dt(e.ts))}">${ago(e.ts)}</span></li>`).join("")}</ul>` : `<div class="empty">Sem eventos</div>`}</div>
    </div>`;
  const pts = m.points;
  drawChart($("#ch-res"), pts, [{ k: "cpu", c: "#38bdf8" }, { k: "ram", c: "#a78bfa" }, { k: "disk", c: "#f59e0b" }, { k: "temp", c: "#ef4444" }], { max: 100, fmt: v => v + "%" });
  drawChart($("#ch-net"), pts, [{ k: "net_rx", c: "#22c55e" }, { k: "net_tx", c: "#f472b6" }], { fmt: bps });
  S.currentDevice = d;
}

function drawChart(cv, pts, series, opt) {
  const dpr = window.devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight;
  cv.width = W * dpr; cv.height = H * dpr;
  const g = cv.getContext("2d"); g.scale(dpr, dpr);
  const L = 58, R = 8, T = 8, B = 22, w = W - L - R, h = H - T - B;
  g.font = "11px Segoe UI, sans-serif"; g.fillStyle = "#6d82ab"; g.strokeStyle = "rgba(120,160,230,.12)";
  if (!pts.length) { g.fillText("Sem dados no período", L + w / 2 - 50, T + h / 2); return; }
  let max = opt.max || Math.max(1, ...pts.flatMap(p => series.map(s => p[s.k] || 0))) * 1.15;
  const t0 = pts[0].t, t1 = Math.max(pts[pts.length - 1].t, t0 + 1);
  for (let i = 0; i <= 4; i++) {
    const y = T + h - h * i / 4;
    g.beginPath(); g.moveTo(L, y); g.lineTo(L + w, y); g.stroke();
    g.fillText(opt.fmt(Math.round(max * i / 4)), 4, y + 4);
  }
  [0, .5, 1].forEach(f => {
    const ts = t0 + (t1 - t0) * f, x = L + w * f;
    const lab = new Date(ts * 1000).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
    g.fillText(lab, Math.min(x - 14, W - 34), H - 6);
  });
  series.forEach(s => {
    g.strokeStyle = s.c; g.lineWidth = 1.8; g.beginPath();
    let started = false, prevT = null;
    pts.forEach(p => {
      const v = p[s.k];
      if (v == null) { started = false; return; }
      const x = L + w * (p.t - t0) / (t1 - t0), y = T + h - h * Math.min(v, max) / max;
      const gap = prevT != null && p.t - prevT > (pts.length > 1 ? (t1 - t0) / pts.length * 4 : 1e9);
      if (!started || gap) { g.moveTo(x, y); started = true; } else g.lineTo(x, y);
      prevT = p.t;
    });
    g.stroke();
  });
}

function editDeviceModal(d) {
  modal(`Editar “${esc(d.name)}”`, `<form id="ed-form"><div class="grid cols2" style="gap:0 14px">
    <label class="f"><span>Nome</span><input name="name" value="${esc(d.name)}" required maxlength="80"></label>
    <label class="f"><span>Sistema operacional (declarado)</span><select name="os">${["Windows", "Linux", "Outro"].map(o => `<option ${d.os_declared === o ? "selected" : ""}>${o}</option>`).join("")}</select></label>
    <label class="f"><span>Endereço IP (declarado)</span><input name="ip" value="${esc(d.ip_declared || "")}"></label>
    <label class="f"><span>Grupo</span><select name="group_id">${groupOptions(d.group_id)}</select></label>
    <label class="f"><span>Localização</span><input name="location" value="${esc(d.location || "")}" maxlength="80"></label>
    <label class="f"><span>Intervalo de envio (s)</span><input name="interval" type="number" min="10" max="3600" value="${esc(d.interval || 30)}"></label></div>
    <label class="f"><span>Descrição</span><textarea name="description" rows="2" maxlength="500">${esc(d.description || "")}</textarea></label>
    <div class="err" id="ed-err"></div></form>`,
    `<button class="btn" data-act="close">Cancelar</button><button class="btn pri" id="ed-go">Salvar</button>`);
  $("#ed-go").addEventListener("click", async () => {
    const fd = Object.fromEntries(new FormData($("#ed-form")));
    fd.interval = Number(fd.interval);
    try { await api("PATCH", `/api/devices/${d.id}`, fd); closeModal(); toast("Dispositivo atualizado"); S.groups = await api("GET", "/api/groups"); route(); }
    catch (e) { $("#ed-err").textContent = e.message; }
  });
}

function rulesForm(r, prefix, overrides) {
  const line = (k, label, unit) => `<tr><td>${label}</td>
    <td><input type="checkbox" name="${prefix}${k}.enabled" ${r[k].enabled ? "checked" : ""}></td>
    <td><input type="number" name="${prefix}${k}.warn" value="${r[k].warn}" style="width:80px"> ${unit}</td>
    <td><input type="number" name="${prefix}${k}.crit" value="${r[k].crit}" style="width:80px"> ${unit}</td>
    <td>${k === "cpu" ? `<input type="number" name="${prefix}cpu.sustain" value="${r.cpu.sustain}" min="1" max="20" style="width:64px"> leituras` : ""}</td></tr>`;
  return `<table><thead><tr><th>Métrica</th><th>Ativo</th><th>Atenção ≥</th><th>Crítico ≥</th><th>Persistência</th></tr></thead><tbody>
    ${line("cpu", "CPU", "%")}${line("ram", "Memória RAM", "%")}${line("disk", "Disco", "%")}${line("temp", "Temperatura", "°C")}
    <tr><td>Computador offline</td><td><input type="checkbox" name="${prefix}offline.enabled" ${r.offline.enabled ? "checked" : ""}></td><td colspan="3" class="sub">Sem comunicação por mais de 3 intervalos</td></tr>
    <tr><td>Agente sem métricas</td><td><input type="checkbox" name="${prefix}metrics_stale.enabled" ${r.metrics_stale.enabled ? "checked" : ""}></td><td colspan="3" class="sub">Responde, mas parou de enviar métricas</td></tr>
    </tbody></table>`;
}
function readRules(root, prefix) {
  const out = {};
  $$("input", root).forEach(i => {
    if (!i.name.startsWith(prefix)) return;
    const [k, f] = i.name.slice(prefix.length).split(".");
    out[k] = out[k] || {};
    out[k][f] = i.type === "checkbox" ? i.checked : Number(i.value);
  });
  return out;
}
function rulesModal(d) {
  modal(`Limites de alerta · ${esc(d.name)}`, `<p class="muted">Valores próprios deste computador (substituem o padrão da organização).</p>
    <div class="tbl-wrap" id="rl">${rulesForm(d.effective_rules, "r_")}</div><div class="err" id="rl-err"></div>`,
    `<button class="btn" id="rl-reset">Voltar ao padrão</button><button class="btn" data-act="close">Cancelar</button><button class="btn pri" id="rl-go">Salvar</button>`);
  $("#rl-go").addEventListener("click", async () => {
    try { await api("PATCH", `/api/devices/${d.id}`, { rules: readRules($("#rl"), "r_") }); closeModal(); toast("Limites salvos"); route(); }
    catch (e) { $("#rl-err").textContent = e.message; }
  });
  $("#rl-reset").addEventListener("click", async () => { await api("PATCH", `/api/devices/${d.id}`, { rules: {} }); closeModal(); toast("Usando limites padrão"); route(); });
}

/* ------------------------------------------------------------------ infraestrutura */
async function viewInfra() {
  const devs = await api("GET", "/api/devices");
  const by = {};
  devs.forEach(d => (by[d.group_name || "Sem grupo"] = by[d.group_name || "Sem grupo"] || []).push(d));
  const sev = d => d.status === "online" ? ({ critical: 0, attention: 1 }[d.health] ?? 2) : d.status === "offline" ? 3 : 4;
  $("#view").innerHTML = setTop("Infraestrutura", `<span class="muted">${devs.filter(d => d.status === "online").length} de ${devs.length} online</span>`) +
    (devs.length ? Object.keys(by).sort().map(g => `<div class="gtitle">${esc(g)} · ${by[g].length}</div><div class="tiles">${by[g].sort((a, b) => sev(a) - sev(b)).map(tile).join("")}</div>`).join("")
      : `<div class="card">${emptyDevices()}</div>`);
}

/* ------------------------------------------------------------------ grupos */
async function viewGroups() {
  S.groups = await api("GET", "/api/groups");
  const op = can("operator");
  $("#view").innerHTML = setTop("Grupos de dispositivos", op ? `<button class="btn pri" data-act="add-group">+ Novo grupo</button>` : "") + `
    <div class="card tbl-wrap"><table><thead><tr><th>Grupo</th><th>Dispositivos</th><th>Tipo</th><th></th></tr></thead><tbody>
    ${S.groups.map(g => `<tr><td class="name"><a href="#/devices" data-gfilter="${g.id}">${esc(g.name)}</a></td><td>${g.devices}</td><td class="sub">${g.builtin ? "Padrão" : "Personalizado"}</td>
      <td class="right">${op && g.name !== "Outros" ? `<button class="btn sm" data-act="rename-group" data-id="${g.id}" data-name="${esc(g.name)}">Renomear</button>
      <button class="btn sm danger" data-act="del-group" data-id="${g.id}" data-name="${esc(g.name)}">Excluir</button>` : ""}</td></tr>`).join("")}
    </tbody></table><p class="sub">Para mover computadores entre grupos, selecione-os na lista de <a href="#/devices">Dispositivos</a> ou edite o dispositivo. Ao excluir um grupo, seus computadores vão para “Outros”.</p></div>`;
}

/* ------------------------------------------------------------------ alertas / eventos */
async function viewAlerts() {
  const list = await api("GET", `/api/alerts?state=${S.alertState}`);
  if (S.alertState === "open") navBadge(list.length);
  $("#view").innerHTML = setTop("Alertas", `<span class="chip ${S.alertState === "open" ? "on" : ""}" data-astate="open">Ativos</span><span class="chip ${S.alertState === "all" ? "on" : ""}" data-astate="all">Histórico</span>`) + `
    <div class="card tbl-wrap">${list.length ? `<table><thead><tr><th>Severidade</th><th>Computador</th><th>Alerta</th><th>Início</th><th>Situação</th><th></th></tr></thead><tbody>
    ${list.map(a => `<tr><td><span class="sev sev-${esc(a.severity)}">${a.severity === "critical" ? "Crítico" : "Atenção"}</span></td>
      <td><a class="name" href="#/device/${esc(a.device_id)}">${esc(a.device_name || "—")}</a><div class="sub">${esc(a.group_name || "")}${a.location ? " · " + esc(a.location) : ""}</div></td>
      <td>${esc(a.message)}</td><td class="sub" title="${esc(dt(a.opened_at))}">${ago(a.opened_at)}</td>
      <td class="sub">${a.closed_at ? "Resolvido " + ago(a.closed_at) : a.acked_by ? "Ciente: " + esc(a.acked_by) : '<span class="hl-attention">Aguardando</span>'}</td>
      <td class="right">${!a.closed_at && !a.acked_by && can("operator") ? `<button class="btn sm" data-act="ack" data-id="${a.id}">Ciente</button>` : ""}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty">${S.alertState === "open" ? "Nenhum alerta ativo ✓" : "Sem histórico"}</div>`}</div>`;
}
async function viewEvents() {
  const list = await api("GET", `/api/events?limit=400${S.evKind ? "&kind=" + S.evKind : ""}`);
  $("#view").innerHTML = setTop("Registro de conexões", `<select id="ev-kind"><option value="">Todos os eventos</option>${Object.entries(EVK).map(([k, l]) => `<option value="${k}" ${S.evKind === k ? "selected" : ""}>${l}</option>`).join("")}</select>`) + `
    <div class="card tbl-wrap">${list.length ? `<table><thead><tr><th>Data/hora</th><th>Evento</th><th>Computador</th><th>IP de origem</th><th>Detalhe</th></tr></thead><tbody>
    ${list.map(e => `<tr><td class="sub">${esc(dt(e.ts))}</td><td><span class="${e.kind.includes("fail") || e.kind === "token_revoked" ? "hl-critical" : e.kind === "disconnect" ? "dim" : ""}">${esc(EVK[e.kind] || e.kind)}</span></td>
      <td>${e.device_id ? `<a href="#/device/${esc(e.device_id)}">${esc(e.device_name || "")}</a>` : esc(e.device_name || "—")}</td><td class="mono sub">${esc(e.ip || "")}</td><td class="sub">${esc(e.detail || "")}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty">Sem eventos</div>`}</div>`;
  $("#ev-kind").addEventListener("change", e => { S.evKind = e.target.value; viewEvents(); });
}

/* ------------------------------------------------------------------ configuracoes */
async function viewSettings() {
  const [st, info] = await Promise.all([api("GET", "/api/settings"), api("GET", "/api/server-info")]);
  S.info = info;
  const admin = can("admin");
  const users = admin ? await api("GET", "/api/users") : [];
  $("#view").innerHTML = setTop("Configurações") + `
    <div class="grid cols2" style="margin-bottom:14px">
      <div class="card"><h3>Servidor central</h3><dl class="kv">
        <dt>Endereço p/ agentes</dt><dd class="mono">${esc(info.public_url)}</dd>
        <dt>IPs deste servidor</dt><dd class="mono">${esc(info.local_ips.join(", "))} · porta ${esc(info.port)}</dd>
        <dt>TLS</dt><dd>${info.tls ? "Ativo (HTTPS)" : '<span class="hl-critical">Desativado</span>'}</dd>
        <dt>Certificado SHA-256</dt><dd class="mono sub">${esc(info.fingerprint || "—")}</dd>
        <dt>Rotação automática</dt><dd>a cada ${esc(st.token_rotation_days)} dias</dd>
        <dt>Retenção de métricas</dt><dd>${esc(st.retention_days)} dias</dd></dl>
        ${admin ? `<label class="f" style="margin-top:14px"><span>Endereço público (para agentes em outras redes). Ex.: https://vigil.suaempresa.com.br ou https://IP-PUBLICO:8443</span>
        <div class="row"><input id="pub-url" value="${esc(st.public_url)}" placeholder="${esc(info.public_url)}" style="flex:1"><button class="btn" data-act="save-url">Salvar</button></div></label>` : ""}</div>
      <div class="card"><h3>Minha conta</h3><form id="pw-form">
        <label class="f"><span>Senha atual</span><input type="password" name="current" required></label>
        <label class="f"><span>Nova senha (mín. 10)</span><input type="password" name="password" required minlength="10"></label>
        <button class="btn">Alterar senha</button><span class="err" id="pw-err"></span></form></div>
    </div>
    <div class="card tbl-wrap" style="margin-bottom:14px"><h3>Limites padrão de alerta (todos os computadores)</h3><div id="org-rules">${rulesForm(st.rules, "o_")}</div>
      ${admin ? `<div class="row" style="margin-top:10px"><button class="btn pri" data-act="save-rules">Salvar limites</button><span class="err" id="rules-err"></span></div>` : ""}</div>
    ${admin ? `<div class="card tbl-wrap"><div class="row"><h3 style="flex:1;margin:0">Usuários do painel</h3><button class="btn sm" data-act="add-user">+ Usuário</button></div>
      <table style="margin-top:10px"><thead><tr><th>Usuário</th><th>Perfil</th><th>Último acesso</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td class="name">${esc(u.username)}</td><td>${esc({ admin: "Administrador", operator: "Operador", viewer: "Somente leitura" }[u.role])}</td><td class="sub">${esc(dt(u.last_login))}</td>
      <td class="right">${u.username !== S.me.username ? `<button class="btn sm danger" data-act="del-user" data-id="${u.id}" data-name="${esc(u.username)}">Excluir</button>` : ""}</td></tr>`).join("")}</tbody></table>
      <p class="sub">Administrador: tudo, inclusive tokens e usuários · Operador: grupos, edição e alertas · Leitura: apenas visualiza.</p></div>` : ""}`;
  $("#pw-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    try { await api("POST", "/api/me/password", Object.fromEntries(new FormData(ev.target))); ev.target.reset(); toast("Senha alterada"); }
    catch (e) { $("#pw-err").textContent = e.message; }
  });
}

/* ------------------------------------------------------------------ modal */
function modal(title, body, foot) {
  $("#modal-root").innerHTML = `<div class="modal-bg"><div class="modal" role="dialog"><header><h2>${title}</h2><button class="x" data-act="close">×</button></header>
    <div class="body">${body}</div>${foot ? `<footer>${foot}</footer>` : ""}</div></div>`;
  $(".modal input:not([type=checkbox]), .modal select")?.focus();
}
function closeModal() { $("#modal-root").innerHTML = ""; }
function prompt2(title, label, value, cb) {
  modal(title, `<label class="f"><span>${label}</span><input id="p2" value="${esc(value || "")}" maxlength="60"></label><div class="err" id="p2-err"></div>`,
    `<button class="btn" data-act="close">Cancelar</button><button class="btn pri" id="p2-go">Salvar</button>`);
  const go = async () => { try { await cb($("#p2").value.trim()); closeModal(); } catch (e) { $("#p2-err").textContent = e.message; } };
  $("#p2-go").addEventListener("click", go);
  $("#p2").addEventListener("keydown", e => e.key === "Enter" && go());
}
function confirm2(title, text, okLabel, cb) {
  modal(title, `<p>${text}</p><div class="err" id="c2-err"></div>`, `<button class="btn" data-act="close">Cancelar</button><button class="btn danger" id="c2-go">${okLabel}</button>`);
  $("#c2-go").addEventListener("click", async () => { try { await cb(); closeModal(); } catch (e) { $("#c2-err").textContent = e.message; } });
}

/* ------------------------------------------------------------------ eventos globais */
document.addEventListener("click", async ev => {
  const t = ev.target;
  const copy = t.closest("[data-copy]");
  if (copy) {
    const txt = $(copy.dataset.copy).textContent;
    try { await navigator.clipboard.writeText(txt); } catch (e) {
      const ta = document.createElement("textarea"); ta.value = txt; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
    }
    return toast("Copiado");
  }
  if (t.matches("[data-sel]")) {
    ev.stopPropagation();
    t.checked ? S.selected.add(t.dataset.sel) : S.selected.delete(t.dataset.sel);
    const b = $("#bulk"); if (b) { b.hidden = !S.selected.size; b.querySelector(".muted").textContent = `${S.selected.size} selecionado(s) →`; }
    return;
  }
  if (t.closest("input,select,a[href^='/download']")) return;
  const open = t.closest("[data-open]");
  if (open && !t.closest("[data-act]")) { location.hash = `#/device/${open.dataset.open}`; return; }
  const fs = t.closest("[data-fstatus]"); if (fs) { S.f.status = fs.dataset.fstatus; return viewDevices(); }
  const rg = t.closest("[data-range]"); if (rg) { S.range = rg.dataset.range; return route(); }
  const as = t.closest("[data-astate]"); if (as) { S.alertState = as.dataset.astate; return viewAlerts(); }
  const gf = t.closest("[data-gfilter]"); if (gf) { S.f = { status: "", os: "", group: gf.dataset.gfilter, location: "", q: "" }; return; }
  const tab = t.closest("[data-tab]");
  if (tab) { $$("[data-tab]").forEach(x => x.classList.toggle("on", x === tab)); $$("[data-pane]").forEach(p => p.hidden = p.dataset.pane !== tab.dataset.tab); return; }
  const a = t.closest("[data-act]"); if (!a) return;
  const act = a.dataset.act, id = a.dataset.id;
  if (a.tagName === "A" && act !== "close") ev.preventDefault();
  try {
    switch (act) {
      case "close": closeModal(); break;
      case "logout": await api("POST", "/api/logout", {}); location.reload(); break;
      case "add-device": addDeviceModal(); break;
      case "edit-device": editDeviceModal(S.currentDevice); break;
      case "rules": rulesModal(S.currentDevice); break;
      case "rotate":
        confirm2("Rotacionar token", "O agente receberá um token novo automaticamente na próxima comunicação, sem reinstalação. O token atual deixa de valer assim que o novo for adotado.", "Rotacionar",
          async () => { await api("POST", `/api/devices/${id}/rotate`, {}); toast("Rotação solicitada"); route(); });
        break;
      case "revoke":
        confirm2("Revogar acesso", "O token deste computador será invalidado imediatamente e ele não poderá mais enviar dados. Para voltar, será preciso reemitir o token e reinstalar/reconfigurar o agente.", "Revogar",
          async () => { await api("POST", `/api/devices/${id}/revoke`, {}); toast("Token revogado"); route(); });
        break;
      case "reissue":
        confirm2("Reemitir token", "Um token novo de cadastro será gerado e o anterior deixa de funcionar. Use para reinstalar o agente ou reativar um computador revogado.", "Reemitir",
          async () => { const r = await api("POST", `/api/devices/${id}/reissue`, {}); const d = S.currentDevice; setTimeout(() => installModal(d, r.token, r.token_expires_at), 50); route(); });
        break;
      case "delete":
        confirm2("Excluir dispositivo", "O dispositivo, seu histórico de métricas e alertas serão apagados. O agente instalado deixará de ser aceito.", "Excluir",
          async () => { await api("DELETE", `/api/devices/${id}`); toast("Dispositivo excluído"); location.hash = "#/devices"; });
        break;
      case "ack": await api("POST", `/api/alerts/${id}/ack`, {}); toast("Alerta marcado como ciente"); route(); break;
      case "bulk-move": {
        const r = await api("POST", "/api/devices/move", { device_ids: [...S.selected], group_id: $("#bulk-group").value });
        S.selected.clear(); S.groups = await api("GET", "/api/groups"); toast(`${r.moved} dispositivo(s) movido(s)`); viewDevices(); break;
      }
      case "bulk-clear": S.selected.clear(); viewDevices(); break;
      case "add-group": prompt2("Novo grupo", "Nome do grupo", "", async n => { await api("POST", "/api/groups", { name: n }); toast("Grupo criado"); viewGroups(); }); break;
      case "rename-group": prompt2("Renomear grupo", "Nome do grupo", a.dataset.name, async n => { await api("PATCH", `/api/groups/${id}`, { name: n }); viewGroups(); }); break;
      case "del-group": confirm2("Excluir grupo", `Excluir o grupo “${esc(a.dataset.name)}”? Os computadores dele irão para “Outros”.`, "Excluir", async () => { await api("DELETE", `/api/groups/${id}`); viewGroups(); }); break;
      case "save-url": await api("PUT", "/api/settings", { public_url: $("#pub-url").value }); S.info = await api("GET", "/api/server-info"); toast("Endereço salvo"); viewSettings(); break;
      case "save-rules":
        try { await api("PUT", "/api/settings", { rules: readRules($("#org-rules"), "o_") }); toast("Limites salvos"); }
        catch (e) { $("#rules-err").textContent = e.message; }
        break;
      case "add-user":
        modal("Novo usuário", `<form id="u-form"><label class="f"><span>Usuário</span><input name="username" required></label>
          <label class="f"><span>Senha (mín. 10)</span><input name="password" type="password" required minlength="10"></label>
          <label class="f"><span>Perfil</span><select name="role"><option value="viewer">Somente leitura</option><option value="operator">Operador</option><option value="admin">Administrador</option></select></label>
          <div class="err" id="u-err"></div></form>`, `<button class="btn" data-act="close">Cancelar</button><button class="btn pri" id="u-go">Criar</button>`);
        $("#u-go").addEventListener("click", async () => {
          try { await api("POST", "/api/users", Object.fromEntries(new FormData($("#u-form")))); closeModal(); toast("Usuário criado"); viewSettings(); }
          catch (e) { $("#u-err").textContent = e.message; }
        });
        break;
      case "del-user": confirm2("Excluir usuário", `Excluir o usuário “${esc(a.dataset.name)}”?`, "Excluir", async () => { await api("DELETE", `/api/users/${id}`); viewSettings(); }); break;
    }
  } catch (e) { toast(e.message, true); }
});
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

boot();
