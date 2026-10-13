"use strict";

const state = {
  csrf: "",
  dashboard: null,
  selectedService: null,
  wireguardService: null,
  wireguard: null,
  wireguardPrevious: null,
  view: "dashboard",
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function encodePart(value) {
  return encodeURIComponent(String(value));
}

function toast(message, error = false) {
  const item = document.createElement("div");
  item.className = `toast${error ? " error" : ""}`;
  item.textContent = message;
  $("#toast-stack").append(item);
  window.setTimeout(() => item.remove(), 5000);
}

async function api(path, options = {}) {
  const request = { credentials: "same-origin", ...options };
  request.headers = { Accept: "application/json", ...(options.headers || {}) };
  if (request.body && typeof request.body !== "string") {
    request.headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(request.body);
  }
  if ((request.method || "GET").toUpperCase() !== "GET") {
    request.headers["X-NControl-CSRF"] = state.csrf;
  }
  const response = await fetch(path, request);
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("登录已失效");
  }
  const data = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
  if (!response.ok) throw new Error(data.error || `请求失败（HTTP ${response.status}）`);
  return data;
}

function stateLabel(value) {
  return { healthy: "正常", starting: "启动中", unhealthy: "异常", stopped: "已停止" }[value] || "未知";
}

function formatBytes(value) {
  let amount = Number(value || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

function formatRate(value) {
  return `${formatBytes(Math.max(0, value || 0))}/s`;
}

function calculateWireGuardRates(previous, current) {
  const elapsed = Math.max(0.001, Number(current.sampledAt || 0) - Number(previous?.sampledAt || 0));
  const previousInterfaces = new Map((previous?.interfaces || []).map((item) => [item.name, item.runtime || {}]));
  const previousConnections = new Map((previous?.connections || []).map((item) => [item.name, item.runtime || {}]));
  current.interfaces.forEach((item) => {
    const old = previousInterfaces.get(item.name) || {};
    item.rate = {
      received: previous ? Math.max(0, Number(item.runtime?.receivedBytes || 0) - Number(old.receivedBytes || 0)) / elapsed : 0,
      sent: previous ? Math.max(0, Number(item.runtime?.sentBytes || 0) - Number(old.sentBytes || 0)) / elapsed : 0,
    };
  });
  current.connections.forEach((item) => {
    const old = previousConnections.get(item.name) || {};
    item.rate = {
      forward: previous ? Math.max(0, Number(item.runtime?.forwardBytes || 0) - Number(old.forwardBytes || 0)) / elapsed : 0,
      returned: previous ? Math.max(0, Number(item.runtime?.returnBytes || 0) - Number(old.returnBytes || 0)) / elapsed : 0,
    };
  });
}

function handshake(value) {
  const timestamp = Number(value || 0);
  if (!timestamp) return "尚未握手";
  const age = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
  if (age < 60) return `${age} 秒前`;
  if (age < 3600) return `${Math.floor(age / 60)} 分钟前`;
  if (age < 86400) return `${Math.floor(age / 3600)} 小时前`;
  return `${Math.floor(age / 86400)} 天前`;
}

function showView(name) {
  state.view = name;
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `${name}-view`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  const labels = {
    dashboard: ["SERVICES", "服务控制台"],
    wireguard: ["PRIVATE NETWORK", "WireGuard 管理"],
    system: ["SYSTEM", "系统管理"],
  };
  [$("#view-eyebrow").textContent, $("#view-title").textContent] = labels[name];
  if (name === "wireguard") refreshWireGuard();
}

function summaryCard(label, value) {
  return `<div class="summary-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function renderDashboard() {
  const services = state.dashboard?.services || [];
  const totals = { healthy: 0, starting: 0, unhealthy: 0, stopped: 0 };
  services.forEach((service) => { totals[service.health?.state] = (totals[service.health?.state] || 0) + 1; });
  $("#summary-grid").innerHTML = [
    summaryCard("服务总数", services.length),
    summaryCard("正常运行", totals.healthy),
    summaryCard("异常 / 启动中", totals.unhealthy + totals.starting),
    summaryCard("已停止", totals.stopped),
  ].join("");
  $("#service-count").textContent = services.length;
  $("#service-list").innerHTML = services.map((service) => {
    const status = service.health?.state || "unhealthy";
    return `<button class="service-item${state.selectedService === service.name ? " active" : ""}" data-service="${escapeHtml(service.name)}">
      <span class="status-dot ${escapeHtml(status)}"></span><span><strong>${escapeHtml(service.name)}</strong><small>${escapeHtml(service.health?.summary || service.description)}</small></span><span class="mini-driver">${escapeHtml(service.driver)}</span>
    </button>`;
  }).join("") || `<div class="empty-state"><p>还没有服务定义。</p></div>`;
  $$("[data-service]", $("#service-list")).forEach((button) => button.addEventListener("click", () => selectService(button.dataset.service)));
  const wireguardServices = services.filter((service) => service.wireguard);
  const select = $("#wireguard-service");
  const previous = state.wireguardService;
  select.innerHTML = wireguardServices.map((service) => `<option value="${escapeHtml(service.name)}">${escapeHtml(service.name)}</option>`).join("");
  state.wireguardService = wireguardServices.some((item) => item.name === previous) ? previous : wireguardServices[0]?.name || null;
  if (state.wireguardService) select.value = state.wireguardService;
  if (state.selectedService && !services.some((service) => service.name === state.selectedService)) state.selectedService = null;
  if (!state.selectedService && services.length) state.selectedService = services[0].name;
  renderServiceDetail();
}

function selectedService() {
  return state.dashboard?.services?.find((item) => item.name === state.selectedService) || null;
}

function actionButton(label, action, css = "small-button") {
  return `<button class="${css}" data-service-action="${escapeHtml(action)}">${escapeHtml(label)}</button>`;
}

function renderServiceDetail() {
  const service = selectedService();
  $("#service-empty").hidden = Boolean(service);
  $("#service-detail").hidden = !service;
  $("#log-clear").disabled = !service;
  $("#log-refresh").disabled = !service;
  if (!service) return;
  const health = service.health || {};
  $("#detail-name").textContent = service.name;
  $("#detail-description").textContent = service.description || "暂无说明";
  $("#detail-driver").textContent = service.driver;
  $("#detail-state").textContent = `${stateLabel(health.state)} · ${health.summary || ""}`;
  $("#detail-dot").className = `status-dot ${health.state || "unhealthy"}`;
  $("#detail-meta").innerHTML = `
    <div class="meta-item"><span>开机启动</span><strong>${service.autostart ? "已启用" : "未启用"}</strong></div>
    <div class="meta-item"><span>驱动</span><strong>${escapeHtml(service.driver)}</strong></div>
    <div class="meta-item"><span>工作目录</span><strong>${escapeHtml(service.workingDirectory)}</strong></div>
    <div class="meta-item"><span>定义文件</span><strong>${escapeHtml(service.definitionFile)}</strong></div>`;
  $("#health-list").innerHTML = (health.checks || []).map((item) => `
    <div class="health-item${item.ok ? "" : " error"}"><b>${item.ok ? "✓" : "×"}</b><span><strong>${escapeHtml(item.name)}</strong><br>${escapeHtml(item.detail)}</span></div>`).join("") || `<div class="health-item"><b>•</b><span>${escapeHtml(health.summary || "暂无健康检查")}</span></div>`;
  const running = ["healthy", "starting", "unhealthy"].includes(health.state);
  $("#service-actions").innerHTML = [
    !running ? actionButton("启动", "start", "button primary") : "",
    running ? actionButton("停止", "stop", "small-button danger-ghost") : "",
    running ? actionButton("重启", "restart") : "",
    actionButton(service.autostart ? "关闭开机启动" : "启用开机启动", "set-autostart"),
    actionButton("配置检查", "config-check"),
    service.wireguard ? `<button class="small-button" data-open-wireguard>管理 WireGuard</button>` : "",
  ].join("");
  $$("[data-service-action]", $("#service-actions")).forEach((button) => button.addEventListener("click", () => runServiceAction(button.dataset.serviceAction)));
  $("[data-open-wireguard]", $("#service-actions"))?.addEventListener("click", () => {
    state.wireguardService = service.name;
    showView("wireguard");
  });
  $("#log-title").textContent = `${service.name} · 最近日志`;
  loadLogs();
}

async function refreshDashboard({ quiet = false } = {}) {
  try {
    const data = await api("/api/dashboard");
    state.dashboard = data;
    state.csrf = data.csrf;
    renderDashboard();
    $("#last-update").textContent = `更新于 ${new Date(data.timestamp * 1000).toLocaleTimeString()}`;
    if (!quiet) toast("状态已刷新");
  } catch (error) {
    $("#last-update").textContent = "连接失败";
    if (!quiet) toast(error.message, true);
  }
}

async function selectService(name) {
  state.selectedService = name;
  renderDashboard();
}

async function loadLogs() {
  const service = selectedService();
  if (!service) return;
  const requested = service.name;
  $("#log-output").textContent = "正在读取日志…";
  try {
    const data = await api(`/api/services/${encodePart(requested)}/logs`);
    if (state.selectedService === requested) {
      $("#log-output").textContent = data.output;
      $("#log-output").scrollTop = $("#log-output").scrollHeight;
    }
  } catch (error) {
    if (state.selectedService === requested) $("#log-output").textContent = `读取失败：${error.message}`;
  }
}

async function runServiceAction(action) {
  const service = selectedService();
  if (!service) return;
  if (action === "config-check") {
    try {
      const data = await api(`/api/services/${encodePart(service.name)}/config-check`);
      showResults(`${service.name} · 配置检查`, data.results, "CONFIG CHECK");
    } catch (error) { toast(error.message, true); }
    return;
  }
  let confirmed = false;
  if (["stop", "restart", "clear-logs"].includes(action)) {
    const wording = { stop: "停止服务", restart: "重启服务", "clear-logs": "永久清空现有日志" }[action];
    confirmed = await confirmAction(`${wording} ${service.name}？`);
    if (!confirmed) return;
  }
  const body = { action, confirmed };
  if (action === "set-autostart") body.enabled = !service.autostart;
  try {
    const data = await api(`/api/services/${encodePart(service.name)}/action`, { method: "POST", body });
    toast(data.message || "操作完成");
    await refreshDashboard({ quiet: true });
    await loadLogs();
  } catch (error) { toast(error.message, true); }
}

function emptyCard(message) {
  return `<div class="wg-card"><p>${escapeHtml(message)}</p></div>`;
}

function wgButton(label, action, data = {}, danger = false) {
  const attrs = Object.entries(data).map(([key, value]) => ` data-${key}="${escapeHtml(value)}"`).join("");
  return `<button class="small-button${danger ? " danger-ghost" : ""}" data-wg-action="${escapeHtml(action)}"${attrs}>${escapeHtml(label)}</button>`;
}

function interfaceCard(item) {
  const runtime = item.runtime || {};
  const running = Boolean(runtime.running);
  const server = item.role === "server";
  const peers = server ? (item.peers || []).map((peer) => `<div class="sub-row"><span><strong>${escapeHtml(peer.name)}</strong><br><span class="muted">${escapeHtml(peer.address || peer.allowedIPs || "")} · ↓ ${formatBytes(peer.runtime?.receivedBytes)} / ↑ ${formatBytes(peer.runtime?.sentBytes)} · ${handshake(peer.runtime?.latestHandshake)}</span></span><span class="inline-actions">${wgButton("导出", "export-peer", { interface: item.name, peer: peer.id })}${wgButton("二维码", "peer-qr", { interface: item.name, peer: peer.id })}${wgButton("删除", "remove-peer", { interface: item.name, peer: peer.id }, true)}</span></div>`).join("") : "";
  const actions = server ? [
    running ? wgButton("断开", "stop-interface", { interface: item.name }, true) : wgButton("连接", "start-interface", { interface: item.name }),
    running ? wgButton("同步配置", "sync-interface", { interface: item.name }) : "",
    wgButton("编辑", "edit-server", { interface: item.name }),
    wgButton("添加客户端", "add-peer", { interface: item.name }),
    wgButton("导入已有客户端", "import-peers", { interface: item.name }),
    wgButton("删除服务端", "delete-server", { interface: item.name }, true),
  ] : [wgButton("删除客户端接口", "delete-client", { interface: item.name }, true)];
  return `<article class="wg-card"><div class="wg-card-head"><div><h3>${escapeHtml(item.name)}</h3><p>${server ? "服务端接口" : "连接其他服务端"} · ${escapeHtml(item.address)}</p></div><span class="status-dot ${running ? "healthy" : "stopped"}"></span></div>
    <div class="metric-row"><div class="metric"><span>接收 / 实时</span><strong>${formatBytes(runtime.receivedBytes)} · ${formatRate(item.rate?.received)}</strong></div><div class="metric"><span>发送 / 实时</span><strong>${formatBytes(runtime.sentBytes)} · ${formatRate(item.rate?.sent)}</strong></div><div class="metric"><span>最近握手</span><strong>${handshake(runtime.latestHandshake)}</strong></div><div class="metric"><span>运行状态</span><strong>${running ? "已连接" : "未连接"}</strong></div></div>
    ${server ? `<div class="sub-list">${peers || `<div class="sub-row muted">还没有受管客户端</div>`}</div>` : ""}<div class="inline-actions">${actions.join("")}</div></article>`;
}

function connectionCard(item) {
  const runtime = item.runtime || {};
  const name = item.name || "未命名";
  const actions = item.connected
    ? wgButton("断开", "disconnect", { connection: name }, true)
    : wgButton("连接", "connect", { connection: name });
  return `<article class="wg-card"><div class="wg-card-head"><div><h3>${escapeHtml(name)}</h3><p>${escapeHtml(item.from)} → ${escapeHtml(item.to)}</p></div><span class="status-dot ${item.connected ? "healthy" : "stopped"}"></span></div>
    <p>来源网段：${escapeHtml(item.sourceNetwork || "未设置")}</p><p>目标网段：${escapeHtml((item.destinationNetworks || []).join?.(", ") || item.destinationNetworks || "由接口配置决定")}</p>
    <div class="metric-row"><div class="metric"><span>转发 / 实时</span><strong>${formatBytes(runtime.forwardBytes)} · ${formatRate(item.rate?.forward)}</strong></div><div class="metric"><span>返回 / 实时</span><strong>${formatBytes(runtime.returnBytes)} · ${formatRate(item.rate?.returned)}</strong></div></div>
    ${item.statusError ? `<p class="error">${escapeHtml(item.statusError)}</p>` : ""}<div class="inline-actions">${actions}${item.statusError ? wgButton("接管旧规则", "adopt-connection", { connection: name }) : ""}${wgButton("编辑", "edit-connection", { connection: name })}${wgButton("删除", "delete-connection", { connection: name }, true)}</div></article>`;
}

function renderWireGuard() {
  const data = state.wireguard;
  if (!data) {
    $("#wg-servers").innerHTML = emptyCard("请选择 WireGuard 服务。");
    $("#wg-clients").innerHTML = emptyCard("请选择 WireGuard 服务。");
    $("#wg-connections").innerHTML = emptyCard("请选择 WireGuard 服务。");
    return;
  }
  const servers = data.interfaces.filter((item) => item.role === "server");
  const clients = data.interfaces.filter((item) => item.role === "client");
  $("#wg-servers").innerHTML = servers.map(interfaceCard).join("") || emptyCard("还没有服务端接口。");
  $("#wg-clients").innerHTML = clients.map(interfaceCard).join("") || emptyCard("还没有连接其他服务端。");
  $("#wg-connections").innerHTML = data.connections.map(connectionCard).join("") || emptyCard("还没有网络连接规则。");
  $$('[data-wg-action]').forEach((button) => button.addEventListener("click", () => handleWireGuardAction(button)));
}

async function refreshWireGuard() {
  if (!state.wireguardService) {
    state.wireguard = null;
    renderWireGuard();
    return;
  }
  try {
    const data = await api(`/api/wireguard/${encodePart(state.wireguardService)}`);
    const previous = state.wireguardPrevious?.service === data.service ? state.wireguardPrevious : null;
    calculateWireGuardRates(previous, data);
    state.wireguardPrevious = data;
    state.wireguard = data;
    renderWireGuard();
  } catch (error) {
    toast(error.message, true);
  }
}

function interfaceNames() {
  return (state.wireguard?.interfaces || []).map((item) => ({ value: item.name, label: `${item.name} · ${item.address}` }));
}

async function handleWireGuardAction(button) {
  const action = button.dataset.wgAction;
  const values = { ...button.dataset };
  delete values.wgAction;
  const dangerous = ["stop-interface", "disconnect", "delete-server", "delete-client", "remove-peer", "delete-connection"].includes(action);
  if (dangerous && !(await confirmAction(`确认执行“${button.textContent.trim()}”？`))) return;
  if (["create-server", "edit-server", "import-client", "add-peer", "add-connection", "edit-connection"].includes(action)) {
    openWireGuardForm(action, values);
    return;
  }
  try {
    const result = await wgPost({ action, confirmed: dangerous, ...values });
    if (action === "peer-qr") showQr(result.filename, result.qr);
    else if (action === "export-peer") downloadText(result.filename, result.content);
    else toast(result.message || "操作完成");
    await refreshWireGuard();
    await refreshDashboard({ quiet: true });
  } catch (error) { toast(error.message, true); }
}

async function wgPost(body) {
  return api(`/api/wireguard/${encodePart(state.wireguardService)}/action`, { method: "POST", body });
}

function nextServerDefaults() {
  const servers = state.wireguard?.interfaces.filter((item) => item.role === "server") || [];
  const used = new Set(state.wireguard?.interfaces.map((item) => item.name));
  let index = 0;
  while (used.has(`wg${index}`)) index += 1;
  const pools = new Set(servers.map((item) => item.settings?.addressPool));
  let subnet = 20;
  while (pools.has(`10.${subnet}.0.0/24`) && subnet < 254) subnet += 1;
  const ports = servers.map((item) => Number(item.settings?.listenPort || 0)).filter(Boolean);
  const endpoint = servers.map((item) => item.settings?.publicEndpoint).find(Boolean) || "服务器公网IP或域名:51820";
  const host = endpoint.includes(":") ? endpoint.slice(0, endpoint.lastIndexOf(":")) : "服务器公网IP或域名";
  const port = Math.min(65535, Math.max(51819, ...ports) + 1);
  return { interface: `wg${index}`, address: `10.${subnet}.0.1`, addressPool: `10.${subnet}.0.0/24`, listenPort: port, publicEndpoint: `${host}:${port}` };
}

function openWireGuardForm(action, initial = {}) {
  const interfaceItem = state.wireguard?.interfaces.find((item) => item.name === initial.interface);
  const connection = state.wireguard?.connections.find((item) => item.name === initial.connection);
  if (action === "create-server") initial = nextServerDefaults();
  if (action === "edit-server") initial = { ...interfaceItem?.settings, interface: interfaceItem?.name };
  if (action === "edit-connection") initial = {
    name: connection?.name, source: connection?.from, target: connection?.to,
    sourceNetwork: connection?.sourceNetwork,
    destinationNetworks: Array.isArray(connection?.destinationNetworks) ? connection.destinationNetworks.join(",") : connection?.destinationNetworks || "",
    allowReturnTraffic: connection?.allowReturnTraffic !== false,
    autoConnect: Boolean(connection?.autoConnect),
  };
  const interfaceOptions = interfaceNames();
  const definitions = {
    "create-server": ["新建服务端", [textField("interface", "接口名", initial.interface), textField("address", "服务端地址（不带掩码）", initial.address), textField("addressPool", "客户端地址池", initial.addressPool), textField("listenPort", "监听端口", initial.listenPort, "number"), textField("publicEndpoint", "公网入口（IP/域名:端口）", initial.publicEndpoint)]],
    "edit-server": ["编辑服务端", [hiddenField("interface", initial.interface), textField("address", "服务端地址（不带掩码）", initial.address), textField("addressPool", "客户端地址池", initial.addressPool), textField("listenPort", "监听端口", initial.listenPort, "number"), textField("publicEndpoint", "公网入口（IP/域名:端口）", initial.publicEndpoint)]],
    "import-client": ["连接其他服务端", [textField("interface", "本地接口名，例如 wg1", initial.interface || "wg1"), textField("sourceConfig", "服务端提供的 .conf 文件路径", initial.sourceConfig || "")]],
    "add-peer": ["添加客户端", [hiddenField("interface", initial.interface), textField("name", "客户端名称", ""), textField("address", "客户端地址（留空则自动分配）", ""), selectField("profile", "访问权限", interfaceItem?.profiles || [], "")]],
    "add-connection": ["添加网络连接", [textField("name", "连接名称", ""), selectField("source", "来源接口", interfaceOptions, ""), selectField("target", "目标接口", interfaceOptions, ""), textField("sourceNetwork", "来源网段，例如 10.10.0.0/24", ""), textField("destinationNetworks", "目标网段，多个用逗号分隔", ""), checkField("allowReturnTraffic", "允许返回流量", true), checkField("autoConnect", "随 WireGuard 自动连接", false)]],
    "edit-connection": ["编辑网络连接", [textField("name", "连接名称", initial.name), selectField("source", "来源接口", interfaceOptions, initial.source), selectField("target", "目标接口", interfaceOptions, initial.target), textField("sourceNetwork", "来源网段", initial.sourceNetwork), textField("destinationNetworks", "目标网段，多个用逗号分隔", initial.destinationNetworks), checkField("allowReturnTraffic", "允许返回流量", initial.allowReturnTraffic), checkField("autoConnect", "随 WireGuard 自动连接", initial.autoConnect)]],
  };
  const [title, fields] = definitions[action];
  openForm(title, fields, async (values) => {
    const result = await wgPost({ action, ...values });
    toast(result.message || "操作完成");
    await refreshWireGuard();
    await refreshDashboard({ quiet: true });
  }, "WIREGUARD");
}

function textField(name, label, value = "", type = "text") {
  return `<label>${escapeHtml(label)}<input name="${escapeHtml(name)}" type="${escapeHtml(type)}" value="${escapeHtml(value)}" required></label>`;
}
function hiddenField(name, value) { return `<input name="${escapeHtml(name)}" type="hidden" value="${escapeHtml(value)}">`; }
function checkField(name, label, checked) { return `<label class="check-field"><input name="${escapeHtml(name)}" type="checkbox"${checked ? " checked" : ""}> ${escapeHtml(label)}</label>`; }
function selectField(name, label, options, selected) {
  const normalized = options.map((item) => typeof item === "string" ? { value: item, label: item } : { value: item.name ?? item.value, label: item.description ? `${item.name} · ${item.description}` : item.label ?? item.name });
  return `<label>${escapeHtml(label)}<select name="${escapeHtml(name)}" required>${normalized.map((item) => `<option value="${escapeHtml(item.value)}"${String(item.value) === String(selected) ? " selected" : ""}>${escapeHtml(item.label)}</option>`).join("")}</select></label>`;
}

function openForm(title, fields, handler, eyebrow = "ACTION") {
  $("#modal-title").textContent = title;
  $("#modal-eyebrow").textContent = eyebrow;
  $("#modal-content").innerHTML = fields.join("");
  $("#modal-confirm").textContent = "确认";
  const dialog = $("#modal");
  const form = $("#modal-form");
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (event.submitter?.value === "cancel") {
      dialog.close();
      return;
    }
    if (!form.reportValidity()) return;
    const values = {};
    new FormData(form).forEach((value, key) => { values[key] = value; });
    $$('input[type="checkbox"]', form).forEach((input) => { values[input.name] = input.checked; });
    $("#modal-confirm").disabled = true;
    try {
      await handler(values);
      dialog.close();
    } catch (error) { toast(error.message, true); }
    finally { $("#modal-confirm").disabled = false; }
  };
  dialog.showModal();
}

function confirmAction(message) {
  return new Promise((resolve) => {
    $("#modal-title").textContent = "确认操作";
    $("#modal-eyebrow").textContent = "CONFIRM";
    $("#modal-content").innerHTML = `<p>${escapeHtml(message)}</p><p class="muted">请确认目标无误后继续。</p>`;
    $("#modal-confirm").textContent = "确认执行";
    const dialog = $("#modal");
    const form = $("#modal-form");
    let submitted = false;
    form.onsubmit = (event) => {
      event.preventDefault();
      submitted = event.submitter?.value !== "cancel";
      dialog.close();
    };
    dialog.onclose = () => { dialog.onclose = null; resolve(submitted); };
    dialog.showModal();
  });
}

function showResults(title, results, eyebrow = "RESULT") {
  $("#modal-title").textContent = title;
  $("#modal-eyebrow").textContent = eyebrow;
  $("#modal-content").innerHTML = (results || []).map((item) => `<div class="result-item${item.level === "error" || item.ok === false ? " error" : ""}"><b>${item.level ? escapeHtml(item.level.toUpperCase()) : item.ok === false ? "×" : "✓"}</b><span>${escapeHtml(item.message || item.detail || "")}</span></div>`).join("") || `<p class="muted">没有发现问题。</p>`;
  $("#modal-confirm").textContent = "关闭";
  const dialog = $("#modal");
  const form = $("#modal-form");
  form.onsubmit = (event) => { event.preventDefault(); dialog.close(); };
  dialog.showModal();
}

function showQr(title, source) {
  $("#modal-title").textContent = title;
  $("#modal-eyebrow").textContent = "CLIENT QR";
  $("#modal-content").innerHTML = `<img src="${escapeHtml(source)}" alt="WireGuard 客户端二维码"><p class="muted">用 WireGuard 客户端扫描。二维码仅在当前浏览器内显示。</p>`;
  $("#modal-confirm").textContent = "关闭";
  const dialog = $("#modal");
  $("#modal-form").onsubmit = (event) => { event.preventDefault(); dialog.close(); };
  dialog.showModal();
}

function downloadText(filename, content) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename || "wireguard.conf";
  anchor.click();
  URL.revokeObjectURL(url);
  toast("客户端配置已下载");
}

function renderResultList(target, results) {
  $(target).innerHTML = (results || []).map((item) => `<div class="result-item${item.level === "error" ? " error" : ""}"><b>${escapeHtml((item.level || "ok").toUpperCase())}</b><span>${escapeHtml(item.message || item.detail || "")}</span></div>`).join("") || `<p class="muted">没有发现问题。</p>`;
}

async function runDoctor() {
  try { renderResultList("#doctor-results", (await api("/api/doctor")).results); }
  catch (error) { toast(error.message, true); }
}

async function checkUpdate() {
  try {
    const info = await api("/api/update");
    $("#update-result").innerHTML = `<div class="result-item"><b>${escapeHtml((info.state || "unknown").toUpperCase())}</b><span>${escapeHtml(info.detail || "")}</span></div>${info.state === "available" ? `<button class="button primary" id="update-apply">安装更新</button>` : ""}`;
    $("#update-apply")?.addEventListener("click", applyUpdate);
  } catch (error) { toast(error.message, true); }
}

async function applyUpdate() {
  if (!(await confirmAction("从 GitHub 安装 NControl 公共代码更新？local/ 数据不会被修改。"))) return;
  try {
    const info = await api("/api/update", { method: "POST", body: { confirmed: true } });
    toast(info.detail || "更新已安装，请刷新页面");
    await checkUpdate();
  } catch (error) { toast(error.message, true); }
}

async function checkMigration() {
  try { renderResultList("#migration-results", (await api("/api/migration")).results); }
  catch (error) { toast(error.message, true); }
}

async function runMigrationAction(action) {
  const descriptions = {
    "apply-public-host": "更新所有受管 WireGuard 客户端的公网入口？",
    "configure-wireguard-host": "开启并持久化 IPv4 转发，并配置限定范围的免交互 sudo？",
    "install-boot": "安装 NControl 开机入口？实际服务仍由 NControl 管理。",
    "start-autostart": "启动全部已启用开机启动的服务？",
    finish: "确认当前迁移检查无错误并标记初始化完成？",
  };
  if (!(await confirmAction(descriptions[action] || "确认执行？"))) return;
  try {
    const body = { action, confirmed: true };
    if (action === "apply-public-host") body.publicHost = $("#public-host").value.trim();
    const result = await api("/api/migration/action", { method: "POST", body });
    toast(result.message || "操作完成");
    await checkMigration();
    await refreshDashboard({ quiet: true });
  } catch (error) { toast(error.message, true); }
}

function bindEvents() {
  $$(".nav-item").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
  $("#refresh-button").addEventListener("click", () => state.view === "wireguard" ? refreshWireGuard() : refreshDashboard());
  $("#log-refresh").addEventListener("click", loadLogs);
  $("#log-clear").addEventListener("click", () => runServiceAction("clear-logs"));
  $("#wireguard-service").addEventListener("change", (event) => { state.wireguardService = event.target.value; refreshWireGuard(); });
  $("#wg-new-server").addEventListener("click", () => openWireGuardForm("create-server"));
  $("#wg-import-client").addEventListener("click", () => openWireGuardForm("import-client"));
  $("#wg-add-connection").addEventListener("click", () => openWireGuardForm("add-connection"));
  $("#doctor-run").addEventListener("click", runDoctor);
  $("#update-check").addEventListener("click", checkUpdate);
  $("#migration-check").addEventListener("click", checkMigration);
  $$('[data-migration]').forEach((button) => button.addEventListener("click", () => runMigrationAction(button.dataset.migration)));
  $("#logout-button").addEventListener("click", async () => {
    try { await fetch("/logout", { method: "POST", headers: { "X-NControl-CSRF": state.csrf } }); }
    finally { window.location.assign("/login"); }
  });
}

async function initialize() {
  bindEvents();
  await refreshDashboard({ quiet: true });
  window.setInterval(async () => {
    if (document.hidden) return;
    if (state.view === "wireguard") await refreshWireGuard();
    else await refreshDashboard({ quiet: true });
  }, 15000);
}

initialize();
