import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

// ===== 类型定义 =====
interface PortInfo {
  port: number;
  protocol: string;
  address: string;
  pid: string;
  process: string;
  user: string;
  command?: string;
}

interface ScanResult {
  scan_time: string;
  total_ports: number;
  unique_apps: number;
  ports: PortInfo[];
}

interface AppGroup {
  process: string;
  pid: string;
  ports: number[];
  command?: string;
}

interface NetworkInterface {
  name: string;
  ip: string;
  netmask: string;
  subnet: string;
}

interface NetworkDevice {
  ip: string;
  mac?: string;
  hostname?: string;
  is_online: boolean;
}

interface RemotePort {
  port: number;
  is_open: boolean;
  service?: string;
}

interface DockerPort {
  host_port: number;
  container_port: number;
  protocol: string;
  host_ip: string;
}

interface DockerContainer {
  id: string;
  name: string;
  image: string;
  status: string;
  ports: DockerPort[];
}

// ===== DOM 元素 =====
// Tab 切换
const tabLocal = document.getElementById("tab-local") as HTMLButtonElement;
const tabNetwork = document.getElementById("tab-network") as HTMLButtonElement;
const pageLocal = document.getElementById("page-local") as HTMLDivElement;
const pageNetwork = document.getElementById("page-network") as HTMLDivElement;

// 本地端口页面
const viewTableBtn = document.getElementById("view-table") as HTMLButtonElement;
const viewGroupBtn = document.getElementById("view-group") as HTMLButtonElement;
const showCommand = document.getElementById("show-command") as HTMLInputElement;
const appFilter = document.getElementById("app-filter") as HTMLInputElement;
const portFilter = document.getElementById("port-filter") as HTMLInputElement;
const excludeSystem = document.getElementById("exclude-system") as HTMLInputElement;
const refreshBtn = document.getElementById("refresh-btn") as HTMLButtonElement;
const statTime = document.getElementById("stat-time") as HTMLSpanElement;
const statApps = document.getElementById("stat-apps") as HTMLSpanElement;
const statPorts = document.getElementById("stat-ports") as HTMLSpanElement;
const portTable = document.getElementById("port-table") as HTMLTableElement;
const portTbody = document.getElementById("port-tbody") as HTMLTableSectionElement;
const groupView = document.getElementById("group-view") as HTMLDivElement;

// 网络扫描页面
const subnetSelect = document.getElementById("subnet-select") as HTMLSelectElement;
const scanDevicesBtn = document.getElementById("scan-devices-btn") as HTMLButtonElement;
const refreshNetworkBtn = document.getElementById("refresh-network-btn") as HTMLButtonElement;
const netStatDevices = document.getElementById("net-stat-devices") as HTMLSpanElement;
const deviceCount = document.getElementById("device-count") as HTMLSpanElement;
const deviceList = document.getElementById("device-list") as HTMLDivElement;
const selectedDeviceIp = document.getElementById("selected-device-ip") as HTMLSpanElement;
const scanType = document.getElementById("scan-type") as HTMLSelectElement;
const portStart = document.getElementById("port-start") as HTMLInputElement;
const portEnd = document.getElementById("port-end") as HTMLInputElement;
const scanPortsBtn = document.getElementById("scan-ports-btn") as HTMLButtonElement;
const portResults = document.getElementById("port-results") as HTMLDivElement;

// ===== 状态 =====
let currentView: "table" | "group" = "table";
let currentPage: "local" | "network" | "monitor" = "local";
let isLoading = false;
let selectedDevice: NetworkDevice | null = null;
let discoveredDevices: NetworkDevice[] = [];
let sourceFilter: "all" | "local" | "docker" = "all";
let cachedDockerPorts: Map<number, string> = new Map();

// 来源筛选按钮
const sourceFilterBtns = document.querySelectorAll("#source-filter .segment");
sourceFilterBtns.forEach((btn) => {
  btn.addEventListener("click", () => {
    sourceFilterBtns.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    sourceFilter = (btn as HTMLElement).dataset.filter as "all" | "local" | "docker";
    scanPorts();
  });
});

// ===== Tab 切换 =====
const tabMonitor = document.getElementById("tab-monitor") as HTMLButtonElement;
const pageMonitor = document.getElementById("page-monitor") as HTMLDivElement;

function switchPage(page: "local" | "network" | "monitor") {
  currentPage = page;

  // 清除所有 Tab 的 active 状态
  tabLocal.classList.remove("active");
  tabNetwork.classList.remove("active");
  tabMonitor?.classList.remove("active");

  // 隐藏所有页面
  pageLocal.classList.add("hidden");
  pageNetwork.classList.add("hidden");
  pageMonitor?.classList.add("hidden");

  // 激活当前 Tab 和页面
  if (page === "local") {
    tabLocal.classList.add("active");
    pageLocal.classList.remove("hidden");
    scanPorts();
  } else if (page === "network") {
    tabNetwork.classList.add("active");
    pageNetwork.classList.remove("hidden");
    loadInterfaces();
  } else if (page === "monitor") {
    tabMonitor?.classList.add("active");
    pageMonitor?.classList.remove("hidden");
    initMonitorPage();
  }
}

tabLocal.addEventListener("click", () => switchPage("local"));
tabNetwork.addEventListener("click", () => switchPage("network"));
tabMonitor?.addEventListener("click", () => switchPage("monitor"));

// ===== 本地端口扫描 =====
async function scanPorts() {
  if (isLoading) return;
  isLoading = true;
  refreshBtn.classList.add("spinning");

  try {
    const includeCommand = showCommand.checked;
    const result: ScanResult = await invoke("tauri_scan_ports", { includeCommand });

    // 获取 Docker 容器端口映射
    let dockerPorts: Map<number, string> = new Map();
    try {
      const containers: DockerContainer[] = await invoke("tauri_get_docker_containers");
      for (const c of containers) {
        for (const p of c.ports) {
          dockerPorts.set(p.host_port, c.name);
        }
      }
    } catch {
      // Docker 不可用，忽略
    }

    let filteredPorts = result.ports;

    const appFilterValue = appFilter.value.trim().toLowerCase();
    if (appFilterValue) {
      filteredPorts = filteredPorts.filter(p =>
        p.process.toLowerCase().includes(appFilterValue)
      );
    }

    const portFilterValue = portFilter.value.trim();
    if (portFilterValue) {
      const portNum = parseInt(portFilterValue);
      if (!isNaN(portNum)) {
        filteredPorts = filteredPorts.filter(p => p.port === portNum);
      }
    }

    if (excludeSystem.checked) {
      const systemProcs = ["controlce", "rapportd", "netdisk_s", "mds", "launchd"];
      filteredPorts = filteredPorts.filter(p =>
        !systemProcs.includes(p.process.toLowerCase())
      );
    }

    // 来源筛选
    cachedDockerPorts = dockerPorts;
    if (sourceFilter === "docker") {
      filteredPorts = filteredPorts.filter(p => dockerPorts.has(p.port));
    } else if (sourceFilter === "local") {
      filteredPorts = filteredPorts.filter(p => !dockerPorts.has(p.port));
    }

    const uniqueApps = new Set(filteredPorts.map(p => `${p.process}:${p.pid}`)).size;
    statTime.textContent = result.scan_time.split(' ')[1] || result.scan_time;
    statApps.textContent = uniqueApps.toString();
    statPorts.textContent = filteredPorts.length.toString();

    if (currentView === "table") {
      renderTable(filteredPorts, includeCommand, dockerPorts);
    }

  } catch (error) {
    console.error("Scan failed:", error);
  } finally {
    isLoading = false;
    refreshBtn.classList.remove("spinning");
  }
}

function renderTable(ports: PortInfo[], showCmd: boolean, dockerPorts?: Map<number, string>) {
  portTbody.innerHTML = "";

  if (ports.length === 0) {
    portTbody.innerHTML = `
      <tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-tertiary);">
        没有找到匹配的端口
      </td></tr>
    `;
    return;
  }

  for (const p of ports) {
    const dockerContainer = dockerPorts?.get(p.port);
    const isDocker = !!dockerContainer;
    const typeIcon = isDocker ? "🐳" : "💻";
    const processDisplay = isDocker
      ? `<span class="docker-tag">🐳 ${dockerContainer}</span>`
      : p.process;

    // 服务协议检测
    const getServiceInfo = (port: number): { name: string; icon: string; canOpen: boolean; protocol: string } => {
      const services: Record<number, { name: string; icon: string; canOpen: boolean; protocol: string }> = {
        21: { name: "FTP", icon: "📁", canOpen: false, protocol: "ftp" },
        22: { name: "SSH", icon: "🔐", canOpen: false, protocol: "ssh" },
        23: { name: "Telnet", icon: "📟", canOpen: false, protocol: "telnet" },
        25: { name: "SMTP", icon: "📧", canOpen: false, protocol: "smtp" },
        53: { name: "DNS", icon: "🌐", canOpen: false, protocol: "dns" },
        80: { name: "HTTP", icon: "🌍", canOpen: true, protocol: "http" },
        110: { name: "POP3", icon: "📬", canOpen: false, protocol: "pop3" },
        143: { name: "IMAP", icon: "📨", canOpen: false, protocol: "imap" },
        443: { name: "HTTPS", icon: "🔒", canOpen: true, protocol: "https" },
        445: { name: "SMB", icon: "💾", canOpen: false, protocol: "smb" },
        3306: { name: "MySQL", icon: "🗄️", canOpen: false, protocol: "mysql" },
        3389: { name: "RDP", icon: "🖥️", canOpen: false, protocol: "rdp" },
        5432: { name: "PostgreSQL", icon: "🐘", canOpen: false, protocol: "postgresql" },
        5433: { name: "PostgreSQL", icon: "🐘", canOpen: false, protocol: "postgresql" },
        6379: { name: "Redis", icon: "🔴", canOpen: false, protocol: "redis" },
        8080: { name: "HTTP", icon: "🌍", canOpen: true, protocol: "http" },
        8443: { name: "HTTPS", icon: "🔒", canOpen: true, protocol: "https" },
        27017: { name: "MongoDB", icon: "🍃", canOpen: false, protocol: "mongodb" },
        9000: { name: "HTTP", icon: "🌍", canOpen: true, protocol: "http" },
        9001: { name: "HTTP", icon: "🌍", canOpen: true, protocol: "http" },
      };
      // 默认假设高端口是 HTTP 服务
      if (services[port]) return services[port];
      if (port >= 3000 && port < 65535) return { name: "HTTP", icon: "🌍", canOpen: true, protocol: "http" };
      return { name: "TCP", icon: "🔌", canOpen: false, protocol: "tcp" };
    };

    const service = getServiceInfo(p.port);

    const row = document.createElement("tr");
    row.className = isDocker ? "docker-row" : "";
    row.innerHTML = `
      <td class="cell-port">
        <span class="port-type-icon">${typeIcon}</span>
        <span class="port-number">${p.port}</span>
        <span class="port-service-tag" title="${service.name}">${service.icon} ${service.name}</span>
      </td>
      <td><span class="cell-protocol ${p.protocol.toLowerCase()}">${p.protocol}</span></td>
      <td class="cell-address">${p.address}</td>
      <td class="cell-pid">${p.pid}</td>
      <td class="cell-process">${processDisplay}</td>
      <td class="cell-user">
        ${p.user}
        ${service.canOpen ? `<button class="port-open-btn" data-port="${p.port}" data-protocol="${service.protocol}" title="在浏览器中打开">🔗</button>` : ''}
      </td>
    `;
    portTbody.appendChild(row);

    if (showCmd && p.command) {
      const cmdRow = document.createElement("tr");
      cmdRow.className = "command-row";
      cmdRow.innerHTML = `
        <td colspan="6" class="command-cell">${truncate(p.command, 120)}</td>
      `;
      portTbody.appendChild(cmdRow);
    }
  }

  // 添加点击事件打开浏览器
  portTbody.addEventListener("click", async (e) => {
    const btn = (e.target as HTMLElement).closest(".port-open-btn") as HTMLElement;
    if (btn) {
      const port = btn.dataset.port;
      const protocol = btn.dataset.protocol || "http";
      const url = `${protocol}://localhost:${port}`;
      try {
        await openUrl(url);
      } catch (error) {
        console.error("Failed to open URL:", error);
        // 回退到 window.open
        window.open(url, "_blank");
      }
    }
  });
}

async function scanGrouped() {
  if (isLoading) return;
  isLoading = true;
  refreshBtn.classList.add("spinning");

  try {
    const groups: AppGroup[] = await invoke("tauri_scan_ports_grouped");

    let filtered = groups;

    const appFilterValue = appFilter.value.trim().toLowerCase();
    if (appFilterValue) {
      filtered = filtered.filter(g =>
        g.process.toLowerCase().includes(appFilterValue)
      );
    }

    if (excludeSystem.checked) {
      const systemProcs = ["controlce", "rapportd", "netdisk_s", "mds", "launchd"];
      filtered = filtered.filter(g =>
        !systemProcs.includes(g.process.toLowerCase())
      );
    }

    const totalPorts = filtered.reduce((sum, g) => sum + g.ports.length, 0);
    statApps.textContent = filtered.length.toString();
    statPorts.textContent = totalPorts.toString();

    renderGroups(filtered);

  } catch (error) {
    console.error("Group failed:", error);
  } finally {
    isLoading = false;
    refreshBtn.classList.remove("spinning");
  }
}

function renderGroups(groups: AppGroup[]) {
  groupView.innerHTML = "";

  if (groups.length === 0) {
    groupView.innerHTML = `
      <div class="empty-state">
        <div class="icon">📭</div>
        <div>没有找到匹配的应用</div>
      </div>
    `;
    return;
  }

  for (const g of groups) {
    const card = document.createElement("div");
    card.className = "app-card";
    card.innerHTML = `
      <div class="app-header">
        <div class="app-icon">📦</div>
        <div class="app-info">
          <div class="app-name">${g.process}</div>
          <div class="app-pid">PID ${g.pid}</div>
        </div>
      </div>
      <div class="app-ports">
        ${g.ports.map(p => `<span class="port-tag">${p}</span>`).join("")}
      </div>
      ${g.command ? `<div class="app-command">${truncate(g.command, 100)}</div>` : ""}
    `;
    groupView.appendChild(card);
  }
}

function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.substring(0, maxLen) + "…" : str;
}

function switchView(view: "table" | "group") {
  currentView = view;

  viewTableBtn.classList.toggle("active", view === "table");
  viewGroupBtn.classList.toggle("active", view === "group");

  portTable.classList.toggle("hidden", view !== "table");
  groupView.classList.toggle("hidden", view !== "group");

  if (view === "table") {
    scanPorts();
  } else {
    scanGrouped();
  }
}

// ===== 网络扫描 =====
async function loadInterfaces() {
  try {
    const interfaces: NetworkInterface[] = await invoke("tauri_get_interfaces");
    const currentSubnet: string | null = await invoke("tauri_get_current_subnet");

    subnetSelect.innerHTML = "";

    for (const iface of interfaces) {
      const option = document.createElement("option");
      option.value = iface.subnet;
      option.textContent = iface.ip ? `${iface.subnet} (${iface.ip})` : iface.subnet;
      if (currentSubnet && iface.subnet === currentSubnet) {
        option.selected = true;
      }
      subnetSelect.appendChild(option);
    }
  } catch (error) {
    console.error("Failed to load interfaces:", error);
  }
}

async function discoverDevices() {
  const subnet = subnetSelect.value;
  if (!subnet) return;

  scanDevicesBtn.disabled = true;
  scanDevicesBtn.textContent = "⏳ 扫描中...";
  deviceList.innerHTML = `<div class="loading">正在扫描局域网设备...</div>`;

  try {
    discoveredDevices = await invoke("tauri_discover_devices", { subnet });

    netStatDevices.textContent = discoveredDevices.length.toString();
    deviceCount.textContent = discoveredDevices.length.toString();

    renderDeviceList();
  } catch (error) {
    console.error("Device discovery failed:", error);
    deviceList.innerHTML = `<div class="empty-state"><div class="icon">❌</div><div>扫描失败</div></div>`;
  } finally {
    scanDevicesBtn.disabled = false;
    scanDevicesBtn.textContent = "🔍 扫描设备";
  }
}

function renderDeviceList() {
  if (discoveredDevices.length === 0) {
    deviceList.innerHTML = `
      <div class="empty-state">
        <div class="icon">📡</div>
        <div>未发现设备</div>
      </div>
    `;
    return;
  }

  deviceList.innerHTML = "";

  for (const device of discoveredDevices) {
    const item = document.createElement("div");
    item.className = "device-item";
    if (selectedDevice?.ip === device.ip) {
      item.classList.add("selected");
    }

    item.innerHTML = `
      <div class="device-status ${device.is_online ? 'online' : 'offline'}"></div>
      <div class="device-info">
        <div class="device-ip">${device.ip}</div>
        <div class="device-details">
          ${device.hostname ? `<span>${device.hostname}</span>` : ""}
          ${device.mac ? `<span class="device-mac">${device.mac}</span>` : ""}
        </div>
      </div>
    `;

    item.addEventListener("click", () => selectDevice(device));
    deviceList.appendChild(item);
  }
}

function selectDevice(device: NetworkDevice) {
  selectedDevice = device;
  selectedDeviceIp.textContent = device.ip;
  scanPortsBtn.disabled = false;

  // 显示设备操作按钮
  const deviceActions = document.getElementById("device-actions");
  if (deviceActions) {
    deviceActions.style.display = "flex";
  }

  // 更新选中状态
  document.querySelectorAll(".device-item").forEach(el => el.classList.remove("selected"));
  const index = discoveredDevices.findIndex(d => d.ip === device.ip);
  if (index >= 0) {
    deviceList.children[index]?.classList.add("selected");
  }

  // 清空端口结果
  portResults.innerHTML = `
    <div class="empty-state">
      <div class="icon">🔌</div>
      <div>点击"扫描端口"、"Ping" 或 "Traceroute"</div>
    </div>
  `;
}

async function scanRemotePorts() {
  if (!selectedDevice) return;

  scanPortsBtn.disabled = true;
  scanPortsBtn.textContent = "⏳ 扫描中...";
  portResults.innerHTML = `<div class="loading">正在扫描 ${selectedDevice.ip} 的端口...</div>`;

  try {
    let ports: RemotePort[];
    const type = scanType.value;

    if (type === "common") {
      ports = await invoke("tauri_quick_scan", { ip: selectedDevice.ip });
    } else if (type === "quick") {
      ports = await invoke("tauri_scan_ports_range", {
        ip: selectedDevice.ip,
        start: 1,
        end: 1000,
        timeoutMs: 300
      });
    } else if (type === "full") {
      ports = await invoke("tauri_scan_ports_range", {
        ip: selectedDevice.ip,
        start: 1,
        end: 65535,
        timeoutMs: 200
      });
    } else {
      const start = parseInt(portStart.value) || 1;
      const end = parseInt(portEnd.value) || 1000;
      ports = await invoke("tauri_scan_ports_range", {
        ip: selectedDevice.ip,
        start,
        end,
        timeoutMs: 300
      });
    }

    renderPortResults(ports);
  } catch (error) {
    console.error("Port scan failed:", error);
    portResults.innerHTML = `<div class="empty-state"><div class="icon">❌</div><div>扫描失败</div></div>`;
  } finally {
    scanPortsBtn.disabled = false;
    scanPortsBtn.textContent = "扫描端口";
  }
}

function renderPortResults(ports: RemotePort[]) {
  const openPorts = ports.filter(p => p.is_open);

  if (openPorts.length === 0) {
    portResults.innerHTML = `
      <div class="empty-state">
        <div class="icon">🔒</div>
        <div>未发现开放端口</div>
      </div>
    `;
    return;
  }

  portResults.innerHTML = `
    <div class="port-results-header">
      发现 <strong>${openPorts.length}</strong> 个开放端口
    </div>
    <div class="port-results-list">
      ${openPorts.map(p => `
        <div class="port-result-item">
          <span class="port-number">${p.port}</span>
          <span class="port-service">${p.service || "未知"}</span>
          <span class="port-status open">开放</span>
        </div>
      `).join("")}
    </div>
  `;
}

// ===== 事件绑定 =====
viewTableBtn.addEventListener("click", () => switchView("table"));
viewGroupBtn.addEventListener("click", () => switchView("group"));
refreshBtn.addEventListener("click", () => {
  if (currentView === "table") scanPorts();
  else scanGrouped();
});

scanDevicesBtn.addEventListener("click", discoverDevices);
refreshNetworkBtn.addEventListener("click", loadInterfaces);
scanPortsBtn.addEventListener("click", scanRemotePorts);

// 手动添加目标 IP/域名
const manualTargetInput = document.getElementById("manual-target") as HTMLInputElement;
const addManualTargetBtn = document.getElementById("add-manual-target");

interface ResolveResult {
  original: string;
  ip: string;
  is_domain: boolean;
  hostname: string | null;
}

addManualTargetBtn?.addEventListener("click", async () => {
  const target = manualTargetInput?.value?.trim();
  if (!target) {
    alert("请输入 IP 地址或域名");
    return;
  }

  try {
    const result: ResolveResult = await invoke("tauri_resolve_target", { target });

    // 创建设备并添加到列表
    const device: NetworkDevice = {
      ip: result.ip,
      mac: undefined,
      hostname: result.hostname || (result.is_domain ? result.original : undefined),
      is_online: true,
    };

    // 检查是否已存在
    const exists = discoveredDevices.some(d => d.ip === device.ip);
    if (!exists) {
      discoveredDevices.push(device);
    }

    // 刷新列表并选中
    renderDeviceList();
    selectDevice(device);

    // 清空输入框
    manualTargetInput.value = "";

    // 提示用户
    if (result.is_domain) {
      console.log(`域名 ${result.original} 解析为 ${result.ip}`);
    }
  } catch (error) {
    alert("解析失败: " + error);
  }
});

// Enter 键快捷提交
manualTargetInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    addManualTargetBtn?.click();
  }
});


scanType.addEventListener("change", () => {
  const isCustom = scanType.value === "custom";
  portStart.style.display = isCustom ? "block" : "none";
  portEnd.style.display = isCustom ? "block" : "none";
});

let filterTimeout: number;
const debouncedScan = () => {
  clearTimeout(filterTimeout);
  filterTimeout = window.setTimeout(() => {
    if (currentView === "table") scanPorts();
    else scanGrouped();
  }, 200);
};

appFilter.addEventListener("input", debouncedScan);
portFilter.addEventListener("input", debouncedScan);
excludeSystem.addEventListener("change", debouncedScan);
showCommand.addEventListener("change", () => {
  if (currentView === "table") scanPorts();
});

// ===== Ping/Traceroute =====
interface PingResult {
  ip: string;
  is_reachable: boolean;
  packets_sent: number;
  packets_received: number;
  packet_loss: number;
  min_ms?: number;
  avg_ms?: number;
  max_ms?: number;
  raw_output: string;
}

interface TraceHop {
  hop: number;
  ip?: string;
  hostname?: string;
  time_ms?: number;
}

interface TracerouteResult {
  target: string;
  hops: TraceHop[];
  raw_output: string;
}

const deviceActions = document.getElementById("device-actions") as HTMLDivElement;
const pingBtn = document.getElementById("ping-btn") as HTMLButtonElement;
const traceBtn = document.getElementById("trace-btn") as HTMLButtonElement;

// Ping 监测状态
let pingMonitorInterval: number | null = null;
let pingHistory: { time: number; ms: number | null }[] = [];

interface PingOneResult {
  ip: string;
  seq: number;
  success: boolean;
  time_ms?: number;
  ttl?: number;
  line: string;
}

async function runPing() {
  if (!selectedDevice) return;

  // 如果正在监测，则停止
  if (pingMonitorInterval) {
    stopPingMonitor();
    return;
  }

  pingBtn.textContent = "⏳ Ping...";
  pingHistory = [];

  const ip = selectedDevice.ip;
  let sent = 0;
  let received = 0;
  let times: number[] = [];

  // 初始化显示
  portResults.innerHTML = `
    <div class="port-results-header">
      Ping ${ip} - 准备中...
      <button class="btn-secondary" id="stop-ping-btn" style="margin-left: auto;">⏹ 停止</button>
    </div>
    <div class="ping-stats" id="ping-live-stats">
      <div class="ping-stat">
        <div class="ping-stat-value" id="ping-sent">0</div>
        <div class="ping-stat-label">已发送</div>
      </div>
      <div class="ping-stat">
        <div class="ping-stat-value" id="ping-received">0</div>
        <div class="ping-stat-label">已收到</div>
      </div>
      <div class="ping-stat">
        <div class="ping-stat-value" id="ping-loss">0%</div>
        <div class="ping-stat-label">丢包率</div>
      </div>
      <div class="ping-stat">
        <div class="ping-stat-value" id="ping-avg">-</div>
        <div class="ping-stat-label">平均延迟</div>
      </div>
    </div>
    <div class="ping-chart" id="ping-chart"></div>
    <div class="trace-results" id="ping-log" style="max-height: 150px;"></div>
  `;

  document.getElementById("stop-ping-btn")?.addEventListener("click", stopPingMonitor);
  pingBtn.textContent = "⏹ 停止";

  // 持续 Ping 函数
  const doPing = async () => {
    try {
      const result: PingOneResult = await invoke("tauri_ping_one", { ip, seq: sent });
      sent++;

      if (result.success && result.time_ms) {
        received++;
        times.push(result.time_ms);
        pingHistory.push({ time: Date.now(), ms: result.time_ms });
      } else {
        pingHistory.push({ time: Date.now(), ms: null });
      }

      // 保留最近 60 条记录
      if (pingHistory.length > 60) pingHistory.shift();
      if (times.length > 60) times.shift();

      // 更新统计
      const avgMs = times.length > 0 ? times.reduce((a, b) => a + b, 0) / times.length : 0;
      const lossRate = sent > 0 ? ((sent - received) / sent * 100).toFixed(1) : "0";

      const sentEl = document.getElementById("ping-sent");
      const receivedEl = document.getElementById("ping-received");
      const lossEl = document.getElementById("ping-loss");
      const avgEl = document.getElementById("ping-avg");
      const logEl = document.getElementById("ping-log");
      const chartEl = document.getElementById("ping-chart");

      if (sentEl) sentEl.textContent = sent.toString();
      if (receivedEl) receivedEl.textContent = received.toString();
      if (lossEl) lossEl.textContent = lossRate + "%";
      if (avgEl) avgEl.textContent = avgMs.toFixed(1) + "ms";

      // 更新日志
      if (logEl) {
        const status = result.success ? "✅" : "❌";
        const timeStr = result.time_ms ? `${result.time_ms.toFixed(1)}ms` : "timeout";
        logEl.innerHTML = `<div>${status} seq=${result.seq} ${timeStr}</div>` + logEl.innerHTML;
      }

      // 更新图表
      if (chartEl) {
        renderPingChart(chartEl, pingHistory);
      }

      // 更新标题
      const header = portResults.querySelector(".port-results-header");
      if (header) {
        const lossNum = parseFloat(lossRate);
        const quality = lossNum === 0 ? "✅ 优秀" : lossNum < 5 ? "⚠️ 良好" : "❌ 较差";
        header.innerHTML = `Ping ${ip} - ${quality} <button class="btn-secondary" id="stop-ping-btn" style="margin-left: auto;">⏹ 停止</button>`;
        document.getElementById("stop-ping-btn")?.addEventListener("click", stopPingMonitor);
      }
    } catch (error) {
      console.error("Ping error:", error);
    }
  };

  // 立即执行一次
  await doPing();

  // 设置间隔
  pingMonitorInterval = window.setInterval(doPing, 1000);
}

function stopPingMonitor() {
  if (pingMonitorInterval) {
    clearInterval(pingMonitorInterval);
    pingMonitorInterval = null;
  }
  pingBtn.textContent = "📡 Ping";
}

function renderPingChart(container: HTMLElement, history: { time: number; ms: number | null }[]) {
  const width = container.clientWidth || 300;
  const height = 60;
  const maxMs = Math.max(100, ...history.filter(h => h.ms !== null).map(h => h.ms!));

  let svg = `<svg width="${width}" height="${height}" style="background: var(--command-bg); border-radius: 4px;">`;

  const barWidth = Math.max(2, (width - 10) / 60);
  const gap = 1;

  history.forEach((h, i) => {
    const x = 5 + i * (barWidth + gap);
    if (h.ms !== null) {
      const barHeight = (h.ms / maxMs) * (height - 10);
      const y = height - 5 - barHeight;
      const color = h.ms < 50 ? "var(--green)" : h.ms < 100 ? "var(--orange)" : "var(--red)";
      svg += `<rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" fill="${color}" rx="1"/>`;
    } else {
      svg += `<rect x="${x}" y="${height - 15}" width="${barWidth}" height="10" fill="var(--red)" opacity="0.5" rx="1"/>`;
    }
  });

  svg += `</svg>`;
  container.innerHTML = svg;
}

async function runTraceroute() {
  if (!selectedDevice) return;

  traceBtn.disabled = true;
  traceBtn.textContent = "⏳ 追踪中...";
  portResults.innerHTML = `<div class="loading">正在追踪到 ${selectedDevice.ip} 的路由...</div>`;

  try {
    const result: TracerouteResult = await invoke("tauri_traceroute", { ip: selectedDevice.ip });

    const hopsHtml = result.hops.map(hop => `
      <div class="port-result-item">
        <span class="port-number">${hop.hop}</span>
        <span class="port-service">${hop.ip || "*"}</span>
        <span class="port-status ${hop.ip ? 'open' : 'closed'}">${hop.time_ms ? hop.time_ms.toFixed(1) + 'ms' : '*'}</span>
      </div>
    `).join("");

    portResults.innerHTML = `
      <div class="port-results-header">
        Traceroute 到 ${result.target} - 共 ${result.hops.length} 跳
      </div>
      <div class="port-results-list">
        ${hopsHtml || '<div class="empty-state"><div class="icon">🔀</div><div>无路由信息</div></div>'}
      </div>
      <div class="trace-results">${escapeHtml(result.raw_output)}</div>
    `;
  } catch (error) {
    console.error("Traceroute failed:", error);
    portResults.innerHTML = `<div class="empty-state"><div class="icon">❌</div><div>Traceroute 失败</div></div>`;
  } finally {
    traceBtn.disabled = false;
    traceBtn.textContent = "🔀 Traceroute";
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ===== 多设备频谱图监测 =====
interface DevicePingData {
  ip: string;
  history: (number | null)[];
  lastMs: number | null;
  sent: number;
  received: number;
}

let multiPingInterval: number | null = null;
let multiPingDevices: Map<string, DevicePingData> = new Map();
const multiPingBtn = document.getElementById("multi-ping-btn") as HTMLButtonElement;

async function runMultiPing() {
  if (multiPingInterval) {
    stopMultiPing();
    return;
  }

  if (discoveredDevices.length === 0) {
    portResults.innerHTML = `<div class="empty-state"><div class="icon">⚠️</div><div>请先扫描设备</div></div>`;
    return;
  }

  // 初始化所有设备的数据
  multiPingDevices.clear();
  for (const device of discoveredDevices) {
    multiPingDevices.set(device.ip, {
      ip: device.ip,
      history: [],
      lastMs: null,
      sent: 0,
      received: 0,
    });
  }

  multiPingBtn.textContent = "⏹ 停止监测";

  // 初始化显示
  renderMultiPingUI();

  // 开始并行 Ping
  const doPingAll = async () => {
    const promises = Array.from(multiPingDevices.keys()).map(async (ip) => {
      const data = multiPingDevices.get(ip)!;
      try {
        const result: PingOneResult = await invoke("tauri_ping_one", { ip, seq: data.sent });
        data.sent++;

        if (result.success && result.time_ms) {
          data.received++;
          data.lastMs = result.time_ms;
          data.history.push(result.time_ms);
        } else {
          data.lastMs = null;
          data.history.push(null);
        }

        // 保留最近 60 条
        if (data.history.length > 60) data.history.shift();
      } catch {
        data.history.push(null);
      }
    });

    await Promise.all(promises);
    renderSpectrumChart();
  };

  await doPingAll();
  multiPingInterval = window.setInterval(doPingAll, 1000);
}

function stopMultiPing() {
  if (multiPingInterval) {
    clearInterval(multiPingInterval);
    multiPingInterval = null;
  }
  multiPingBtn.textContent = "📊 多设备监测";
}

function renderMultiPingUI() {
  const deviceCount = multiPingDevices.size;

  portResults.innerHTML = `
    <div class="port-results-header">
      📊 多设备网络质量监测 - ${deviceCount} 台设备
      <button class="btn-secondary" id="stop-multi-btn" style="margin-left: auto;">⏹ 停止</button>
    </div>
    <div class="spectrum-container" id="spectrum-container">
      <canvas id="spectrum-canvas" width="600" height="300"></canvas>
    </div>
    <div class="spectrum-legend" id="spectrum-legend"></div>
  `;

  document.getElementById("stop-multi-btn")?.addEventListener("click", stopMultiPing);
}

function renderSpectrumChart() {
  const canvas = document.getElementById("spectrum-canvas") as HTMLCanvasElement;
  const legendEl = document.getElementById("spectrum-legend");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const devices = Array.from(multiPingDevices.values());
  const width = canvas.width;
  const height = canvas.height;
  const deviceHeight = Math.floor((height - 40) / Math.max(devices.length, 1));
  const maxHistory = 60;

  // 清除画布
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--command-bg') || '#1a1a2e';
  ctx.fillRect(0, 0, width, height);

  // 绘制标题
  ctx.fillStyle = '#888';
  ctx.font = '12px SF Mono, Monaco, monospace';
  ctx.fillText('延迟 (ms) - 时间轴 →', 10, 15);

  // 绘制每个设备的频谱行
  devices.forEach((device, deviceIndex) => {
    const y = 25 + deviceIndex * deviceHeight;
    const barWidth = (width - 100) / maxHistory;

    // 设备 IP 标签
    ctx.fillStyle = '#aaa';
    ctx.font = '10px SF Mono, Monaco, monospace';
    const shortIp = device.ip.split('.').slice(-1)[0];
    ctx.fillText(`.${shortIp}`, 5, y + deviceHeight / 2 + 3);

    // 绘制历史数据条
    device.history.forEach((ms, i) => {
      const x = 35 + i * barWidth;
      const barHeight = deviceHeight - 4;

      if (ms !== null) {
        // 根据延迟选择颜色 (频谱风格)
        const hue = Math.max(0, 120 - ms * 1.2); // 绿(120) -> 红(0)
        const saturation = 80;
        const lightness = 50 + Math.min(ms / 5, 20);
        ctx.fillStyle = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
      } else {
        // 超时用深红色
        ctx.fillStyle = 'rgba(255, 59, 48, 0.3)';
      }

      ctx.fillRect(x, y, barWidth - 1, barHeight);
    });

    // 当前延迟值
    const lastMs = device.lastMs;
    ctx.fillStyle = lastMs !== null ? '#0f0' : '#f00';
    ctx.font = 'bold 10px SF Mono, Monaco, monospace';
    const msText = lastMs !== null ? `${lastMs.toFixed(0)}ms` : 'X';
    ctx.fillText(msText, width - 45, y + deviceHeight / 2 + 3);
  });

  // 绘制色标
  if (legendEl) {
    const stats = devices.map(d => ({
      ip: d.ip,
      avg: d.history.filter(m => m !== null).length > 0
        ? (d.history.filter(m => m !== null) as number[]).reduce((a, b) => a + b, 0) / d.history.filter(m => m !== null).length
        : null,
      loss: d.sent > 0 ? ((d.sent - d.received) / d.sent * 100).toFixed(1) : '0',
    }));

    legendEl.innerHTML = `
      <div style="display: flex; gap: 8px; flex-wrap: wrap; font-size: 11px; padding: 8px;">
        <span style="color: var(--green);">■ &lt;30ms</span>
        <span style="color: var(--orange);">■ 30-80ms</span>
        <span style="color: var(--red);">■ &gt;80ms</span>
        <span style="color: rgba(255,59,48,0.5);">■ 超时</span>
        <span style="margin-left: auto; color: var(--text-secondary);">
          最佳: ${stats.filter(s => s.avg !== null).sort((a, b) => (a.avg || 999) - (b.avg || 999))[0]?.ip || '-'}
        </span>
      </div>
    `;
  }
}

pingBtn.addEventListener("click", runPing);
traceBtn.addEventListener("click", runTraceroute);
multiPingBtn?.addEventListener("click", runMultiPing);

// ===== 独立监测页面 =====
const monitorSubnet = document.getElementById("monitor-subnet") as HTMLSelectElement;
const startMonitorBtn = document.getElementById("start-monitor-btn") as HTMLButtonElement;
const stopMonitorBtn = document.getElementById("stop-monitor-btn") as HTMLButtonElement;
const monitorCanvas = document.getElementById("monitor-canvas") as HTMLCanvasElement;
const deviceGrid = document.getElementById("device-grid") as HTMLDivElement;

interface MonitorDevice {
  ip: string;
  history: (number | null)[];
  lastMs: number | null;
  sent: number;
  received: number;
}

let monitorInterval: number | null = null;
let monitorDevices: Map<string, MonitorDevice> = new Map();

async function initMonitorPage() {
  // 加载网络接口
  try {
    const interfaces: NetworkInterface[] = await invoke("tauri_get_interfaces");
    monitorSubnet.innerHTML = '<option value="">选择网段...</option>';
    interfaces.forEach((iface) => {
      if (iface.ip && !iface.ip.startsWith("127.")) {
        const subnet = iface.ip.split(".").slice(0, 3).join(".") + ".0/24";
        const opt = document.createElement("option");
        opt.value = subnet;
        opt.textContent = `${iface.name} - ${subnet}`;
        monitorSubnet.appendChild(opt);
      }
    });
  } catch (error) {
    console.error("Failed to load interfaces:", error);
  }

  // 初始渲染 canvas（显示提示信息）
  renderMonitorCanvas();
}

async function startMonitor() {
  const subnet = monitorSubnet.value;
  if (!subnet) {
    alert("请选择网段");
    return;
  }

  startMonitorBtn.style.display = "none";
  stopMonitorBtn.style.display = "block";
  monitorDevices.clear();

  // 先扫描设备
  try {
    const devices: NetworkDevice[] = await invoke("tauri_discover_devices", { subnet });
    devices.forEach((d) => {
      monitorDevices.set(d.ip, {
        ip: d.ip,
        history: [],
        lastMs: null,
        sent: 0,
        received: 0,
      });
    });
    updateMonitorStats();
    renderDeviceGrid();
  } catch (error) {
    console.error("Failed to discover devices:", error);
    stopMonitor();
    return;
  }

  // 开始批量 Ping（分批执行避免卡顿）
  const doPingBatch = async () => {
    const devices = Array.from(monitorDevices.keys());
    const batchSize = 5; // 每批 5 个设备

    for (let i = 0; i < devices.length; i += batchSize) {
      const batch = devices.slice(i, i + batchSize);
      await Promise.all(batch.map(async (ip) => {
        const data = monitorDevices.get(ip)!;
        try {
          const result: PingOneResult = await invoke("tauri_ping_one", { ip, seq: data.sent });
          data.sent++;
          if (result.success && result.time_ms) {
            data.received++;
            data.lastMs = result.time_ms;
            data.history.push(result.time_ms);
          } else {
            data.lastMs = null;
            data.history.push(null);
          }
          if (data.history.length > 60) data.history.shift();
        } catch {
          data.history.push(null);
        }
      }));
    }

    updateMonitorStats();
    renderMonitorCanvas();
    renderDeviceGrid();
  };

  await doPingBatch();
  monitorInterval = window.setInterval(doPingBatch, 2000); // 每 2 秒一轮
}

function stopMonitor() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }
  startMonitorBtn.style.display = "block";
  stopMonitorBtn.style.display = "none";
}

function updateMonitorStats() {
  const devices = Array.from(monitorDevices.values());
  const online = devices.filter((d) => d.lastMs !== null);
  const latencies = online.map((d) => d.lastMs!).filter((m) => m !== null);
  const avgLatency = latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
  const best = online.sort((a, b) => (a.lastMs || 999) - (b.lastMs || 999))[0];

  const el = (id: string) => document.getElementById(id);
  if (el("mon-devices")) el("mon-devices")!.textContent = devices.length.toString();
  if (el("mon-online")) el("mon-online")!.textContent = online.length.toString();
  if (el("mon-avg-latency")) el("mon-avg-latency")!.textContent = avgLatency > 0 ? avgLatency.toFixed(1) + "ms" : "-";
  if (el("mon-best")) el("mon-best")!.textContent = best ? best.ip.split(".").pop()! : "-";
}

function renderMonitorCanvas() {
  if (!monitorCanvas) return;
  const ctx = monitorCanvas.getContext("2d");
  if (!ctx) return;

  // 高 DPI 支持
  const dpr = window.devicePixelRatio || 1;
  const rect = monitorCanvas.getBoundingClientRect();

  // 如果容器尺寸为 0，跳过渲染
  if (rect.width === 0 || rect.height === 0) return;

  const logicalWidth = rect.width;
  const logicalHeight = rect.height;
  const physicalWidth = Math.floor(rect.width * dpr);
  const physicalHeight = Math.floor(rect.height * dpr);

  // 检查是否需要调整 canvas 尺寸
  if (monitorCanvas.width !== physicalWidth || monitorCanvas.height !== physicalHeight) {
    monitorCanvas.width = physicalWidth;
    monitorCanvas.height = physicalHeight;
  }

  // 每次渲染前重置变换矩阵，然后应用 DPI 缩放
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const devices = Array.from(monitorDevices.values());
  const maxHistory = 60;

  // 清除背景
  ctx.fillStyle = "#1a1a2e";
  ctx.fillRect(0, 0, logicalWidth, logicalHeight);

  // 如果没有设备，显示提示信息
  if (devices.length === 0) {
    ctx.fillStyle = "#666";
    ctx.font = "14px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("选择网段并点击开始监测", logicalWidth / 2, logicalHeight / 2);
    ctx.textAlign = "left";
    return;
  }

  // 标题
  ctx.fillStyle = "#888";
  ctx.font = "12px SF Mono, Monaco, monospace";
  ctx.fillText("网络延迟频谱图 - 时间轴 →", 10, 20);

  const deviceHeight = Math.max(12, Math.floor((logicalHeight - 50) / devices.length));
  const barWidth = Math.max(2, (logicalWidth - 80) / maxHistory);

  devices.forEach((device, idx) => {
    const y = 35 + idx * deviceHeight;

    // IP标签
    ctx.fillStyle = "#888";
    ctx.font = "10px SF Mono, Monaco, monospace";
    const ipLabel = "." + device.ip.split(".").pop();
    ctx.fillText(ipLabel, 5, y + deviceHeight / 2 + 3);

    // 频谱条 - 从右侧向左绘制最新数据
    device.history.forEach((ms, i) => {
      const x = 40 + i * barWidth;
      if (ms !== null) {
        // 绿色(120) -> 黄色(60) -> 红色(0)
        const hue = Math.max(0, Math.min(120, 120 - ms * 1.5));
        ctx.fillStyle = `hsl(${hue}, 85%, 50%)`;
      } else {
        ctx.fillStyle = "rgba(255, 59, 48, 0.4)";
      }
      ctx.fillRect(x, y, Math.max(1, barWidth - 1), deviceHeight - 2);
    });

    // 当前延迟值
    const msText = device.lastMs !== null ? device.lastMs.toFixed(0) + "ms" : "超时";
    ctx.fillStyle = device.lastMs !== null ? "#00ff88" : "#ff3b30";
    ctx.font = "bold 10px SF Mono, Monaco, monospace";
    ctx.fillText(msText, logicalWidth - 40, y + deviceHeight / 2 + 3);
  });
}

function renderDeviceGrid() {
  if (!deviceGrid) return;
  const devices = Array.from(monitorDevices.values());

  deviceGrid.innerHTML = devices.map((d) => `
    <div class="device-card ${d.lastMs !== null ? 'online' : 'offline'}">
      <span>.${d.ip.split(".").pop()}</span>
      <span class="device-latency" style="color: ${d.lastMs !== null ? 'var(--green)' : 'var(--red)'}">
        ${d.lastMs !== null ? d.lastMs.toFixed(0) + 'ms' : '×'}
      </span>
    </div>
  `).join("");
}

startMonitorBtn?.addEventListener("click", startMonitor);
stopMonitorBtn?.addEventListener("click", stopMonitor);

// ===== 初始化 =====
window.addEventListener("DOMContentLoaded", () => {
  scanPorts();
});

