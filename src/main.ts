import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { toCommandErrorMessage, formatCommandErrorMessage } from "./error-utils";
import { showToast } from "./ui-feedback";
import {
  buildSubnetScanEstimateMessage,
  estimateScanDurationSeconds,
  getSubnetInput,
  isValidSubnetRange,
} from "./network-utils";
import {
  buildDiscoverDevicesLoadingHtml,
  buildMonitorLoadingHtml,
  DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE,
  applyMonitorTimeoutFallback,
  setMonitorErrorState,
  setDiscoverDevicesIdleState,
  setDiscoverDevicesLoadingState,
  setDiscoverDevicesErrorState,
  setMonitorStartState,
  setMonitorStopState,
  startMonitorLoadingTimer,
  stopMonitorLoadingTimer,
  startMonitorStartupTimeout,
  stopMonitorStartupTimeout,
  setPortScanIdleState,
  setPortScanLoadingState,
  setPortScanErrorState,
} from "./scan-ui-state";

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

// ===== 进程管理类型 =====
interface KillResult {
  success: boolean;
  pid: number;
  message: string;
}

interface ProcessInfo {
  pid: number;
  name: string;
  is_system: boolean;
}

// ===== 导出类型 =====
interface ExportResult {
  success: boolean;
  path: string | null;
  message: string;
  record_count: number;
}

interface HistorySummary {
  timestamp: string;
  port_count: number;
  scan_duration_ms: number;
}

// ===== DNS 查询类型 =====
interface DnsRecord {
  name: string;
  rtype: string;
  ttl: number;
  data: string;
}

interface DnsQueryResult {
  domain: string;
  record_type: string;
  records: DnsRecord[];
  query_time_ms: number;
  dns_server: string;
  error: string | null;
}

// ===== Whois 类型 =====
interface WhoisResult {
  domain: string;
  registrar: string | null;
  created: string | null;
  expires: string | null;
  updated: string | null;
  status: string[];
  nameservers: string[];
  dnssec: string | null;
  raw_output: string;
  error: string | null;
}

// ===== SSL 证书类型 =====
interface CertChainItem {
  subject: string;
  issuer: string;
  is_self_signed: boolean;
}

interface SslCertInfo {
  host: string;
  port: number;
  subject: string;
  issuer: string;
  valid_from: string;
  valid_until: string;
  is_valid: boolean;
  is_expired: boolean;
  is_self_signed: boolean;
  days_until_expiry: number;
  signature_algorithm: string;
  version: string;
  serial_number: string;
  key_size: number | null;
  certificate_chain: CertChainItem[];
  tls_version: string;
  cipher_suite: string | null;
  error: string | null;
}

// ===== DOM 元素 =====
// Tab 切换
const tabLocal = document.getElementById("tab-local") as HTMLButtonElement;
const tabNetwork = document.getElementById("tab-network") as HTMLButtonElement;
const tabMonitor = document.getElementById("tab-monitor") as HTMLButtonElement;
const tabDns = document.getElementById("tab-dns") as HTMLButtonElement;
const tabWhois = document.getElementById("tab-whois") as HTMLButtonElement;
const tabSsl = document.getElementById("tab-ssl") as HTMLButtonElement;
const pageLocal = document.getElementById("page-local") as HTMLDivElement;
const pageNetwork = document.getElementById("page-network") as HTMLDivElement;
const pageMonitor = document.getElementById("page-monitor") as HTMLDivElement;
const pageDns = document.getElementById("page-dns") as HTMLDivElement;
const pageWhois = document.getElementById("page-whois") as HTMLDivElement;
const pageSsl = document.getElementById("page-ssl") as HTMLDivElement;

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
const manualSubnetInput = document.getElementById("manual-subnet") as HTMLInputElement;
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
let currentPage: "local" | "network" | "monitor" | "dns" | "whois" | "ssl" = "local";
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
function switchPage(page: "local" | "network" | "monitor" | "dns" | "whois" | "ssl") {
  currentPage = page;

  // 清除所有 Tab 的 active 状态
  tabLocal.classList.remove("active");
  tabNetwork.classList.remove("active");
  tabMonitor?.classList.remove("active");
  tabDns?.classList.remove("active");
  tabWhois?.classList.remove("active");
  tabSsl?.classList.remove("active");

  // 隐藏所有页面
  pageLocal.classList.add("hidden");
  pageNetwork.classList.add("hidden");
  pageMonitor?.classList.add("hidden");
  pageDns?.classList.add("hidden");
  pageWhois?.classList.add("hidden");
  pageSsl?.classList.add("hidden");

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
  } else if (page === "dns") {
    tabDns?.classList.add("active");
    pageDns?.classList.remove("hidden");
  } else if (page === "whois") {
    tabWhois?.classList.add("active");
    pageWhois?.classList.remove("hidden");
  } else if (page === "ssl") {
    tabSsl?.classList.add("active");
    pageSsl?.classList.remove("hidden");
  }
}

tabLocal.addEventListener("click", () => switchPage("local"));
tabNetwork.addEventListener("click", () => switchPage("network"));
tabMonitor?.addEventListener("click", () => switchPage("monitor"));
tabDns?.addEventListener("click", () => switchPage("dns"));
tabWhois?.addEventListener("click", () => switchPage("whois"));
tabSsl?.addEventListener("click", () => switchPage("ssl"));

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

    // 保存结果用于导出
    lastScanResult = result;
    lastFilteredPorts = filteredPorts;

    if (currentView === "table") {
      renderTable(filteredPorts, includeCommand, dockerPorts);
    }

  } catch (error) {
    reportCommandError("扫描本地端口", error);
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

    // 创建各个单元格
    const cellPort = document.createElement("td");
    cellPort.className = "cell-port";
    cellPort.innerHTML = `
      <span class="port-type-icon">${typeIcon}</span>
      <span class="port-number">${p.port}</span>
      <span class="port-service-tag" title="${service.name}">${service.icon} ${service.name}</span>
    `;

    const cellProtocol = document.createElement("td");
    cellProtocol.innerHTML = `<span class="cell-protocol ${p.protocol.toLowerCase()}">${p.protocol}</span>`;

    const cellAddress = document.createElement("td");
    cellAddress.className = "cell-address";
    cellAddress.textContent = p.address;

    const cellPid = document.createElement("td");
    cellPid.className = "cell-pid";
    cellPid.textContent = p.pid;

    const cellProcess = document.createElement("td");
    cellProcess.className = "cell-process";
    cellProcess.innerHTML = processDisplay;

    const cellActions = document.createElement("td");
    cellActions.className = "cell-actions";

    // 创建打开按钮
    if (service.canOpen) {
      const openBtn = document.createElement("button");
      openBtn.className = "port-open-btn action-btn";
      openBtn.title = "在浏览器中打开";
      openBtn.textContent = "🔗";
      openBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const url = `${service.protocol}://localhost:${p.port}`;
        try {
          await openUrl(url);
        } catch (error) {
        reportCommandError("打开端口链接", error);
          window.open(url, "_blank");
        }
      });
      cellActions.appendChild(openBtn);
    }

    // 创建终止按钮
    const killBtn = document.createElement("button");
    killBtn.className = "port-kill-btn action-btn";
    killBtn.title = "终止进程";
    killBtn.textContent = "🔴";
    killBtn.onclick = async (e) => {
      console.log("=== KILL BUTTON CLICKED ===", p.pid, p.process);
      e.preventDefault();
      e.stopPropagation();

      const pid = parseInt(p.pid);
      if (isNaN(pid) || pid === 0) {
        showToast("❌ 无效的进程 ID", "error");
        return;
      }

      const confirmed = confirm(`确定要终止进程 "${p.process}" (PID: ${pid}, 端口: ${p.port}) 吗？\n\n此操作不可撤销。`);
      if (!confirmed) return;

      try {
        const result: KillResult = await invoke("tauri_kill_process", { pid, force: false });
        if (result.success) {
          await scanPorts();
          showToast(`✅ ${result.message}`, "success");
        } else {
          showToast(`❌ ${result.message}`, "error");
        }
      } catch (error) {
        reportCommandError("终止进程", error);
      }
    };
    console.log("Kill button created for PID:", p.pid);
    cellActions.appendChild(killBtn);

    // 组装行
    row.appendChild(cellPort);
    row.appendChild(cellProtocol);
    row.appendChild(cellAddress);
    row.appendChild(cellPid);
    row.appendChild(cellProcess);
    row.appendChild(cellActions);
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
}

// 初始化表格点击事件（只执行一次）
let tableClickHandlerInitialized = false;
function initTableClickHandler() {
  if (tableClickHandlerInitialized) return;
  tableClickHandlerInitialized = true;

  portTbody.addEventListener("click", async (e) => {
    const target = e.target as HTMLElement;
    console.log("Click detected on:", target.tagName, target.className);

    // 处理打开按钮
    const openBtn = target.closest(".port-open-btn") as HTMLElement;
    if (openBtn) {
      e.preventDefault();
      e.stopPropagation();
      const port = openBtn.dataset.port;
      const protocol = openBtn.dataset.protocol || "http";
      const url = `${protocol}://localhost:${port}`;
      console.log("Open URL:", url);
      try {
        await openUrl(url);
      } catch (error) {
        reportCommandError("打开端口链接", error);
        window.open(url, "_blank");
      }
      return;
    }

    // 处理终止进程按钮
    const killBtn = target.closest(".port-kill-btn") as HTMLElement;
    if (killBtn) {
      e.preventDefault();
      e.stopPropagation();
      console.log("Kill button clicked!", killBtn.dataset);

      const pid = parseInt(killBtn.dataset.pid || "0");
      const port = killBtn.dataset.port;
      const processName = killBtn.dataset.process;

      if (pid === 0) {
        console.log("PID is 0, skipping");
        return;
      }

      // 确认对话框
      const confirmed = confirm(`确定要终止进程 "${processName}" (PID: ${pid}, 端口: ${port}) 吗？\n\n此操作不可撤销。`);
      if (!confirmed) return;

      try {
        const result: KillResult = await invoke("tauri_kill_process", { pid, force: false });
        if (result.success) {
          // 刷新端口列表
          await scanPorts();
          showToast(`✅ ${result.message}`, "success");
        } else {
          showToast(`❌ ${result.message}`, "error");
        }
      } catch (error) {
        reportCommandError("终止进程", error);
      }
    }
  });

  console.log("Table click handler initialized on:", portTbody);
}

// 在页面加载时初始化
initTableClickHandler();

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
    reportCommandError("扫描应用分组", error);
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

function isValidHost(input: string): boolean {
  const value = input.trim().toLowerCase();
  if (!value) return false;

  if (value === "localhost") return true;

  // IPv4 校验
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(value)) {
    return value.split('.').every((part) => {
      const n = Number(part);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }

  if (!/^[a-z0-9.-]+$/.test(value)) return false;
  if (value.startsWith('-') || value.endsWith('-') || value.startsWith('.') || value.endsWith('.')) return false;
  if (value.includes('..')) return false;

  const labels = value.split('.');
  if (labels.length < 1) return false;
  return labels.every((label) => {
    if (!label || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    return true;
  });
}

function parsePort(input: string): number | null {
  const value = input.trim();
  if (!/^\d+$/.test(value)) return null;

  const num = Number.parseInt(value, 10);
  if (!Number.isInteger(num) || num < 1 || num > 65535) return null;
  return num;
}

function parsePortRange(startInput: string, endInput: string, defaultStart = 1, defaultEnd = 1000): { start: number; end: number } | null {
  const start = startInput.trim() ? parsePort(startInput) : defaultStart;
  const end = endInput.trim() ? parsePort(endInput) : defaultEnd;

  if (start === null || end === null) return null;
  if (start > end) return null;
  return { start, end };
}

function reportCommandError(action: string, error: unknown): void {
  const formatted = formatCommandErrorMessage(action, error);
  console.error(`${action} 失败:`, error);
  showToast(formatted, "error");
}

// ===== 导出功能 =====
let lastScanResult: ScanResult | null = null;
let lastFilteredPorts: PortInfo[] = [];

async function exportData(format: "csv" | "json" | "txt") {
  if (lastFilteredPorts.length === 0) {
    showToast("没有可导出的数据，请先扫描端口", "error");
    return;
  }

  try {
    const result: ExportResult = await invoke("tauri_export_auto", {
      ports: lastFilteredPorts,
      scanResult: lastScanResult || { scan_time: new Date().toISOString(), total_ports: lastFilteredPorts.length, unique_apps: 0, ports: lastFilteredPorts, scan_time_ms: 0 },
      format
    });

    if (result.success) {
      showToast(`✅ ${result.message}\n📁 ${result.path}`, "success");
    } else {
      showToast(`❌ ${result.message}`, "error");
    }
  } catch (error) {
    reportCommandError("导出数据", error);
  }
}

// 绑定导出按钮事件
document.addEventListener("DOMContentLoaded", () => {
  const exportBtn = document.getElementById("export-btn");
  const exportMenu = document.getElementById("export-menu");

  exportBtn?.addEventListener("click", () => {
    exportMenu?.classList.toggle("visible");
  });

  document.getElementById("export-csv")?.addEventListener("click", () => {
    exportData("csv");
    exportMenu?.classList.remove("visible");
  });

  document.getElementById("export-json")?.addEventListener("click", () => {
    exportData("json");
    exportMenu?.classList.remove("visible");
  });

  document.getElementById("export-txt")?.addEventListener("click", () => {
    exportData("txt");
    exportMenu?.classList.remove("visible");
  });

  // 点击其他地方关闭菜单
  document.addEventListener("click", (e) => {
    if (!exportBtn?.contains(e.target as Node) && !exportMenu?.contains(e.target as Node)) {
      exportMenu?.classList.remove("visible");
    }
  });
});

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
    manualSubnetInput.value = "";
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
    reportCommandError("加载网络接口", error);
  }
}

async function discoverDevices() {
  const subnet = getSubnetInput(subnetSelect.value, manualSubnetInput.value, "");
  if (!subnet) return;

  if (!isValidSubnetRange(subnet)) {
    showToast("⚠️ 子网格式应为 IPv4 CIDR，当前支持 /22~24（如 192.168.1.0/24）", "warning");
    return;
  }

  const rangeEstimateMessage = buildSubnetScanEstimateMessage(subnet);
  if (rangeEstimateMessage) {
    showToast(`⚠️ ${rangeEstimateMessage}`, "warning");
  }
  const estimateSeconds = estimateScanDurationSeconds(subnet);
  const scanStartAt = Date.now();
  const loadingBase = "正在扫描局域网设备...";
  let loadingTimer: number | null = null;

  const buildLoadingHtml = () =>
    buildDiscoverDevicesLoadingHtml(
      loadingBase,
      scanStartAt,
      estimateSeconds,
      rangeEstimateMessage,
    );
  setDiscoverDevicesLoadingState(scanDevicesBtn, deviceList, buildLoadingHtml());
  if (rangeEstimateMessage || estimateSeconds) {
    loadingTimer = window.setInterval(() => {
      deviceList.innerHTML = buildLoadingHtml();
    }, 1000);
  }

  try {
    discoveredDevices = await invoke("tauri_discover_devices", { subnet });

    netStatDevices.textContent = discoveredDevices.length.toString();
    deviceCount.textContent = discoveredDevices.length.toString();

    renderDeviceList();
  } catch (error) {
    reportCommandError("扫描局域网设备", error);
    setDiscoverDevicesErrorState(deviceList);
  } finally {
    if (loadingTimer) {
      window.clearInterval(loadingTimer);
      loadingTimer = null;
    }
    setDiscoverDevicesIdleState(scanDevicesBtn);
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
  if (!isValidHost(selectedDevice.ip)) {
    showToast("⚠️ 选中的设备地址不合法", "warning");
    return;
  }

  setPortScanLoadingState(scanPortsBtn, portResults, selectedDevice.ip);

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
      const range = parsePortRange(portStart.value, portEnd.value, 1, 1000);
      if (!range) {
        showToast("⚠️ 请输入合法端口范围（1-65535，起始 ≤ 结束）", "warning");
        return;
      }
      const { start, end } = range;
      ports = await invoke("tauri_scan_ports_range", {
        ip: selectedDevice.ip,
        start,
        end,
        timeoutMs: 300
      });
    }

    renderPortResults(ports);
  } catch (error) {
    reportCommandError("远程端口扫描", error);
    setPortScanErrorState(portResults);
  } finally {
    setPortScanIdleState(scanPortsBtn);
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
    showToast("⚠️ 请输入 IP 地址或域名", "warning");
    return;
  }
  if (!isValidHost(target)) {
    showToast("⚠️ 请输入有效的 IP 或域名", "warning");
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
    reportCommandError("解析目标", error);
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
  if (!isValidHost(selectedDevice.ip)) {
    showToast("⚠️ 选中的设备地址不合法", "warning");
    return;
  }

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
      reportCommandError("Ping", error);
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
  if (!isValidHost(selectedDevice.ip)) {
    showToast("⚠️ 选中的设备地址不合法", "warning");
    return;
  }

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
    reportCommandError("Traceroute", error);
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
    if (!isValidHost(device.ip)) continue;
    multiPingDevices.set(device.ip, {
      ip: device.ip,
      history: [],
      lastMs: null,
      sent: 0,
      received: 0,
    });
  }
  if (multiPingDevices.size === 0) {
    showToast("⚠️ 当前列表中未找到可用 IP", "warning");
    return;
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
const monitorManualSubnetInput = document.getElementById("monitor-manual-subnet") as HTMLInputElement;
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
let monitorLoadingInterval: number | null = null;
let monitorStartupTimeout: number | null = null;
let monitorSessionId = 0;
let monitorDevices: Map<string, MonitorDevice> = new Map();

async function initMonitorPage() {
  // 加载网络接口
  try {
    monitorManualSubnetInput.value = "";
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
    reportCommandError("加载监测网段", error);
  }

  // 初始渲染 canvas（显示提示信息）
  renderMonitorCanvas();
}

async function startMonitor() {
  const subnet = getSubnetInput(monitorSubnet.value, monitorManualSubnetInput.value, "");
  if (!subnet) {
    showToast("⚠️ 请选择网段", "warning");
    return;
  }
  if (!isValidSubnetRange(subnet)) {
    showToast("⚠️ 监测网段支持 IPv4 CIDR /22~24（如 192.168.1.0/24）", "warning");
    return;
  }

  const rangeEstimateMessage = buildSubnetScanEstimateMessage(subnet);
  if (rangeEstimateMessage) {
    showToast(`⚠️ ${rangeEstimateMessage}`, "warning");
  }
  const estimateSeconds = estimateScanDurationSeconds(subnet);
  const currentSessionId = ++monitorSessionId;
  const monitorStartAt = Date.now();

  setMonitorStartState(startMonitorBtn, stopMonitorBtn);
  monitorDevices.clear();
  monitorLoadingInterval = stopMonitorLoadingTimer(monitorLoadingInterval);
  monitorStartupTimeout = stopMonitorStartupTimeout(monitorStartupTimeout);
  const monitorLoadingBase = "正在初始化监测目标...";
  const monitorLoadingHint = (estimateSeconds
    ? `当前扫描范围约：${rangeEstimateMessage}`
    : "正在初始化监测目标...");
  const renderMonitorLoading = () => {
    if (!deviceGrid) return "";
    return buildMonitorLoadingHtml(
      monitorLoadingBase,
      monitorStartAt,
      estimateSeconds,
      monitorLoadingHint,
    );
  };
  monitorLoadingInterval = startMonitorLoadingTimer(deviceGrid, renderMonitorLoading, estimateSeconds);
  monitorStartupTimeout = startMonitorStartupTimeout(
    deviceGrid,
    estimateSeconds,
    DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE,
    () => {
      if (currentSessionId !== monitorSessionId) {
        return;
      }
      monitorSessionId = currentSessionId + 1;
      monitorLoadingInterval = stopMonitorLoadingTimer(monitorLoadingInterval);
      monitorStartupTimeout = stopMonitorStartupTimeout(monitorStartupTimeout);
      applyMonitorTimeoutFallback(deviceGrid, startMonitorBtn, stopMonitorBtn, DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE);
    },
  );

  // 先扫描设备
  try {
    const devices: NetworkDevice[] = await invoke("tauri_discover_devices", { subnet });
    if (currentSessionId !== monitorSessionId) {
      return;
    }
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
    monitorLoadingInterval = stopMonitorLoadingTimer(monitorLoadingInterval);
    monitorStartupTimeout = stopMonitorStartupTimeout(monitorStartupTimeout);
  } catch (error) {
    if (currentSessionId !== monitorSessionId) {
      return;
    }
    reportCommandError("监测模式设备发现", error);
    monitorLoadingInterval = stopMonitorLoadingTimer(monitorLoadingInterval);
    monitorStartupTimeout = stopMonitorStartupTimeout(monitorStartupTimeout);
    if (deviceGrid) {
      setMonitorErrorState(deviceGrid);
    }
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
  monitorSessionId += 1;
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }
  monitorLoadingInterval = stopMonitorLoadingTimer(monitorLoadingInterval);
  monitorStartupTimeout = stopMonitorStartupTimeout(monitorStartupTimeout);
  setMonitorStopState(startMonitorBtn, stopMonitorBtn);
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

// ===== Whois 查询 =====
const whoisInput = document.getElementById("whois-input") as HTMLInputElement;
const whoisQueryBtn = document.getElementById("whois-query-btn") as HTMLButtonElement;
const whoisLoading = document.getElementById("whois-loading") as HTMLDivElement;
const whoisError = document.getElementById("whois-error") as HTMLDivElement;
const whoisResults = document.getElementById("whois-results") as HTMLDivElement;

// Whois 结果元素
const whoisDomain = document.getElementById("whois-domain") as HTMLDivElement;
const whoisRegistrar = document.getElementById("whois-registrar") as HTMLDivElement;
const whoisCreated = document.getElementById("whois-created") as HTMLDivElement;
const whoisExpires = document.getElementById("whois-expires") as HTMLDivElement;
const whoisStatus = document.getElementById("whois-status") as HTMLDivElement;
const whoisNameservers = document.getElementById("whois-nameservers") as HTMLDivElement;
const whoisDnssec = document.getElementById("whois-dnssec") as HTMLDivElement;
const whoisDnssecSection = document.getElementById("whois-dnssec-section") as HTMLDivElement;
const whoisRaw = document.getElementById("whois-raw") as HTMLElement;

async function queryWhois() {
  const domain = whoisInput.value.trim();
  if (!domain) {
    showToast("请输入域名", "error");
    return;
  }
  if (!isValidHost(domain)) {
    showToast("⚠️ 请输入有效的域名", "warning");
    return;
  }

  // 显示加载状态
  whoisLoading.classList.remove("hidden");
  whoisError.classList.add("hidden");
  whoisResults.classList.add("hidden");
  whoisQueryBtn.disabled = true;

  try {
    const result: WhoisResult = await invoke("tauri_whois_query", { domain });

    if (result.error) {
      whoisError.textContent = `查询失败: ${result.error}`;
      whoisError.classList.remove("hidden");
      return;
    }

    // 填充结果
    whoisDomain.textContent = result.domain || "-";
    whoisRegistrar.textContent = result.registrar || "-";
    whoisCreated.textContent = formatDate(result.created) || "-";
    whoisExpires.textContent = formatDate(result.expires) || "-";

    // 状态标签
    if (result.status && result.status.length > 0) {
      whoisStatus.innerHTML = result.status
        .map(s => `<span class="whois-tag">${escapeHtml(s)}</span>`)
        .join("");
    } else {
      whoisStatus.innerHTML = `<span class="whois-empty">无状态信息</span>`;
    }

    // 域名服务器
    if (result.nameservers && result.nameservers.length > 0) {
      whoisNameservers.innerHTML = result.nameservers
        .map(ns => `<div class="whois-nameserver-item">${escapeHtml(ns)}</div>`)
        .join("");
    } else {
      whoisNameservers.innerHTML = `<span class="whois-empty">无域名服务器信息</span>`;
    }

    // DNSSEC
    if (result.dnssec) {
      whoisDnssec.textContent = result.dnssec;
      whoisDnssecSection.classList.remove("hidden");
    } else {
      whoisDnssecSection.classList.add("hidden");
    }

    // 原始输出
    whoisRaw.textContent = result.raw_output || "无原始输出";

    // 显示结果
    whoisResults.classList.remove("hidden");
  } catch (error) {
    const msg = toCommandErrorMessage(error);
    reportCommandError("Whois 查询", error);
    whoisError.textContent = `查询失败: ${msg}`;
    whoisError.classList.remove("hidden");
  } finally {
    whoisLoading.classList.add("hidden");
    whoisQueryBtn.disabled = false;
  }
}

function formatDate(dateStr: string | null): string | null {
  if (!dateStr) return null;
  try {
    const date = new Date(dateStr);
    if (!isNaN(date.getTime())) {
      return date.toLocaleDateString("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      });
    }
  } catch {
    // 忽略解析错误
  }
  return dateStr;
}

// 绑定 Whois 事件
whoisQueryBtn?.addEventListener("click", queryWhois);
whoisInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    queryWhois();
  }
});

// ===== SSL 证书检查 =====
const sslHostInput = document.getElementById("ssl-host-input") as HTMLInputElement;
const sslPortInput = document.getElementById("ssl-port-input") as HTMLInputElement;
const sslCheckBtn = document.getElementById("ssl-check-btn") as HTMLButtonElement;
const sslLoading = document.getElementById("ssl-loading") as HTMLDivElement;
const sslError = document.getElementById("ssl-error") as HTMLDivElement;
const sslResults = document.getElementById("ssl-results") as HTMLDivElement;

// SSL 证书结果元素
const sslHost = document.getElementById("ssl-host") as HTMLDivElement;
const sslSubject = document.getElementById("ssl-subject") as HTMLDivElement;
const sslIssuer = document.getElementById("ssl-issuer") as HTMLDivElement;
const sslValidFrom = document.getElementById("ssl-valid-from") as HTMLDivElement;
const sslValidUntil = document.getElementById("ssl-valid-until") as HTMLDivElement;
const sslDaysLeft = document.getElementById("ssl-days-left") as HTMLDivElement;
const sslKeySize = document.getElementById("ssl-key-size") as HTMLDivElement;
const sslSignature = document.getElementById("ssl-signature") as HTMLDivElement;
const sslVersion = document.getElementById("ssl-version") as HTMLDivElement;
const sslSerial = document.getElementById("ssl-serial") as HTMLDivElement;
const sslTlsVersion = document.getElementById("ssl-tls-version") as HTMLDivElement;
const sslCipherSuite = document.getElementById("ssl-cipher-suite") as HTMLDivElement;
const sslChain = document.getElementById("ssl-chain") as HTMLDivElement;
const sslSelfSigned = document.getElementById("ssl-self-signed") as HTMLSpanElement;
const sslStatus = document.getElementById("ssl-status") as HTMLDivElement;

async function checkSslCert() {
  const host = sslHostInput.value.trim();
  const rawPort = sslPortInput.value.trim();
  const port = rawPort ? parsePort(rawPort) : 443;
  if (rawPort && port === null) {
    showToast("⚠️ 请输入 1-65535 的端口", "warning");
    return;
  }

  if (!host) {
    showToast("请输入主机名或 IP 地址", "error");
    return;
  }
  if (!isValidHost(host)) {
    showToast("⚠️ 请输入有效主机地址", "warning");
    return;
  }

  // 显示加载状态
  sslLoading.classList.remove("hidden");
  sslError.classList.add("hidden");
  sslResults.classList.add("hidden");
  sslCheckBtn.disabled = true;

  try {
    const result: SslCertInfo = await invoke("tauri_check_ssl_cert", { host, port });

    if (result.error) {
      sslError.textContent = `检查失败: ${result.error}`;
      sslError.classList.remove("hidden");
      return;
    }

    // 填充基本信息
    sslHost.textContent = `${result.host}:${result.port}`;
    sslSubject.textContent = result.subject || "未知";
    sslIssuer.textContent = result.issuer || "未知";
    sslValidFrom.textContent = result.valid_from || "未知";
    sslValidUntil.textContent = result.valid_until || "未知";

    // 状态和剩余天数
    if (result.is_expired) {
      sslStatus.innerHTML = `<span class="cert-status expired">已过期</span>`;
      sslDaysLeft.innerHTML = `<span class="cert-days expired">已过期 ${Math.abs(result.days_until_expiry)} 天</span>`;
    } else if (result.days_until_expiry <= 30) {
      sslStatus.innerHTML = `<span class="cert-status warning">即将过期</span>`;
      sslDaysLeft.innerHTML = `<span class="cert-days warning">剩余 ${result.days_until_expiry} 天</span>`;
    } else {
      sslStatus.innerHTML = `<span class="cert-status valid">有效</span>`;
      sslDaysLeft.innerHTML = `<span class="cert-days valid">剩余 ${result.days_until_expiry} 天</span>`;
    }

    // 自签名标记
    if (result.is_self_signed) {
      sslSelfSigned.classList.remove("hidden");
    } else {
      sslSelfSigned.classList.add("hidden");
    }

    // 证书详情
    sslKeySize.textContent = result.key_size ? `${result.key_size} 位` : "未知";
    sslSignature.textContent = result.signature_algorithm || "未知";
    sslVersion.textContent = result.version || "未知";
    sslSerial.textContent = result.serial_number || "未知";
    sslTlsVersion.textContent = result.tls_version || "未知";
    sslCipherSuite.textContent = result.cipher_suite || "未获取";

    // 证书链
    if (result.certificate_chain && result.certificate_chain.length > 0) {
      sslChain.innerHTML = result.certificate_chain.map((cert, index) => `
        <div class="cert-chain-item">
          <div class="cert-chain-title">${index === 0 ? "服务器证书" : `中间证书 #${index}`}</div>
          <div class="cert-chain-detail">主体: ${escapeHtml(cert.subject)}</div>
          <div class="cert-chain-detail">颁发者: ${escapeHtml(cert.issuer)}</div>
          ${cert.is_self_signed ? '<span class="cert-tag self-signed">自签名</span>' : ''}
        </div>
      `).join("");
    } else {
      sslChain.innerHTML = `<span class="whois-empty">无证书链信息</span>`;
    }

    // 显示结果
    sslResults.classList.remove("hidden");
  } catch (error) {
    const msg = toCommandErrorMessage(error);
    reportCommandError("SSL 证书检查", error);
    sslError.textContent = `检查失败: ${msg}`;
    sslError.classList.remove("hidden");
  } finally {
    sslLoading.classList.add("hidden");
    sslCheckBtn.disabled = false;
  }
}

// 绑定 SSL 事件
sslCheckBtn?.addEventListener("click", checkSslCert);
sslHostInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    checkSslCert();
  }
});
sslPortInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    checkSslCert();
  }
});

// ===== DNS 查询 =====
const dnsDomainInput = document.getElementById("dns-domain-input") as HTMLInputElement;
const dnsRecordType = document.getElementById("dns-record-type") as HTMLSelectElement;
const dnsServer = document.getElementById("dns-server") as HTMLSelectElement;
const dnsQueryBtn = document.getElementById("dns-query-btn") as HTMLButtonElement;
const dnsLoading = document.getElementById("dns-loading") as HTMLDivElement;
const dnsError = document.getElementById("dns-error") as HTMLDivElement;
const dnsResults = document.getElementById("dns-results") as HTMLDivElement;

// DNS 结果元素
const dnsDomain = document.getElementById("dns-domain") as HTMLDivElement;
const dnsType = document.getElementById("dns-type") as HTMLDivElement;
const dnsCount = document.getElementById("dns-count") as HTMLDivElement;
const dnsTime = document.getElementById("dns-time") as HTMLDivElement;
const dnsRecordsList = document.getElementById("dns-records-list") as HTMLDivElement;

async function queryDns() {
  const domain = dnsDomainInput.value.trim();
  const recordType = dnsRecordType.value;
  const server = dnsServer.value || undefined;

  if (!domain) {
    showToast("请输入域名", "error");
    return;
  }
  if (!isValidHost(domain)) {
    showToast("⚠️ 请输入有效域名", "warning");
    return;
  }
  if (server && !isValidHost(server)) {
    showToast("⚠️ DNS 服务器地址不合法", "warning");
    return;
  }

  // 显示加载状态
  dnsLoading.classList.remove("hidden");
  dnsError.classList.add("hidden");
  dnsResults.classList.add("hidden");
  dnsQueryBtn.disabled = true;

  try {
    const result: DnsQueryResult = await invoke("tauri_dns_query", {
      domain,
      recordType,
      dnsServer: server,
    });

    if (result.error) {
      dnsError.textContent = `查询失败: ${result.error}`;
      dnsError.classList.remove("hidden");
      return;
    }

    // 填充结果
    dnsDomain.textContent = result.domain;
    dnsType.textContent = result.record_type;
    dnsCount.textContent = result.records.length.toString();
    dnsTime.textContent = `${result.query_time_ms} ms`;
    dnsTime.classList.add("dns-time-value");

    // 显示记录列表
    if (result.records && result.records.length > 0) {
      dnsRecordsList.innerHTML = result.records.map(record => `
        <div class="dns-record-item">
          <div class="dns-record-name">${escapeHtml(record.name)}</div>
          <div class="dns-record-type">${record.rtype}</div>
          <div class="dns-record-ttl">TTL: ${record.ttl}s</div>
          <div class="dns-record-data">${escapeHtml(record.data)}</div>
        </div>
      `).join("");
    } else {
      dnsRecordsList.innerHTML = `<span class="whois-empty">未找到记录</span>`;
    }

    // 显示结果
    dnsResults.classList.remove("hidden");
  } catch (error) {
    const msg = toCommandErrorMessage(error);
    reportCommandError("DNS 查询", error);
    dnsError.textContent = `查询失败: ${msg}`;
    dnsError.classList.remove("hidden");
  } finally {
    dnsLoading.classList.add("hidden");
    dnsQueryBtn.disabled = false;
  }
}

// 绑定 DNS 事件
dnsQueryBtn?.addEventListener("click", queryDns);
dnsDomainInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    queryDns();
  }
});

// ===== 初始化 =====
window.addEventListener("DOMContentLoaded", () => {
  scanPorts();
});
