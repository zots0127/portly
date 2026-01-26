import { invoke } from "@tauri-apps/api/core";

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

// DOM elements
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

let currentView: "table" | "group" = "table";
let isLoading = false;

// Scan ports
async function scanPorts() {
  if (isLoading) return;
  isLoading = true;
  refreshBtn.classList.add("spinning");

  try {
    const includeCommand = showCommand.checked;
    const result: ScanResult = await invoke("tauri_scan_ports", { includeCommand });

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

    // Update stats
    const uniqueApps = new Set(filteredPorts.map(p => `${p.process}:${p.pid}`)).size;
    statTime.textContent = result.scan_time.split(' ')[1] || result.scan_time;
    statApps.textContent = uniqueApps.toString();
    statPorts.textContent = filteredPorts.length.toString();

    if (currentView === "table") {
      renderTable(filteredPorts, includeCommand);
    }

  } catch (error) {
    console.error("Scan failed:", error);
  } finally {
    isLoading = false;
    refreshBtn.classList.remove("spinning");
  }
}

// Render table
function renderTable(ports: PortInfo[], showCmd: boolean) {
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
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="cell-port">${p.port}</td>
      <td><span class="cell-protocol ${p.protocol.toLowerCase()}">${p.protocol}</span></td>
      <td class="cell-address">${p.address}</td>
      <td class="cell-pid">${p.pid}</td>
      <td class="cell-process">${p.process}</td>
      <td class="cell-user">${p.user}</td>
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
}

// Scan grouped
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

// Render groups
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

// Event bindings
viewTableBtn.addEventListener("click", () => switchView("table"));
viewGroupBtn.addEventListener("click", () => switchView("group"));
refreshBtn.addEventListener("click", () => {
  if (currentView === "table") scanPorts();
  else scanGrouped();
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

// Initial scan
window.addEventListener("DOMContentLoaded", () => {
  scanPorts();
});
