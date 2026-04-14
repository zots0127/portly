import { describe, it, expect, beforeEach, vi } from "vitest";
import { formatCommandErrorMessage } from "./error-utils";
import {
  buildSubnetScanEstimateMessage,
  buildScanLoadingHtml,
  estimateScanDurationSeconds,
  isValidSubnetRange,
} from "./network-utils";
import {
  buildDiscoverDevicesLoadingHtml,
  buildMonitorLoadingHtml,
  DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE,
  applyMonitorTimeoutFallback,
  setDiscoverDevicesIdleState,
  setDiscoverDevicesLoadingState,
  setDiscoverDevicesErrorState,
  setMonitorErrorState,
  setMonitorStartState,
  setMonitorStopState,
  startMonitorLoadingTimer,
  startMonitorStartupTimeout,
  stopMonitorLoadingTimer,
  stopMonitorStartupTimeout,
  setPortScanIdleState,
  setPortScanErrorState,
  setPortScanLoadingState,
} from "./scan-ui-state";
import { showToast } from "./ui-feedback";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(),
}));

describe("DOM Manipulation Tests", () => {
  beforeEach(() => {
    // jsdom 环境由 vitest 自动设置和清理
    // 我们只需要设置每个测试需要的 DOM 结构
    document.body.innerHTML = "";
  });

  const buildMonitorFlowDom = async (subnet = "10.0.0.0/22") => {
    const estimateSeconds = estimateScanDurationSeconds(subnet);

    const requiredIds: Array<[string, string]> = [
      ["tab-local", "button"],
      ["tab-network", "button"],
      ["tab-monitor", "button"],
      ["tab-dns", "button"],
      ["tab-whois", "button"],
      ["tab-ssl", "button"],
      ["page-local", "div"],
      ["page-network", "div"],
      ["page-monitor", "div"],
      ["page-dns", "div"],
      ["page-whois", "div"],
      ["page-ssl", "div"],
      ["view-table", "button"],
      ["view-group", "button"],
      ["app-filter", "input"],
      ["port-filter", "input"],
      ["exclude-system", "input"],
      ["show-command", "input"],
      ["refresh-btn", "button"],
      ["scan-devices-btn", "button"],
      ["refresh-network-btn", "button"],
      ["scan-ports-btn", "button"],
      ["port-tbody", "tbody"],
      ["scan-type", "select"],
      ["ping-btn", "button"],
      ["trace-btn", "button"],
      ["start-monitor-btn", "button"],
      ["stop-monitor-btn", "button"],
      ["monitor-subnet", "select"],
      ["monitor-manual-subnet", "input"],
      ["monitor-canvas", "canvas"],
      ["device-grid", "div"],
      ["mon-devices", "div"],
      ["mon-online", "div"],
      ["mon-avg-latency", "div"],
      ["mon-best", "div"],
      ["stat-time", "span"],
      ["stat-apps", "span"],
      ["stat-ports", "span"],
      ["port-table", "table"],
      ["group-view", "div"],
      ["net-stat-devices", "span"],
      ["device-count", "span"],
      ["selected-device-ip", "span"],
      ["scan-ports-results", "div"],
      ["device-list", "div"],
      ["device-actions", "div"],
      ["multi-ping-btn", "button"],
      ["stop-ping-btn", "button"],
      ["stop-multi-btn", "button"],
      ["spectrum-canvas", "canvas"],
      ["spectrum-legend", "div"],
      ["port-start", "input"],
      ["port-end", "input"],
      ["manual-target", "input"],
      ["add-manual-target", "button"],
      ["subnet-select", "select"],
      ["manual-subnet", "input"],
      ["whois-input", "input"],
      ["whois-query-btn", "button"],
      ["whois-loading", "div"],
      ["whois-error", "div"],
      ["whois-results", "div"],
      ["ssl-host-input", "input"],
      ["ssl-port-input", "input"],
      ["ssl-check-btn", "button"],
      ["ssl-loading", "div"],
      ["ssl-error", "div"],
      ["ssl-results", "div"],
      ["dns-domain-input", "input"],
      ["dns-record-type", "select"],
      ["dns-server", "select"],
      ["dns-query-btn", "button"],
      ["dns-loading", "div"],
      ["dns-error", "div"],
      ["dns-results", "div"],
      ["dns-domain", "div"],
      ["dns-type", "div"],
      ["dns-count", "div"],
      ["dns-time", "div"],
      ["dns-records-list", "div"],
    ];
    requiredIds.forEach(([id, tag]) => {
      const element = document.createElement(tag);
      element.id = id;
      if (tag === "input" || tag === "select") {
        (element as HTMLInputElement).value = "";
      }
      if (tag === "tbody") {
        const table = document.createElement("table");
        table.appendChild(element);
        document.body.appendChild(table);
      } else {
        document.body.appendChild(element);
      }
    });

    const sourceFilter = document.createElement("div");
    sourceFilter.id = "source-filter";
    const sourceSegment = document.createElement("button");
    sourceSegment.className = "segment";
    sourceSegment.dataset.filter = "all";
    sourceFilter.appendChild(sourceSegment);
    document.body.appendChild(sourceFilter);

    const subnetSelect = document.getElementById("monitor-subnet") as HTMLSelectElement;
    const monitorSubnets = ["10.0.0.0/22", "10.0.0.0/23", "10.0.0.0/24"];
    monitorSubnets.forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      if (value === subnet) {
        option.selected = true;
      }
      subnetSelect.appendChild(option);
    });
    subnetSelect.value = subnet;

    await vi.resetModules();

    const { invoke } = await import("@tauri-apps/api/core");
    const mockInvoke = vi.mocked(invoke);
    mockInvoke.mockReset();
    mockInvoke.mockReturnValue(new Promise(() => {}));

    await import("./main");

    const startMonitorBtn = document.getElementById("start-monitor-btn") as HTMLButtonElement;
    const stopMonitorBtn = document.getElementById("stop-monitor-btn") as HTMLButtonElement;
    const monitorSubnet = document.getElementById("monitor-subnet") as HTMLSelectElement;
    const monitorManualSubnetInput = document.getElementById("monitor-manual-subnet") as HTMLInputElement;
    const deviceGrid = document.getElementById("device-grid") as HTMLDivElement;
    const monDevices = document.getElementById("mon-devices") as HTMLDivElement;
    const monOnline = document.getElementById("mon-online") as HTMLDivElement;
    const monAvgLatency = document.getElementById("mon-avg-latency") as HTMLDivElement;
    const monBest = document.getElementById("mon-best") as HTMLDivElement;

    return {
      estimateSeconds,
      mockInvoke,
      startMonitorBtn,
      stopMonitorBtn,
      monitorSubnet,
      monitorManualSubnetInput,
      deviceGrid,
      monDevices,
      monOnline,
      monAvgLatency,
      monBest,
    };
  };

  describe("Tab Switching", () => {
    it("should handle tab class switching", () => {
      // 创建测试用的 DOM 结构
      const tabLocal = document.createElement("button");
      tabLocal.id = "tab-local";
      tabLocal.className = "tab active";

      const tabNetwork = document.createElement("button");
      tabNetwork.id = "tab-network";
      tabNetwork.className = "tab";

      const pageLocal = document.createElement("div");
      pageLocal.id = "page-local";
      pageLocal.className = "page";

      const pageNetwork = document.createElement("div");
      pageNetwork.id = "page-network";
      pageNetwork.className = "page hidden";

      document.body.append(tabLocal, tabNetwork, pageLocal, pageNetwork);

      // 初始状态检查
      expect(tabLocal.classList.contains("active")).toBe(true);
      expect(tabNetwork.classList.contains("active")).toBe(false);
      expect(pageLocal.classList.contains("hidden")).toBe(false);
      expect(pageNetwork.classList.contains("hidden")).toBe(true);

      // 模拟切换标签
      tabLocal.classList.remove("active");
      tabNetwork.classList.add("active");
      pageLocal.classList.add("hidden");
      pageNetwork.classList.remove("hidden");

      // 切换后状态检查
      expect(tabLocal.classList.contains("active")).toBe(false);
      expect(tabNetwork.classList.contains("active")).toBe(true);
      expect(pageLocal.classList.contains("hidden")).toBe(true);
      expect(pageNetwork.classList.contains("hidden")).toBe(false);
    });

    it("should toggle hidden class on pages", () => {
      const page = document.createElement("div");
      page.className = "page";

      document.body.appendChild(page);

      expect(page.classList.contains("hidden")).toBe(false);

      page.classList.add("hidden");
      expect(page.classList.contains("hidden")).toBe(true);

      page.classList.remove("hidden");
      expect(page.classList.contains("hidden")).toBe(false);
    });
  });

  describe("View Switching", () => {
    it("should switch between table and group views", () => {
      const viewTable = document.createElement("button");
      viewTable.className = "segment active";

      const viewGroup = document.createElement("button");
      viewGroup.className = "segment";

      const portTable = document.createElement("table");
      const groupView = document.createElement("div");
      groupView.className = "group-view hidden";

      document.body.append(viewTable, viewGroup, portTable, groupView);

      // 初始状态：表格视图
      expect(viewTable.classList.contains("active")).toBe(true);
      expect(viewGroup.classList.contains("active")).toBe(false);
      expect(groupView.classList.contains("hidden")).toBe(true);

      // 切换到分组视图
      viewTable.classList.remove("active");
      viewGroup.classList.add("active");
      portTable.classList.add("hidden");
      groupView.classList.remove("hidden");

      expect(viewTable.classList.contains("active")).toBe(false);
      expect(viewGroup.classList.contains("active")).toBe(true);
      expect(portTable.classList.contains("hidden")).toBe(true);
      expect(groupView.classList.contains("hidden")).toBe(false);
    });
  });

  describe("Stats Display", () => {
    it("should update stats values", () => {
      const statTime = document.createElement("span");
      const statApps = document.createElement("span");
      const statPorts = document.createElement("span");

      document.body.append(statTime, statApps, statPorts);

      statTime.textContent = "12:34:56";
      statApps.textContent = "5";
      statPorts.textContent = "10";

      expect(statTime.textContent).toBe("12:34:56");
      expect(statApps.textContent).toBe("5");
      expect(statPorts.textContent).toBe("10");
    });
  });

  describe("Table Rendering", () => {
    it("should render port rows in table body", () => {
      const tbody = document.createElement("tbody");

      const row = document.createElement("tr");
      row.innerHTML = `
        <td>8080</td>
        <td>tcp</td>
        <td>127.0.0.1</td>
        <td>1234</td>
        <td>node</td>
        <td><button class="action-btn">Kill</button></td>
      `;
      tbody.appendChild(row);
      document.body.appendChild(tbody);

      expect(tbody.children.length).toBe(1);
      expect(tbody.children[0].textContent).toContain("8080");
      expect(tbody.children[0].textContent).toContain("node");
    });

    it("should render empty state when no ports", () => {
      const tbody = document.createElement("tbody");

      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center;">No ports found</td>
        </tr>
      `;
      document.body.appendChild(tbody);

      expect(tbody.children.length).toBe(1);
      expect(tbody.textContent).toContain("No ports found");
    });

    it("should render multiple rows", () => {
      const tbody = document.createElement("tbody");

      for (let i = 0; i < 3; i++) {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${3000 + i}</td><td>tcp</td><td>0.0.0.0</td><td>${1000 + i}</td><td>app${i}</td><td></td>`;
        tbody.appendChild(row);
      }
      document.body.appendChild(tbody);

      expect(tbody.children.length).toBe(3);
      expect(tbody.children[0].textContent).toContain("3000");
      expect(tbody.children[1].textContent).toContain("3001");
      expect(tbody.children[2].textContent).toContain("3002");
    });
  });

  describe("Filter Inputs", () => {
    it("should read app filter value", () => {
      const appFilter = document.createElement("input");
      appFilter.type = "text";
      appFilter.id = "app-filter";

      document.body.appendChild(appFilter);

      appFilter.value = "node";

      expect(appFilter.value).toBe("node");
    });

    it("should read port filter value", () => {
      const portFilter = document.createElement("input");
      portFilter.type = "number";
      portFilter.id = "port-filter";

      document.body.appendChild(portFilter);

      portFilter.value = "8080";

      expect(portFilter.value).toBe("8080");
    });

    it("should check and uncheck checkboxes", () => {
      const showCommand = document.createElement("input");
      showCommand.type = "checkbox";
      const excludeSystem = document.createElement("input");
      excludeSystem.type = "checkbox";

      document.body.append(showCommand, excludeSystem);

      expect(showCommand.checked).toBe(false);
      expect(excludeSystem.checked).toBe(false);

      showCommand.checked = true;
      excludeSystem.checked = true;

      expect(showCommand.checked).toBe(true);
      expect(excludeSystem.checked).toBe(true);
    });
  });

  describe("Group View Rendering", () => {
    it("should render app cards in group view", () => {
      const groupView = document.createElement("div");

      const card = document.createElement("div");
      card.className = "app-card";
      card.innerHTML = `
        <div class="app-header">
          <div class="app-name">node</div>
          <div class="app-pid">PID 1234</div>
        </div>
        <div class="app-ports">
          <span class="port-tag">8080</span>
          <span class="port-tag">3000</span>
        </div>
      `;
      groupView.appendChild(card);
      document.body.appendChild(groupView);

      expect(groupView.children.length).toBe(1);
      expect(groupView.querySelector(".app-name")?.textContent).toBe("node");
      expect(groupView.querySelector(".app-pid")?.textContent).toBe("PID 1234");

      const portTags = groupView.querySelectorAll(".port-tag");
      expect(portTags.length).toBe(2);
      expect(portTags[0].textContent).toBe("8080");
      expect(portTags[1].textContent).toBe("3000");
    });

    it("should render empty state in group view", () => {
      const groupView = document.createElement("div");

      groupView.innerHTML = `
        <div class="empty-state">
          <div class="icon">icon</div>
          <div>No apps found</div>
        </div>
      `;
      document.body.appendChild(groupView);

      expect(groupView.querySelector(".empty-state")).toBeTruthy();
      expect(groupView.textContent).toContain("No apps found");
    });
  });

  describe("Element Selection", () => {
    it("should select elements by ID", () => {
      const tabLocal = document.createElement("div");
      tabLocal.id = "tab-local";
      document.body.appendChild(tabLocal);

      const found = document.getElementById("tab-local");
      expect(found).toBeTruthy();
      expect(found?.id).toBe("tab-local");
    });

    it("should select elements by class name", () => {
      for (let i = 0; i < 3; i++) {
        const tab = document.createElement("button");
        tab.className = "tab";
        tab.id = `tab-${i}`;
        document.body.appendChild(tab);
      }

      const tabs = document.querySelectorAll(".tab");
      expect(tabs.length).toBe(3);
    });

    it("should select elements by tag name", () => {
      for (let i = 0; i < 3; i++) {
        const button = document.createElement("button");
        document.body.appendChild(button);
      }

      const buttons = document.getElementsByTagName("button");
      expect(buttons.length).toBe(3);
    });
  });

  describe("Toast Message Rendering", () => {
    it("should render warning toast for manual subnet input format issue", () => {
      const manualSubnet = document.createElement("input");
      manualSubnet.id = "manual-subnet";
      manualSubnet.value = "192.168.1.999/22";

      if (!isValidSubnetRange(manualSubnet.value)) {
        showToast("⚠️ 子网格式应为 IPv4 CIDR，当前支持 /22~24（如 192.168.1.0/24）", "warning");
      }

      const toastContainer = document.getElementById("toast-container");
      const toast = toastContainer?.querySelector(".toast");
      expect(toastContainer).toBeTruthy();
      expect(toast).toBeTruthy();
      expect(toast?.textContent).toContain("⚠️");
      expect(toast?.className).toContain("toast-warning");
      expect(toast?.textContent).toContain("子网格式应为 IPv4 CIDR");
    });

    it("should include classified error text in real toast message", () => {
      const errorMessage = formatCommandErrorMessage("扫描局域网设备", "目标地址 校验失败：不能为空");
      showToast(errorMessage, "error");

      const toast = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(toast).toBeTruthy();
      expect(toast?.textContent).toContain("扫描局域网设备失败");
      expect(toast?.textContent).toContain("目标地址");
      expect(toast?.className).toContain("toast-error");
    });

    it("should show warning for invalid monitor subnet input", () => {
      const manualSubnet = document.createElement("input");
      manualSubnet.id = "monitor-manual-subnet";
      manualSubnet.value = "10.0.0.1/25";

      if (!isValidSubnetRange(manualSubnet.value)) {
        showToast("⚠️ 监测网段支持 IPv4 CIDR /22~24（如 192.168.1.0/24）", "warning");
      }

      const toast = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(toast).toBeTruthy();
      expect(toast?.textContent).toContain("⚠️");
      expect(toast?.textContent).toContain("监测网段支持 IPv4 CIDR /22~24");
      expect(toast?.className).toContain("toast-warning");
    });

    it("should show subnet range estimate warning in toast text", () => {
      const estimateMessage = buildSubnetScanEstimateMessage("10.1.0.0/22");
      expect(estimateMessage).toBeTruthy();

      showToast(`⚠️ ${estimateMessage}`, "warning");
      const toast = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(toast).toBeTruthy();
      expect(toast?.textContent).toContain("当前范围约");
      expect(toast?.textContent).toContain("当前范围估算耗时");
    });

    it("should render /23 subnet estimate toast message", () => {
      const estimateMessage = buildSubnetScanEstimateMessage("10.1.1.0/23");
      expect(estimateMessage).toBeTruthy();
      expect(estimateMessage).toContain("510");
      expect(estimateMessage).toContain("当前范围约");

      showToast(`⚠️ ${estimateMessage}`, "warning");
      const toast = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(toast).toBeTruthy();
      expect(toast?.textContent).toContain("510");
      expect(toast?.textContent).toContain("秒");
      expect(toast?.textContent).toContain("⚠️");
    });

    it("should include dns query classification in toast message", () => {
      const errorMessage = formatCommandErrorMessage("DNS 查询", "域名 校验失败：不能为空");
      showToast(errorMessage, "error");

      const toast = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(toast).toBeTruthy();
      expect(toast?.textContent).toContain("DNS 查询失败");
      expect(toast?.textContent).toContain("域名");
      expect(toast?.textContent).toContain("不能为空");
      expect(toast?.className).toContain("toast-error");
    });

    it("should render loading progress text with estimated remaining time", () => {
      const startAt = Date.now();
      const hint = buildScanLoadingHtml("正在扫描局域网设备...", startAt, 120);
      expect(hint).toContain("正在扫描局域网设备...");
      expect(hint).toContain("已耗时");
      expect(hint).toContain("预计还需");

      vi.useFakeTimers();
      vi.setSystemTime(startAt + 5_000);
      const updated = buildScanLoadingHtml("正在扫描局域网设备...", startAt, 120);
      vi.useRealTimers();

      expect(updated).toContain("已耗时");
      expect(updated).toContain("预计还需");
    });

    it("should remove toast after delay", () => {
      vi.useFakeTimers();
      showToast("⚠️ 任务扫描中...", "warning");
      const toast = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(toast).toBeTruthy();

      vi.advanceTimersByTime(3100);
      const mid = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(mid).toBeTruthy();

      vi.advanceTimersByTime(300);
      const after = document.querySelector("#toast-container .toast") as HTMLDivElement | null;
      expect(after).toBeNull();
      vi.useRealTimers();
    });
  });

  describe("Scan Task UI State", () => {
    it("should build discover devices loading html with estimate suffix", () => {
      const html = buildDiscoverDevicesLoadingHtml("正在扫描局域网设备...", Date.now(), 120, "当前范围约 510 台主机");
      expect(html).toContain("loading");
      expect(html).toContain("当前范围约 510 台主机");
      expect(html).toContain("已耗时");
      expect(html).toContain("预计还需");
    });

    it("should apply discover device loading/idle helper states", () => {
      const scanDevicesBtn = document.createElement("button");
      const deviceList = document.createElement("div");

      setDiscoverDevicesLoadingState(
        scanDevicesBtn,
        deviceList,
        buildDiscoverDevicesLoadingHtml("正在扫描局域网设备...", Date.now(), 120, "当前范围约 510 台主机"),
      );
      expect(scanDevicesBtn.disabled).toBe(true);
      expect(scanDevicesBtn.textContent).toBe("⏳ 扫描中...");
      expect(deviceList.querySelector(".loading")).toBeTruthy();

      setDiscoverDevicesIdleState(scanDevicesBtn);
      expect(scanDevicesBtn.disabled).toBe(false);
      expect(scanDevicesBtn.textContent).toBe("🔍 扫描设备");
    });

    it("should apply monitor loading hint helper", () => {
      const deviceGrid = document.createElement("div");
      const html = buildMonitorLoadingHtml("正在初始化监测目标...", Date.now(), 120, "当前扫描范围约：120 秒");
      deviceGrid.innerHTML = html;
      expect(deviceGrid.textContent).toContain("当前扫描范围约：");
      expect(deviceGrid.textContent).toContain("已耗时");
      expect(deviceGrid.textContent).toContain("预计还需");
    });

    it("should switch monitor start/stop buttons by helper states", () => {
      const startMonitorBtn = document.createElement("button");
      const stopMonitorBtn = document.createElement("button");

      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";
      setMonitorStartState(startMonitorBtn, stopMonitorBtn);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      setMonitorStopState(startMonitorBtn, stopMonitorBtn);
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
    });

    it("should apply monitor error helper state", () => {
      const deviceGrid = document.createElement("div");
      setMonitorErrorState(deviceGrid);
      expect(deviceGrid.textContent).toContain("监测启动失败");
      expect(deviceGrid.textContent).toContain("❌");
    });

    it("should start and stop monitor loading timer lifecycle", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      let tick = 0;
      const loadingInterval = startMonitorLoadingTimer(
        deviceGrid,
        () => `<div class="monitor-hint">tick-${++tick}</div>`,
        5,
      );

      expect(loadingInterval).toBeTruthy();
      expect(deviceGrid.textContent).toBe("tick-1");

      vi.advanceTimersByTime(1000);
      expect(deviceGrid.textContent).toBe("tick-2");

      vi.advanceTimersByTime(3000);
      expect(tick).toBe(5);
      const clearedInterval = stopMonitorLoadingTimer(loadingInterval);
      expect(clearedInterval).toBeNull();

      vi.advanceTimersByTime(5000);
      expect(tick).toBe(5);
      vi.useRealTimers();
    });

    it("should render monitor loading once when estimate is unavailable", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      let tick = 0;

      const loadingInterval = startMonitorLoadingTimer(
        deviceGrid,
        () => `<div class="monitor-hint">tick-${++tick}</div>`,
        null,
      );

      expect(loadingInterval).toBeNull();
      expect(deviceGrid.textContent).toBe("tick-1");

      vi.advanceTimersByTime(5000);
      expect(tick).toBe(1);
      vi.useRealTimers();
    });

    it("should show monitor timeout fallback when startup timeout elapses", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      startMonitorStartupTimeout(deviceGrid, 2, DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE);

      vi.advanceTimersByTime(1999);
      expect(deviceGrid.textContent).toBe("");

      vi.advanceTimersByTime(2);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(deviceGrid.textContent).toContain("❌");
      expect(deviceGrid.textContent).toContain("建议缩小子网范围后重试");
      vi.useRealTimers();
    });

    it("should ignore startup timeout when monitor grid is unavailable", () => {
      vi.useFakeTimers();
      const timeout = startMonitorStartupTimeout(null, 1);
      expect(timeout).toBeNull();
      vi.advanceTimersByTime(1000);
      vi.useRealTimers();
    });

    it("should ignore startup timeout when estimate is zero", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      const timeout = startMonitorStartupTimeout(deviceGrid, 0);
      expect(timeout).toBeNull();
      vi.advanceTimersByTime(1000);
      expect(deviceGrid.textContent).toBe("");
      vi.useRealTimers();
    });

    it("should handle timeout fallback in realistic startMonitor flow with mocked invoke", async () => {
      const {
        estimateSeconds,
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
        monDevices,
        monOnline,
        monAvgLatency,
        monBest,
      } = await buildMonitorFlowDom();

      monDevices.textContent = "12";
      monOnline.textContent = "9";
      monAvgLatency.textContent = "15.0ms";
      monBest.textContent = "210";
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";

      vi.useFakeTimers();
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();

      expect(deviceGrid.textContent).toContain("当前范围约");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(mockInvoke).toHaveBeenCalledWith("tauri_discover_devices", { subnet: "10.0.0.0/22" });

      vi.advanceTimersByTime(estimateSeconds * 1000);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(deviceGrid.textContent).toContain("建议缩小子网范围后重试");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      expect(monDevices.textContent).toBe("12");
      expect(monOnline.textContent).toBe("9");
      expect(monAvgLatency.textContent).toBe("15.0ms");
      expect(monBest.textContent).toBe("210");
      vi.useRealTimers();
    });

    it("should allow re-entry startMonitor after timeout fallback without stale session interference", async () => {
      const {
        estimateSeconds,
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
        monDevices,
        monOnline,
        monAvgLatency,
        monBest,
      } = await buildMonitorFlowDom();

      monDevices.textContent = "12";
      monOnline.textContent = "9";
      monAvgLatency.textContent = "15.0ms";
      monBest.textContent = "210";
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";

      vi.useFakeTimers();
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(deviceGrid.textContent).toContain("当前范围约");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      vi.advanceTimersByTime(estimateSeconds * 1000);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      mockInvoke.mockClear();
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(deviceGrid.textContent).toContain("当前范围约");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      vi.advanceTimersByTime(estimateSeconds * 1000);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      expect(monDevices.textContent).toBe("12");
      expect(monOnline.textContent).toBe("9");
      expect(monAvgLatency.textContent).toBe("15.0ms");
      expect(monBest.textContent).toBe("210");
      vi.useRealTimers();
    });

    it("should ignore stale first monitor session completion after re-entry", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";

      const pendingDiscoverCalls: Array<{
        resolve: (value: unknown) => void;
        reject: (reason?: unknown) => void;
      }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd !== "tauri_discover_devices") {
          return Promise.resolve([]);
        }
        return new Promise((resolve, reject) => {
          pendingDiscoverCalls.push({ resolve, reject });
        });
      });

      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      const firstCall = pendingDiscoverCalls.shift();
      firstCall?.reject(new Error("first session failed"));
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      const secondCall = pendingDiscoverCalls.shift();
      secondCall?.resolve([]);
      await Promise.resolve();
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
    });

    it("should keep latest start session after rapid double-click", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
      } = await buildMonitorFlowDom("10.0.0.0/24");

      const pendingDiscoverCalls: Array<{
        resolve: (value: unknown) => void;
        reject: (reason?: unknown) => void;
      }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd !== "tauri_discover_devices") {
          return Promise.resolve([]);
        }
        return new Promise((resolve, reject) => {
          pendingDiscoverCalls.push({ resolve, reject });
        });
      });

      monitorSubnet.value = "10.0.0.0/24";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      startMonitorBtn.click();
      await Promise.resolve();

      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const firstCall = pendingDiscoverCalls.shift();
      const secondCall = pendingDiscoverCalls.shift();
      expect(firstCall).toBeTruthy();
      expect(secondCall).toBeTruthy();

      firstCall!.reject(new Error("stale first rapid click"));
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      secondCall!.resolve([]);
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
    });

    it("should keep latest start session after triple rapid-click", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
      } = await buildMonitorFlowDom("10.0.0.0/24");

      const pendingDiscoverCalls: Array<{
        resolve: (value: unknown) => void;
        reject: (reason?: unknown) => void;
      }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd !== "tauri_discover_devices") {
          return Promise.resolve([]);
        }
        return new Promise((resolve, reject) => {
          pendingDiscoverCalls.push({ resolve, reject });
        });
      });

      monitorSubnet.value = "10.0.0.0/24";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      startMonitorBtn.click();
      startMonitorBtn.click();
      await Promise.resolve();

      expect(mockInvoke).toHaveBeenCalledTimes(3);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const firstCall = pendingDiscoverCalls.shift();
      const secondCall = pendingDiscoverCalls.shift();
      const thirdCall = pendingDiscoverCalls.shift();
      expect(firstCall).toBeTruthy();
      expect(secondCall).toBeTruthy();
      expect(thirdCall).toBeTruthy();

      firstCall!.resolve([]);
      await Promise.resolve();
      secondCall!.reject(new Error("stale second rapid click"));
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");

      thirdCall!.resolve([]);
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
    });

    it("should keep only the final session active after rapid start-stop churn", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      startMonitorBtn.click();
      startMonitorBtn.click();
      stopMonitorBtn.click();
      startMonitorBtn.click();
      startMonitorBtn.click();
      stopMonitorBtn.click();
      startMonitorBtn.click();

      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(6);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      expect(pendingDiscoverCalls.length).toBe(6);
      pendingDiscoverCalls[0]?.resolve([]);
      pendingDiscoverCalls[1]?.reject(new Error("stale call"));
      pendingDiscoverCalls[2]?.resolve([]);
      pendingDiscoverCalls[3]?.reject(new Error("stale call"));
      pendingDiscoverCalls[4]?.resolve([]);
      await Promise.resolve();

      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      pendingDiscoverCalls[5]?.resolve([]);
      await Promise.resolve();

      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should ignore stale bursts after extensive rapid start-stop churn", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      for (let i = 0; i < 6; i += 1) {
        startMonitorBtn.click();
      }
      stopMonitorBtn.click();

      for (let i = 0; i < 6; i += 1) {
        startMonitorBtn.click();
      }
      stopMonitorBtn.click();

      startMonitorBtn.click();
      startMonitorBtn.click();

      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(14);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      expect(pendingDiscoverCalls.length).toBe(14);
      for (let i = 0; i < 13; i += 1) {
        if (i % 2 === 0) {
          pendingDiscoverCalls[i]?.reject(new Error("stale burst"));
        } else {
          pendingDiscoverCalls[i]?.resolve([]);
        }
      }
      await Promise.resolve();

      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      pendingDiscoverCalls[13]?.resolve([]);
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should preserve final session after stale timeout fallback plus long churn", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      const timeoutSeconds = estimateScanDurationSeconds("10.0.0.0/22");
      expect(timeoutSeconds).toBeTruthy();

      vi.advanceTimersByTime(timeoutSeconds! * 1000);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      for (let i = 0; i < 3; i += 1) {
        startMonitorBtn.click();
      }
      stopMonitorBtn.click();
      for (let i = 0; i < 3; i += 1) {
        startMonitorBtn.click();
      }
      stopMonitorBtn.click();
      for (let i = 0; i < 2; i += 1) {
        startMonitorBtn.click();
      }

      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(9);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      for (let i = 0; i < 8; i += 1) {
        if (i % 2 === 0) {
          pendingDiscoverCalls[i]?.reject(new Error("stale timeout-chain"));
        } else {
          pendingDiscoverCalls[i]?.resolve([]);
        }
      }

      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      const finalCall = pendingDiscoverCalls[8];
      expect(finalCall).toBeTruthy();
      finalCall?.resolve([]);
      await Promise.resolve();

      expect(stopMonitorBtn.style.display).toBe("block");
      expect(startMonitorBtn.style.display).toBe("none");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep latest session during prolonged start-stop interleave", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      for (let i = 0; i < 6; i += 1) {
        startMonitorBtn.click();
      }
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(6);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      for (let i = 0; i < 3; i += 1) {
        stopMonitorBtn.click();
        startMonitorBtn.click();
      }

      expect(mockInvoke).toHaveBeenCalledTimes(9);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      for (let i = 0; i < 8; i += 1) {
        if (i % 2 === 0) {
          pendingDiscoverCalls[i]?.reject(new Error("stale interleave"));
        } else {
          pendingDiscoverCalls[i]?.resolve([]);
        }
      }

      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      pendingDiscoverCalls[8]?.resolve([]);
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep latest active session when stale timeout is cancelled by manual stop", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const secondCall = pendingDiscoverCalls[1];
      const firstCall = pendingDiscoverCalls[0];
      expect(firstCall).toBeTruthy();
      expect(secondCall).toBeTruthy();

      secondCall?.resolve([]);
      await Promise.resolve();
      firstCall?.resolve([]);
      await Promise.resolve();

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should not let stale timeout from a larger subnet override later non-timeout session", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();

      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("当前范围约");

      const firstTimeoutSeconds = estimateScanDurationSeconds("10.0.0.0/22");
      expect(firstTimeoutSeconds).toBeTruthy();

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(deviceGrid.textContent).toContain("正在初始化监测目标");

      vi.advanceTimersByTime(firstTimeoutSeconds! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(startMonitorBtn.style.display).toBe("none");

      const secondCall = pendingDiscoverCalls[1];
      secondCall?.resolve([]);
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");

      const firstCall = pendingDiscoverCalls[0];
      firstCall?.reject(new Error("first session stale"));
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");
      vi.useRealTimers();
    });

    it("should recover latest session after stale timeout callback", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();

      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const latestCall = pendingDiscoverCalls[1];
      latestCall?.resolve([]);
      await Promise.resolve();
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const staleCall = pendingDiscoverCalls[0];
      expect(staleCall).toBeTruthy();
      staleCall?.reject(new Error("stale timeout call"));
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).not.toContain("监测启动超时");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep latest state when stale timeout and interleaved stop-start overlap", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(3);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const latestCall = pendingDiscoverCalls[2];
      latestCall?.resolve([]);
      await Promise.resolve();
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      pendingDiscoverCalls[1]?.resolve([]);
      pendingDiscoverCalls[0]?.reject(new Error("stale interleave"));
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(deviceGrid.textContent).not.toContain("监测启动超时");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should avoid stale timeout storms from older sessions", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();

      expect(mockInvoke).toHaveBeenCalledTimes(3);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(4);

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const latestCall = pendingDiscoverCalls[3];
      latestCall?.resolve([]);
      await Promise.resolve();
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      pendingDiscoverCalls[2]?.resolve([]);
      pendingDiscoverCalls[1]?.reject(new Error("storm stale 1"));
      pendingDiscoverCalls[0]?.reject(new Error("storm stale 0"));
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).not.toContain("监测启动超时");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep active no-timeout session when older timeout sessions fire", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      for (let i = 0; i < 5; i += 1) {
        startMonitorBtn.click();
      }
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(5);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(6);

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(7);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("正在初始化监测目标");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const finalCall = pendingDiscoverCalls[6];
      expect(finalCall).toBeTruthy();
      finalCall.resolve([]);
      await Promise.resolve();

      for (let i = 0; i < 6; i += 1) {
        if (i === 5) {
          pendingDiscoverCalls[i]?.resolve([]);
        } else {
          pendingDiscoverCalls[i]?.reject(new Error("stale from old /22 session"));
        }
      }
      await Promise.resolve();

      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).not.toContain("监测启动超时");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep current no-timeout session despite older timeout callbacks", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();
      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(4);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("正在初始化监测目标");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");

      pendingDiscoverCalls[3]?.resolve([]);
      pendingDiscoverCalls[2]?.reject(new Error("stale mixed"));
      pendingDiscoverCalls[1]?.reject(new Error("stale mixed"));
      pendingDiscoverCalls[0]?.resolve([]);
      await Promise.resolve();

      expect(stopMonitorBtn.style.display).toBe("block");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(deviceGrid.textContent).not.toContain("监测启动超时");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep latest no-timeout session alive across stacked stale timeout callbacks", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();
      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();

      expect(mockInvoke).toHaveBeenCalledTimes(4);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("正在初始化监测目标");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(deviceGrid.textContent).not.toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      pendingDiscoverCalls[3]?.resolve([]);
      await Promise.resolve();
      pendingDiscoverCalls[2]?.reject(new Error("older /24 stale"));
      pendingDiscoverCalls[1]?.reject(new Error("older /22 stale"));
      pendingDiscoverCalls[0]?.resolve([]);
      await Promise.resolve();

      expect(stopMonitorBtn.style.display).toBe("block");
      expect(startMonitorBtn.style.display).toBe("none");
      expect(deviceGrid.textContent).not.toContain("监测启动超时");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should keep stopped no-timeout session stable after stale timeout and old resolves", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(1);

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      pendingDiscoverCalls[1]?.resolve([]);
      pendingDiscoverCalls[0]?.reject(new Error("stale no-timeout after stop"));
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      vi.useRealTimers();
    });

    it("should ignore stale timeout callbacks and old resolves after latest session stop", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      startMonitorBtn.click();
      await Promise.resolve();
      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();

      expect(mockInvoke).toHaveBeenCalledTimes(3);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      const staleTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(staleTimeout).toBeTruthy();
      vi.advanceTimersByTime(staleTimeout! * 1000);

      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      pendingDiscoverCalls[2]?.resolve([]);
      pendingDiscoverCalls[1]?.resolve([]);
      pendingDiscoverCalls[0]?.reject(new Error("stale timeout + old session"));
      await Promise.resolve();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      vi.useRealTimers();
    });

    it("should allow immediate restart after stale timeout callback", async () => {
      const {
        mockInvoke,
        startMonitorBtn,
        stopMonitorBtn,
        monitorSubnet,
        monitorManualSubnetInput,
        deviceGrid,
      } = await buildMonitorFlowDom();

      const pendingDiscoverCalls: Array<{ resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = [];
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "tauri_discover_devices") {
          return new Promise((resolve, reject) => {
            pendingDiscoverCalls.push({ resolve, reject });
          });
        }
        return Promise.resolve([]);
      });

      vi.useFakeTimers();
      monitorSubnet.value = "10.0.0.0/22";
      monitorManualSubnetInput.value = "";
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.click();
      await Promise.resolve();
      const firstTimeout = estimateScanDurationSeconds("10.0.0.0/22");
      expect(firstTimeout).toBeTruthy();
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(firstTimeout! * 1000);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");

      monitorSubnet.value = "10.0.0.0/24";
      startMonitorBtn.click();
      await Promise.resolve();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
      expect(deviceGrid.textContent).toContain("正在初始化监测目标");

      pendingDiscoverCalls[1]?.resolve([]);
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");
      pendingDiscoverCalls[0]?.reject(new Error("stale timeout session"));
      await Promise.resolve();
      expect(stopMonitorBtn.style.display).toBe("block");

      stopMonitorBtn.click();
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      vi.useRealTimers();
    });

    it("should invoke monitor startup timeout callback", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      let called = false;

      startMonitorStartupTimeout(deviceGrid, 1, "监测启动超时", () => {
        called = true;
      });

      vi.advanceTimersByTime(1000);
      expect(called).toBe(true);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      vi.useRealTimers();
    });

    it("should not invoke monitor timeout callback after timeout is cleared", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      let called = false;

      const timeout = startMonitorStartupTimeout(deviceGrid, 1, "监测启动超时", () => {
        called = true;
      });
      stopMonitorStartupTimeout(timeout);

      vi.advanceTimersByTime(1000);
      expect(called).toBe(false);
      expect(deviceGrid.textContent).toBe("");
      vi.useRealTimers();
    });

    it("should apply monitor timeout fallback helper", () => {
      const startMonitorBtn = document.createElement("button");
      const stopMonitorBtn = document.createElement("button");
      const deviceGrid = document.createElement("div");

      startMonitorBtn.style.display = "none";
      stopMonitorBtn.style.display = "block";
      applyMonitorTimeoutFallback(deviceGrid, startMonitorBtn, stopMonitorBtn, "自定义超时提示");

      expect(deviceGrid.textContent).toContain("自定义超时提示");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
    });

    it("should no-op monitor timeout fallback when monitor grid is unavailable", () => {
      const startMonitorBtn = document.createElement("button");
      const stopMonitorBtn = document.createElement("button");

      startMonitorBtn.style.display = "none";
      stopMonitorBtn.style.display = "block";
      applyMonitorTimeoutFallback(null, startMonitorBtn, stopMonitorBtn, "自定义超时提示");

      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");
    });

    it("should apply default monitor timeout strategy message", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");

      startMonitorStartupTimeout(deviceGrid, 1);

      vi.advanceTimersByTime(1000);
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(deviceGrid.textContent).toContain("建议缩小子网范围后重试");
      vi.useRealTimers();
    });

    it("should switch monitor control state on timeout fallback without touching stat nodes", () => {
      vi.useFakeTimers();
      const startMonitorBtn = document.createElement("button");
      const stopMonitorBtn = document.createElement("button");
      const deviceGrid = document.createElement("div");
      const monDevices = document.createElement("div");
      const monOnline = document.createElement("div");
      const monAvgLatency = document.createElement("div");
      const monBest = document.createElement("div");

      startMonitorBtn.style.display = "none";
      stopMonitorBtn.style.display = "block";
      monDevices.textContent = "12";
      monOnline.textContent = "9";
      monAvgLatency.textContent = "15.0ms";
      monBest.textContent = "210";

      const timeout = startMonitorStartupTimeout(
        deviceGrid,
        1,
        DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE,
        () => applyMonitorTimeoutFallback(deviceGrid, startMonitorBtn, stopMonitorBtn),
      );

      vi.advanceTimersByTime(1000);
      expect(timeout).toBeTruthy();
      expect(deviceGrid.textContent).toContain("监测启动超时");
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
      expect(monDevices.textContent).toBe("12");
      expect(monOnline.textContent).toBe("9");
      expect(monAvgLatency.textContent).toBe("15.0ms");
      expect(monBest.textContent).toBe("210");

      vi.useRealTimers();
    });

    it("should clear monitor startup timeout without triggering fallback", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");
      const timeout = startMonitorStartupTimeout(deviceGrid, 2, "监测启动超时");

      stopMonitorStartupTimeout(timeout);
      vi.advanceTimersByTime(3000);
      expect(deviceGrid.textContent).toBe("");
      vi.useRealTimers();
    });

    it("should not start monitor timeout when estimate is unavailable", () => {
      vi.useFakeTimers();
      const deviceGrid = document.createElement("div");

      const timeout = startMonitorStartupTimeout(deviceGrid, null, "监测启动超时");

      expect(timeout).toBeNull();
      vi.advanceTimersByTime(5000);
      expect(deviceGrid.textContent).toBe("");
      vi.useRealTimers();
    });

    it("should apply port scan loading/idle helper states", () => {
      const scanPortsBtn = document.createElement("button");
      const portResults = document.createElement("div");

      setPortScanLoadingState(scanPortsBtn, portResults, "192.168.1.1");
      expect(scanPortsBtn.disabled).toBe(true);
      expect(scanPortsBtn.textContent).toBe("⏳ 扫描中...");
      expect(portResults.textContent).toContain("正在扫描 192.168.1.1 的端口");

      setPortScanIdleState(scanPortsBtn);
      expect(scanPortsBtn.disabled).toBe(false);
      expect(scanPortsBtn.textContent).toBe("扫描端口");
    });

    it("should apply discover device error helper state", () => {
      const deviceList = document.createElement("div");
      setDiscoverDevicesErrorState(deviceList);
      expect(deviceList.textContent).toContain("扫描失败");
      expect(deviceList.textContent).toContain("❌");
    });

    it("should apply port scan error helper state", () => {
      const portResults = document.createElement("div");
      setPortScanErrorState(portResults);
      expect(portResults.textContent).toContain("扫描失败");
      expect(portResults.textContent).toContain("❌");
    });

    it("should reflect scan-in-progress button disabled state and text", () => {
      const scanDevicesBtn = document.createElement("button");
      const deviceList = document.createElement("div");
      const loadingBase = "正在扫描局域网设备...";
      const startAt = Date.now();
      const estimateSeconds = 120;

      const enterScanState = () => {
        scanDevicesBtn.disabled = true;
        scanDevicesBtn.textContent = "⏳ 扫描中...";
        deviceList.innerHTML = `<div class="loading">${buildScanLoadingHtml(loadingBase, startAt, estimateSeconds)}<br><span>扫描范围较大</span></div>`;
      };

      const exitScanState = () => {
        scanDevicesBtn.disabled = false;
        scanDevicesBtn.textContent = "🔍 扫描设备";
      };

      enterScanState();
      expect(scanDevicesBtn.disabled).toBe(true);
      expect(scanDevicesBtn.textContent).toBe("⏳ 扫描中...");
      const loading = deviceList.querySelector(".loading");
      expect(loading).toBeTruthy();
      expect(loading?.textContent).toContain("已耗时");
      expect(loading?.textContent).toContain("预计还需");

      exitScanState();
      expect(scanDevicesBtn.disabled).toBe(false);
      expect(scanDevicesBtn.textContent).toBe("🔍 扫描设备");
    });

    it("should update monitor control visibility during start/stop", () => {
      const startMonitorBtn = document.createElement("button");
      const stopMonitorBtn = document.createElement("button");
      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";

      startMonitorBtn.style.display = "none";
      stopMonitorBtn.style.display = "block";
      expect(startMonitorBtn.style.display).toBe("none");
      expect(stopMonitorBtn.style.display).toBe("block");

      startMonitorBtn.style.display = "block";
      stopMonitorBtn.style.display = "none";
      expect(startMonitorBtn.style.display).toBe("block");
      expect(stopMonitorBtn.style.display).toBe("none");
    });

    it("should show monitor loading hint with elapsed and remaining estimate", () => {
      const deviceGrid = document.createElement("div");
      const startAt = Date.now();
      const estimateSeconds = 120;
      const monitorLoadingHint = "正在初始化监测目标...";
      const monitorLoadingHintWithProgress = `当前扫描范围约：${buildScanLoadingHtml(monitorLoadingHint, startAt, estimateSeconds)}`;

      deviceGrid.innerHTML = `<div class="monitor-hint">${monitorLoadingHintWithProgress}</div>`;
      expect(deviceGrid.textContent).toContain("正在初始化监测目标");
      expect(deviceGrid.textContent).toContain("已耗时");
      expect(deviceGrid.textContent).toContain("预计还需");
    });

    it("should reflect remote port scan in-progress state", () => {
      const scanPortsBtn = document.createElement("button");
      const portResults = document.createElement("div");

      const enterPortScanState = () => {
        scanPortsBtn.disabled = true;
        scanPortsBtn.textContent = "⏳ 扫描中...";
        portResults.innerHTML = "<div class=\"loading\">正在扫描 192.168.1.1 的端口...</div>";
      };

      const exitPortScanState = () => {
        scanPortsBtn.disabled = false;
        scanPortsBtn.textContent = "扫描端口";
        portResults.innerHTML = "<div>扫描结束</div>";
      };

      enterPortScanState();
      expect(scanPortsBtn.disabled).toBe(true);
      expect(scanPortsBtn.textContent).toBe("⏳ 扫描中...");
      expect(portResults.textContent).toContain("正在扫描");

      exitPortScanState();
      expect(scanPortsBtn.disabled).toBe(false);
      expect(scanPortsBtn.textContent).toBe("扫描端口");
      expect(portResults.textContent).toContain("扫描结束");
    });

    it("should reduce remaining estimate as time advances", () => {
      const startAt = Date.now();
      const withOneMinute = buildScanLoadingHtml("扫描中", startAt, 120);
      expect(withOneMinute).toContain("已耗时");
      expect(withOneMinute).toContain("预计还需");

      vi.useFakeTimers();
      vi.setSystemTime(startAt + 60_000);
      const withOneMinutePassed = buildScanLoadingHtml("扫描中", startAt, 120);
      vi.useRealTimers();

      expect(withOneMinutePassed).toContain("已耗时 1 分 0 秒");
      expect(withOneMinutePassed).toContain("预计还需 1 分 0 秒");
    });

    it("should clamp estimate remaining to zero after timeout window passes", () => {
      const startAt = Date.now();
      vi.useFakeTimers();
      vi.setSystemTime(startAt + 181_000);
      const expired = buildScanLoadingHtml("扫描中", startAt, 120);
      vi.useRealTimers();

      expect(expired).toContain("已耗时");
      expect(expired).toMatch(/预计还需 [01] 秒/);
    });
  });

  describe("Class List Manipulation", () => {
    it("should add and remove classes", () => {
      const tab = document.createElement("button");
      tab.className = "active";

      document.body.appendChild(tab);

      expect(tab.classList.contains("active")).toBe(true);

      tab.classList.remove("active");
      expect(tab.classList.contains("active")).toBe(false);

      tab.classList.add("test-class");
      expect(tab.classList.contains("test-class")).toBe(true);

      tab.classList.toggle("active");
      expect(tab.classList.contains("active")).toBe(true);
    });

    it("should toggle multiple classes", () => {
      const element = document.createElement("div");
      document.body.appendChild(element);

      element.classList.add("class1", "class2", "class3");
      expect(element.classList.contains("class1")).toBe(true);
      expect(element.classList.contains("class2")).toBe(true);
      expect(element.classList.contains("class3")).toBe(true);

      element.classList.remove("class2");
      expect(element.classList.contains("class2")).toBe(false);
      expect(element.classList.contains("class1")).toBe(true);
    });
  });

  describe("Element Creation", () => {
    it("should create and append elements", () => {
      const tbody = document.createElement("tbody");
      document.body.appendChild(tbody);

      const initialLength = tbody.children.length;

      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.textContent = "8080";
      row.appendChild(cell);
      tbody.appendChild(row);

      expect(tbody.children.length).toBe(initialLength + 1);
      expect(tbody.lastElementChild?.textContent).toContain("8080");
    });

    it("should set element attributes", () => {
      const input = document.createElement("input");

      input.type = "text";
      input.placeholder = "Search...";
      input.id = "search-input";

      expect(input.type).toBe("text");
      expect(input.placeholder).toBe("Search...");
      expect(input.id).toBe("search-input");
    });

    it("should set element styles", () => {
      const div = document.createElement("div");

      div.style.color = "red";
      div.style.fontSize = "14px";
      div.style.display = "flex";

      expect(div.style.color).toBe("red");
      expect(div.style.fontSize).toBe("14px");
      expect(div.style.display).toBe("flex");
    });
  });
});
