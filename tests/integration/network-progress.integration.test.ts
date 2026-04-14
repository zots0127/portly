import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

type MockInvoke = ReturnType<typeof vi.fn>;

function setupMainDom(): void {
  document.body.innerHTML = `
    <div id="toast-container"></div>

    <button id="tab-local" class="tab active"></button>
    <button id="tab-network" class="tab"></button>
    <button id="tab-monitor" class="tab"></button>
    <button id="tab-dns" class="tab"></button>
    <button id="tab-whois" class="tab"></button>
    <button id="tab-ssl" class="tab"></button>

    <div id="page-local" class="page">
      <button id="view-table" class="segment active"></button>
      <button id="view-group" class="segment"></button>
      <input id="app-filter" />
      <input id="port-filter" />
      <input id="exclude-system" />
      <input id="show-command" />
      <button id="refresh-btn"></button>
      <span id="stat-time"></span>
      <span id="stat-apps"></span>
      <span id="stat-ports"></span>
      <table id="port-table">
        <tbody id="port-tbody"></tbody>
      </table>
      <div id="group-view" class="group-view hidden"></div>
      <div id="source-filter">
        <button class="segment active" data-filter="all"></button>
        <button class="segment" data-filter="local"></button>
        <button class="segment" data-filter="docker"></button>
      </div>
      <button id="export-btn"></button>
      <div id="export-menu">
        <button id="export-csv"></button>
        <button id="export-json"></button>
        <button id="export-txt"></button>
      </div>
    </div>

    <div id="page-network" class="page hidden">
      <select id="subnet-select"></select>
      <input id="manual-subnet" />
      <button id="scan-devices-btn"></button>
      <span id="net-stat-devices"></span>
      <button id="refresh-network-btn"></button>
      <span id="device-count"></span>
      <div id="device-list"></div>
      <span id="selected-device-ip"></span>
      <select id="scan-type">
        <option value="common"></option>
        <option value="quick"></option>
        <option value="full"></option>
        <option value="custom"></option>
      </select>
      <input id="port-start" />
      <input id="port-end" />
      <button id="scan-ports-btn" disabled></button>
      <div id="port-results"></div>
      <div id="device-actions"></div>
      <button id="ping-btn"></button>
      <button id="trace-btn"></button>
      <button id="multi-ping-btn"></button>
      <input id="manual-target" />
      <button id="add-manual-target"></button>
    </div>

    <div id="page-monitor" class="page hidden">
      <select id="monitor-subnet"></select>
      <input id="monitor-manual-subnet" />
      <button id="start-monitor-btn"></button>
      <button id="stop-monitor-btn" style="display: none;"></button>
      <span id="mon-devices"></span>
      <span id="mon-online"></span>
      <span id="mon-avg-latency"></span>
      <span id="mon-best"></span>
      <canvas id="monitor-canvas"></canvas>
      <div id="device-grid"></div>
    </div>

    <div id="page-dns" class="page hidden">
      <input id="dns-domain-input" />
      <select id="dns-record-type"></select>
      <select id="dns-server"></select>
      <button id="dns-query-btn"></button>
      <div id="dns-loading"></div>
      <div id="dns-error"></div>
      <div id="dns-results"></div>
      <div id="dns-domain"></div>
      <div id="dns-type"></div>
      <div id="dns-count"></div>
      <div id="dns-time"></div>
      <div id="dns-records-list"></div>
    </div>

    <div id="page-whois" class="page hidden">
      <input id="whois-input" />
      <button id="whois-query-btn"></button>
      <div id="whois-loading"></div>
      <div id="whois-error"></div>
      <div id="whois-results"></div>
      <div id="whois-domain"></div>
      <div id="whois-registrar"></div>
      <div id="whois-created"></div>
      <div id="whois-expires"></div>
      <div id="whois-status"></div>
      <div id="whois-nameservers"></div>
      <div id="whois-dnssec"></div>
      <div id="whois-dnssec-section"></div>
      <div id="whois-raw"></div>
    </div>

    <div id="page-ssl" class="page hidden">
      <input id="ssl-host-input" />
      <input id="ssl-port-input" />
      <button id="ssl-check-btn"></button>
      <div id="ssl-loading"></div>
      <div id="ssl-error"></div>
      <div id="ssl-results"></div>
      <div id="ssl-host"></div>
      <div id="ssl-subject"></div>
      <div id="ssl-issuer"></div>
      <div id="ssl-valid-from"></div>
      <div id="ssl-valid-until"></div>
      <div id="ssl-days-left"></div>
      <div id="ssl-key-size"></div>
      <div id="ssl-signature"></div>
      <div id="ssl-version"></div>
      <div id="ssl-serial"></div>
      <div id="ssl-tls-version"></div>
      <div id="ssl-cipher-suite"></div>
      <div id="ssl-chain"></div>
      <span id="ssl-self-signed"></span>
      <div id="ssl-status"></div>
    </div>
  `;
}

function flushAsync(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function loadMainModule(): Promise<MockInvoke> {
  vi.resetModules();
  await import("../../src/main");
  return (globalThis as any).__mockInvoke as MockInvoke;
}

describe("Network Progress Prompt Regressions", () => {
  let mockInvoke: MockInvoke;

  beforeEach(async () => {
    setupMainDom();
    mockInvoke = await loadMainModule();
    mockInvoke.mockClear();
  });

  afterEach(() => {
    document.getElementById("stop-monitor-btn")?.click();
    vi.clearAllMocks();
  });

  it("should show scan-page startup elapsed and remaining estimate text", async () => {
    const subnetInput = document.getElementById("manual-subnet") as HTMLInputElement;
    const scanBtn = document.getElementById("scan-devices-btn") as HTMLButtonElement;
    const deviceList = document.getElementById("device-list") as HTMLDivElement;

    subnetInput.value = "192.168.1.0/22";
    scanBtn.click();

    expect(deviceList.textContent).toContain("正在扫描局域网设备");
    expect(deviceList.textContent).toContain("已耗时");
    expect(deviceList.textContent).toContain("预计还需");
    expect(deviceList.textContent).toContain("当前范围约 1022 台主机");

    await flushAsync();
    await flushAsync();

    expect(scanBtn.disabled).toBe(false);
    expect(scanBtn.textContent).toBe("🔍 扫描设备");
  });

  it("should show monitor init loading hint with progress while initializing", async () => {
    const monitorSubnetInput = document.getElementById("monitor-manual-subnet") as HTMLInputElement;
    const startMonitorBtn = document.getElementById("start-monitor-btn") as HTMLButtonElement;
    const stopMonitorBtn = document.getElementById("stop-monitor-btn") as HTMLButtonElement;
    const deviceGrid = document.getElementById("device-grid") as HTMLDivElement;

    monitorSubnetInput.value = "192.168.1.0/22";
    startMonitorBtn.click();

    expect(deviceGrid.textContent).toContain("正在初始化监测目标");
    expect(deviceGrid.textContent).toContain("当前扫描范围约");
    expect(deviceGrid.textContent).toContain("已耗时");
    expect(deviceGrid.textContent).toContain("预计还需");

    await flushAsync();

    stopMonitorBtn.click();
    expect(stopMonitorBtn.style.display).toBe("none");
  });

  it("should keep timeout failure text aligned with command error formatting", async () => {
    const monitorSubnetInput = document.getElementById("monitor-manual-subnet") as HTMLInputElement;
    const startMonitorBtn = document.getElementById("start-monitor-btn") as HTMLButtonElement;

    monitorSubnetInput.value = "192.168.1.0/22";
    mockInvoke.mockRejectedValueOnce(new Error("Network monitor timed out"));
    startMonitorBtn.click();

    await flushAsync();
    await flushAsync();

    const toasts = Array.from(document.querySelectorAll("#toast-container .toast")) as HTMLDivElement[];
    const timeoutToast = toasts.find((t) => t.textContent?.includes("监测模式设备发现失败"));
    expect(timeoutToast).toBeTruthy();
    expect(timeoutToast?.textContent).toContain("监测模式设备发现失败");
    expect(timeoutToast?.textContent).toContain("Network monitor timed out");
  });
});
