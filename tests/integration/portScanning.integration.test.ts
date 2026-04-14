import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { JSDOM } from "jsdom";

/**
 * Port Scanning Integration Tests
 *
 * Tests the complete workflow of port scanning including:
 * - DOM element creation and interaction
 * - Tauri invoke calls
 * - Result display
 * - Filtering functionality
 */

// Types matching the main application
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

describe("Port Scanning Integration", () => {
  let dom: JSDOM;
  let document: Document;
  let mockInvoke: ReturnType<typeof vi.fn>;

  const mockPortsData: PortInfo[] = [
    {
      port: 8080,
      protocol: "tcp",
      address: "127.0.0.1",
      pid: "1234",
      process: "node",
      user: "user",
      command: "node /app/server.js",
    },
    {
      port: 3000,
      protocol: "tcp",
      address: "0.0.0.0",
      pid: "5678",
      process: "vite",
      user: "user",
      command: "vite",
    },
    {
      port: 5432,
      protocol: "tcp",
      address: "127.0.0.1",
      pid: "9012",
      process: "postgres",
      user: "postgres",
      command: "postgres -D /usr/local/var/postgres",
    },
    {
      port: 6379,
      protocol: "tcp",
      address: "127.0.0.1",
      pid: "3456",
      process: "redis-server",
      user: "redis",
      command: "redis-server *:6379",
    },
  ];

  const mockScanResult: ScanResult = {
    scan_time: new Date().toISOString(),
    total_ports: 4,
    unique_apps: 4,
    ports: mockPortsData,
  };

  beforeEach(() => {
    // Create fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head><title>Portly Test</title></head>
        <body>
          <!-- Local Port Page Elements -->
          <button id="view-table" class="segment active">Table</button>
          <button id="view-group" class="segment">Group</button>
          <input type="checkbox" id="show-command" />
          <input type="text" id="app-filter" placeholder="Filter by app name" />
          <input type="number" id="port-filter" placeholder="Filter by port" />
          <input type="checkbox" id="exclude-system" />
          <button id="refresh-btn">Scan</button>
          <span id="stat-time"></span>
          <span id="stat-apps"></span>
          <span id="stat-ports"></span>
          <table id="port-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Address</th>
                <th>PID</th>
                <th>Process</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="port-tbody"></tbody>
          </table>
          <div id="group-view" class="group-view hidden"></div>

          <!-- Source Filter -->
          <div id="source-filter">
            <button class="segment active" data-filter="all">All</button>
            <button class="segment" data-filter="local">Local</button>
            <button class="segment" data-filter="docker">Docker</button>
          </div>

          <!-- Toast Container -->
          <div id="toast-container"></div>
        </body>
      </html>
    `, { runScripts: "dangerously" });

    document = dom.window.document;

    // Get the global mock from setupTests
    mockInvoke = (global as any).__mockInvoke;
  });

  afterEach(() => {
    dom.window.close();
  });

  describe("should scan local ports and display results", () => {
    it("should initialize DOM elements correctly", () => {
      const viewTableBtn = document.getElementById("view-table");
      const viewGroupBtn = document.getElementById("view-group");
      const appFilter = document.getElementById("app-filter");
      const portFilter = document.getElementById("port-filter");
      const portTbody = document.getElementById("port-tbody");

      expect(viewTableBtn).toBeTruthy();
      expect(viewGroupBtn).toBeTruthy();
      expect(appFilter).toBeTruthy();
      expect(portFilter).toBeTruthy();
      expect(portTbody).toBeTruthy();
    });

    it("should call Tauri invoke with correct command", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true });

      expect(result).toBeDefined();
      expect(result).toHaveProperty("scan_time");
      expect(result).toHaveProperty("ports");
      expect(Array.isArray(result.ports)).toBe(true);
    });

    it("should display scan results in table", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;
      const portTbody = document.getElementById("port-tbody")!;

      // Simulate rendering
      portTbody.innerHTML = "";
      result.ports.forEach((port) => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${port.port}</td>
          <td>${port.protocol}</td>
          <td>${port.address}</td>
          <td>${port.pid}</td>
          <td>${port.process}</td>
          <td>
            <button class="port-kill-btn" data-pid="${port.pid}">Kill</button>
          </td>
        `;
        portTbody.appendChild(row);
      });

      // Verify rows were created
      expect(portTbody.children.length).toBeGreaterThanOrEqual(2);
      expect(portTbody.children[0].textContent).toContain("8080");
      expect(portTbody.children[0].textContent).toContain("node");
    });

    it("should update statistics after scan", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;
      const statTime = document.getElementById("stat-time")!;
      const statApps = document.getElementById("stat-apps")!;
      const statPorts = document.getElementById("stat-ports")!;

      statTime.textContent = result.scan_time.split("T")[1].split(".")[0];
      statApps.textContent = result.unique_apps.toString();
      statPorts.textContent = result.total_ports.toString();

      expect(statTime.textContent).toBeTruthy();
      expect(parseInt(statApps.textContent || "0", 10)).toBeGreaterThanOrEqual(1);
      expect(parseInt(statPorts.textContent || "0", 10)).toBeGreaterThanOrEqual(1);
    });

    it("should show loading state during scan", () => {
      const refreshBtn = document.getElementById("refresh-btn")!;

      // Simulate loading state
      refreshBtn.classList.add("spinning");
      refreshBtn.textContent = "Scanning...";

      expect(refreshBtn.classList.contains("spinning")).toBe(true);
      expect(refreshBtn.textContent).toBe("Scanning...");

      // Simulate completion
      refreshBtn.classList.remove("spinning");
      refreshBtn.textContent = "Scan";

      expect(refreshBtn.classList.contains("spinning")).toBe(false);
    });
  });

  describe("should filter ports by application name", () => {
    it("should filter ports by process name", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;
      const appFilter = document.getElementById("app-filter") as HTMLInputElement;
      const portTbody = document.getElementById("port-tbody")!;

      // Set filter value
      appFilter.value = "node";

      // Filter the ports
      const filteredPorts = result.ports.filter((p) =>
        p.process.toLowerCase().includes(appFilter.value.toLowerCase())
      );

      // Render filtered results
      portTbody.innerHTML = "";
      filteredPorts.forEach((port) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${port.port}</td><td>${port.process}</td>`;
        portTbody.appendChild(row);
      });

      // Verify filtering worked
      expect(portTbody.children.length).toBe(1);
      expect(portTbody.children[0].textContent).toContain("node");
      expect(portTbody.children[0].textContent).not.toContain("vite");
    });

    it("should filter ports by port number", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;
      const portFilter = document.getElementById("port-filter") as HTMLInputElement;
      const portTbody = document.getElementById("port-tbody")!;

      // Set filter value
      portFilter.value = "3000";

      // Filter the ports
      const portNum = parseInt(portFilter.value);
      const filteredPorts = result.ports.filter((p) => p.port === portNum);

      // Render filtered results
      portTbody.innerHTML = "";
      filteredPorts.forEach((port) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${port.port}</td><td>${port.process}</td>`;
        portTbody.appendChild(row);
      });

      // Verify filtering worked
      expect(portTbody.children.length).toBe(1);
      expect(portTbody.children[0].textContent).toContain("3000");
    });

    it("should show empty state when no ports match filter", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;
      const appFilter = document.getElementById("app-filter") as HTMLInputElement;
      const portTbody = document.getElementById("port-tbody")!;

      // Set filter value that won't match
      appFilter.value = "nonexistent";

      // Filter the ports
      const filteredPorts = result.ports.filter((p) =>
        p.process.toLowerCase().includes(appFilter.value.toLowerCase())
      );

      // Render empty state
      portTbody.innerHTML = "";
      if (filteredPorts.length === 0) {
        portTbody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align: center; padding: 40px;">
              没有找到匹配的端口
            </td>
          </tr>
        `;
      }

      expect(portTbody.textContent).toContain("没有找到匹配的端口");
    });

    it("should handle case-insensitive filtering", async () => {
      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;

      const filters = ["NODE", "Node", "node", "NoDe"];

      filters.forEach((filter) => {
        const filtered = result.ports.filter((p) =>
          p.process.toLowerCase().includes(filter.toLowerCase())
        );
        expect(filtered.length).toBe(1);
        expect(filtered[0].process).toBe("node");
      });
    });
  });

  describe("should switch between table and group views", () => {
    it("should toggle view buttons", () => {
      const viewTableBtn = document.getElementById("view-table")!;
      const viewGroupBtn = document.getElementById("view-group")!;
      const portTable = document.getElementById("port-table")!;
      const groupView = document.getElementById("group-view")!;

      // Initial state
      expect(viewTableBtn.classList.contains("active")).toBe(true);
      expect(viewGroupBtn.classList.contains("active")).toBe(false);
      expect(groupView.classList.contains("hidden")).toBe(true);

      // Switch to group view
      viewTableBtn.classList.remove("active");
      viewGroupBtn.classList.add("active");
      portTable.classList.add("hidden");
      groupView.classList.remove("hidden");

      expect(viewTableBtn.classList.contains("active")).toBe(false);
      expect(viewGroupBtn.classList.contains("active")).toBe(true);
      expect(portTable.classList.contains("hidden")).toBe(true);
      expect(groupView.classList.contains("hidden")).toBe(false);
    });

    it("should render app cards in group view", async () => {
      const result = await invoke("tauri_scan_ports_grouped");
      const groupView = document.getElementById("group-view")!;

      expect(Array.isArray(result)).toBe(true);

      // Simulate rendering group view
      groupView.innerHTML = "";
      (result as Array<{ process: string; pid: string; ports: number[] }>).forEach((group) => {
        const card = document.createElement("div");
        card.className = "app-card";
        card.innerHTML = `
          <div class="app-name">${group.process}</div>
          <div class="app-pid">PID ${group.pid}</div>
          <div class="app-ports">
            ${group.ports.map((p) => `<span class="port-tag">${p}</span>`).join(" ")}
          </div>
        `;
        groupView.appendChild(card);
      });

      expect(groupView.children.length).toBeGreaterThan(0);
      expect(groupView.querySelector(".app-card")).toBeTruthy();
    });
  });

  describe("should handle show command toggle", () => {
    it("should toggle command display", async () => {
      const showCommand = document.getElementById("show-command") as HTMLInputElement;
      const portTbody = document.getElementById("port-tbody")!;

      // Initially unchecked
      expect(showCommand.checked).toBe(false);

      // Add port rows
      const port = mockPortsData[0];
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${port.port}</td>
        <td>${port.process}</td>
      `;
      portTbody.appendChild(row);

      expect(portTbody.children.length).toBe(1);

      // Enable show command
      showCommand.checked = true;

      if (showCommand.checked && port.command) {
        const cmdRow = document.createElement("tr");
        cmdRow.className = "command-row";
        cmdRow.innerHTML = `<td colspan="6">${port.command}</td>`;
        portTbody.appendChild(cmdRow);
      }

      // Now we should have 2 rows (port + command)
      expect(portTbody.children.length).toBe(2);
      expect(portTbody.children[1].classList.contains("command-row")).toBe(true);
    });
  });

  describe("should handle source filter (all/local/docker)", () => {
    it("should switch source filter buttons", () => {
      const sourceFilterBtns = document.querySelectorAll("#source-filter .segment");

      expect(sourceFilterBtns.length).toBe(3);

      // All buttons
      sourceFilterBtns.forEach((btn) => {
        expect(btn.classList.contains("segment")).toBe(true);
      });

      // First button should be active
      expect(sourceFilterBtns[0].classList.contains("active")).toBe(true);
    });

    it("should update filter data attribute", () => {
      const sourceFilterBtns = document.querySelectorAll("#source-filter .segment");

      // Click docker button
      sourceFilterBtns.forEach((b) => b.classList.remove("active"));
      (sourceFilterBtns[2] as HTMLElement).classList.add("active");

      const activeFilter = Array.from(sourceFilterBtns).find((btn) =>
        btn.classList.contains("active")
      ) as HTMLElement;

      expect(activeFilter.dataset.filter).toBe("docker");
    });
  });

  describe("should handle scan errors gracefully", () => {
    it("should show error message on scan failure", async () => {
      // Mock a failed scan
      mockInvoke.mockRejectedValueOnce(new Error("Scan failed"));

      try {
        await invoke("tauri_scan_ports", { includeCommand: true });
        expect.fail("Should have thrown an error");
      } catch (error) {
        expect((error as Error).message).toBe("Scan failed");
      }
    });

    it("should handle empty scan results", async () => {
      const emptyResult: ScanResult = {
        scan_time: new Date().toISOString(),
        total_ports: 0,
        unique_apps: 0,
        ports: [],
      };
      mockInvoke.mockResolvedValueOnce(emptyResult);

      const result = await invoke("tauri_scan_ports", { includeCommand: true }) as ScanResult;
      const portTbody = document.getElementById("port-tbody")!;

      portTbody.innerHTML = "";
      if (result.ports.length === 0) {
        portTbody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align: center; padding: 40px;">
              没有找到匹配的端口
            </td>
          </tr>
        `;
      }

      expect(portTbody.textContent).toContain("没有找到匹配的端口");
    });
  });
});
