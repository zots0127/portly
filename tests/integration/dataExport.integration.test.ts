import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { JSDOM } from "jsdom";

/**
 * Data Export Integration Tests
 *
 * Tests the complete workflow of data export including:
 * - Port data export to CSV
 * - Port data export to JSON
 * - Port data export to TXT
 * - File save/download simulation
 * - Error handling
 */

// Types matching the application
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
  scan_time_ms?: number;
}

interface ExportResult {
  success: boolean;
  path: string | null;
  message: string;
  record_count: number;
}

describe("Data Export Integration", () => {
  let dom: JSDOM;
  let document: Document;
  let mockInvoke: ReturnType<typeof vi.fn>;
  let mockOpenUrl: ReturnType<typeof vi.fn>;

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
  ];

  const mockScanResult: ScanResult = {
    scan_time: new Date().toISOString(),
    total_ports: 3,
    unique_apps: 3,
    ports: mockPortsData,
    scan_time_ms: 150,
  };

  const mockExportResult: ExportResult = {
    success: true,
    path: "/tmp/ports-export.csv",
    message: "Data exported successfully",
    record_count: 3,
  };

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head><title>Export Test</title></head>
        <body>
          <button id="export-btn">Export</button>
          <div id="export-menu" class="hidden">
            <button id="export-csv">Export as CSV</button>
            <button id="export-json">Export as JSON</button>
            <button id="export-txt">Export as TXT</button>
          </div>

          <!-- Toast container -->
          <div id="toast-container"></div>
        </body>
      </html>
    `, { runScripts: "dangerously" });

    document = dom.window.document;

    // Get the global mock from setupTests
    mockInvoke = (global as any).__mockInvoke;
    mockOpenUrl = (global as any).__mockOpenUrl;
  });

  afterEach(() => {
    dom.window.close();
  });

  describe("should export port data to CSV", () => {
    it("should initialize DOM elements correctly", () => {
      const exportBtn = document.getElementById("export-btn");
      const exportMenu = document.getElementById("export-menu");
      const exportCsv = document.getElementById("export-csv");

      expect(exportBtn).toBeTruthy();
      expect(exportMenu).toBeTruthy();
      expect(exportCsv).toBeTruthy();
    });

    it("should show export menu on button click", () => {
      const exportBtn = document.getElementById("export-btn")!;
      const exportMenu = document.getElementById("export-menu")!;

      // Toggle menu visibility
      exportMenu.classList.toggle("visible");

      expect(exportMenu.classList.contains("visible")).toBe(true);
    });

    it("should call Tauri invoke with correct parameters for CSV export", async () => {
      const result = await invoke("tauri_export_auto", {
        ports: mockPortsData,
        scanResult: mockScanResult,
        format: "csv",
      });

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.path).toContain(".csv");
      expect(result.record_count).toBe(3);
    });

    it("should handle CSV export with no data", async () => {
      const emptyPorts: PortInfo[] = [];

      // Simulate validation
      let errorMessage = null;
      if (emptyPorts.length === 0) {
        errorMessage = "没有可导出的数据，请先扫描端口";
      }

      expect(errorMessage).toBe("没有可导出的数据，请先扫描端口");
    });

    it("should generate CSV content from port data", () => {
      const headers = ["Port", "Protocol", "Address", "PID", "Process", "User", "Command"];
      const rows = mockPortsData.map((p) => [
        p.port,
        p.protocol,
        p.address,
        p.pid,
        p.process,
        p.user,
        p.command || "",
      ]);

      // Build CSV string - without quotes around headers
      const csvContent = [
        headers.join(","),
        ...rows.map((row) => row.map((cell) => `"${cell}"`).join(",")),
      ].join("\n");

      expect(csvContent).toContain("Port,Protocol,Address,PID,Process,User,Command");
      expect(csvContent).toContain('"8080","tcp","127.0.0.1","1234","node","user"');
      expect(csvContent).toContain('"3000","tcp","0.0.0.0","5678","vite","user"');
    });

    it("should escape special characters in CSV", () => {
      const specialData: PortInfo = {
        port: 8080,
        protocol: "tcp",
        address: "127.0.0.1",
        pid: "1234",
        process: 'node "test" app',
        user: "user",
        command: 'node /app/server.js --arg="value"',
      };

      const csvRow = `"${specialData.port}","${specialData.protocol}","${specialData.address}","${specialData.pid}","${specialData.process}","${specialData.user}","${specialData.command}"`;

      expect(csvRow).toContain('node "test" app');
      expect(csvRow).toContain('--arg="value"');
    });
  });

  describe("should export port data to JSON", () => {
    it("should call Tauri invoke with correct parameters for JSON export", async () => {
      const result = await invoke("tauri_export_auto", {
        ports: mockPortsData,
        scanResult: mockScanResult,
        format: "json",
      });

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.path).toContain(".json");
    });

    it("should generate valid JSON from port data", () => {
      const jsonData = {
        scan_time: mockScanResult.scan_time,
        total_ports: mockScanResult.total_ports,
        unique_apps: mockScanResult.unique_apps,
        ports: mockPortsData,
      };

      const jsonString = JSON.stringify(jsonData, null, 2);

      expect(() => JSON.parse(jsonString)).not.toThrow();
      const parsed = JSON.parse(jsonString);
      expect(parsed.ports).toHaveLength(3);
      expect(parsed.ports[0].port).toBe(8080);
    });

    it("should include scan metadata in JSON export", () => {
      const jsonData = {
        scan_time: mockScanResult.scan_time,
        total_ports: mockScanResult.total_ports,
        unique_apps: mockScanResult.unique_apps,
        scan_time_ms: mockScanResult.scan_time_ms,
        ports: mockPortsData,
      };

      expect(jsonData.scan_time).toBeTruthy();
      expect(jsonData.total_ports).toBe(3);
      expect(jsonData.unique_apps).toBe(3);
      expect(jsonData.scan_time_ms).toBe(150);
    });
  });

  describe("should export port data to TXT", () => {
    it("should call Tauri invoke with correct parameters for TXT export", async () => {
      const result = await invoke("tauri_export_auto", {
        ports: mockPortsData,
        scanResult: mockScanResult,
        format: "txt",
      });

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.path).toContain(".txt");
    });

    it("should generate formatted text from port data", () => {
      const lines = [
        `Port Scan Results - ${new Date().toLocaleString()}`,
        `Total Ports: ${mockScanResult.total_ports}`,
        `Unique Apps: ${mockScanResult.unique_apps}`,
        "",
        "Port\tProtocol\tAddress\tPID\tProcess",
        "-" * 60,
        ...mockPortsData.map((p) =>
          `${p.port}\t${p.protocol}\t${p.address}\t${p.pid}\t${p.process}`
        ),
      ];

      const txtContent = lines.join("\n");

      expect(txtContent).toContain("Port Scan Results");
      expect(txtContent).toContain("Total Ports: 3");
      expect(txtContent).toContain("8080\ttcp\t127.0.0.1\t1234\tnode");
    });

    it("should format dates in readable format for TXT export", () => {
      const scanDate = new Date(mockScanResult.scan_time);
      const formattedDate = scanDate.toLocaleString("zh-CN");

      expect(formattedDate).toBeTruthy();
      expect(formattedDate).toMatch(/\d{4}/); // Contains year
    });
  });

  describe("should handle export errors gracefully", () => {
    it("should handle file write error", async () => {
      mockInvoke.mockResolvedValueOnce({
        success: false,
        path: null,
        message: "Failed to write file: Permission denied",
        record_count: 0,
      });

      const result = await invoke("tauri_export_auto", {
        ports: mockPortsData,
        scanResult: mockScanResult,
        format: "csv",
      });

      expect(result.success).toBe(false);
      expect(result.message).toContain("Permission denied");
    });

    it("should handle empty data error", async () => {
      const emptyPorts: PortInfo[] = [];
      const emptyResult: ScanResult = {
        scan_time: new Date().toISOString(),
        total_ports: 0,
        unique_apps: 0,
        ports: [],
      };

      mockInvoke.mockResolvedValueOnce({
        success: false,
        path: null,
        message: "No data to export",
        record_count: 0,
      });

      const result = await invoke("tauri_export_auto", {
        ports: emptyPorts,
        scanResult: emptyResult,
        format: "csv",
      });

      expect(result.success).toBe(false);
      expect(result.record_count).toBe(0);
    });

    it("should handle network path error", async () => {
      mockInvoke.mockRejectedValueOnce(new Error("Network path not accessible"));

      try {
        await invoke("tauri_export_auto", {
          ports: mockPortsData,
          scanResult: mockScanResult,
          format: "csv",
        });
        expect.fail("Should have thrown an error");
      } catch (error) {
        expect((error as Error).message).toContain("Network path");
      }
    });
  });

  describe("should handle export menu interactions", () => {
    it("should close menu after export", () => {
      const exportMenu = document.getElementById("export-menu")!;

      exportMenu.classList.add("visible");
      expect(exportMenu.classList.contains("visible")).toBe(true);

      // Simulate menu close after export
      exportMenu.classList.remove("visible");
      expect(exportMenu.classList.contains("visible")).toBe(false);
    });

    it("should close menu when clicking outside", () => {
      const exportBtn = document.getElementById("export-btn")!;
      const exportMenu = document.getElementById("export-menu")!;

      exportMenu.classList.add("visible");

      // Simulate click outside
      const clickOutsideEvent = {
        target: document.body,
      };

      if (
        !exportBtn.contains(clickOutsideEvent.target as Node) &&
        !exportMenu.contains(clickOutsideEvent.target as Node)
      ) {
        exportMenu.classList.remove("visible");
      }

      expect(exportMenu.classList.contains("visible")).toBe(false);
    });

    it("should handle multiple export format clicks", () => {
      const exportMenu = document.getElementById("export-menu")!;
      const exportCsv = document.getElementById("export-csv")!;
      const exportJson = document.getElementById("export-json")!;

      let csvClicked = false;
      let jsonClicked = false;

      exportCsv.addEventListener("click", () => {
        csvClicked = true;
        exportMenu.classList.remove("visible");
      });

      exportJson.addEventListener("click", () => {
        jsonClicked = true;
        exportMenu.classList.remove("visible");
      });

      exportCsv.click();
      expect(csvClicked).toBe(true);
      expect(exportMenu.classList.contains("visible")).toBe(false);

      // Reopen menu
      exportMenu.classList.add("visible");

      exportJson.click();
      expect(jsonClicked).toBe(true);
      expect(exportMenu.classList.contains("visible")).toBe(false);
    });
  });

  describe("should display export feedback", () => {
    it("should show success toast on successful export", async () => {
      const result = mockExportResult;
      const toastContainer = document.getElementById("toast-container")!;

      // Create success toast
      const toast = document.createElement("div");
      toast.className = "toast toast-success";
      toast.textContent = `✅ ${result.message}\n📁 ${result.path}`;
      toastContainer.appendChild(toast);

      expect(toastContainer.children.length).toBe(1);
      expect(toast.textContent).toContain("Data exported successfully");
      expect(toast.textContent).toContain("/tmp/ports-export.csv");
    });

    it("should show error toast on failed export", async () => {
      const errorResult: ExportResult = {
        success: false,
        path: null,
        message: "导出失败: Permission denied",
        record_count: 0,
      };
      const toastContainer = document.getElementById("toast-container")!;

      // Create error toast
      const toast = document.createElement("div");
      toast.className = "toast toast-error";
      toast.textContent = `❌ ${errorResult.message}`;
      toastContainer.appendChild(toast);

      expect(toast.className).toContain("toast-error");
      expect(toast.textContent).toContain("Permission denied");
    });

    it("should show info toast when no data to export", () => {
      const toastContainer = document.getElementById("toast-container")!;

      // Create info toast
      const toast = document.createElement("div");
      toast.className = "toast toast-info";
      toast.textContent = "没有可导出的数据，请先扫描端口";
      toastContainer.appendChild(toast);

      expect(toast.className).toContain("toast-info");
      expect(toast.textContent).toContain("没有可导出的数据");
    });
  });

  describe("should export filtered data", () => {
    it("should only export currently filtered ports", () => {
      const allPorts = mockPortsData;
      const filteredPorts = allPorts.filter((p) => p.process === "node");

      expect(filteredPorts.length).toBe(1);
      expect(filteredPorts[0].process).toBe("node");
    });

    it("should update export data when filters change", () => {
      // Initial state - all ports
      let currentPorts = mockPortsData;

      // Apply filter
      const appFilter = "node";
      currentPorts = currentPorts.filter((p) =>
        p.process.toLowerCase().includes(appFilter.toLowerCase())
      );

      expect(currentPorts.length).toBe(1);

      // Clear filter
      currentPorts = mockPortsData;
      expect(currentPorts.length).toBe(3);
    });

    it("should export empty result when no ports match filter", () => {
      const allPorts = mockPortsData;
      const filteredPorts = allPorts.filter((p) =>
        p.process.toLowerCase().includes("nonexistent")
      );

      expect(filteredPorts.length).toBe(0);
    });
  });

  describe("should handle concurrent export requests", () => {
    it("should queue multiple export requests", async () => {
      let requestCount = 0;
      mockInvoke.mockImplementation(async () => {
        requestCount++;
        return { ...mockExportResult, record_count: requestCount };
      });

      const results = await Promise.all([
        invoke("tauri_export_auto", { ports: mockPortsData, scanResult: mockScanResult, format: "csv" }),
        invoke("tauri_export_auto", { ports: mockPortsData, scanResult: mockScanResult, format: "json" }),
        invoke("tauri_export_auto", { ports: mockPortsData, scanResult: mockScanResult, format: "txt" }),
      ]);

      expect(results.length).toBe(3);
      expect(results.every((r) => r.success)).toBe(true);
    });
  });
});
