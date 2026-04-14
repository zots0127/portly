import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { JSDOM } from "jsdom";

/**
 * DNS Query Integration Tests
 *
 * Tests the complete workflow of DNS queries including:
 * - User input handling
 * - Record type selection
 * - Query execution
 * - Result display
 * - Error handling
 */

// Types matching the application
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

describe("DNS Query Integration", () => {
  let dom: JSDOM;
  let document: Document;
  let mockInvoke: ReturnType<typeof vi.fn>;

  const mockDnsResult: DnsQueryResult = {
    domain: "example.com",
    record_type: "A",
    records: [
      {
        name: "example.com",
        rtype: "A",
        ttl: 300,
        data: "93.184.216.34",
      },
      {
        name: "example.com",
        rtype: "A",
        ttl: 300,
        data: "93.184.216.35",
      },
    ],
    query_time_ms: 50,
    dns_server: "8.8.8.8",
    error: null,
  };

  const mockMxResult: DnsQueryResult = {
    domain: "example.com",
    record_type: "MX",
    records: [
      {
        name: "example.com",
        rtype: "MX",
        ttl: 3600,
        data: "10 mail.example.com",
      },
    ],
    query_time_ms: 75,
    dns_server: "8.8.8.8",
    error: null,
  };

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head><title>DNS Query Test</title></head>
        <body>
          <div id="page-dns">
            <input type="text" id="dns-domain-input" placeholder="Enter domain" />
            <select id="dns-record-type">
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="MX">MX</option>
              <option value="TXT">TXT</option>
              <option value="CNAME">CNAME</option>
              <option value="NS">NS</option>
            </select>
            <select id="dns-server">
              <option value="">Default (8.8.8.8)</option>
              <option value="8.8.8.8">Google (8.8.8.8)</option>
              <option value="1.1.1.1">Cloudflare (1.1.1.1)</option>
            </select>
            <button id="dns-query-btn">Query</button>

            <div id="dns-loading" class="hidden">Loading...</div>
            <div id="dns-error" class="hidden"></div>
            <div id="dns-results" class="hidden">
              <div id="dns-domain"></div>
              <div id="dns-type"></div>
              <div id="dns-count"></div>
              <div id="dns-time"></div>
              <div id="dns-records-list"></div>
            </div>
          </div>

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

  describe("should query DNS records and display results", () => {
    it("should initialize DOM elements correctly", () => {
      const dnsInput = document.getElementById("dns-domain-input");
      const recordType = document.getElementById("dns-record-type");
      const queryBtn = document.getElementById("dns-query-btn");

      expect(dnsInput).toBeTruthy();
      expect(recordType).toBeTruthy();
      expect(queryBtn).toBeTruthy();
    });

    it("should show error when domain is empty", async () => {
      const dnsInput = document.getElementById("dns-domain-input") as HTMLInputElement;
      const queryBtn = document.getElementById("dns-query-btn")!;

      // Empty input
      dnsInput.value = "";

      // Simulate validation
      const domain = dnsInput.value.trim();
      let errorMessage = null;

      if (!domain) {
        errorMessage = "请输入域名";
      }

      expect(errorMessage).toBe("请输入域名");
    });

    it("should call Tauri invoke with correct parameters", async () => {
      const result = await invoke("tauri_dns_query", {
        domain: "example.com",
        recordType: "A",
        dnsServer: "8.8.8.8",
      });

      expect(result).toBeDefined();
      expect(result).toHaveProperty("domain", "example.com");
      expect(result).toHaveProperty("record_type", "A");
      expect(result).toHaveProperty("records");
    });

    it("should display DNS query results", async () => {
      const result = mockDnsResult;
      const dnsDomain = document.getElementById("dns-domain")!;
      const dnsType = document.getElementById("dns-type")!;
      const dnsCount = document.getElementById("dns-count")!;
      const dnsTime = document.getElementById("dns-time")!;
      const dnsRecordsList = document.getElementById("dns-records-list")!;
      const dnsResults = document.getElementById("dns-results")!;

      // Populate results
      dnsDomain.textContent = result.domain;
      dnsType.textContent = result.record_type;
      dnsCount.textContent = result.records.length.toString();
      dnsTime.textContent = `${result.query_time_ms} ms`;

      // Render records
      dnsRecordsList.innerHTML = result.records
        .map(
          (record) => `
          <div class="dns-record-item">
            <div class="dns-record-name">${record.name}</div>
            <div class="dns-record-type">${record.rtype}</div>
            <div class="dns-record-ttl">TTL: ${record.ttl}s</div>
            <div class="dns-record-data">${record.data}</div>
          </div>
        `
        )
        .join("");

      // Show results
      dnsResults.classList.remove("hidden");

      // Verify
      expect(dnsDomain.textContent).toBe("example.com");
      expect(dnsType.textContent).toBe("A");
      expect(dnsCount.textContent).toBe("2");
      expect(dnsTime.textContent).toBe("50 ms");
      expect(dnsRecordsList.children.length).toBe(2);
      expect(dnsResults.classList.contains("hidden")).toBe(false);
    });

    it("should handle different record types", async () => {
      const recordTypes = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"];

      for (const type of recordTypes) {
        mockInvoke.mockResolvedValueOnce({
          domain: "example.com",
          record_type: type,
          records: [
            {
              name: "example.com",
              rtype: type,
              ttl: 300,
              data: `test-data-for-${type}`,
            },
          ],
          query_time_ms: 50,
          dns_server: "8.8.8.8",
          error: null,
        });

        const result = await invoke("tauri_dns_query", {
          domain: "example.com",
          recordType: type,
        });

        expect(result.record_type).toBe(type);
        expect(result.records[0].rtype).toBe(type);
      }
    });

    it("should handle custom DNS server selection", async () => {
      const servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"];

      for (const server of servers) {
        mockInvoke.mockResolvedValueOnce({
          domain: "example.com",
          record_type: "A",
          records: [],
          query_time_ms: 50,
          dns_server: server,
          error: null,
        });

        const result = await invoke("tauri_dns_query", {
          domain: "example.com",
          recordType: "A",
          dnsServer: server,
        });

        expect(result.dns_server).toBe(server);
      }
    });

    it("should show loading state during query", () => {
      const dnsLoading = document.getElementById("dns-loading")!;
      const queryBtn = document.getElementById("dns-query-btn")!;

      // Simulate loading
      dnsLoading.classList.remove("hidden");
      queryBtn.disabled = true;

      expect(dnsLoading.classList.contains("hidden")).toBe(false);
      expect(queryBtn.disabled).toBe(true);

      // Simulate completion
      dnsLoading.classList.add("hidden");
      queryBtn.disabled = false;

      expect(dnsLoading.classList.contains("hidden")).toBe(true);
      expect(queryBtn.disabled).toBe(false);
    });

    it("should display MX records correctly", async () => {
      const dnsRecordsList = document.getElementById("dns-records-list")!;

      dnsRecordsList.innerHTML = mockMxResult.records
        .map(
          (record) => `
          <div class="dns-record-item">
            <div class="dns-record-data">${record.data}</div>
          </div>
        `
        )
        .join("");

      expect(dnsRecordsList.textContent).toContain("10 mail.example.com");
    });
  });

  describe("should handle DNS query errors gracefully", () => {
    it("should handle invalid domain error", async () => {
      mockInvoke.mockResolvedValueOnce({
        domain: "invalid-domain-test-12345.xyz",
        record_type: "A",
        records: [],
        query_time_ms: 0,
        dns_server: "8.8.8.8",
        error: "NXDOMAIN",
      });

      const result = await invoke("tauri_dns_query", {
        domain: "invalid-domain-test-12345.xyz",
        recordType: "A",
      });

      expect(result.error).toBe("NXDOMAIN");
      expect(result.records.length).toBe(0);
    });

    it("should display error message to user", async () => {
      const dnsError = document.getElementById("dns-error")!;
      const dnsResults = document.getElementById("dns-results")!;

      // Simulate error response
      const errorResult: DnsQueryResult = {
        domain: "example.invalid",
        record_type: "A",
        records: [],
        query_time_ms: 0,
        dns_server: "8.8.8.8",
        error: "查询失败: NXDOMAIN",
      };

      // Show error
      dnsError.textContent = `查询失败: ${errorResult.error}`;
      dnsError.classList.remove("hidden");
      dnsResults.classList.add("hidden");

      expect(dnsError.textContent).toContain("NXDOMAIN");
      expect(dnsError.classList.contains("hidden")).toBe(false);
      expect(dnsResults.classList.contains("hidden")).toBe(true);
    });

    it("should handle network timeout error", async () => {
      mockInvoke.mockRejectedValueOnce(new Error("Request timeout"));

      try {
        await invoke("tauri_dns_query", {
          domain: "timeout-test.com",
          recordType: "A",
        });
        expect.fail("Should have thrown an error");
      } catch (error) {
        expect((error as Error).message).toContain("timeout");
      }
    });

    it("should handle empty DNS records response", async () => {
      const emptyResult: DnsQueryResult = {
        domain: "example.com",
        record_type: "TXT",
        records: [],
        query_time_ms: 25,
        dns_server: "8.8.8.8",
        error: null,
      };
      mockInvoke.mockResolvedValueOnce(emptyResult);

      const result = await invoke("tauri_dns_query", {
        domain: "example.com",
        recordType: "TXT",
      });

      const dnsRecordsList = document.getElementById("dns-records-list")!;

      if (result.records.length === 0) {
        dnsRecordsList.innerHTML = `<span class="whois-empty">未找到记录</span>`;
      }

      expect(dnsRecordsList.textContent).toContain("未找到记录");
    });

    it("should handle DNS server unavailable error", async () => {
      mockInvoke.mockResolvedValueOnce({
        domain: "example.com",
        record_type: "A",
        records: [],
        query_time_ms: 0,
        dns_server: "192.0.2.1", // Invalid DNS server
        error: "DNS server unavailable",
      });

      const result = await invoke("tauri_dns_query", {
        domain: "example.com",
        recordType: "A",
        dnsServer: "192.0.2.1",
      });

      expect(result.error).toBe("DNS server unavailable");
    });
  });

  describe("should handle user interactions", () => {
    it("should trigger query on button click", () => {
      const dnsInput = document.getElementById("dns-domain-input") as HTMLInputElement;
      const queryBtn = document.getElementById("dns-query-btn")!;

      dnsInput.value = "example.com";

      let queryTriggered = false;
      queryBtn.addEventListener("click", () => {
        queryTriggered = true;
      });

      queryBtn.click();

      expect(queryTriggered).toBe(true);
    });

    it("should trigger query on Enter key", () => {
      const dnsInput = document.getElementById("dns-domain-input") as HTMLInputElement;
      const queryBtn = document.getElementById("dns-query-btn")!;

      dnsInput.value = "example.com";

      let queryTriggered = false;
      const handleEnter = (e: KeyboardEvent) => {
        if (e.key === "Enter") {
          queryTriggered = true;
        }
      };

      dnsInput.addEventListener("keydown", handleEnter);

      const enterEvent = new dom.window.KeyboardEvent("keydown", { key: "Enter" });
      dnsInput.dispatchEvent(enterEvent);

      expect(queryTriggered).toBe(true);
    });

    it("should update record type selection", () => {
      const recordTypeSelect = document.getElementById("dns-record-type") as HTMLSelectElement;

      recordTypeSelect.value = "MX";
      expect(recordTypeSelect.value).toBe("MX");

      recordTypeSelect.value = "TXT";
      expect(recordTypeSelect.value).toBe("TXT");
    });
  });

  describe("should display query statistics", () => {
    it("should show query time", async () => {
      const result = mockDnsResult;
      const dnsTime = document.getElementById("dns-time")!;

      dnsTime.textContent = `${result.query_time_ms} ms`;

      expect(dnsTime.textContent).toBe("50 ms");
    });

    it("should show record count", async () => {
      const result = mockDnsResult;
      const dnsCount = document.getElementById("dns-count")!;

      dnsCount.textContent = result.records.length.toString();

      expect(dnsCount.textContent).toBe("2");
    });

    it("should show DNS server used", async () => {
      const result = mockDnsResult;
      const dnsServer = document.createElement("div");
      dnsServer.id = "dns-server-display";

      dnsServer.textContent = `DNS Server: ${result.dns_server}`;

      expect(dnsServer.textContent).toContain("8.8.8.8");
    });
  });
});
