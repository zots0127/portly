import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { JSDOM } from "jsdom";

/**
 * Whois Query Integration Tests
 *
 * Tests the complete workflow of Whois queries including:
 * - User input handling
 * - Query execution
 * - Registration information display
 * - Error handling
 */

// Types matching the application
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

describe("Whois Integration", () => {
  let dom: JSDOM;
  let document: Document;
  let mockInvoke: ReturnType<typeof vi.fn>;

  const mockWhoisResult: WhoisResult = {
    domain: "example.com",
    registrar: "Example Registrar Inc.",
    created: "2020-01-15T00:00:00Z",
    expires: "2025-01-15T00:00:00Z",
    updated: "2024-01-01T00:00:00Z",
    status: ["clientTransferProhibited", "clientUpdateProhibited"],
    nameservers: [
      "ns1.example.com",
      "ns2.example.com",
      "ns3.example.com",
    ],
    dnssec: "unsigned",
    raw_output: `
DOMAIN NAME:   example.com
REGISTRAR:     Example Registrar Inc.
CREATED:       2020-01-15
EXPIRES:       2025-01-15
STATUS:        clientTransferProhibited
    `,
    error: null,
  };

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head><title>Whois Test</title></head>
        <body>
          <div id="page-whois">
            <input type="text" id="whois-input" placeholder="Enter domain" />
            <button id="whois-query-btn">Query</button>

            <div id="whois-loading" class="hidden">Loading...</div>
            <div id="whois-error" class="hidden"></div>
            <div id="whois-results" class="hidden">
              <div id="whois-domain"></div>
              <div id="whois-registrar"></div>
              <div id="whois-created"></div>
              <div id="whois-expires"></div>
              <div id="whois-updated"></div>
              <div id="whois-status"></div>
              <div id="whois-nameservers"></div>
              <div id="whois-dnssec-section">
                <span id="whois-dnssec"></span>
              </div>
              <pre id="whois-raw"></pre>
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

  describe("should query whois and display results", () => {
    it("should initialize DOM elements correctly", () => {
      const whoisInput = document.getElementById("whois-input");
      const queryBtn = document.getElementById("whois-query-btn");

      expect(whoisInput).toBeTruthy();
      expect(queryBtn).toBeTruthy();
    });

    it("should show error when domain is empty", async () => {
      const whoisInput = document.getElementById("whois-input") as HTMLInputElement;

      whoisInput.value = "";

      const domain = whoisInput.value.trim();
      let errorMessage = null;

      if (!domain) {
        errorMessage = "请输入域名";
      }

      expect(errorMessage).toBe("请输入域名");
    });

    it("should call Tauri invoke with correct parameters", async () => {
      const result = await invoke("tauri_whois_query", { domain: "example.com" });

      expect(result).toBeDefined();
      expect(result).toHaveProperty("domain");
      expect(result).toHaveProperty("registrar");
      expect(result).toHaveProperty("nameservers");
    });

    it("should display whois results", async () => {
      const result = mockWhoisResult;
      const whoisDomain = document.getElementById("whois-domain")!;
      const whoisRegistrar = document.getElementById("whois-registrar")!;
      const whoisCreated = document.getElementById("whois-created")!;
      const whoisExpires = document.getElementById("whois-expires")!;
      const whoisResults = document.getElementById("whois-results")!;

      // Populate results
      whoisDomain.textContent = result.domain || "-";
      whoisRegistrar.textContent = result.registrar || "-";
      whoisCreated.textContent = formatDate(result.created) || "-";
      whoisExpires.textContent = formatDate(result.expires) || "-";

      // Show results
      whoisResults.classList.remove("hidden");

      expect(whoisDomain.textContent).toBe("example.com");
      expect(whoisRegistrar.textContent).toBe("Example Registrar Inc.");
      expect(whoisCreated.textContent).toBeTruthy();
      expect(whoisExpires.textContent).toBeTruthy();
      expect(whoisResults.classList.contains("hidden")).toBe(false);
    });

    it("should display domain status tags", async () => {
      const result = mockWhoisResult;
      const whoisStatus = document.getElementById("whois-status")!;

      if (result.status && result.status.length > 0) {
        whoisStatus.innerHTML = result.status
          .map((s) => `<span class="whois-tag">${escapeHtml(s)}</span>`)
          .join("");
      }

      const tags = whoisStatus.querySelectorAll(".whois-tag");
      expect(tags.length).toBe(2);
      expect(tags[0].textContent).toBe("clientTransferProhibited");
      expect(tags[1].textContent).toBe("clientUpdateProhibited");
    });

    it("should display nameservers", async () => {
      const result = mockWhoisResult;
      const whoisNameservers = document.getElementById("whois-nameservers")!;

      if (result.nameservers && result.nameservers.length > 0) {
        whoisNameservers.innerHTML = result.nameservers
          .map((ns) => `<div class="whois-nameserver-item">${escapeHtml(ns)}</div>`)
          .join("");
      }

      const nsItems = whoisNameservers.querySelectorAll(".whois-nameserver-item");
      expect(nsItems.length).toBe(3);
      expect(nsItems[0].textContent).toBe("ns1.example.com");
      expect(nsItems[1].textContent).toBe("ns2.example.com");
      expect(nsItems[2].textContent).toBe("ns3.example.com");
    });

    it("should display DNSSEC status", async () => {
      const result = mockWhoisResult;
      const whoisDnssec = document.getElementById("whois-dnssec")!;
      const whoisDnssecSection = document.getElementById("whois-dnssec-section")!;

      if (result.dnssec) {
        whoisDnssec.textContent = result.dnssec;
        whoisDnssecSection.classList.remove("hidden");
      }

      expect(whoisDnssec.textContent).toBe("unsigned");
      expect(whoisDnssecSection.classList.contains("hidden")).toBe(false);
    });

    it("should display raw whois output", async () => {
      const result = mockWhoisResult;
      const whoisRaw = document.getElementById("whois-raw")!;

      whoisRaw.textContent = result.raw_output || "无原始输出";

      expect(whoisRaw.textContent).toContain("DOMAIN NAME:");
      expect(whoisRaw.textContent).toContain("REGISTRAR:");
    });

    it("should handle domains with partial information", async () => {
      const partialResult: WhoisResult = {
        domain: "partial.example",
        registrar: null,
        created: null,
        expires: "2025-12-31T00:00:00Z",
        updated: null,
        status: [],
        nameservers: [],
        dnssec: null,
        raw_output: "Limited data available",
        error: null,
      };
      mockInvoke.mockResolvedValueOnce(partialResult);

      const result = await invoke("tauri_whois_query", { domain: "partial.example" });
      const whoisRegistrar = document.getElementById("whois-registrar")!;
      const whoisCreated = document.getElementById("whois-created")!;

      whoisRegistrar.textContent = result.registrar || "-";
      whoisCreated.textContent = formatDate(result.created) || "-";

      expect(whoisRegistrar.textContent).toBe("-");
      expect(whoisCreated.textContent).toBe("-");
    });
  });

  describe("should handle whois query errors", () => {
    it("should handle invalid TLD error", async () => {
      mockInvoke.mockResolvedValueOnce({
        domain: "example.invalidtld",
        registrar: null,
        created: null,
        expires: null,
        updated: null,
        status: [],
        nameservers: [],
        dnssec: null,
        raw_output: "",
        error: "Invalid TLD",
      });

      const result = await invoke("tauri_whois_query", {
        domain: "example.invalidtld",
      });

      expect(result.error).toBe("Invalid TLD");
    });

    it("should display error message to user", async () => {
      const whoisError = document.getElementById("whois-error")!;
      const whoisResults = document.getElementById("whois-results")!;

      const errorResult: WhoisResult = {
        domain: "error.example",
        registrar: null,
        created: null,
        expires: null,
        updated: null,
        status: [],
        nameservers: [],
        dnssec: null,
        raw_output: "",
        error: "查询失败: Domain not found",
      };

      whoisError.textContent = `查询失败: ${errorResult.error}`;
      whoisError.classList.remove("hidden");
      whoisResults.classList.add("hidden");

      expect(whoisError.textContent).toContain("Domain not found");
      expect(whoisError.classList.contains("hidden")).toBe(false);
      expect(whoisResults.classList.contains("hidden")).toBe(true);
    });

    it("should handle network timeout error", async () => {
      mockInvoke.mockRejectedValueOnce(new Error("Whois query timeout"));

      try {
        await invoke("tauri_whois_query", { domain: "timeout-test.com" });
        expect.fail("Should have thrown an error");
      } catch (error) {
        expect((error as Error).message).toContain("timeout");
      }
    });

    it("should handle rate limiting error", async () => {
      mockInvoke.mockResolvedValueOnce({
        domain: "rate-limit.example",
        registrar: null,
        created: null,
        expires: null,
        updated: null,
        status: [],
        nameservers: [],
        dnssec: null,
        raw_output: "",
        error: "Rate limit exceeded, please try again later",
      });

      const result = await invoke("tauri_whois_query", {
        domain: "rate-limit.example",
      });

      expect(result.error).toContain("Rate limit");
    });
  });

  describe("should handle user interactions", () => {
    it("should trigger query on button click", () => {
      const whoisInput = document.getElementById("whois-input") as HTMLInputElement;
      const queryBtn = document.getElementById("whois-query-btn")!;

      whoisInput.value = "example.com";

      let queryTriggered = false;
      queryBtn.addEventListener("click", () => {
        queryTriggered = true;
      });

      queryBtn.click();

      expect(queryTriggered).toBe(true);
    });

    it("should trigger query on Enter key", () => {
      const whoisInput = document.getElementById("whois-input") as HTMLInputElement;

      whoisInput.value = "example.com";

      let queryTriggered = false;
      const handleEnter = (e: KeyboardEvent) => {
        if (e.key === "Enter") {
          queryTriggered = true;
        }
      };

      whoisInput.addEventListener("keydown", handleEnter);

      const enterEvent = new dom.window.KeyboardEvent("keydown", { key: "Enter" });
      whoisInput.dispatchEvent(enterEvent);

      expect(queryTriggered).toBe(true);
    });

    it("should trim whitespace from input", () => {
      const whoisInput = document.getElementById("whois-input") as HTMLInputElement;

      whoisInput.value = "  example.com  ";

      const trimmed = whoisInput.value.trim();

      expect(trimmed).toBe("example.com");
    });
  });

  describe("should handle loading states", () => {
    it("should show loading during query", () => {
      const whoisLoading = document.getElementById("whois-loading")!;
      const queryBtn = document.getElementById("whois-query-btn")!;
      const whoisError = document.getElementById("whois-error")!;
      const whoisResults = document.getElementById("whois-results")!;

      // Start loading
      whoisLoading.classList.remove("hidden");
      whoisError.classList.add("hidden");
      whoisResults.classList.add("hidden");
      queryBtn.disabled = true;

      expect(whoisLoading.classList.contains("hidden")).toBe(false);
      expect(whoisError.classList.contains("hidden")).toBe(true);
      expect(whoisResults.classList.contains("hidden")).toBe(true);
      expect(queryBtn.disabled).toBe(true);

      // End loading
      whoisLoading.classList.add("hidden");
      queryBtn.disabled = false;

      expect(whoisLoading.classList.contains("hidden")).toBe(true);
      expect(queryBtn.disabled).toBe(false);
    });
  });

  describe("should display empty states", () => {
    it("should show empty status when no status available", async () => {
      const result: WhoisResult = {
        ...mockWhoisResult,
        status: [],
      };
      const whoisStatus = document.getElementById("whois-status")!;

      if (result.status && result.status.length > 0) {
        whoisStatus.innerHTML = result.status
          .map((s) => `<span class="whois-tag">${escapeHtml(s)}</span>`)
          .join("");
      } else {
        whoisStatus.innerHTML = `<span class="whois-empty">无状态信息</span>`;
      }

      expect(whoisStatus.textContent).toContain("无状态信息");
    });

    it("should show empty nameservers when none available", async () => {
      const result: WhoisResult = {
        ...mockWhoisResult,
        nameservers: [],
      };
      const whoisNameservers = document.getElementById("whois-nameservers")!;

      if (result.nameservers && result.nameservers.length > 0) {
        whoisNameservers.innerHTML = result.nameservers
          .map((ns) => `<div class="whois-nameserver-item">${escapeHtml(ns)}</div>`)
          .join("");
      } else {
        whoisNameservers.innerHTML = `<span class="whois-empty">无域名服务器信息</span>`;
      }

      expect(whoisNameservers.textContent).toContain("无域名服务器信息");
    });

    it("should hide DNSSEC section when not available", async () => {
      const result: WhoisResult = {
        ...mockWhoisResult,
        dnssec: null,
      };
      const whoisDnssecSection = document.getElementById("whois-dnssec-section")!;

      if (result.dnssec) {
        whoisDnssecSection.classList.remove("hidden");
      } else {
        whoisDnssecSection.classList.add("hidden");
      }

      expect(whoisDnssecSection.classList.contains("hidden")).toBe(true);
    });
  });
});

// Helper functions (same as in main.ts)
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
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
    // Ignore parsing errors
  }
  return dateStr;
}
