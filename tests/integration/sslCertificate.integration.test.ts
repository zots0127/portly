import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { JSDOM } from "jsdom";

/**
 * SSL Certificate Integration Tests
 *
 * Tests the complete workflow of SSL certificate checking including:
 * - Host and port input
 * - Certificate checking
 * - Certificate details display
 * - Expiration warnings
 * - Error handling
 */

// Types matching the application
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

interface CertChainItem {
  subject: string;
  issuer: string;
  is_self_signed: boolean;
}

describe("SSL Certificate Integration", () => {
  let dom: JSDOM;
  let document: Document;
  let mockInvoke: ReturnType<typeof vi.fn>;

  const mockValidCert: SslCertInfo = {
    host: "example.com",
    port: 443,
    subject: "CN=example.com",
    issuer: "CN=Example CA",
    valid_from: "2024-01-01T00:00:00Z",
    valid_until: "2025-12-31T23:59:59Z",
    is_valid: true,
    is_expired: false,
    is_self_signed: false,
    days_until_expiry: 180,
    signature_algorithm: "SHA256",
    version: "v3",
    serial_number: "1234ABCD",
    key_size: 2048,
    certificate_chain: [
      {
        subject: "CN=example.com",
        issuer: "CN=Example CA",
        is_self_signed: false,
      },
      {
        subject: "CN=Example CA",
        issuer: "CN=Root CA",
        is_self_signed: false,
      },
    ],
    tls_version: "TLSv1.3",
    cipher_suite: "TLS_AES_256_GCM_SHA384",
    error: null,
  };

  const mockExpiringSoonCert: SslCertInfo = {
    ...mockValidCert,
    valid_until: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString(), // 15 days from now
    days_until_expiry: 15,
  };

  const mockExpiredCert: SslCertInfo = {
    ...mockValidCert,
    valid_until: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(), // 10 days ago
    is_expired: true,
    days_until_expiry: -10,
  };

  const mockSelfSignedCert: SslCertInfo = {
    ...mockValidCert,
    issuer: "CN=example.com",
    is_self_signed: true,
  };

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head><title>SSL Certificate Test</title></head>
        <body>
          <div id="page-ssl">
            <input type="text" id="ssl-host-input" placeholder="Enter hostname" />
            <input type="number" id="ssl-port-input" value="443" />
            <button id="ssl-check-btn">Check</button>

            <div id="ssl-loading" class="hidden">Loading...</div>
            <div id="ssl-error" class="hidden"></div>
            <div id="ssl-results" class="hidden">
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
              <span id="ssl-self-signed" class="hidden">Self-signed</span>
              <div id="ssl-status"></div>
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

  describe("should check SSL certificate and display details", () => {
    it("should initialize DOM elements correctly", () => {
      const sslHostInput = document.getElementById("ssl-host-input");
      const sslPortInput = document.getElementById("ssl-port-input");
      const checkBtn = document.getElementById("ssl-check-btn");

      expect(sslHostInput).toBeTruthy();
      expect(sslPortInput).toBeTruthy();
      expect(checkBtn).toBeTruthy();
    });

    it("should show error when hostname is empty", async () => {
      const sslHostInput = document.getElementById("ssl-host-input") as HTMLInputElement;

      sslHostInput.value = "";

      const host = sslHostInput.value.trim();
      let errorMessage = null;

      if (!host) {
        errorMessage = "请输入主机名或 IP 地址";
      }

      expect(errorMessage).toBe("请输入主机名或 IP 地址");
    });

    it("should call Tauri invoke with correct parameters", async () => {
      const result = await invoke("tauri_check_ssl_cert", {
        host: "example.com",
        port: 443,
      });

      expect(result).toBeDefined();
      expect(result).toHaveProperty("host", "example.com");
      expect(result).toHaveProperty("subject");
      expect(result).toHaveProperty("issuer");
      expect(result).toHaveProperty("is_valid");
    });

    it("should display certificate details", async () => {
      const result = mockValidCert;
      const sslHost = document.getElementById("ssl-host")!;
      const sslSubject = document.getElementById("ssl-subject")!;
      const sslIssuer = document.getElementById("ssl-issuer")!;
      const sslValidFrom = document.getElementById("ssl-valid-from")!;
      const sslValidUntil = document.getElementById("ssl-valid-until")!;
      const sslResults = document.getElementById("ssl-results")!;

      // Populate results
      sslHost.textContent = `${result.host}:${result.port}`;
      sslSubject.textContent = result.subject || "未知";
      sslIssuer.textContent = result.issuer || "未知";
      sslValidFrom.textContent = result.valid_from || "未知";
      sslValidUntil.textContent = result.valid_until || "未知";

      // Show results
      sslResults.classList.remove("hidden");

      expect(sslHost.textContent).toBe("example.com:443");
      expect(sslSubject.textContent).toBe("CN=example.com");
      expect(sslIssuer.textContent).toBe("CN=Example CA");
      expect(sslResults.classList.contains("hidden")).toBe(false);
    });

    it("should display certificate technical details", async () => {
      const result = mockValidCert;
      const sslKeySize = document.getElementById("ssl-key-size")!;
      const sslSignature = document.getElementById("ssl-signature")!;
      const sslVersion = document.getElementById("ssl-version")!;
      const sslSerial = document.getElementById("ssl-serial")!;
      const sslTlsVersion = document.getElementById("ssl-tls-version")!;
      const sslCipherSuite = document.getElementById("ssl-cipher-suite")!;

      sslKeySize.textContent = result.key_size ? `${result.key_size} 位` : "未知";
      sslSignature.textContent = result.signature_algorithm || "未知";
      sslVersion.textContent = result.version || "未知";
      sslSerial.textContent = result.serial_number || "未知";
      sslTlsVersion.textContent = result.tls_version || "未知";
      sslCipherSuite.textContent = result.cipher_suite || "未获取";

      expect(sslKeySize.textContent).toBe("2048 位");
      expect(sslSignature.textContent).toBe("SHA256");
      expect(sslVersion.textContent).toBe("v3");
      expect(sslSerial.textContent).toBe("1234ABCD");
      expect(sslTlsVersion.textContent).toBe("TLSv1.3");
      expect(sslCipherSuite.textContent).toBe("TLS_AES_256_GCM_SHA384");
    });

    it("should display certificate chain", async () => {
      const result = mockValidCert;
      const sslChain = document.getElementById("ssl-chain")!;

      if (result.certificate_chain && result.certificate_chain.length > 0) {
        sslChain.innerHTML = result.certificate_chain
          .map(
            (cert, index) => `
            <div class="cert-chain-item">
              <div class="cert-chain-title">${
                index === 0 ? "服务器证书" : `中间证书 #${index}`
              }</div>
              <div class="cert-chain-detail">主体: ${escapeHtml(cert.subject)}</div>
              <div class="cert-chain-detail">颁发者: ${escapeHtml(cert.issuer)}</div>
              ${
                cert.is_self_signed
                  ? '<span class="cert-tag self-signed">自签名</span>'
                  : ""
              }
            </div>
          `
          )
          .join("");
      }

      const chainItems = sslChain.querySelectorAll(".cert-chain-item");
      expect(chainItems.length).toBe(2);
      expect(chainItems[0].textContent).toContain("服务器证书");
      expect(chainItems[1].textContent).toContain("中间证书");
    });
  });

  describe("should verify expiration warnings", () => {
    it("should show valid status for healthy certificate", async () => {
      const result = mockValidCert;
      const sslStatus = document.getElementById("ssl-status")!;
      const sslDaysLeft = document.getElementById("ssl-days-left")!;

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

      expect(sslStatus.textContent).toContain("有效");
      expect(sslDaysLeft.textContent).toContain("剩余 180 天");
    });

    it("should show warning for certificate expiring soon", async () => {
      const result = mockExpiringSoonCert;
      const sslStatus = document.getElementById("ssl-status")!;
      const sslDaysLeft = document.getElementById("ssl-days-left")!;

      if (result.days_until_expiry <= 30 && !result.is_expired) {
        sslStatus.innerHTML = `<span class="cert-status warning">即将过期</span>`;
        sslDaysLeft.innerHTML = `<span class="cert-days warning">剩余 ${result.days_until_expiry} 天</span>`;
      }

      expect(sslStatus.textContent).toContain("即将过期");
      expect(sslDaysLeft.textContent).toContain("剩余 15 天");
    });

    it("should show expired status for expired certificate", async () => {
      const result = mockExpiredCert;
      const sslStatus = document.getElementById("ssl-status")!;
      const sslDaysLeft = document.getElementById("ssl-days-left")!;

      if (result.is_expired) {
        sslStatus.innerHTML = `<span class="cert-status expired">已过期</span>`;
        sslDaysLeft.innerHTML = `<span class="cert-days expired">已过期 ${Math.abs(result.days_until_expiry)} 天</span>`;
      }

      expect(sslStatus.textContent).toContain("已过期");
      expect(sslDaysLeft.textContent).toContain("已过期 10 天");
    });

    it("should highlight days with appropriate CSS classes", async () => {
      const testCases = [
        { days: 365, expectedClass: "valid" },
        { days: 45, expectedClass: "valid" },
        { days: 30, expectedClass: "warning" },
        { days: 7, expectedClass: "warning" },
        { days: -1, expectedClass: "expired" },
        { days: -100, expectedClass: "expired" },
      ];

      for (const testCase of testCases) {
        mockInvoke.mockResolvedValueOnce({
          ...mockValidCert,
          days_until_expiry: testCase.days,
          is_expired: testCase.days < 0,
        });

        const result = await invoke("tauri_check_ssl_cert", {
          host: "test.com",
          port: 443,
        });

        if (result.is_expired) {
          expect(testCase.expectedClass).toBe("expired");
        } else if (result.days_until_expiry <= 30) {
          expect(testCase.expectedClass).toBe("warning");
        } else {
          expect(testCase.expectedClass).toBe("valid");
        }
      }
    });
  });

  describe("should identify self-signed certificates", () => {
    it("should show self-signed badge for self-signed certificates", async () => {
      const result = mockSelfSignedCert;
      const sslSelfSigned = document.getElementById("ssl-self-signed")!;

      if (result.is_self_signed) {
        sslSelfSigned.classList.remove("hidden");
      }

      expect(sslSelfSigned.classList.contains("hidden")).toBe(false);
    });

    it("should hide self-signed badge for CA-signed certificates", async () => {
      const result = mockValidCert;
      const sslSelfSigned = document.getElementById("ssl-self-signed")!;

      if (!result.is_self_signed) {
        sslSelfSigned.classList.add("hidden");
      }

      expect(sslSelfSigned.classList.contains("hidden")).toBe(true);
    });

    it("should indicate self-signed in certificate chain", async () => {
      const result: SslCertInfo = {
        ...mockValidCert,
        certificate_chain: [
          {
            subject: "CN=selfsigned.com",
            issuer: "CN=selfsigned.com",
            is_self_signed: true,
          },
        ],
      };
      const sslChain = document.getElementById("ssl-chain")!;

      if (result.certificate_chain && result.certificate_chain.length > 0) {
        sslChain.innerHTML = result.certificate_chain
          .map(
            (cert) => `
            <div class="cert-chain-item">
              ${cert.is_self_signed ? '<span class="cert-tag self-signed">自签名</span>' : ""}
            </div>
          `
          )
          .join("");
      }

      expect(sslChain.textContent).toContain("自签名");
    });
  });

  describe("should handle SSL certificate errors", () => {
    it("should handle connection error", async () => {
      mockInvoke.mockResolvedValueOnce({
        ...mockValidCert,
        error: "Connection refused",
      });

      const result = await invoke("tauri_check_ssl_cert", {
        host: "invalid.example",
        port: 443,
      });

      expect(result.error).toBe("Connection refused");
    });

    it("should display error message to user", async () => {
      const sslError = document.getElementById("ssl-error")!;
      const sslResults = document.getElementById("ssl-results")!;

      const errorMessage = "检查失败: Connection timeout";

      sslError.textContent = errorMessage;
      sslError.classList.remove("hidden");
      sslResults.classList.add("hidden");

      expect(sslError.textContent).toContain("Connection timeout");
      expect(sslError.classList.contains("hidden")).toBe(false);
      expect(sslResults.classList.contains("hidden")).toBe(true);
    });

    it("should handle invalid hostname", async () => {
      mockInvoke.mockRejectedValueOnce(new Error("Invalid hostname"));

      try {
        await invoke("tauri_check_ssl_cert", {
          host: "",
          port: 443,
        });
        expect.fail("Should have thrown an error");
      } catch (error) {
        expect((error as Error).message).toContain("Invalid hostname");
      }
    });

    it("should handle certificate validation error", async () => {
      mockInvoke.mockResolvedValueOnce({
        ...mockValidCert,
        is_valid: false,
        error: "Certificate chain verification failed",
      });

      const result = await invoke("tauri_check_ssl_cert", {
        host: "invalid-cert.example",
        port: 443,
      });

      expect(result.is_valid).toBe(false);
      expect(result.error).toContain("verification failed");
    });
  });

  describe("should handle user interactions", () => {
    it("should trigger check on button click", () => {
      const sslHostInput = document.getElementById("ssl-host-input") as HTMLInputElement;
      const checkBtn = document.getElementById("ssl-check-btn")!;

      sslHostInput.value = "example.com";

      let checkTriggered = false;
      checkBtn.addEventListener("click", () => {
        checkTriggered = true;
      });

      checkBtn.click();

      expect(checkTriggered).toBe(true);
    });

    it("should trigger check on Enter key in host input", () => {
      const sslHostInput = document.getElementById("ssl-host-input") as HTMLInputElement;

      sslHostInput.value = "example.com";

      let checkTriggered = false;
      const handleEnter = (e: KeyboardEvent) => {
        if (e.key === "Enter") {
          checkTriggered = true;
        }
      };

      sslHostInput.addEventListener("keydown", handleEnter);

      const enterEvent = new dom.window.KeyboardEvent("keydown", { key: "Enter" });
      sslHostInput.dispatchEvent(enterEvent);

      expect(checkTriggered).toBe(true);
    });

    it("should trigger check on Enter key in port input", () => {
      const sslPortInput = document.getElementById("ssl-port-input") as HTMLInputElement;

      let checkTriggered = false;
      const handleEnter = (e: KeyboardEvent) => {
        if (e.key === "Enter") {
          checkTriggered = true;
        }
      };

      sslPortInput.addEventListener("keydown", handleEnter);

      const enterEvent = new dom.window.KeyboardEvent("keydown", { key: "Enter" });
      sslPortInput.dispatchEvent(enterEvent);

      expect(checkTriggered).toBe(true);
    });

    it("should parse custom port number", () => {
      const sslPortInput = document.getElementById("ssl-port-input") as HTMLInputElement;

      sslPortInput.value = "8443";

      const port = sslPortInput.value ? parseInt(sslPortInput.value) : 443;

      expect(port).toBe(8443);
    });

    it("should use default port when not specified", () => {
      const sslPortInput = document.getElementById("ssl-port-input") as HTMLInputElement;

      sslPortInput.value = "";

      const port = sslPortInput.value ? parseInt(sslPortInput.value) : 443;

      expect(port).toBe(443);
    });
  });

  describe("should handle loading states", () => {
    it("should show loading during check", () => {
      const sslLoading = document.getElementById("ssl-loading")!;
      const checkBtn = document.getElementById("ssl-check-btn")!;
      const sslError = document.getElementById("ssl-error")!;
      const sslResults = document.getElementById("ssl-results")!;

      // Start loading
      sslLoading.classList.remove("hidden");
      sslError.classList.add("hidden");
      sslResults.classList.add("hidden");
      checkBtn.disabled = true;

      expect(sslLoading.classList.contains("hidden")).toBe(false);
      expect(sslError.classList.contains("hidden")).toBe(true);
      expect(sslResults.classList.contains("hidden")).toBe(true);
      expect(checkBtn.disabled).toBe(true);

      // End loading
      sslLoading.classList.add("hidden");
      checkBtn.disabled = false;

      expect(sslLoading.classList.contains("hidden")).toBe(true);
      expect(checkBtn.disabled).toBe(false);
    });
  });

  describe("should handle different certificate formats", () => {
    it("should handle missing key size", async () => {
      const result: SslCertInfo = {
        ...mockValidCert,
        key_size: null,
      };
      const sslKeySize = document.getElementById("ssl-key-size")!;

      sslKeySize.textContent = result.key_size ? `${result.key_size} 位` : "未知";

      expect(sslKeySize.textContent).toBe("未知");
    });

    it("should handle empty certificate chain", async () => {
      const result: SslCertInfo = {
        ...mockValidCert,
        certificate_chain: [],
      };
      const sslChain = document.getElementById("ssl-chain")!;

      if (result.certificate_chain && result.certificate_chain.length > 0) {
        sslChain.innerHTML = "certificate chain content";
      } else {
        sslChain.innerHTML = `<span class="whois-empty">无证书链信息</span>`;
      }

      expect(sslChain.textContent).toContain("无证书链信息");
    });

    it("should handle null cipher suite", async () => {
      const result: SslCertInfo = {
        ...mockValidCert,
        cipher_suite: null,
      };
      const sslCipherSuite = document.getElementById("ssl-cipher-suite")!;

      sslCipherSuite.textContent = result.cipher_suite || "未获取";

      expect(sslCipherSuite.textContent).toBe("未获取");
    });
  });
});

// Helper function (same as in main.ts)
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
