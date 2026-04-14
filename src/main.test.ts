import { describe, it, expect, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { toCommandErrorMessage, formatCommandErrorMessage } from "./error-utils";
import {
  buildScanLoadingHtml,
  buildSubnetScanEstimateMessage,
  estimateSubnetHostCount,
  estimateScanDurationSeconds,
  formatEstimatedDuration,
  getSubnetInput,
  isValidSubnetRange,
} from "./network-utils";

// 从 main.ts 复制的工具函数用于测试
function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.substring(0, maxLen) + "..." : str;
}

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
    // 忽略解析错误
  }
  return dateStr;
}

describe("Utility Functions", () => {
  describe("truncate", () => {
    it("should not truncate short strings", () => {
      expect(truncate("hello", 10)).toBe("hello");
    });

    it("should truncate long strings and add ellipsis", () => {
      expect(truncate("very long string", 5)).toBe("very ...");
    });

    it("should handle empty string", () => {
      expect(truncate("", 10)).toBe("");
    });

    it("should handle string exactly at max length", () => {
      expect(truncate("hello", 5)).toBe("hello");
    });

    it("should handle string one character over max", () => {
      expect(truncate("hello!", 5)).toBe("hello...");
    });

    it("should truncate command strings", () => {
      const longCommand = "node /very/long/path/to/some/application.js --arg1 --arg2 --arg3";
      expect(truncate(longCommand, 30)).toHaveLength(33); // 30 + "..."
    });
  });

  describe("escapeHtml", () => {
    it("should escape ampersands", () => {
      expect(escapeHtml("Tom & Jerry")).toBe("Tom &amp; Jerry");
    });

    it("should escape less than signs", () => {
      expect(escapeHtml("<script>")).toBe("&lt;script&gt;");
    });

    it("should escape greater than signs", () => {
      expect(escapeHtml("a > b")).toBe("a &gt; b");
    });

    it("should escape double quotes", () => {
      expect(escapeHtml('Hello "World"')).toBe("Hello &quot;World&quot;");
    });

    it("should escape single quotes", () => {
      expect(escapeHtml("It's mine")).toBe("It&#039;s mine");
    });

    it("should escape multiple special characters", () => {
      expect(escapeHtml('<script>alert("XSS")</script>')).toBe(
        "&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;"
      );
    });

    it("should handle empty string", () => {
      expect(escapeHtml("")).toBe("");
    });

    it("should handle string without special characters", () => {
      expect(escapeHtml("Hello World 123")).toBe("Hello World 123");
    });

    it("should escape all ampersands first to avoid double escaping", () => {
      expect(escapeHtml("a & b < c")).toBe("a &amp; b &lt; c");
    });
  });

  describe("formatDate", () => {
    it("should format valid ISO date string", () => {
      const result = formatDate("2024-01-15T00:00:00Z");
      expect(result).toBeTruthy();
      expect(result).toContain("2024");
      expect(result).toContain("01");
    });

    it("should return null for null input", () => {
      expect(formatDate(null)).toBeNull();
    });

    it("should handle various date formats", () => {
      expect(formatDate("2024-12-31")).toBeTruthy();
      expect(formatDate("2024-06-15T10:30:00")).toBeTruthy();
    });

    it("should return original string for invalid dates", () => {
      expect(formatDate("invalid-date")).toBe("invalid-date");
    });

    it("should handle empty string", () => {
      // Empty string is falsy, so it should return null
      expect(formatDate("")).toBeNull();
    });
  });
});

describe("Subnet Utilities", () => {
  it("should validate /22~24 CIDR formats", () => {
    expect(isValidSubnetRange("192.168.1.0/22")).toBe(true);
    expect(isValidSubnetRange("10.0.0.0/23")).toBe(true);
    expect(isValidSubnetRange("172.16.0.0/24")).toBe(true);
    expect(isValidSubnetRange("192.168.1.0/25")).toBe(false);
    expect(isValidSubnetRange("192.168.1.256/24")).toBe(false);
  });

  it("should prioritize manual subnet input", () => {
    expect(getSubnetInput("192.168.0.0/24", "10.0.0.0/23", "")).toBe("10.0.0.0/23");
    expect(getSubnetInput("192.168.0.0/24", "", "")).toBe("192.168.0.0/24");
    expect(getSubnetInput("", "", "172.16.0.0/22")).toBe("172.16.0.0/22");
  });

  it("should calculate subnet host count", () => {
    expect(estimateSubnetHostCount("192.168.1.0/22")).toBe(1022);
    expect(estimateSubnetHostCount("192.168.1.0/23")).toBe(510);
    expect(estimateSubnetHostCount("192.168.1.0/24")).toBe(254);
    expect(estimateSubnetHostCount("192.168.1.0/25")).toBeNull();
  });

  it("should provide large range estimation hint", () => {
    const message = buildSubnetScanEstimateMessage("192.168.1.0/22");
    expect(message).toBeTruthy();
    expect(message).toContain("当前范围估算耗时");
    expect(message).toContain("1022");
  });

  it("should estimate scan duration seconds for large ranges", () => {
    expect(estimateScanDurationSeconds("192.168.1.0/22")).toBe(123);
    expect(estimateScanDurationSeconds("192.168.1.0/23")).toBe(61);
    expect(estimateScanDurationSeconds("192.168.1.0/24")).toBeNull();
  });

  it("should format estimated duration string", () => {
    expect(formatEstimatedDuration(70)).toBe("1 分 10 秒");
    expect(formatEstimatedDuration(45)).toBe("45 秒");
  });

  it("should render scan loading html with estimate remaining", () => {
    const startAt = Date.now();
    const html = buildScanLoadingHtml("扫描中", startAt, 12);
    expect(html).toContain("扫描中");
    expect(html).toContain("已耗时");
    expect(html).toContain("预计还需");
  });

  it("should render base text when no estimate is set", () => {
    const html = buildScanLoadingHtml("扫描中", Date.now(), null);
    expect(html).toBe("扫描中");
  });
});

describe("Tauri API Mock", () => {
  it("should mock tauri_scan_ports command", async () => {
    const result = await invoke("tauri_scan_ports", { includeCommand: true });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("scan_time");
    expect(result).toHaveProperty("ports");
    expect(Array.isArray(result.ports)).toBe(true);
    expect(result.ports.length).toBeGreaterThan(0);
    expect(result.ports[0]).toHaveProperty("port");
    expect(result.ports[0]).toHaveProperty("protocol");
    expect(result.ports[0]).toHaveProperty("process");
  });

  it("should mock tauri_dns_query command", async () => {
    const result = await invoke("tauri_dns_query", {
      domain: "example.com",
      recordType: "A",
    });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("domain", "example.com");
    expect(result).toHaveProperty("records");
    expect(Array.isArray(result.records)).toBe(true);
  });

  it("should mock tauri_whois_query command", async () => {
    const result = await invoke("tauri_whois_query", { domain: "example.com" });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("domain");
    expect(result).toHaveProperty("registrar");
    expect(result).toHaveProperty("nameservers");
    expect(Array.isArray(result.nameservers)).toBe(true);
  });

  it("should mock tauri_check_ssl_cert command", async () => {
    const result = await invoke("tauri_check_ssl_cert", {
      host: "example.com",
      port: 443,
    });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("host");
    expect(result).toHaveProperty("subject");
    expect(result).toHaveProperty("issuer");
    expect(result).toHaveProperty("is_valid");
    expect(result.is_valid).toBe(true);
  });

  it("should mock tauri_get_interfaces command", async () => {
    const result = await invoke("tauri_get_interfaces");

    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]).toHaveProperty("name");
    expect(result[0]).toHaveProperty("ip");
    expect(result[0]).toHaveProperty("subnet");
  });

  it("should mock tauri_discover_devices command", async () => {
    const result = await invoke("tauri_discover_devices", {
      subnet: "192.168.1.0/24",
    });

    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]).toHaveProperty("ip");
    expect(result[0]).toHaveProperty("is_online");
  });

  it("should mock tauri_ping_one command", async () => {
    const result = await invoke("tauri_ping_one", { ip: "192.168.1.1", seq: 1 });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("success");
    expect(result).toHaveProperty("time_ms");
    expect(result.success).toBe(true);
  });

  it("should mock tauri_kill_process command", async () => {
    const result = await invoke("tauri_kill_process", { pid: 1234, force: false });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("success");
    expect(result).toHaveProperty("pid");
    expect(result.success).toBe(true);
    expect(result.pid).toBe(1234);
  });
});

describe("Error Message Utilities", () => {
  it("should return original error message string", () => {
    const rawMessage = "目标地址 校验失败：不能为空";
    expect(toCommandErrorMessage(rawMessage)).toBe(rawMessage);
  });

  it("should return message from Error instance", () => {
    const err = new Error("Command execution failed");
    expect(toCommandErrorMessage(err)).toBe("Command execution failed");
  });

  it("should extract message from object payload", () => {
    expect(toCommandErrorMessage({ message: "DNS 解析失败：no such host" })).toBe(
      "DNS 解析失败：no such host",
    );
    expect(toCommandErrorMessage({ error: "命令执行失败（exit:1）" })).toBe(
      "命令执行失败（exit:1）",
    );
    expect(toCommandErrorMessage({ cause: "权限不足：拒绝访问" })).toBe(
      "权限不足：拒绝访问",
    );
  });

  it("should include classification keywords in formatted message", () => {
    const message = formatCommandErrorMessage("端口扫描", "目标地址 校验失败：不能为空");
    expect(message).toContain("目标地址");
    expect(message).toContain("校验失败");
    expect(message).toContain("端口扫描失败");
  });

  it("should fallback to JSON for unknown error types", () => {
    const err = { code: 500, message: "", details: { reason: "timeout" } };
    expect(toCommandErrorMessage(err)).toBe(JSON.stringify(err));
  });

  it("should handle empty or null errors as unknown", () => {
    expect(toCommandErrorMessage(null)).toBe("未知错误");
    expect(toCommandErrorMessage(undefined)).toBe("未知错误");
  });
});
