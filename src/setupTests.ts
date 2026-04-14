import { expect, afterEach, vi } from "vitest";
import { getConfig } from "@testing-library/dom";
import "@testing-library/jest-dom";

// 获取 testing-library 的配置
const config = getConfig();

// 在每个测试后清理 DOM
afterEach(() => {
  // 手动清理 DOM，因为 @testing-library/dom v10 的 cleanup 方式不同
  document.body.innerHTML = "";
  // 清理所有测试节点
  const testIds = document.querySelectorAll("[data-testid]");
  testIds.forEach((node) => node.remove());
});

// 模拟 Tauri invoke API
const mockInvoke = vi.fn((cmd: string, args?: unknown) => {
  // 根据命令返回模拟数据
  if (cmd === "tauri_scan_ports") {
    // Check if a custom response was set
    if ((mockInvoke as any).__customResponse) {
      const response = (mockInvoke as any).__customResponse;
      (mockInvoke as any).__customResponse = null;
      return Promise.resolve(response);
    }
    return Promise.resolve({
      scan_time: new Date().toISOString(),
      total_ports: 2,
      unique_apps: 1,
      ports: [
        {
          port: 8080,
          protocol: "tcp",
          address: "127.0.0.1",
          pid: "1234",
          process: "node",
          user: "user",
          command: "node /app",
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
      ],
    });
  }
  if (cmd === "tauri_scan_ports_grouped") {
    return Promise.resolve([
      {
        process: "node",
        pid: "1234",
        ports: [8080, 3000],
        command: "node /app",
      },
    ]);
  }
  if (cmd === "tauri_check_ssl_cert") {
    return Promise.resolve({
      host: args?.host || "example.com",
      port: args?.port || 443,
      subject: "CN=example.com",
      issuer: "CN=Example CA",
      valid_from: "2024-01-01T00:00:00Z",
      valid_until: "2025-01-01T00:00:00Z",
      is_valid: true,
      is_expired: false,
      is_self_signed: false,
      days_until_expiry: 365,
      signature_algorithm: "SHA256",
      version: "v3",
      serial_number: "1234",
      key_size: 2048,
      certificate_chain: [],
      tls_version: "TLSv1.3",
      cipher_suite: null,
      error: null,
    });
  }
  if (cmd === "tauri_dns_query") {
    return Promise.resolve({
      domain: args?.domain || "example.com",
      record_type: args?.recordType || "A",
      records: [
        {
          name: args?.domain || "example.com",
          rtype: args?.recordType || "A",
          ttl: 300,
          data: "93.184.216.34",
        },
      ],
      query_time_ms: 50,
      dns_server: args?.dnsServer || "8.8.8.8",
      error: null,
    });
  }
  if (cmd === "tauri_whois_query") {
    return Promise.resolve({
      domain: args?.domain || "example.com",
      registrar: "Example Registrar",
      created: "2020-01-01T00:00:00Z",
      expires: "2025-01-01T00:00:00Z",
      updated: "2024-01-01T00:00:00Z",
      status: ["active", "clientTransferProhibited"],
      nameservers: ["ns1.example.com", "ns2.example.com"],
      dnssec: "unsigned",
      raw_output: "test output",
      error: null,
    });
  }
  if (cmd === "tauri_get_interfaces") {
    return Promise.resolve([
      {
        name: "en0",
        ip: "192.168.1.100",
        netmask: "255.255.255.0",
        subnet: "192.168.1.0/24",
      },
    ]);
  }
  if (cmd === "tauri_get_current_subnet") {
    return Promise.resolve("192.168.1.0/24");
  }
  if (cmd === "tauri_discover_devices") {
    return Promise.resolve([
      {
        ip: "192.168.1.1",
        mac: "00:11:22:33:44:55",
        hostname: "router",
        is_online: true,
      },
      {
        ip: "192.168.1.2",
        mac: "00:11:22:33:44:56",
        hostname: "laptop",
        is_online: true,
      },
    ]);
  }
  if (cmd === "tauri_resolve_target") {
    return Promise.resolve({
      original: args?.target || "example.com",
      ip: "93.184.216.34",
      is_domain: true,
      hostname: "example.com",
    });
  }
  if (cmd === "tauri_quick_scan") {
    return Promise.resolve([
      { port: 22, is_open: true, service: "SSH" },
      { port: 80, is_open: true, service: "HTTP" },
      { port: 443, is_open: true, service: "HTTPS" },
    ]);
  }
  if (cmd === "tauri_scan_ports_range") {
    return Promise.resolve([
      { port: 80, is_open: true, service: "HTTP" },
      { port: 443, is_open: true, service: "HTTPS" },
    ]);
  }
  if (cmd === "tauri_ping_one") {
    return Promise.resolve({
      ip: args?.ip || "192.168.1.1",
      seq: args?.seq || 1,
      success: true,
      time_ms: 25,
      ttl: 64,
      line: "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=25.0 ms",
    });
  }
  if (cmd === "tauri_traceroute") {
    return Promise.resolve({
      target: args?.ip || "192.168.1.1",
      hops: [
        { hop: 1, ip: "192.168.1.1", hostname: "router", time_ms: 2.5 },
        { hop: 2, ip: "10.0.0.1", hostname: "gateway", time_ms: 15.3 },
      ],
      raw_output: "traceroute to 192.168.1.1...",
    });
  }
  if (cmd === "tauri_kill_process") {
    return Promise.resolve({
      success: true,
      pid: args?.pid || 1234,
      message: "Process terminated successfully",
    });
  }
  if (cmd === "tauri_get_docker_containers") {
    return Promise.resolve([
      {
        id: "abc123",
        name: "nginx",
        image: "nginx:latest",
        status: "running",
        ports: [
          { host_port: 8080, container_port: 80, protocol: "tcp", host_ip: "0.0.0.0" },
        ],
      },
    ]);
  }
  if (cmd === "tauri_export_auto") {
    const format = args?.format || "csv";
    return Promise.resolve({
      success: true,
      path: `/tmp/ports-export.${format}`,
      message: "Data exported successfully",
      record_count: args?.ports?.length || 0,
    });
  }
  return Promise.resolve(undefined);
});

// 模拟 Tauri API 模块
vi.mock("@tauri-apps/api/core", () => ({
  invoke: mockInvoke,
}));

// 模拟 Tauri OPENER plugin
const mockOpenUrl = vi.fn();

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: mockOpenUrl,
}));

// 导出到全局以便在测试中使用
(globalThis as any).__mockInvoke = mockInvoke;
(globalThis as any).__mockOpenUrl = mockOpenUrl;

// 创建容器元素的 mock
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// 模拟 requestAnimationFrame
global.requestAnimationFrame = (callback: FrameRequestCallback) => {
  return setTimeout(callback, 16) as unknown as number;
};

global.cancelAnimationFrame = (id: number) => {
  clearTimeout(id);
};

// 模拟 setInterval 和 clearInterval
const nativeSetInterval = globalThis.setInterval;
const nativeClearInterval = globalThis.clearInterval;
global.setInterval = ((fn: TimerHandler, timeout?: number, ...args: unknown[]) => {
  return nativeSetInterval(fn, timeout, ...args) as unknown as number;
}) as typeof globalThis.setInterval;
global.clearInterval = ((id: ReturnType<typeof nativeSetInterval>) => {
  return nativeClearInterval(id);
}) as typeof globalThis.clearInterval;

// 模拟 console 方法以减少测试输出噪音
global.console = {
  ...console,
  log: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};
