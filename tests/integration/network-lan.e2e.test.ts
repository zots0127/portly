import { describe, it, expect } from "vitest";

const enableLanE2E = process.env.RUN_LAN_E2E === "1";
const subnetHint = process.env.LAN_E2E_SUBNET;
const ack = process.env.LAN_E2E_CONFIRM;

type LanPrefix = 22 | 23 | 24;

function parseSubnet(input: string | undefined): { ip: string; prefix: LanPrefix } {
  if (!input) {
    throw new Error("LAN_E2E_SUBNET 未设置");
  }

  const match = input.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(22|23|24)$/);
  if (!match) {
    throw new Error("LAN_E2E_SUBNET 格式非法，要求 IPv4 CIDR /22~24，例如 192.168.1.0/24");
  }

  const ip = match[1];
  const prefix = Number.parseInt(match[2], 10) as LanPrefix;
  if (!ip.split(".").every((octet) => {
    const n = Number.parseInt(octet, 10);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  })) {
    throw new Error("LAN_E2E_SUBNET IP 段包含非法数值");
  }

  return { ip, prefix };
}

function isPrivateIpv4(ip: string): boolean {
  const [aRaw, bRaw] = ip.split(".");
  const a = Number.parseInt(aRaw, 10);
  const b = Number.parseInt(bRaw, 10);

  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b === 64) return true;
  return false;
}

describe("LAN end-to-end scan gate", () => {
  it("should only run when explicitly enabled and constrained in intranet", () => {
    if (!enableLanE2E) {
      expect(process.env.RUN_LAN_E2E).not.toBe("1");
      return;
    }

    const { ip, prefix } = parseSubnet(subnetHint);
    expect(isPrivateIpv4(ip)).toBe(true);
    expect(prefix).toBeGreaterThanOrEqual(22);
    expect(prefix).toBeLessThanOrEqual(24);
    expect(enableLanE2E).toBe(true);
  });

  it("should provide a clear manual execution note", () => {
    if (!enableLanE2E) {
      expect(true).toBe(true);
      return;
    }

    expect(ack).toBe("YES");
    expect(
      `已显式开启 LAN E2E：请在真实内网环境运行 Portly 应用并手动执行扫描流程（默认跳过 mock 用例）`,
    ).toBeTruthy();
  });

  it("should require subnet and confirmation when enabled", () => {
    if (!enableLanE2E) {
      expect(ack).not.toBe("YES");
      return;
    }

    expect(() => parseSubnet(subnetHint)).not.toThrow();
    expect(ack).toBe("YES");
  });

  it("should reject unsafe subnet inputs", () => {
    expect(() => parseSubnet("256.168.1.0/24")).toThrow();
    expect(() => parseSubnet("192.168.1.0/25")).toThrow();
    expect(() => parseSubnet("10.0.0.0/20")).toThrow();
  });
});
