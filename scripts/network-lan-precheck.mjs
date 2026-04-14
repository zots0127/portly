#!/usr/bin/env node

const isPrivateIpv4 = (ip) => {
  const [aRaw, bRaw] = ip.split(".");
  const a = Number.parseInt(aRaw, 10);
  const b = Number.parseInt(bRaw, 10);

  if (Number.isNaN(a) || Number.isNaN(b)) return false;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b === 64) return true;
  return false;
};

const parseSubnet = (input) => {
  if (!input) {
    throw new Error("LAN_E2E_SUBNET 未设置");
  }
  const match = input.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(22|23|24)$/);
  if (!match) {
    throw new Error("LAN_E2E_SUBNET 格式非法，要求 IPv4 CIDR /22~24，例如 192.168.1.0/24");
  }
  const ip = match[1];
  const prefix = Number.parseInt(match[2], 10);
  const octets = ip.split(".").map((octet) => Number.parseInt(octet, 10));
  if (octets.some((octet) => Number.isNaN(octet) || octet < 0 || octet > 255)) {
    throw new Error("LAN_E2E_SUBNET IP 段包含非法数值");
  }
  if (!isPrivateIpv4(ip)) {
    throw new Error("LAN_E2E_SUBNET 需为内网网段（10/8, 172.16~31/12, 192.168/16, 100.64/10）");
  }
  return { ip, prefix };
};

if (process.env.RUN_LAN_E2E !== "1") {
  console.info("[LAN E2E] RUN_LAN_E2E 未开启：跳过真实扫描预检查，进入 Mock 保护模式。");
  process.exit(0);
}

try {
  const { ip, prefix } = parseSubnet(process.env.LAN_E2E_SUBNET);
  if (process.env.LAN_E2E_CONFIRM !== "YES") {
    throw new Error("未设置 LAN_E2E_CONFIRM=YES，禁止执行真实内网 E2E。");
  }

  console.info("[LAN E2E] 风险确认通过，准备执行真实内网端到端检测。");
  console.info(`[LAN E2E] 目标网段: ${ip}/${prefix}`);
  console.info("[LAN E2E] 注意：请确认当前设备已连接至目标内网，并手动在应用界面启动扫描。");
  process.exit(0);
} catch (error) {
  console.error("[LAN E2E] 预检查失败:");
  console.error(`  ${(error instanceof Error ? error.message : String(error))}`);
  console.error("[LAN E2E] 建议执行：");
  console.error("  RUN_LAN_E2E=1 LAN_E2E_SUBNET=<192.168.1.0/24> LAN_E2E_CONFIRM=YES npm run test:lan-e2e");
  process.exit(1);
}
