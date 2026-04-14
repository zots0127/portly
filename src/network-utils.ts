export const SUBNET_MIN_PREFIX = 22;
export const SUBNET_MAX_PREFIX = 24;

const SUBNET_RANGE_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}\/(\d+)$/;

function isValidIpv4Part(part: string): boolean {
  const n = Number(part);
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

function extractSubnetParts(input: string): { ipPart: string; prefix: number } | null {
  const value = input.trim();
  if (!SUBNET_RANGE_REGEX.test(value)) {
    return null;
  }

  const [ipPart, prefixPart] = value.split("/");
  const prefix = Number.parseInt(prefixPart, 10);
  if (!Number.isInteger(prefix) || prefix < SUBNET_MIN_PREFIX || prefix > SUBNET_MAX_PREFIX) {
    return null;
  }

  return { ipPart, prefix };
}

export function isValidSubnetRange(input: string): boolean {
  const value = input.trim();
  const parsed = extractSubnetParts(value);
  if (!parsed) return false;
  return parsed.ipPart.split(".").every(isValidIpv4Part);
}

export function getSubnetInput(
  subnetSelectValue: string,
  manualValue: string,
  fallback: string,
): string {
  const manual = manualValue.trim();
  if (manual) return manual;
  if (subnetSelectValue.trim()) return subnetSelectValue.trim();
  return fallback.trim();
}

export function estimateSubnetHostCount(subnet: string): number | null {
  const parsed = extractSubnetParts(subnet);
  if (!parsed) return null;
  const isIpValid = parsed.ipPart.split(".").every(isValidIpv4Part);
  if (!isIpValid) return null;

  const hostBits = 32 - parsed.prefix;
  const totalAddresses = 1 << hostBits;
  return Math.max(totalAddresses - 2, 0);
}

export function formatEstimatedDuration(seconds: number): string {
  const s = Math.max(Math.round(seconds), 1);
  const minutes = Math.floor(s / 60);
  const remain = s % 60;
  if (minutes > 0) {
    return `${minutes} 分 ${remain} 秒`;
  }
  return `${remain} 秒`;
}

export function estimateScanDurationSeconds(subnet: string): number | null {
  const hostCount = estimateSubnetHostCount(subnet);
  if (hostCount === null || hostCount < 500) return null;

  return Math.max(12, Math.round(hostCount * 0.12));
}

export function buildSubnetScanEstimateMessage(subnet: string): string | null {
  const hostCount = estimateSubnetHostCount(subnet);
  const estimatedSeconds = estimateScanDurationSeconds(subnet);
  if (hostCount === null || estimatedSeconds === null) return null;

  const estimateText = formatEstimatedDuration(estimatedSeconds);
  const warningSuffix =
    hostCount >= 900
      ? "范围较大，请考虑在低峰时段或分段执行，降低误报与网络抖动干扰。"
      : "建议先确认网段权限与防火墙策略，以减少连续超时导致的无效扫描。";
  return `当前范围约 ${hostCount} 台主机，当前范围估算耗时 ${estimateText}，${warningSuffix}`;
}

export function buildScanLoadingHtml(baseMessage: string, startAt: number, estimateSeconds: number | null): string {
  if (!estimateSeconds) return baseMessage;

  const elapsed = Math.max(1, Math.round((Date.now() - startAt) / 1000));
  const remain = Math.max(estimateSeconds - elapsed, 0);
  return `${baseMessage}<br><span style="font-size: 11px; opacity: 0.85;">已耗时 ${formatEstimatedDuration(elapsed)}，预计还需 ${formatEstimatedDuration(remain)}</span>`;
}
