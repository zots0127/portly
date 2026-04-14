import { buildScanLoadingHtml } from "./network-utils";

export const DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE = "监测启动超时，建议缩小子网范围后重试";

export function buildDiscoverDevicesLoadingHtml(
  loadingBase: string,
  startAt: number,
  estimateSeconds: number | null,
  rangeEstimateMessage: string | null,
): string {
  const loadingHint = estimateSeconds
    ? `${buildScanLoadingHtml(loadingBase, startAt, estimateSeconds)}`
    : loadingBase;
  if (rangeEstimateMessage) {
    return `<div class="loading">${loadingHint}<br><span style="font-size: 11px; opacity: 0.85;">${rangeEstimateMessage}</span></div>`;
  }
  return `<div class="loading">${loadingHint}</div>`;
}

export function setDiscoverDevicesLoadingState(
  button: HTMLButtonElement,
  deviceList: HTMLDivElement,
  loadingHtml: string,
): void {
  button.disabled = true;
  button.textContent = "⏳ 扫描中...";
  deviceList.innerHTML = loadingHtml;
}

export function setDiscoverDevicesIdleState(
  button: HTMLButtonElement,
  buttonText = "🔍 扫描设备",
): void {
  button.disabled = false;
  button.textContent = buttonText;
}

export function setDiscoverDevicesErrorState(
  deviceList: HTMLDivElement,
  errorText = "扫描失败",
): void {
  deviceList.innerHTML = `<div class="empty-state"><div class="icon">❌</div><div>${errorText}</div></div>`;
}

export function setPortScanLoadingState(
  button: HTMLButtonElement,
  portResults: HTMLDivElement,
  targetIp: string,
): void {
  button.disabled = true;
  button.textContent = "⏳ 扫描中...";
  portResults.innerHTML = `<div class="loading">正在扫描 ${targetIp} 的端口...</div>`;
}

export function setPortScanIdleState(
  button: HTMLButtonElement,
): void {
  button.disabled = false;
  button.textContent = "扫描端口";
}

export function setPortScanErrorState(
  portResults: HTMLDivElement,
  errorText = "扫描失败",
): void {
  portResults.innerHTML = `<div class="empty-state"><div class="icon">❌</div><div>${errorText}</div></div>`;
}

export function buildMonitorLoadingHtml(
  loadingBase: string,
  startAt: number,
  estimateSeconds: number | null,
  rangeEstimateMessage: string,
): string {
  if (estimateSeconds) {
    return `<div class="monitor-hint">${rangeEstimateMessage}<br><span style="font-size: 11px; opacity: 0.8;">${buildScanLoadingHtml(loadingBase, startAt, estimateSeconds)}</span></div>`;
  }
  return `<div class="monitor-hint">${rangeEstimateMessage}</div>`;
}

export function startMonitorLoadingTimer(
  deviceGrid: HTMLDivElement | null,
  renderMonitorLoadingHtml: () => string,
  estimateSeconds: number | null,
): number | null {
  if (!deviceGrid) return null;
  deviceGrid.innerHTML = renderMonitorLoadingHtml();
  if (!estimateSeconds) {
    return null;
  }
  return window.setInterval(() => {
    if (!deviceGrid) return;
    deviceGrid.innerHTML = renderMonitorLoadingHtml();
  }, 1000);
}

export function stopMonitorLoadingTimer(loadingTimer: number | null): number | null {
  if (loadingTimer) {
    clearInterval(loadingTimer);
  }
  return null;
}

export function startMonitorStartupTimeout(
  deviceGrid: HTMLDivElement | null,
  estimateSeconds: number | null,
  timeoutMessage = DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE,
  onTimeout?: () => void,
): number | null {
  if (!deviceGrid || !estimateSeconds) {
    return null;
  }
  return window.setTimeout(() => {
    setMonitorErrorState(deviceGrid, timeoutMessage);
    onTimeout?.();
  }, estimateSeconds * 1000);
}

export function stopMonitorStartupTimeout(startupTimeout: number | null): number | null {
  if (startupTimeout) {
    clearTimeout(startupTimeout);
  }
  return null;
}

export function applyMonitorTimeoutFallback(
  deviceGrid: HTMLDivElement | null,
  startButton: HTMLButtonElement,
  stopButton: HTMLButtonElement,
  timeoutMessage = DEFAULT_MONITOR_STARTUP_TIMEOUT_MESSAGE,
): void {
  if (!deviceGrid) {
    return;
  }
  setMonitorErrorState(deviceGrid, timeoutMessage);
  setMonitorStopState(startButton, stopButton);
}

export function setMonitorErrorState(
  deviceGrid: HTMLDivElement,
  errorText = "监测启动失败",
): void {
  deviceGrid.innerHTML = `<div class="empty-state"><div class="icon">❌</div><div>${errorText}</div></div>`;
}

export function setMonitorStartState(
  startButton: HTMLButtonElement,
  stopButton: HTMLButtonElement,
): void {
  startButton.style.display = "none";
  stopButton.style.display = "block";
}

export function setMonitorStopState(
  startButton: HTMLButtonElement,
  stopButton: HTMLButtonElement,
): void {
  startButton.style.display = "block";
  stopButton.style.display = "none";
}
