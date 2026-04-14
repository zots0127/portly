export function toCommandErrorMessage(error: unknown): string {
  if (error === null || error === undefined) {
    return "未知错误";
  }
  if (typeof error === "string") {
    return error;
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  if (typeof error === "object") {
    const candidate = error as Record<string, unknown>;
    if (typeof candidate.message === "string" && candidate.message.trim()) {
      return candidate.message;
    }
    if (typeof candidate.error === "string" && candidate.error.trim()) {
      return candidate.error;
    }
    if (typeof candidate.cause === "string" && candidate.cause.trim()) {
      return candidate.cause;
    }
    if (typeof candidate.reason === "string" && candidate.reason.trim()) {
      return candidate.reason;
    }
  }
  return JSON.stringify(error);
}

export function formatCommandErrorMessage(action: string, error: unknown): string {
  const detail = toCommandErrorMessage(error);
  return `❌ ${action}失败: ${detail}`;
}

