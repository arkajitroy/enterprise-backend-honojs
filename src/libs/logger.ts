import { Context } from "hono";

type LogLevel = "info" | "warn" | "error";

interface LogPayload {
  requestId?: string;
  method?: string;
  url?: string;
  ip?: string;
  timestamp?: string;
  message?: string;
  error?: unknown;
  [key: string]: any;
}

const formatLog = (level: LogLevel, payload: LogPayload) => {
  const log = {
    level,
    ...payload,
    timestamp: payload.timestamp || new Date().toISOString(),
  };

  return JSON.stringify(log);
};

export const logger = {
  info: (payload: LogPayload) => {
    console.log(`🟢 ${formatLog("info", payload)}`);
  },
  warn: (payload: LogPayload) => {
    console.warn(`🟡 ${formatLog("warn", payload)}`);
  },
  error: (payload: LogPayload) => {
    console.error(`🔴 ${formatLog("error", payload)}`);
  },

  fromContext: (c: Context, requestId?: string) => {
    const method = c.req.method;
    const url = c.req.url;
    const ip = c.req.header("x-forwarded-for") || c.req.header("cf-connecting-ip") || "unknown";

    return {
      requestId: requestId || crypto.randomUUID(),
      method,
      url,
      ip,
      timestamp: new Date().toISOString(),
    };
  },
};
