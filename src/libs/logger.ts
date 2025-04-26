import { Context } from "hono";
import path from "path";
import fs from "fs";
import winston from "winston";
import colors from "colors";

type LogLevel = "info" | "warn" | "error" | "debug" | "verbose";

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

const colorize = (level: LogLevel, message: string) => {
  const label = `[${level.toUpperCase()}]`;

  switch (level) {
    case "info":
      return colors.green(`${label} ${message}`);
    case "warn":
      return colors.yellow(`${label} ${message}`);
    case "error":
      return colors.red(`${label} ${message}`);
    case "debug":
      return colors.cyan(`${label} ${message}`);
    case "verbose":
      return colors.magenta(`${label} ${message}`);
    default:
      return message;
  }
};

// ============================WINSTON LOGGER=============================

const LOG_DIR = path.join(process.cwd(), "logs");

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);

const winstonLogger = winston.createLogger({
  level: "debug",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(LOG_DIR, "app.log") }),
    new winston.transports.File({ filename: path.join(LOG_DIR, "error.log"), level: "error" }),
  ],
});

const formatTerminalLog = (level: LogLevel, payload: LogPayload) => {
  const { method, url, ip, message, requestId } = payload;
  const base = `[${new Date().toISOString()}] ${method || "METHOD"} ${url || "URL"} - ${ip || "IP"}`;
  return `${base} ${requestId ? `[req: ${requestId}]` : ""} → ${message || "No message"}`;
};

export const logger = {
  log: (level: LogLevel, payload: LogPayload) => {
    // Terminal Output
    console.log(colorize(level, formatTerminalLog(level, payload)));

    // File Output
    winstonLogger.log(level, {
      ...payload,
      level,
      timestamp: payload.timestamp || new Date().toISOString(),
    });
  },

  info: (payload: LogPayload) => logger.log("info", payload),
  warn: (payload: LogPayload) => logger.log("warn", payload),
  error: (payload: LogPayload) => logger.log("error", payload),
  debug: (payload: LogPayload) => logger.log("debug", payload),
  verbose: (payload: LogPayload) => logger.log("verbose", payload),

  fromContext: (c: Context, requestId?: string): LogPayload => {
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
