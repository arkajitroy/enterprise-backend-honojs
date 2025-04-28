import { Hono } from "hono";
import { jwt, sign, verify } from "hono/jwt";
import { serve } from "@hono/node-server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import Database from "better-sqlite3";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { logger as honoLogger } from "hono/logger";
import winston from "winston";
import { v4 as uuidv4 } from "uuid";
import { RateLimiterMemory } from "rate-limiter-flexible";
import * as path from "path";
import * as fs from "fs";

// Environment configuration
const JWT_SECRET = process.env.JWT_SECRET || "your-secure-secret";
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || "./auth.db";
const LOG_DIR = process.env.LOG_DIR || "./logs";

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR);
}

// Winston Logger Setup
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: path.join(LOG_DIR, "app.log") }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, "error.log"),
      level: "error",
    }),
  ],
});

// Rate Limiter Setup
const rateLimiter = new RateLimiterMemory({
  points: 10, // 10 requests
  duration: 60, // per minute
});

// Schemas for validation
const UserSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(8)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: "Password must contain at least one uppercase letter, one lowercase letter, and one number",
    }),
});

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

// Interfaces
interface User {
  id: string;
  email: string;
  password: string; // Hashed in DB
}

interface AuthResponse {
  token: string;
  user: Pick<User, "id" | "email">;
}

// Database Setup
class DatabaseService {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const stmt = this.db.prepare("SELECT * FROM users WHERE email = ?");
    return stmt.get(email) as User | null;
  }

  async saveUser(user: User): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO users (id, email, password) VALUES (?, ?, ?)
    `);
    stmt.run(user.id, user.email, user.password);
  }
}

// Middleware
class Middleware {
  static async validateRequest(schema: z.ZodSchema) {
    return async (c: any, next: () => Promise<void>) => {
      const body = await c.req.json();
      const validation = schema.safeParse(body);
      if (!validation.success) {
        throw new HTTPException(400, {
          message: "Invalid input data",
          errors: validation.error.issues,
        });
      }
      c.set("validatedBody", validation.data);
      await next();
    };
  }

  static async rateLimit(c: any, next: () => Promise<void>) {
    try {
      await rateLimiter.consume(c.req.ip || "unknown");
      await next();
    } catch (error) {
      throw new HTTPException(429, { message: "Too many requests" });
    }
  }

  static requestLogger(c: any, next: () => Promise<void>) {
    const requestId = uuidv4();
    c.set("requestId", requestId);

    logger.info({
      requestId,
      method: c.req.method,
      url: c.req.url,
      ip: c.req.ip,
      timestamp: new Date().toISOString(),
    });

    return next();
  }
}

// Abstract Auth Service
abstract class AuthService {
  abstract register(data: z.infer<typeof UserSchema>): Promise<AuthResponse>;
  abstract login(data: z.infer<typeof LoginSchema>): Promise<AuthResponse>;
  abstract logout(): Promise<void>;
  protected abstract generateToken(user: Pick<User, "id" | "email">): Promise<string>;
}

// Concrete Auth Service Implementation
class JwtAuthService implements AuthService {
  private db: DatabaseService;

  constructor(db: DatabaseService) {
    this.db = db;
  }

  private async hashPassword(password: string): Promise<string> {
    // In production, use bcrypt or argon2
    // This is a simple hash for demonstration
    const encoder = new TextEncoder();
    const data = encoder.encode(password + JWT_SECRET);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Buffer.from(hash).toString("hex");
  }

  private generateUserId(): string {
    return uuidv4();
  }

  protected async generateToken(user: Pick<User, "id" | "email">): Promise<string> {
    return sign(
      {
        sub: user.id,
        email: user.email,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour
      },
      JWT_SECRET
    );
  }

  async register(data: z.infer<typeof UserSchema>): Promise<AuthResponse> {
    const { email, password } = data;
    const existingUser = await this.db.findUserByEmail(email);
    if (existingUser) {
      throw new HTTPException(409, { message: "User already exists" });
    }

    const hashedPassword = await this.hashPassword(password);
    const user: User = {
      id: this.generateUserId(),
      email,
      password: hashedPassword,
    };

    await this.db.saveUser(user);
    const token = await this.generateToken(user);

    logger.info({
      event: "user_registered",
      userId: user.id,
      email: user.email,
    });

    return { token, user: { id: user.id, email: user.email } };
  }

  async login(data: z.infer<typeof LoginSchema>): Promise<AuthResponse> {
    const { email, password } = data;
    const user = await this.db.findUserByEmail(email);
    if (!user) {
      logger.warn({
        event: "login_failed",
        email,
        reason: "user_not_found",
      });
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

    const hashedInputPassword = await this.hashPassword(password);
    if (user.password !== hashedInputPassword) {
      logger.warn({
        event: "login_failed",
        email,
        reason: "invalid_password",
      });
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

    const token = await this.generateToken(user);

    logger.info({
      event: "user_login",
      userId: user.id,
      email: user.email,
    });

    return { token, user: { id: user.id, email: user.email } };
  }

  async logout(): Promise<void> {
    // Could implement token blacklisting here
    logger.info({
      event: "user_logout",
    });
  }
}

// API Controller
class AuthController {
  private authService: AuthService;

  constructor(authService: AuthService) {
    this.authService = authService;
  }

  async register(c: any): Promise<Response> {
    const body = c.get("validatedBody");
    try {
      const result = await this.authService.register(body);
      return c.json(result, 201);
    } catch (error) {
      logger.error({
        requestId: c.get("requestId"),
        error: error.message,
        stack: error.stack,
      });
      if (error instanceof HTTPException) {
        return c.json({ message: error.message }, error.status);
        mands;
      }
      return c.json({ message: "Internal server error" }, 500);
    }
  }

  async login(c: any): Promise<Response> {
    const body = c.get("validatedBody");
    try {
      const result = await this.authService.login(body);
      return c.json(result);
    } catch (error) {
      logger.error({
        requestId: c.get("requestId"),
        error: error.message,
        stack: error.stack,
      });
      if (error instanceof HTTPException) {
        return c.json({ message: error.message }, error.status);
      }
      return c.json({ message: "Internal server error" }, 500);
    }
  }

  async logout(c: any): Promise<Response> {
    try {
      await this.authService.logout();
      return c.json({ message: "Logged out successfully" });
    } catch (error) {
      logger.error({
        requestId: c.get("requestId"),
        error: error.message,
        stack: error.stack,
      });
      return c.json({ message: "Internal server error" }, 500);
    }
  }
}

// Initialize Hono app
const app = new Hono();
const dbService = new DatabaseService(DB_PATH);
const authService = new JwtAuthService(dbService);
const authController = new AuthController(authService);

// Global Middleware
app.use("*", honoLogger());
app.use("*", Middleware.requestLogger);
app.use(
  "*",
  cors({
    origin: ["http://localhost:3000"], // Adjust for production
    credentials: true,
  })
);
app.use("*", secureHeaders());
app.use("/auth/*", Middleware.rateLimit);

// Routes
app.post("/auth/register", Middleware.validateRequest(UserSchema), authController.register.bind(authController));
app.post("/auth/login", Middleware.validateRequest(LoginSchema), authController.login.bind(authController));
app.post("/auth/logout", jwt({ secret: JWT_SECRET }), authController.logout.bind(authController));

// Error handling
app.onError((err, c) => {
  logger.error({
    requestId: c.get("requestId"),
    error: err.message,
    stack: err.stack,
  });
  return c.json({ message: err.message }, 500);
});

// Start server
serve({
  fetch: app.fetch,
  port: Number(PORT),
});

logger.info(`Server running on port ${PORT}`);
