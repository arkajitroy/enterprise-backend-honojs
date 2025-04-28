import { Hono } from "hono";
import { jwt, sign, verify } from "hono/jwt";
import { serve } from "@hono/node-server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import mongoose, { Schema, model } from "mongoose";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { logger as honoLogger } from "hono/logger";
import winston from "winston";
import { v4 as uuidv4 } from "uuid";
import { RateLimiterMemory } from "rate-limiter-flexible";
import * as path from "path";
import * as fs from "fs";
import { setCookie, getCookie } from "hono/cookie";

// Environment configuration
const JWT_SECRET = process.env.JWT_SECRET || "your-secure-secret";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your-refresh-secret";
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME || "auth_db";
const LOG_DIR = process.env.LOG_DIR || "./logs";

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
  password: string;
  refreshToken?: string;
}

interface AuthResponse {
  accessToken: string;
  user: Pick<User, "id" | "email">;
}

// Mongoose Schema
const userSchema = new Schema<User>({
  id: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  refreshToken: { type: String },
  created_at: { type: Date, default: Date.now },
});

const UserModel = model<User>("User", userSchema);

// Database Service
class DatabaseService {
  constructor(uri: string) {
    this.initialize(uri);
  }

  private async initialize(uri: string): Promise<void> {
    try {
      await mongoose.connect(uri, { dbName: DB_NAME });
      logger.info("Connected to MongoDB via Mongoose");
    } catch (error) {
      logger.error("MongoDB connection error:", error);
      throw error;
    }
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return await UserModel.findOne({ email }).exec();
  }

  async saveUser(user: User): Promise<void> {
    await UserModel.create(user);
  }

  async updateRefreshToken(userId: string, refreshToken: string): Promise<void> {
    await UserModel.updateOne({ id: userId }, { refreshToken }).exec();
  }

  async clearRefreshToken(userId: string): Promise<void> {
    await UserModel.updateOne({ id: userId }, { $unset: { refreshToken: "" } }).exec();
  }

  async close(): Promise<void> {
    await mongoose.connection.close();
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

  static async authenticate(c: any, next: () => Promise<void>) {
    const accessToken = getCookie(c, "accessToken");
    if (!accessToken) {
      throw new HTTPException(401, { message: "Access token missing" });
    }

    try {
      const payload = await verify(accessToken, JWT_SECRET);
      c.set("user", payload);
      await next();
    } catch (error) {
      throw new HTTPException(401, { message: "Invalid or expired access token" });
    }
  }

  static async refreshToken(c: any, next: () => Promise<void>) {
    const refreshToken = getCookie(c, "refreshToken");
    if (!refreshToken) {
      throw new HTTPException(401, { message: "Refresh token missing" });
    }

    try {
      const payload = await verify(refreshToken, REFRESH_SECRET);
      const user = await new DatabaseService(MONGODB_URI).findUserByEmail(payload.email);

      if (!user || user.refreshToken !== refreshToken) {
        throw new HTTPException(401, { message: "Invalid refresh token" });
      }

      c.set("user", payload);
      await next();
    } catch (error) {
      throw new HTTPException(401, { message: "Invalid or expired refresh token" });
    }
  }
}

// Auth Service
class JwtAuthService implements AuthService {
  private db: DatabaseService;

  constructor(db: DatabaseService) {
    this.db = db;
  }

  private async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + JWT_SECRET);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Buffer.from(hash).toString("hex");
  }

  private generateUserId(): string {
    return uuidv4();
  }

  private async generateAccessToken(user: Pick<User, "id" | "email">): Promise<string> {
    return sign(
      {
        sub: user.id,
        email: user.email,
        exp: Math.floor(Date.now() / 1000) + 15 * 60, // 15 minutes
      },
      JWT_SECRET
    );
  }

  private async generateRefreshToken(user: Pick<User, "id" | "email">): Promise<string> {
    return sign(
      {
        sub: user.id,
        email: user.email,
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 days
      },
      REFRESH_SECRET
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
    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    await this.db.updateRefreshToken(user.id, refreshToken);

    logger.info({
      event: "user_registered",
      userId: user.id,
      email: user.email,
    });

    return { accessToken, user: { id: user.id, email: user.email } };
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

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    await this.db.updateRefreshToken(user.id, refreshToken);

    logger.info({
      event: "user_login",
      userId: user.id,
      email: user.email,
    });

    return { accessToken, user: { id: user.id, email: user.email } };
  }

  async refresh(c: any): Promise<AuthResponse> {
    const user = c.get("user");
    const newAccessToken = await this.generateAccessToken({
      id: user.sub,
      email: user.email,
    });

    return {
      accessToken: newAccessToken,
      user: { id: user.sub, email: user.email },
    };
  }

  async logout(userId: string): Promise<void> {
    await this.db.clearRefreshToken(userId);
    logger.info({
      event: "user_logout",
      userId,
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
      setCookie(c, "accessToken", result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 15 * 60, // 15 minutes
      });
      setCookie(c, "refreshToken", await this.authService["generateRefreshToken"](result.user), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60, // 7 days
      });
      return c.json({ user: result.user }, 201);
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

  async login(c: any): Promise<Response> {
    const body = c.get("validatedBody");
    try {
      const result = await this.authService.login(body);
      setCookie(c, "accessToken", result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 15 * 60, // 15 minutes
      });
      setCookie(c, "refreshToken", await this.authService["generateRefreshToken"](result.user), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60, // 7 days
      });
      return c.json({ user: result.user });
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

  async refresh(c: any): Promise<Response> {
    try {
      const result = await this.authService.refresh(c);
      setCookie(c, "accessToken", result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 15 * 60, // 15 minutes
      });
      return c.json({ user: result.user });
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
      const user = c.get("user");
      await this.authService.logout(user.sub);
      setCookie(c, "accessToken", "", { maxAge: 0 });
      setCookie(c, "refreshToken", "", { maxAge: 0 });
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
const dbService = new DatabaseService(MONGODB_URI);
const authService = new JwtAuthService(dbService);
const authController = new AuthController(authService);

// Global Middleware
app.use("*", honoLogger());
app.use("*", Middleware.requestLogger);
app.use(
  "*",
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  })
);
app.use("*", secureHeaders());
app.use("/auth/*", Middleware.rateLimit);

// Routes
app.post("/auth/register", Middleware.validateRequest(UserSchema), authController.register.bind(authController));
app.post("/auth/login", Middleware.validateRequest(LoginSchema), authController.login.bind(authController));
app.post("/auth/refresh", Middleware.refreshToken, authController.refresh.bind(authController));
app.post("/auth/logout", Middleware.authenticate, authController.logout.bind(authController));

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

// Graceful shutdown
process.on("SIGTERM", async () => {
  logger.info("Shutting down...");
  await dbService.close();
  process.exit(0);
});
