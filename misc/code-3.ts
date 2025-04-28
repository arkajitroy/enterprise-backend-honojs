import { Hono } from "hono";
import { jwt, sign, verify } from "hono/jwt";
import { serve } from "@hono/node-server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import { MongoClient, ServerApiVersion } from "mongodb";
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
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME || "auth_db";
const LOG_DIR = process.env.LOG_DIR || "./logs";

// Database Setup
class DatabaseService {
  private client: MongoClient;
  private db: any;

  constructor(uri: string) {
    this.client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });
    this.initialize();
  }

  private async initialize(): Promise<void> {
    try {
      await this.client.connect();
      this.db = this.client.db(DB_NAME);
      // Create index for unique email
      await this.db.collection("users").createIndex({ email: 1 }, { unique: true });
      logger.info("Connected to MongoDB");
    } catch (error) {
      logger.error("MongoDB connection error:", error);
      throw error;
    }
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return await this.db.collection("users").findOne({ email });
  }

  async saveUser(user: User): Promise<void> {
    await this.db.collection("users").insertOne({
      ...user,
      created_at: new Date(),
    });
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

// Initialize Hono app
const app = new Hono();
const dbService = new DatabaseService(MONGODB_URI);
const authService = new JwtAuthService(dbService);
const authController = new AuthController(authService);

// Graceful shutdown
process.on("SIGTERM", async () => {
  logger.info("Shutting down...");
  await dbService.close();
  process.exit(0);
});
