import mongoose from "mongoose";
import { DB_NAME, MONGODB_LOCAL_URL } from "@/constants/env";
import { logger } from "@/libs/logger";

class Database {
  private db: mongoose.Connection | null = null;

  constructor() {
    this.db = null;
  }

  private initialize(): void {
    this.db = mongoose.connection;
    this.db.on("error", (error) => logger.error({ message: "MongoDB connection error", error }));
    this.db.once("open", () => logger.info({ message: "MongoDB connected successfully", ip: MONGODB_LOCAL_URL }));
  }

  public async connect(): Promise<void> {
    if (this.db) return;
    this.initialize();
    try {
      await mongoose.connect(MONGODB_LOCAL_URL, {
        dbName: DB_NAME,
      });
    } catch (error) {
      logger.error({ message: "MongoDB connection failed", error });
      throw new Error("Failed to connect to MongoDB");
    }
  }
}

export default Database;
