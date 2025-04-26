import { ApiError } from "@/libs/utils";
import { StatusCodes } from "http-status-codes";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { logger } from "@/libs/logger";
import { cors } from "hono/cors";
import { RateLimiterMemory } from "rate-limiter-flexible";

class Middleware {
  constructor() {
    console.log("Middleware initialized!");
  }

  private static rateLimiter = new RateLimiterMemory({
    points: 10,
    duration: 60,
    blockDuration: 60,
  });

  static async validateRequest(schema: z.ZodSchema) {
    return async (c: any, next: () => Promise<void>) => {
      const body = await c.req.json();
      const validation = schema.safeParse(body);
      if (!validation.success) {
        throw new ApiError("Invalid request body", StatusCodes.BAD_REQUEST, validation.error.issues);
      }
      c.set("validatedBody", validation.data);
      await next();
    };
  }

  static requestLogger(c: any, next: () => Promise<void>) {
    const requestId = uuidv4();
    c.set("requestId", requestId);

    logger.info({
      ...logger.fromContext(c, requestId),
    });

    return next();
  }

  static corsConfig() {
    return cors({
      origin: "*",
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization"],
      maxAge: 3600,
    });
  }

  static async rateLimit(c: any, next: () => Promise<void>) {
    try {
      await this.rateLimiter.consume(c.req.ip);
      await next();
    } catch (err: any) {
      if (err?.msBeforeNext) {
        throw new ApiError("Too many requests", StatusCodes.TOO_MANY_REQUESTS, {
          retryAfter: err.msBeforeNext,
        });
      }
      throw err;
    }
  }
}

export default Middleware;
