import { ApiError } from "@/libs/utils";
import { StatusCodes } from "http-status-codes";
import { ZodSchema } from "zod";
import { v4 as uuidv4 } from "uuid";
import { logger } from "@/libs/logger";
import { cors } from "hono/cors";
import { RateLimiterMemory } from "rate-limiter-flexible";
import { Context } from "hono";
import { TUserSchema } from "@/app/model/users";
import { ALLOWED_USER_ROLES } from "@/constants/auth";

class Middleware {
  constructor() {}

  static rateLimiter = new RateLimiterMemory({
    points: 10,
    duration: 60,
    blockDuration: 60,
  });

  static extractValidatedBody() {
    return async (c: any, next: () => Promise<Response>): Promise<Response> => {
      const validated = c.req.valid?.("json");
      if (!validated) {
        throw new ApiError("Missing validated body", StatusCodes.BAD_REQUEST);
      }
      c.set("validatedBody", validated);

      return next();
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
    const ip =
      c.req.header("x-forwarded-for") || c.req.header("cf-connecting-ip") || c.req.ip || "unknown";

    try {
      await Middleware.rateLimiter.consume(ip);
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

  static hasRole(allowedRoles: typeof ALLOWED_USER_ROLES) {
    return async (c: Context, next: () => Promise<void>) => {
      const user: TUserSchema = c.get("user");
      if (!user || !allowedRoles.includes(user.role)) {
        throw new ApiError("Forbidden", StatusCodes.FORBIDDEN);
      }
      await next();
    };
  }
}

export default Middleware;
