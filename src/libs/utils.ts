import { MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { ContentfulStatusCode } from "hono/utils/http-status";
import { StatusCodes } from "http-status-codes";

/**
 * Unified API response wrapper
 */
export class ApiResponse<T> {
  statusCode: number;
  data: T | null;
  message: string;
  success: boolean;

  constructor(data: T | null, message = "Success", statusCode = StatusCodes.OK) {
    this.statusCode = statusCode;
    this.data = data;
    this.message = message;
    this.success = statusCode < StatusCodes.BAD_REQUEST;
  }

  static success<T>(data: T, message = "Success", statusCode = StatusCodes.OK) {
    return new ApiResponse<T>(data, message, statusCode);
  }

  static error<T>(message = "Error", statusCode = StatusCodes.INTERNAL_SERVER_ERROR, data: T | null = null) {
    return new ApiResponse<T>(data, message, statusCode);
  }
}

/**
 * Custom API error class
 */
export class ApiError extends Error {
  statusCode: number;
  data?: unknown;

  constructor(message: string, statusCode = StatusCodes.INTERNAL_SERVER_ERROR, data?: unknown) {
    super(message);
    this.statusCode = statusCode;
    this.data = data;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Centralized error handling middleware
 */
export const MiddlewareError: MiddlewareHandler = async (c, next) => {
  try {
    await next();
  } catch (err) {
    let statusCode = StatusCodes.INTERNAL_SERVER_ERROR;
    let message = "Internal Server Error";
    let data: unknown = null;

    if (err instanceof ApiError) {
      statusCode = err.statusCode;
      message = err.message;
      data = err.data;
    } else if (err instanceof HTTPException) {
      statusCode = err.status as StatusCodes;
      message = err.message || "HTTP Error";
    }

    return c.json(ApiResponse.error(message, statusCode, data), statusCode as unknown as ContentfulStatusCode);
  }
};
