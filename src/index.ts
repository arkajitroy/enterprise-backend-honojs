import { Hono } from "hono";
import { logger as appLogger } from "hono/logger";
import { PORT } from "@/constants/env";
import Middleware from "./config/middleware";
import AppRouter from "./app/routes/index.routes";
import { MiddlewareError } from "./libs/utils";
import Database from "./config/db.config";

const app = new Hono();
const database = new Database();

// Middleware Initialization
app.use("*", appLogger());
app.use("*", Middleware.requestLogger);
app.use("*", Middleware.corsConfig());
app.use("*", Middleware.rateLimit);
app.use("*", MiddlewareError);

// ROUTING CONFIGURATION
app.get("/", (c) => c.text("Welcome to the API!"));
app.route("/api", AppRouter);

// Database Connection
(async () => await database.connect())();

export default {
  fetch: app.fetch,
  port: PORT,
};
