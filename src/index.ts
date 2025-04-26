import { Hono } from "hono";
import { logger as appLogger } from "hono/logger";
import { PORT } from "@/constants/env";
import Middleware from "./config/middleware";
import { routes } from "./app/routes";

const app = new Hono();

// Middleware Initialization
app.use("*", appLogger());
app.use("*", Middleware.requestLogger);
app.use("*", Middleware.corsConfig());
app.use("*", Middleware.rateLimit);

// ROUTING CONFIGURATION
app.get("/", (c) => c.text("Welcome to the API!"));
app.route("api/auth", routes.authRoutes);

export default {
  fetch: app.fetch,
  port: PORT,
};
