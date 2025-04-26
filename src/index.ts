import { Hono } from "hono";
import { logger as appLogger } from "hono/logger";
import { PORT } from "@/constants/env";
import Middleware from "./config/middleware";

const app = new Hono();

// Middleware Initialization
app.use("*", appLogger());
app.use("*", Middleware.requestLogger);
app.use("*", Middleware.corsConfig());

app.get("/", (c) => {
  return c.text("Hello Hono!");
});

export default {
  fetch: app.fetch,
  port: PORT,
};
