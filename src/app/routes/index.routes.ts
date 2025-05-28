import { AuthModule } from "@/app/core/auth/auth.module";
import { OpenAPIHono } from "@hono/zod-openapi";

const AppRouter = new OpenAPIHono();
const authModule = new AuthModule();

AppRouter.get("/", (c) => c.text("Server is running successfully"));

AppRouter.doc("/docs", {
  openapi: "3.0.0",
  info: {
    title: "Hono API Documentation",
    description: "API documentation for the hono application.",
    version: "1.0.0",
  },
});

AppRouter.route("/auth", authModule.router);

export default AppRouter;
