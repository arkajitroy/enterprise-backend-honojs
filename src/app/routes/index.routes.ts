import { AuthModule } from "@/app/core/auth/auth.module";
import { OpenAPIHono } from "@hono/zod-openapi";

const AppRouter = new OpenAPIHono();
const authModule = new AuthModule();

AppRouter.get("/", (c) => c.text("Welcome to the API!"));

AppRouter.doc("/openapi", {
  openapi: "3.0.0",
  info: {
    title: "API Documentation",
    description: "API documentation for the application.",
    version: "1.0.0",
  },
});

AppRouter.route("/auth", authModule.router);

export default AppRouter;
