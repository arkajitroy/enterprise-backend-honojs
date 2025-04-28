import { Hono } from "hono";
import { AuthModule } from "../core/users/users.module";

const AppRouter = new Hono();

const authModule = new AuthModule();

// Routes Configuration
const routes = {
  "/auth": authModule.router,
  // Add more routes here as needed
};

// Register routes with the main app
for (const [path, router] of Object.entries(routes)) {
  AppRouter.route(path, router);
}

export type TRoutes = typeof routes;
export type TRouteKeys = keyof TRoutes;
export type RouteValues = TRoutes[TRouteKeys];

export default AppRouter;
