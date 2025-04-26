import authRoutes from "./auth.routes";

export const routes = {
  authRoutes,
};

export type Routes = typeof routes;
export type RouteKeys = keyof Routes;
export type RouteValues = Routes[RouteKeys];
