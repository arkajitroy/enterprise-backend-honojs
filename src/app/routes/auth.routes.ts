import { Hono } from "hono";
// import authController from "@/controllers/auth.controller";
// import Middleware from "@/config/middleware";
// import { UserSchema, LoginSchema } from "@/schemas/auth.schema";

const authRoutes = new Hono();

// authRoutes.post("/register", Middleware.validateRequest(UserSchema), authController.register.bind(authController));
// authRoutes.post("/login", Middleware.validateRequest(LoginSchema), authController.login.bind(authController));
// authRoutes.post("/refresh", Middleware.refreshToken, authController.refresh.bind(authController));
// authRoutes.post("/logout", Middleware.authenticate, authController.logout.bind(authController));

export default authRoutes;

// TODO: Implement the whole thing in a classbased approach
// TODO: use the module based pattern for the keeping all the controller and the services
