import { OpenAPIHono } from "@hono/zod-openapi";
import AuthService from "./auth.service";
import AuthController from "./auth.controller";
import authRoutes from "@/app/routes/docs/auth.routes";

export class AuthModule {
  public router = new OpenAPIHono();
  private authService = new AuthService();
  private authController = new AuthController(this.authService);

  constructor() {
    this.routes();
  }

  private routes() {
    this.router.openapi(authRoutes.register, (payload) => this.authController.register(payload));
    this.router.openapi(authRoutes.login, (payload) => this.authController.login(payload));
    this.router.openapi(authRoutes.googleLogin, (payload) =>
      this.authController.googleLogin(payload)
    );
    this.router.openapi(authRoutes.refresh, (payload) => this.authController.refresh(payload));
  }
}
