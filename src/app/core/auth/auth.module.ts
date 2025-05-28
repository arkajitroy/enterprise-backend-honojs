import AuthService from "./auth.service";
import AuthController from "./auth.controller";
import { OpenAPIHono } from "@hono/zod-openapi";
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
  }
}
