import { Hono } from "hono";
import AuthService from "./users.service";
import AuthController from "./users.controller";
import { loginSchema, registerSchema } from "@/schemas/users.schema";
import Middleware from "@/config/middleware";

export class AuthModule {
  public router = new Hono();
  private authService = new AuthService();
  private authController = new AuthController(this.authService);

  constructor() {
    this.routes();
  }

  private routes() {
    this.router.post("/register", Middleware.validateRequest(registerSchema), (c) => this.authController.register(c));
    this.router.post("/login", Middleware.validateRequest(loginSchema), (c) => this.authController.login(c));
    this.router.post("/logout", (c) => this.authController.logout(c));
  }
}
