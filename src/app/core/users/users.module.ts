import { Hono } from "hono";
import { AuthService } from "./users.service";
import { AuthController } from "./users.controller";

export class AuthModule {
  public router = new Hono();
  private authService = new AuthService();
  private authController = new AuthController(this.authService);

  constructor() {
    this.routes();
  }

  private routes() {
    // this.router.post("/register", (c) => this.authController.register(c));
    // this.router.post("/login", (c) => this.authController.login(c));
    // this.router.post("/logout", (c) => this.authController.logout(c));
  }
}
