import { Context } from "hono";
import { AuthService } from "./users.service";

export class AuthController {
  constructor(private readonly authService: AuthService) {}

  async register(c: Context) {
    try {
      const body = await c.req.json();
      const result = await this.authService.register(body);
      return c.json(result, 201);
    } catch (error) {
      if (error instanceof Error) {
        return c.json({ message: error.message }, (error as any).status || 500);
      }
      return c.json({ message: "Internal Server Error" }, 500);
    }
  }

  async login(c: Context) {
    try {
      const body = await c.req.json();
      const result = await this.authService.login(body);
      return c.json(result);
    } catch (error) {
      if (error instanceof Error) {
        return c.json({ message: error.message }, (error as any).status || 500);
      }
      return c.json({ message: "Internal Server Error" }, 500);
    }
  }

  async logout(c: Context) {
    try {
      await this.authService.logout();
      return c.json({ message: "Logged out successfully" });
    } catch (error) {
      return c.json({ message: "Internal Server Error" }, 500);
    }
  }
}
