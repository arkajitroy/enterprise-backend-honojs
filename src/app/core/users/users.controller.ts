import { Context } from "hono";
import { AuthService } from "./users.service";
import { setCookie } from "hono/cookie";
import { accessTokenConfig, refreshTokenConfig } from "@/config/token.config";
import { logger } from "@/libs/logger";
import { ApiResponse } from "@/libs/utils";
import { StatusCodes } from "http-status-codes";

export class AuthController {
  constructor(private readonly authService: AuthService) {}

  async register(c: any) {
    const validated = c.get("validatedBody");

    const { user, accessToken, refreshToken } = await this.authService.register(validated);

    setCookie(c, "accessToken", accessToken, accessTokenConfig);
    setCookie(c, "refreshToken", refreshToken, refreshTokenConfig);

    logger.info({ ...logger.fromContext(c), message: "User registered" });

    return c.json(ApiResponse.success({ user }), StatusCodes.CREATED);
  }

  async login(c: Context) {
    const validated = c.get("validatedBody");

    const { user, accessToken, refreshToken } = await this.authService.login(validated);

    setCookie(c, "accessToken", accessToken, accessTokenConfig);
    setCookie(c, "refreshToken", refreshToken, refreshTokenConfig);

    logger.info({ ...logger.fromContext(c), message: "User logged in" });

    return c.json(ApiResponse.success({ user }));
  }

  async refresh(c: any) {
    const { accessToken, user } = await this.authService.refresh(c);

    setCookie(c, "accessToken", accessToken, { httpOnly: true, secure: true, sameSite: "Strict", maxAge: 900 });

    return c.json(ApiResponse.success({ user }));
  }

  async logout(c: Context) {
    const user = c.get("user");
    await this.authService.logout(user.sub);

    setCookie(c, "accessToken", "", { maxAge: 0 });
    setCookie(c, "refreshToken", "", { maxAge: 0 });
  }
}
