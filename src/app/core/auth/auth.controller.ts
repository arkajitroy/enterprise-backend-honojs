import { Context } from "hono";
import { StatusCodes } from "http-status-codes";
import { setCookie } from "hono/cookie";

import AuthService from "./auth.service";
import { accessTokenConfig, refreshTokenConfig } from "@/config/token.config";
import { logger } from "@/libs/logger";
import { ApiResponse, getValidatedBody } from "@/libs/utils";
import { LoginDto, RegisterDto } from "./auth.dto";

class AuthController {
  constructor(private readonly authService: AuthService) {}

  async register(c: Context) {
    const validated = getValidatedBody<RegisterDto>(c);

    const { user, accessToken, refreshToken } = await this.authService.register(validated);

    setCookie(c, "accessToken", accessToken, accessTokenConfig);
    setCookie(c, "refreshToken", refreshToken, refreshTokenConfig);

    logger.info({ ...logger.fromContext(c), message: "User registered" });

    return c.json(ApiResponse.success({ user }), StatusCodes.CREATED);
  }

  async login(c: Context) {
    const validated = getValidatedBody<LoginDto>(c);

    const { user, accessToken, refreshToken } = await this.authService.login(validated);

    setCookie(c, "accessToken", accessToken, accessTokenConfig);
    setCookie(c, "refreshToken", refreshToken, refreshTokenConfig);

    logger.info({ ...logger.fromContext(c), message: "User logged in" });

    return c.json(ApiResponse.success({ user }));
  }

  async refresh(c: Context) {
    const { accessToken, user } = await this.authService.refresh(c);

    setCookie(c, "accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 900,
    });

    return c.json(ApiResponse.success({ user }));
  }

  async logout(c: Context) {
    const user = c.get("user");
    await this.authService.logout(user.sub);

    setCookie(c, "accessToken", "", { maxAge: 0 });
    setCookie(c, "refreshToken", "", { maxAge: 0 });
  }
}

export default AuthController;
