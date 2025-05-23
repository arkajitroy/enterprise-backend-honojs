import { CookieOptions } from "hono/utils/cookie";

export const accessTokenConfig: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  maxAge: 900,
};

export const refreshTokenConfig: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  maxAge: 604800,
};
