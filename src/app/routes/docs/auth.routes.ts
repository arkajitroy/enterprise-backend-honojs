import { createRoute } from "@hono/zod-openapi";
import { loginSchema, oauthGoogleLoginSchema, registerSchema } from "@/schemas/auth.schema";
import StatusCodes from "http-status-codes";

const authRoutes = {
  register: createRoute({
    method: "post",
    path: "/register",
    request: {
      body: {
        content: {
          "application/json": {
            schema: registerSchema,
          },
        },
      },
    },
    responses: {
      [StatusCodes.CREATED]: {
        description: "User registered successfully",
      },
      [StatusCodes.BAD_REQUEST]: {
        description: "Invalid request body",
      },
    },
  }),
  login: createRoute({
    method: "post",
    path: "/login",
    request: {
      body: {
        content: {
          "application/json": {
            schema: loginSchema,
          },
        },
      },
    },
    responses: {
      [StatusCodes.OK]: {
        description: "User logged in successfully",
      },
      [StatusCodes.BAD_REQUEST]: {
        description: "Invalid request body",
      },
    },
  }),

  googleLogin: createRoute({
    method: "post",
    path: "/google",
    request: {
      body: {
        content: {
          "application/json": {
            schema: oauthGoogleLoginSchema,
          },
        },
      },
    },
    responses: {
      [StatusCodes.OK]: {
        description: "User logged in successfully",
      },
      [StatusCodes.BAD_REQUEST]: {
        description: "Invalid request body",
      },
    },
  }),
  refresh: createRoute({
    method: "get",
    path: "/refresh",
    responses: {
      [StatusCodes.OK]: {
        description: "Token refreshed successfully",
      },
    },
  }),
};

export default authRoutes;
