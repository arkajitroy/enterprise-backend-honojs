import { createRoute } from "@hono/zod-openapi";
import { registerSchema } from "@/schemas/users.schema";
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
};

export default authRoutes;
