import { TUserSchema } from "@/app/model/user-schema";
import { loginSchema, registerSchema } from "@/schemas/users.schema";
import { z } from "zod";

export type TUserPayload = Pick<TUserSchema, "id" | "email" | "password">;

export type RegisterDto = z.infer<typeof registerSchema>;
export type LoginDto = z.infer<typeof loginSchema>;
export type LogoutDto = string;

export interface AuthResponse {
  user: {
    id: string;
    email: string;
  };
  accessToken: string;
  refreshToken: string;
}
