import { TUserSchema } from "@/app/model/users";
import { loginSchema, registerSchema } from "@/schemas/auth.schema";
import { z } from "zod";

export type TUserPayload = Pick<
  TUserSchema,
  "id" | "username" | "firstname" | "lastname" | "email" | "password" | "role"
>;

export type RegisterDto = z.infer<typeof registerSchema>;
export type LoginDto = z.infer<typeof loginSchema>;
export type LogoutDto = string;

export interface AuthResponse {
  user: Omit<TUserPayload, "password">;
  accessToken: string;
  refreshToken: string;
}
