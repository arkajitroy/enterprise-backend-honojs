import { TUserSchema } from "@/app/model/users";
import { loginSchema, registerSchema } from "@/schemas/auth.schema";
import { z } from "zod";

export type TUserPayload = Pick<TUserSchema, "id" | "email" | "password" | "provider" | "role">;

export type RegisterDto = z.infer<typeof registerSchema>;
export type LoginDto = z.infer<typeof loginSchema>;
export type OAuthGoogleDto = Pick<TUserSchema, "email"> & { googleId: string };

export type LogoutDto = string;

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    role: string;
    provider: string;
  };
  accessToken: string;
  refreshToken: string;
}
