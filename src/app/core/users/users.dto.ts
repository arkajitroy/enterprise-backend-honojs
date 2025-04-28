import { TUserSchema } from "@/app/model/user-schema";
import { LoginSchema, UserSchema } from "@/schemas/users.schema";
import { z } from "zod";

export type TUserPayload = Pick<TUserSchema, "id" | "email" | "password">;

export type RegisterDto = z.infer<typeof UserSchema>;
export type LoginDto = z.infer<typeof LoginSchema>;
export type LogoutDto = string;

export interface AuthResponse {
  user: {
    id: string;
    email: string;
  };
  accessToken: string;
  refreshToken: string;
}
