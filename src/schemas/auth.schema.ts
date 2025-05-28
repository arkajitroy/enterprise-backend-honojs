import { z } from "zod";

export const registerSchema = z.object({
  email: z.string().email(),
  username: z.string().min(4),
  firstname: z.string().min(4),
  lastname: z.string().min(4),
  password: z.string().min(8),
  role: z.enum(["USER", "ADMIN"]).optional(),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});
