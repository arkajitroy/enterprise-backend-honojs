import { Hono } from "hono";
import { jwt, sign, verify } from "hono/jwt";
import { serve } from "@hono/node-server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";

// Environment configuration
const JWT_SECRET = process.env.JWT_SECRET || "your-secure-secret";
const PORT = process.env.PORT || 3000;

// Schemas for validation
const UserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const LoginSchema = UserSchema;

// Interfaces
interface User {
  id: string;
  email: string;
  password: string; // In production, this should be hashed
}

interface AuthResponse {
  token: string;
  user: Pick<User, "id" | "email">;
}

// Simulated database (replace with actual DB in production)
class Database {
  private static users: Map<string, User> = new Map();

  static async findUserByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) return user;
    }
    return null;
  }

  static async saveUser(user: User): Promise<void> {
    this.users.set(user.id, user);
  }
}

// Abstract Auth Service
abstract class AuthService {
  abstract register(data: z.infer<typeof UserSchema>): Promise<AuthResponse>;
  abstract login(data: z.infer<typeof LoginSchema>): Promise<AuthResponse>;
  abstract logout(): Promise<void>;
  protected abstract generateToken(user: Pick<User, "id" | "email">): Promise<string>;
}

// Concrete Auth Service Implementation
class JwtAuthService implements AuthService {
  private async hashPassword(password: string): Promise<string> {
    // In production, use a proper hashing algorithm like bcrypt
    return password; // Placeholder
  }

  private generateUserId(): string {
    return Math.random().toString(36).slice(2);
  }

  protected async generateToken(user: Pick<User, "id" | "email">): Promise<string> {
    return sign(
      { sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 60 * 60 }, // 1 hour
      JWT_SECRET
    );
  }

  async register(data: z.infer<typeof UserSchema>): Promise<AuthResponse> {
    const validation = UserSchema.safeParse(data);
    if (!validation.success) {
      throw new HTTPException(400, { message: "Invalid input data" });
    }

    const { email, password } = validation.data;
    const existingUser = await Database.findUserByEmail(email);
    if (existingUser) {
      throw new HTTPException(409, { message: "User already exists" });
    }

    const hashedPassword = await this.hashPassword(password);
    const user: User = {
      id: this.generateUserId(),
      email,
      password: hashedPassword,
    };

    await Database.saveUser(user);
    const token = await this.generateToken(user);
    return { token, user: { id: user.id, email: user.email } };
  }

  async login(data: z.infer<typeof LoginSchema>): Promise<AuthResponse> {
    const validation = LoginSchema.safeParse(data);
    if (!validation.success) {
      throw new HTTPException(400, { message: "Invalid input data" });
    }

    const { email, password } = validation.data;
    const user = await Database.findUserByEmail(email);
    if (!user) {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

    // In production, compare hashed passwords
    if (user.password !== password) {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

    const token = await this.generateToken(user);
    return { token, user: { id: user.id, email: user.email } };
  }

  async logout(): Promise<void> {
    // In a real app, you might want to invalidate the token
    // This could involve maintaining a token blacklist
  }
}

// API Controller
class AuthController {
  private authService: AuthService;

  constructor(authService: AuthService) {
    this.authService = authService;
  }

  async register(c: any): Promise<Response> {
    const body = await c.req.json();
    try {
      const result = await this.authService.register(body);
      return c.json(result, 201);
    } catch (error) {
      if (error instanceof HTTPException) {
        return c.json({ message: error.message }, error.status);
      }
      return c.json({ message: "Internal server error" }, 500);
    }
  }

  async login(c: any): Promise<Response> {
    const body = await c.req.json();
    try {
      const result = await this.authService.login(body);
      return c.json(result);
    } catch (error) {
      if (error instanceof HTTPException) {
        return c.json({ message: error.message }, error.status);
      }
      return c.json({ message: "Internal server error" }, 500);
    }
  }

  async logout(c: any): Promise<Response> {
    try {
      await this.authService.logout();
      return c.json({ message: "Logged out successfully" });
    } catch (error) {
      return c.json({ message: "Internal server error" }, 500);
    }
  }
}

// Initialize Hono app
const app = new Hono();
const authService = new JwtAuthService();
const authController = new AuthController(authService);

// Routes
app.post("/register", authController.register.bind(authController));
app.post("/login", authController.login.bind(authController));
app.post("/logout", jwt({ secret: JWT_SECRET }), authController.logout.bind(authController));

// Error handling
app.onError((err, c) => {
  return c.json({ message: err.message }, 500);
});

// Start server
serve({
  fetch: app.fetch,
  port: Number(PORT),
});

console.log(`Server running on port ${PORT}`);
