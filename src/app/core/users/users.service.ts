import userModel, { TUserSchema } from "@/app/model/user-schema";
import { AuthResponse, LoginDto, LogoutDto, RegisterDto, TUserPayload } from "./users.dto";
import { v4 as uuidv4 } from "uuid";
import { JWT_SECRET, REFRESH_TOKEN_SECRET } from "@/constants/env";
import { sign } from "hono/jwt";
import { ApiError } from "@/libs/utils";
import { StatusCodes } from "http-status-codes";

// ==================================== AUTH SERVICE ========================================

abstract class AuthServiceAbstaction {
  abstract register(data: RegisterDto): Promise<AuthResponse>;
  abstract login(data: LoginDto): Promise<AuthResponse>;
  abstract logout(data: LogoutDto): Promise<void>;
  protected abstract generateRefreshToken(user: Pick<TUserSchema, "id" | "email">): Promise<string>;
  protected abstract generateAccessToken(user: Pick<TUserSchema, "id" | "email">): Promise<string>;
}

// ==================================== AUTH SERVICE ========================================

class AuthService extends AuthServiceAbstaction {
  private async hashPassword(password: string): Promise<string> {
    return password; // Replace with real hashing in production
  }

  private generateUserId(): string {
    return uuidv4();
  }

  protected async generateRefreshToken(user: Pick<TUserSchema, "id" | "email">): Promise<string> {
    return sign(
      { sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 },
      REFRESH_TOKEN_SECRET
    );
  }

  protected async generateAccessToken(user: Pick<TUserSchema, "id" | "email">): Promise<string> {
    return sign({ sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 15 * 60 }, JWT_SECRET);
  }

  async register(data: RegisterDto) {
    const existingUser = await userModel.findOne({ email: data.email });
    if (existingUser) throw new ApiError("User already exists", StatusCodes.CONFLICT);

    const hashedPassword = await this.hashPassword(data.password);
    const user: TUserPayload = {
      id: this.generateUserId(),
      email: data.email,
      password: hashedPassword,
    };

    const newUser = await userModel.create(user);

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);

    await userModel.updateOne({ id: user.id }, { refreshToken });

    return { user, accessToken, refreshToken };
  }

  async login(data: LoginDto) {
    const user = await userModel.findOne({ email: data.email });
    if (!user) throw new ApiError("Invalid credentials", 401);

    const hashedPassword = await this.hashPassword(data.password);
    if (user.password !== hashedPassword) throw new ApiError("Invalid credentials", 401);

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    await userModel.updateOne({ id: user.id }, { refreshToken });

    return { user, accessToken, refreshToken };
  }

  async logout(userId: string) {
    await userModel.updateOne({ id: userId }, { $unset: { refreshToken: "" } });
  }

  async refresh(c: { get: (arg0: string) => any }) {
    const user = c.get("user");
    const accessToken = await this.generateAccessToken({ id: user.sub, email: user.email });
    return { accessToken, user: { id: user.sub, email: user.email } };
  }
}

export { AuthService };
