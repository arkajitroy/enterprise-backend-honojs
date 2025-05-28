import userModel, { TUserSchema } from "@/app/model/users";
import {
  AuthResponse,
  LoginDto,
  LogoutDto,
  OAuthGoogleDto,
  RegisterDto,
  TUserPayload,
} from "./auth.dto";
import { v4 as uuidv4 } from "uuid";
import { JWT_SECRET, REFRESH_TOKEN_SECRET } from "@/constants/env";
import { sign } from "hono/jwt";
import { ApiError } from "@/libs/utils";
import { StatusCodes } from "http-status-codes";
import { hash, compare } from "bcryptjs";
import { AUTH_PROVIDER, AUTH_ROLES } from "@/constants/auth";

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
  private generateUserId(): string {
    return uuidv4();
  }

  private async encryptPassword(password: string): Promise<string> {
    const hashedPassword = await hash(password, 10);
    return hashedPassword;
  }

  private async comparePassword(password: string, hashedPassword: string): Promise<boolean> {
    return compare(password, hashedPassword);
  }

  protected async generateRefreshToken(user: Pick<TUserSchema, "id" | "email">): Promise<string> {
    return sign(
      { sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 },
      REFRESH_TOKEN_SECRET
    );
  }

  protected async generateAccessToken(user: Pick<TUserSchema, "id" | "email">): Promise<string> {
    return sign(
      { sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 15 * 60 },
      JWT_SECRET
    );
  }

  // ================================== AUTH METHODS ==================================

  async register(data: RegisterDto) {
    const existingUser = await userModel.findOne({ email: data.email });
    if (existingUser) throw new ApiError("User already exists", StatusCodes.CONFLICT);

    const hashedPassword = await this.encryptPassword(data.password);
    const user: TUserPayload = {
      id: this.generateUserId(),
      email: data.email,
      password: hashedPassword,
      role: data.role || "USER",
      provider: "credentials",
    };

    await userModel.create(user);

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);

    await userModel.updateOne({ id: user.id }, { refreshToken });

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        provider: user.provider,
      },
      accessToken,
      refreshToken,
    };
  }

  async login(data: LoginDto) {
    const user = await userModel.findOne({ email: data.email });
    if (!user || !user.password)
      throw new ApiError("Invalid credentials", StatusCodes.UNAUTHORIZED);

    const isMatch = await this.comparePassword(data.password, user.password);
    if (!isMatch) throw new ApiError("Invalid credentials", StatusCodes.UNAUTHORIZED);

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    await userModel.updateOne({ id: user.id }, { refreshToken });

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        provider: user.provider,
      },
      accessToken,
      refreshToken,
    };
  }

  async loginWithGoogle(data: OAuthGoogleDto) {
    let user = await userModel.findOne({ email: data.email, provider: AUTH_PROVIDER.GOOGLE });

    if (!user) {
      const userId = this.generateUserId();
      user = await userModel.create({
        id: userId,
        email: data.email,
        password: null,
        provider: AUTH_PROVIDER.GOOGLE,
        role: AUTH_ROLES.USER,
      });
    }

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);

    await userModel.updateOne({ id: user.id }, { refreshToken });

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        provider: user.provider,
      },
      accessToken,
      refreshToken,
    };
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

export default AuthService;
