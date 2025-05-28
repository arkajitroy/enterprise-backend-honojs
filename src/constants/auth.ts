export const AUTH_PROVIDER = {
  CREDENTIALS: "credentials",
  GOOGLE: "google",
};

export const AUTH_ROLES = {
  USER: "user",
  ADMIN: "admin",
};

export const ALLOWED_USER_ROLES = [...Object.values(AUTH_ROLES)];
export const ALLOWED_AUTH_PROVIDERS = [...Object.values(AUTH_PROVIDER)];
