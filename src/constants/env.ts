import { getEnvironmentVariable } from "@/libs/env";

const env = {
  NODE_ENV: getEnvironmentVariable("NODE_ENV"),
  PORT: getEnvironmentVariable("PORT"),
  HOST: getEnvironmentVariable("HOST"),
  CLIENT_URL: getEnvironmentVariable("CLIENT_URL"),
  API_VERSION: getEnvironmentVariable("API_VERSION"),
  API_PREFIX: getEnvironmentVariable("API_PREFIX"),
  JWT_SECRET: getEnvironmentVariable("JWT_SECRET"),
  REFRESH_TOKEN_SECRET: getEnvironmentVariable("REFRESH_TOKEN_SECRET"),
  MONGODB_LOCAL_URL: getEnvironmentVariable("MONGODB_LOCAL_URL"),
  DB_NAME: getEnvironmentVariable("MONGODB_DB_NAME"),
  LOGS_PATH: "/logs",
};

export const {
  NODE_ENV,
  PORT,
  HOST,
  CLIENT_URL,
  API_VERSION,
  API_PREFIX,
  JWT_SECRET,
  REFRESH_TOKEN_SECRET,
  MONGODB_LOCAL_URL,
  DB_NAME,
  LOGS_PATH,
} = env;
