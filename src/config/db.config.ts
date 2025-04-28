import mongoose from "mongoose";
import { DB_NAME, MONGODB_LOCAL_URL } from "@/constants/env";
import { logger } from "@/libs/logger";

const dbConnect = async (): Promise<typeof mongoose> => {
  const db_uri = `${MONGODB_LOCAL_URL}/${DB_NAME}`;

  mongoose.set("strictQuery", true);

  const connection = await mongoose.connect(db_uri);
  logger.info({
    message: "MongoDB connected successfully",
    db_uri,
  });

  return connection;
};

export default dbConnect;
