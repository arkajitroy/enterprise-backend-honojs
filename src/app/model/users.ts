import mongoose, { InferSchemaType, Schema } from "mongoose";

const userSchema = new Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  firstname: { type: String, required: true, unique: false },
  lastname: { type: String, required: true, unique: false },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  refreshToken: { type: String },
  role: { type: String, enum: ["USER", "ADMIN"], default: "USER" },
  created_at: { type: Date, default: Date.now },
});

const userModel = mongoose.model("users", userSchema);

export type TUserSchema = InferSchemaType<typeof userSchema>;

export default userModel;
