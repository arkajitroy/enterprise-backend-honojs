import mongoose, { InferSchemaType, Schema } from "mongoose";

const userSchema = new Schema({
  id: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  refreshToken: { type: String },
  created_at: { type: Date, default: Date.now },
});

const userModel = mongoose.model("users", userSchema);

export type TUserSchema = InferSchemaType<typeof userSchema>;

export default userModel;
