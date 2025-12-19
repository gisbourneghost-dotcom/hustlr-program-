// USER
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,

  firstName: String,
  lastName: String,
  ownerSlug: { type: String, unique: true, sparse: true},
  ownerphone: String,
  location: String,
});

const User = mongoose.model("User", userSchema);
export default User;