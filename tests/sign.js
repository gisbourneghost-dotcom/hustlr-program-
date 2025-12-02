import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// ----------------- MONGO CONNECTION -----------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log("DB ERROR:", err));


// ----------------- USER MODEL -----------------
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  Userpassword: { type: String, required: true }
});

const User = mongoose.model("User", UserSchema);


// =====================================================
// --------------   S I G N   U P    -------------------
// =====================================================

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, ConfirmPassword } = req.body;

    if (!email || !password || !ConfirmPassword) {
      return res.status(400).json({ success: false, error: "Fill all fields" });
    }

    if (password !== ConfirmPassword) {
      return res.status(400).json({ success: false, error: "Passwords do not match" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ success: false, error: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({ email, password: hashed });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "12h"
    });

    res.json({
      success: true,
      message: "Account created",
      token,
      userId: user._id
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({ success: false, error: "Server Error" });
  }
});


// =====================================================
// ---------------  S I G N   I N  ---------------------
// =====================================================

app.post("/api/signin", async (req, res) => {
  try {
    const { email, Userpassword } = req.body;

    if (!email || !Userpassword) {
      return res.status(400).json({ success: false, error: "Fill all fields" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, error: "Email not found" });
    }

    const match = await bcrypt.compare(Userpassword, user.Userpassword);
    if (!match) {
      return res.status(400).json({ success: false, error: "Incorrect password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "12h"
    });

    res.json({
      success: true,
      message: "Logged in",
      token,
      user
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({ success: false, error: "Server Error" });
  }
});


// ----------------- START SERVER -----------------
app.listen(process.env.PORT || 4000, () => {
  console.log("Server running...");
});
