// server.js
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import multer from "multer";
import dotenv from "dotenv";
import { v2 as cloudinary } from "cloudinary";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { auth } from "./middleware/auth.js";
import User from "./models/User.js";

dotenv.config();

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

/* ================= APP INIT ================= */
const app = express();
app.use(cors());
app.use(express.json({ limit: "12mb" }));

/* ================= CLOUDINARY ================= */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/* ================= MULTER ================= */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* ================= DB ================= */
await mongoose.connect(MONGO_URI);
console.log("MongoDB connected");

/* ================= MODELS ================= */

// USER
//const userSchema = new mongoose.Schema({
//email: { type: String, unique: true },
// password: String,

//  firstName: String,
//  lastName: String,
//  ownerSlug: { type: String, unique: true, sparse: true},
//  ownerphone: String,
//  location: String,
//});

//const User = mongoose.model("User", userSchema);

// PRODUCT
const productSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  ownerSlug: String,
  ownerphone: String,

  productName: String,
  productDescription: String,
  productSize: String,
  productBrand: String,
  productPrice: String,
  imageUrl: String,

  createdAt: { type: Date, default: Date.now },
});

const Product = mongoose.model("Product", productSchema);

// ORDER
const orderSchema = new mongoose.Schema({
  productId: mongoose.Schema.Types.ObjectId,
  ownerId: mongoose.Schema.Types.ObjectId,
  ownerphone: String,
  productSnapshot: Object,

  Jinalamnunuzi: String,
  SimuNambayamnunuzi: String,
  DeliveryLocation: String,
  Message: String,

  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", orderSchema);

/* ================= HELPERS ================= */

function slugify(text) {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function uploadToCloudinary(buffer) {
  const b64 = buffer.toString("base64");
  const dataUri = `data:image/jpeg;base64,${b64}`;
  const res = await cloudinary.uploader.upload(dataUri, {
    folder: "products",
  });
  return res.secure_url;
}

/* ================= AUTH ================= */

// SIGNUP
app.post("/api/signup",auth,  async (req, res) => {
  
   try {
  const { email, password} = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const exists = await User.findOne({ email });
  if (exists) return res.status(404).json({ error: "Email exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ email, password: hashed });
  await user.save();

  const token = jwt.sign({ userId: user._id }, JWT_SECRET);
  
  return res.json({
      success: true,
      message: "Account created",
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ success: false, error: "Server Error" });
  }
});

// SIGNIN
app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Fill all fields" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: "Email or password incorrect" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ success: false, error: "Email or password incorrect" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.json({
      success: true,
      message: "Logged in",
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    console.error("Signin error:", err);
    res.status(500).json({ success: false, error: "Server Error" });
  }
});


/* ================= PROFILE ================= */

// CREATE / UPDATE PROFILE + SLUG
app.post("/api/profile", auth, async (req, res) => {
  try {
    // Validate req.user
    if (!req.user || !req.user._id) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const userId = req.user._id;
    const { firstName, lastName, ownerphone, location } = req.body;

    // Validate required fields
    if (!firstName || !lastName || !ownerphone) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    // Validate input types
    if (typeof firstName !== "string" || typeof lastName !== "string" || typeof ownerphone !== "string") {
      return res.status(400).json({ success: false, message: "Invalid input types" });
    }

    // Generate slug safely
    const ownerSlug = slugify(`${firstName}-${lastName}`, { lower: true, strict: true });

    // Check for duplicate slug
    const exists = await User.findOne({ ownerSlug });
    if (exists && exists._id.toString() !== userId.toString()) {
      return res.status(400).json({ success: false, message: "Slug already taken" });
    }

    // Update user and persist slug
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { firstName, lastName, ownerphone, location, ownerSlug },
      { new: true }
    );

    // Handle null user case
    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      ownerSlug,
      message: "Profile updated successfully",
      user: updatedUser
    });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


/* ================= PRODUCTS ================= */

// CREATE PRODUCT (max 5 per owner)
app.post("/api/products", auth, upload.single("image"), async (req, res) => {
  try {
    const count = await Product.countDocuments({ ownerId: req.user.id });
    if (count >= 5) return res.status(403).json({ error: "Product limit reached" });

    let imageUrl = req.body.imageUrl || null;
    if (req.file) {
      const cloudRes = await uploadBufferToCloudinary(req.file.buffer, "shopper_products");
      imageUrl = cloudRes.secure_url;
    }

    const product = await Product.create({
      ownerId: req.user.id,
      ownerSlug: req.user.slug,   // from profile
      ownerPhone: req.user.ownerphone, // from profile
      productName: req.body.productName,
      productDescription: req.body.productDescription,
      productSize: req.body.productSize,
      productBrand: req.body.productBrand,
      productPrice: req.body.productPrice,
      imageUrl,
    });

    res.json(product);
  } catch (err) {
    res.status(500).json({ error: "Create failed", details: String(err) });
  }
});

// PUBLIC: GET ALL PRODUCTS FOR AN OWNER BY SLUG
app.get("/api/:slug/products", async (req, res) => {
  try {
    const products = await Product.find({ ownerSlug: req.params.slug }).sort({ _id: -1 });
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ADMIN: GET SINGLE PRODUCT (ensure belongs to owner)
app.get("/api/:slug/products/:id", auth, async (req, res) => {
  try {
    if (req.params.slug !== req.user.slug) {
      return res.status(403).json({ error: "Forbidden" });
    }
    const p = await Product.findOne({
      _id: req.params.id,
      ownerId: req.user.id,
      ownerSlug: req.user.slug,
    });
    if (!p) return res.status(404).json({ error: "Not found" });
    res.json(p);
  } catch (err) {
    res.status(500).json({ error: "Fetch failed", details: String(err) });
  }
});

// UPDATE PRODUCT (owner-only)
app.put("/api/:slug/products/:id", auth, upload.single("image"), async (req, res) => {
  try {
    if (req.params.slug !== req.user.slug) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const updates = {
      productName: req.body.productName,
      productDescription: req.body.productDescription,
      productSize: req.body.productSize,
      productBrand: req.body.productBrand,
      productPrice: req.body.productPrice,
    };

    if (req.file) {
      const cloudRes = await uploadBufferToCloudinary(req.file.buffer, "shopper_products");
      updates.imageUrl = cloudRes.secure_url;
    } else if (req.body.imageUrl) {
      updates.imageUrl = req.body.imageUrl;
    }

    const p = await Product.findOneAndUpdate(
      { _id: req.params.id, ownerId: req.user.id, ownerSlug: req.user.slug },
      updates,
      { new: true }
    );
    if (!p) return res.status(404).json({ error: "Not found" });
    res.json(p);
  } catch (err) {
    res.status(500).json({ error: "Update failed", details: String(err) });
  }
});

// DELETE PRODUCT (owner-only)
app.delete("/api/:slug/products/:id", auth, async (req, res) => {
  try {
    if (req.params.slug !== req.user.slug) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const p = await Product.findOneAndDelete({
      _id: req.params.id,
      ownerId: req.user.id,
      ownerSlug: req.user.slug,
    });

    if (!p) return res.status(404).json({ error: "Not found" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Delete failed", details: String(err) });
  }
});


/* ================= CHECKOUT ================= */

app.post("/api/checkout", async (req, res) => {

	try {
  const { productId, Jinalamnunuzi, SimuNambayamnunuzi, DeliveryLocation, Message } = req.body;

  const product = await Product.findById(productId);
  if (!product) return res.status(404).json({ error: "Product not found" });

  const ownerphone = product.productownerphone || "";

  const order = await Order.create({
    productId,
    ownerId: product.ownerId,
    ownerphone,
    productSnapshot: product,
    Jinalamnunuzi,
    SimuNambayamnunuzi,
    DeliveryLocation,
    Message,
  });

    if (!ownerphone) {
     return res.json({ success: true, order, whatsappUrl: null });
     }

  const digits = ownerphone.replace(/[^\d]/g, "");
  const textpart = [
    `Order: ${product.productName}`,
    ` Price: ${product.productPrice} TZS`,
    ` Buyer: ${Jinalamnunuzi}`,
    `Phone: ${SimuNambayamnunuzi}`,
     `Message: ${Message}`,
  ].filter(Boolean);

  res.json({
    success: true,
    whatsappUrl: `https://wa.me/${digits}?text=${text}`,
    order, });

   const text = encodeURIComponent(textpart.join(" • "));

	} catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({ success: false, error: "Failed kuweka order jaribu tena" });
  }
});

/* ================= START ================= */

app.listen(PORT, () =>
  console.log(`Server running → http://localhost:${PORT}`)
);
