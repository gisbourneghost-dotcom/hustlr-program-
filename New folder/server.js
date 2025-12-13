// server.js
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import multer from "multer";
import dotenv from "dotenv";
import { v2 as cloudinary } from "cloudinary";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { auth } from "./middleware/auth.js"; // Assuming this middleware exists

dotenv.config();

// --- Config
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "my-secret-admin-token";
const JWT_SECRET = process.env.JWT_SECRET || "default_jwt_secret";

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- Init
const app = express();
app.use(cors());
app.use(express.json({ limit: "12mb" }));

// multer (store file in RAM)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// --- MongoDB connection
try {
  await mongoose.connect(MONGO_URI);
  console.log("Connected to MongoDB");
} catch (err) {
  console.error("MongoDB connect error:", err);
  process.exit(1);
}

// --- Models
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: String,

  firstName: String,
  lastName: String,
  location: String,
  ownerphone: String,
  slug: { type: String, unique: true, sparse: true }, // ADDED: For dynamic store link
});

const User = mongoose.model("User", userSchema);

const productSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  productName: String,
  productDescription: String,
  productSize: String,
  productBrand: String,
  productPrice: String,
  imageUrl: String,
  ownerphone: String, // Kept for checkout fix
  createdAt: { type: Date, default: Date.now },
});

const Product = mongoose.model("Product", productSchema);

const orderSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
  productSnapshot: Object,
  Jinalamnunuzi: String,
  SimuNambayamnunuzi: String,
  DeliveryLocation: String, // ADDED: For checkout fix
  Message: String,
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", orderSchema);

// --- Helpers

// Helper to generate a URL-friendly slug
function generateSlug(firstName, lastName) {
    if (!firstName && !lastName) return null;
    let full = (firstName || "") + " " + (lastName || "");
    return full.toLowerCase().trim().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
}

function checkAdminHeader(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Upload buffer to Cloudinary using a data URI
async function uploadBufferToCloudinary(buffer, folder = "") {
  try {
    const b64 = buffer.toString("base64");
    const dataUri = `data:application/octet-stream;base64,${b64}`;
    const res = await cloudinary.uploader.upload(dataUri, { folder: folder || undefined });
    return res;
  } catch (err) {
    throw err;
  }
}

// --- ROUTES ---------------------

// Health
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------------- SIGNUP ----------------
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Fill all fields" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ success: false, error: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, message: "User registered", token, user: { _id: user._id, email: user.email } });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------------- SIGN IN ----------------
app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: "Email or password incorrect" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });

    // Return all user data (including slug) on login
    res.json({ success: true, message: "Login successful", token, user: user.toObject() });
  } catch (err) {
    console.error("Sign in error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});


// ---------------- PROFILE UPDATE (WITH SLUG GENERATION) ----------------
app.post("/api/profile", auth, async (req, res) => {
  try {
    const { firstName, lastName, location, ownerphone } = req.body;
    
    // Generate slug from first and last name
    const slug = generateSlug(firstName, lastName); 

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Optional: Check for slug conflict
    if (slug && (!user.slug || user.slug !== slug)) {
        const existingUserWithSlug = await User.findOne({ slug, _id: { $ne: user._id } });
        if (existingUserWithSlug) {
            return res.status(400).json({ success: false, error: "Store name is already taken. Please try a different name." });
        }
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { firstName, lastName, location, ownerphone, slug }, // Save the slug
      { new: true }
    );
    // Return the updated user object with the slug
    res.json({ success: true, message: "Profile updated", user: updatedUser.toObject() });
  } catch (err) {
      console.error("Profile update error:", err);
      res.status(500).json({ error: "Server error" });
  }
});

// ---------------- DYNAMIC PRODUCT LIST FOR STORE FRONT ----------------
app.get("/api/store/:slug/products", async (req, res) => {
  try {
    const { slug } = req.params;
    const owner = await User.findOne({ slug });

    if (!owner) {
      return res.status(404).json({ error: "Store not found" });
    }

    // Fetch products only belonging to this user
    const products = await Product.find({ ownerId: owner._id }).sort({ createdAt: -1 }).lean();
    
    // Return a store name for the product page header
    const storeName = `${owner.firstName || ''} ${owner.lastName || 'Store'}`.trim();
    
    res.json({ products, storeName });
  } catch (err) {
    console.error("Store products error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// ---------------- ADMIN PRODUCT LIST (PRIVATE) ----------------
app.get("/api/admin/products", auth, async (req, res) => {
  try {
    // Fetch products ONLY for the logged-in user (req.user.userId is set by auth middleware)
    const products = await Product.find({ ownerId: req.user.userId }).sort({ createdAt: -1 }).lean();
    res.json(products);
  } catch (err) {
    console.error("Admin products error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// ---------------- CREATE PRODUCT ----------------
app.post("/api/products", auth, upload.single("image"), async (req, res) => {
  try {
    // Find the user to get ownerphone and ID
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    // Check if the user has provided a phone number
    if (!user.ownerphone) {
        return res.status(400).json({ error: "Please update your profile with a WhatsApp number first." });
    }

    let imageUrl = req.body.imageUrl || null;
    if (req.file) {
      const cloudRes = await uploadBufferToCloudinary(
        req.file.buffer,
        "shopper_products"
      );
      imageUrl = cloudRes.secure_url;
    }

    const { productName, productDescription, productSize, productBrand, productPrice } = req.body;

    const product = new Product({
      ownerId: req.user.userId, // Use ID from authenticated user
      productName,
      productDescription,
      productSize,
      productBrand,
      productPrice,
      imageUrl,
      ownerphone: user.ownerphone, // FIXED: Add the owner's phone number from their profile
    });

    await product.save();
    res.status(201).json(product);
  } catch (err) {
    console.error("Product creation error:", err);
    res.status(400).json({ error: "Product creation failed" });
  }
});

// ---------------- CHECKOUT (ORDERS FIX) ----------------
app.post("/api/checkout", async (req, res) => {
  try {
    const { productId, Jinalamnunuzi, SimuNambayamnunuzi, DeliveryLocation, Message } = req.body;
    
    // Check for essential data
    if (!productId || !SimuNambayamnunuzi || !Jinalamnunuzi || !DeliveryLocation) {
      return res.status(400).json({ error: "Tafadhali jaza taarifa zote za mnunuzi." });
    }

    const product = await Product.findById(productId).lean();
    if (!product) return res.status(404).json({ error: "Bidhaa haipo haijapatikana" });

    const ownerphone = product.ownerphone || "";

    // Save order to MongoDB
    const order = await Order.create({
      productId,
      productSnapshot: product,
      Jinalamnunuzi,
      SimuNambayamnunuzi,
      DeliveryLocation, // FIXED: Saving DeliveryLocation to MongoDB
      Message,
    });

    if (!ownerphone) {
        // If the seller hasn't set their phone number, still save the order, but skip WhatsApp redirect
        return res.json({ success: true, order, whatsappUrl: null, message: "Oda imepokelewa. Muuzaji hana namba ya simu. " });
    }

    const digitsOnly = ownerphone.replace(/[^\\d]/g, "");

    // Construct detailed WhatsApp message for the seller
    const textParts = [
      `ODER MPYA (Order ID: ${order._id})`,
      `Bidhaa: ${product.productName}`,
      `Bei: ${product.productPrice} TZS`,
      `Jina la Mnunuzi: ${Jinalamnunuzi}`,
      `Simu ya Mnunuzi: ${SimuNambayamnunuzi}`,
      `Eneo la Kuletewa: ${DeliveryLocation}`, // FIXED: Added Delivery Location
      Message ? `Ujumbe: ${Message}` : "",
      `URL ya Picha: ${product.imageUrl || 'No image link'}`
    ].filter(Boolean);

    const text = encodeURIComponent(textParts.join("\n")); // Use newline for clarity in WhatsApp
    const whatsappUrl = `https://wa.me/${digitsOnly}?text=${text}`; // FIXED: Correct phone number logic

    res.json({ success: true, order, whatsappUrl });
  } catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// Catch-all route for other product methods (PUT, DELETE) - assuming existing logic works
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});