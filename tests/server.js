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
  ownerphone: String,
  createdAt: { type: Date, default: Date.now },
});

const Product = mongoose.model("Product", productSchema);

const orderSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
  productSnapshot: Object,
  buyerName: String,
  buyerPhone: String,
  message: String,
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", orderSchema);

// --- Helpers
function checkAdminHeader(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Upload buffer to Cloudinary using a data URI (avoids needing streamifier)
async function uploadBufferToCloudinary(buffer, folder = "") {
  try {
    const b64 = buffer.toString("base64");
    // use generic mime type; Cloudinary will detect, but you can refine if you know the file type
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

// List products
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 }).lean();
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Single product
app.get("/api/products/:id", async (req, res) => {
  try {
    const p = await Product.findById(req.params.id);
    if (!p) return res.status(404).json({ error: "Not found" });
    res.json(p);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Invalid id" });
  }
});

// ---------------- SIGNUP ----------------
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, ConfirmPassword } = req.body;

    // Minimal validation
    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Fill all fields" });
    }

    // Optional: confirm password check (frontend already checks)
    if (ConfirmPassword !== undefined && password !== ConfirmPassword) {
      return res.status(400).json({ success: false, error: "Passwords do not match" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ success: false, error: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();

    //Create token here
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.json({
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

// ---------------- SIGNIN ----------------
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

//------CREATE PROFILE----------
app.post("/api/profile", auth, async (req, res) => {
  try {
    const userId = req.user._id; // From JWT

    const { firstName, lastName, ownerphone, location } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        firstName: firstName,
        lastName: lastName,
        ownerphone: ownerphone,
        location: location
      },
      { new: true }
    );

    res.json({
      success: true,
      message: "Profile updated",
      user: updatedUser
    });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- GET ALL PRODUCTS ----------
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 }).lean();
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


// ---------- CREATE PRODUCT ----------
app.post("/api/products", checkAdminHeader, upload.single("image"), async (req, res) => {
    try {
        let imageUrl = req.body.imageUrl || null;

        if (req.file) {
            const cloudRes = await uploadBufferToCloudinary(
                req.file.buffer,
                "shopper_products"
            );
            imageUrl = cloudRes.secure_url;
        }

        const product = await Product.create({
            productName: req.body.productName,
            productDescription: req.body.productDescription,
            productSize: req.body.productSize,
            productBrand: req.body.productBrand,
            productPrice: req.body.productPrice,
            imageUrl
        });

        res.status(201).json(product);
    } catch (err) {
        res.status(500).json({ error: "Create failed", details: String(err) });
    }
});

// ---------- UPDATE PRODUCT ----------
app.put("/api/products/:id", checkAdminHeader, upload.single("image"), async (req, res) => {
    try {
        let updates = {
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

        const p = await Product.findByIdAndUpdate(req.params.id, updates, { new: true });
        if (!p) return res.status(404).json({ error: "Not found" });

        res.json(p);
    } catch {
        res.status(500).json({ error: "Update failed" });
    }
});

// ---------- DELETE PRODUCT ----------
app.delete("/api/products/:id", checkAdminHeader, async (req, res) => {
    try {
        const p = await Product.findByIdAndDelete(req.params.id);
        if (!p) return res.status(404).json({ error: "Not found" });
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: "Delete failed" });
    }
});




// -------- CHECKOUT --------
app.post("/api/checkout", async (req, res) => {
  try {
    const { productId, buyerName, buyerPhone, message } = req.body;
    if (!productId || !buyerPhone) return res.status(400).json({ error: "Missing productId or buyerPhone" });

    const product = await Product.findById(productId).lean();
    if (!product) return res.status(404).json({ error: "Product not found" });

    const ownerNumber = product.ownerphone || "";

    const order = await Order.create({
      productId,
      productSnapshot: product,
      buyerName,
      buyerPhone,
      message,
    });

    if (!ownerNumber) return res.json({ ok: true, order, whatsappUrl: null });

    const digitsOnly = ownerNumber.replace(/[^\d]/g, "");

    const textParts = [
      `Hello, I'm interested in your product: ${product.name}`,
      `Price: ${product.price} TZS`,
      buyerName ? `Buyer: ${buyerName}` : "",
      buyerPhone ? `Contact: ${buyerPhone}` : "",
      message ? `Message: ${message}` : "",
    ].filter(Boolean);

    const text = encodeURIComponent(textParts.join(" • "));
    const whatsappUrl = `https://wa.me/${digitsOnly}?text=${text}`;

    res.json({ ok: true, order, whatsappUrl });
  } catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({ error: "Checkout failed" });
  }
});

// --- Start
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));

