// auth.js
import jwt from "jsonwebtoken";
import User from "../models/User.js"; // adjust path to your User model

export const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token provided" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // decoded should at least contain userId
    if (!decoded?.userId) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    // Always fetch the latest user to get up-to-date slug/phone
    const user = await User.findById(decoded.userId).lean();
    if (!user) return res.status(401).json({ error: "User not found" });

    req.user = {
      id: user._id.toString(),
      ownerSlug: user.slug,        // created on profile page
      ownerphone: user.ownerphone,      // WhatsApp number from profile page
      email: user.email,
      name: `${user.firstName || ""} ${user.lastName || ""}`.trim(),
    };

    next();
  } catch (err) {
    console.error("AUTH ERROR:", err);
    res.status(401).json({ error: "Invalid token" });
  }
};
