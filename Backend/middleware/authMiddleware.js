const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

// Verify Token Middleware
const protect = async (req, res, next) => {
  let token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Access Denied: No Token Provided" });

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-password");

    if (!req.user) {
      return res.status(401).json({ message: "User not found" });
    }
    
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid Token" });
  }
};

// Role-based Access Control with Admin Protection
const checkRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: "Access Denied: Insufficient Permissions" });
  }
  next();
};

// Prevent Admin from Updating Another Admin
const restrictAdminUpdate = async (req, res, next) => {
  try {
    const userToUpdate = await User.findById(req.params.id);

    if (!userToUpdate) {
      return res.status(404).json({ message: "User not found" });
    }

    // If the user being updated is an admin & the requester is also an admin (not super-admin), deny access
    if (userToUpdate.role === "admin" && req.user.role === "admin" && req.user._id.toString() !== userToUpdate._id.toString()) {
      return res.status(403).json({ message: "Access Denied: Admins cannot update other admins" });
    }

    next();
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
};

module.exports = { protect, checkRole, restrictAdminUpdate };
