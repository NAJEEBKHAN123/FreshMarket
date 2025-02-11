const User = require("../models/userModel");
const bcrypt = require("bcrypt");

// 1️⃣ Create Admin (Superadmin only)
const createAdmin = async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (req.user.role !== "superadmin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only superadmins can create admins",
      });
    }

    if (await User.findOne({ email })) {
      return res.status(400).json({ success: false, message: "Admin already exists" });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const admin = new User({
      username,
      email,
      password: hashPassword,
      role: "admin",
      createdBy: req.user._id,
    });

    await admin.save();
    res.status(201).json({
      success: true,
      message: "Admin created successfully",
      data: admin,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 2️⃣ Create User (Admin only)
const createUser = async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only admins can create users",
      });
    }

    const existingUser = await User.findOne({ email, createdBy: req.user._id });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists under this admin",
      });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashPassword,
      role: "user",
      createdBy: req.user._id,
    });

    await user.save();
    res.status(201).json({
      success: true,
      message: "User created successfully",
      data: user,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 3️⃣ Get Users Created by Logged-in Admin
const getMyUsers = async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only admins can view their users",
      });
    }

    const users = await User.find({ createdBy: req.user._id }).select("-password");
    res.status(200).json({
      success: true,
      message: "Users fetched successfully",
      data: users,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 4️⃣ Get All Users (Superadmin & Admin)
const getUsers = async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  try {
    const query = req.user.role === "superadmin" ? {} : { createdBy: req.user._id };
    const users = await User.find(query)
      .select("-password")
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
    const totalUsers = await User.countDocuments(query);

    res.status(200).json({
      success: true,
      message: "Users fetched successfully",
      totalPages: Math.ceil(totalUsers / limit),
      currentPage: page,
      data: users,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 5️⃣ Get All Admins (Superadmin only)
const getAdmins = async (req, res) => {
  try {
    if (req.user.role !== "superadmin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only superadmins can view admins",
      });
    }

    const admins = await User.find({ role: "admin" }).select("-password");

    res.status(200).json({
      success: true,
      message: "Admins fetched successfully",
      data: admins,
    });
  } catch (error) {
    console.error("Error fetching admins:", error);
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 6️⃣ Update Admin (Superadmin only)
const updateAdmin = async (req, res) => {
  const { id } = req.params;
  const { username, email, password } = req.body;
  try {
    if (req.user.role !== "superadmin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only superadmins can update admins",
      });
    }

    const admin = await User.findOneAndUpdate(
      { _id: id, role: "admin" },
      {
        username,
        email,
        ...(password && { password: await bcrypt.hash(password, 10) }),
      },
      { new: true }
    );

    if (!admin)
      return res.status(404).json({ success: false, message: "Admin not found" });

    res.status(200).json({
      success: true,
      message: "Admin updated successfully",
      data: admin,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 7️⃣ Update User (Admin only) - Fixed Function
const update_user = async (req, res) => {
  const { id } = req.params;
  const { username, email, password } = req.body;
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only admins can update users",
      });
    }

    const updatedUser = await User.findOneAndUpdate(
      { _id: id, role: "user" },
      {
        username,
        email,
        ...(password && { password: await bcrypt.hash(password, 10) }),
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      message: "User updated successfully",
      data: updatedUser,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// 8️⃣ Delete Admin (Superadmin only)
const deleteAdmin = async (req, res) => {
  try {
    if (req.user.role !== "superadmin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Only superadmins can delete admins",
      });
    }

    const admin = await User.findOneAndDelete({ _id: req.params.id, role: "admin" });
    if (!admin)
      return res.status(404).json({ success: false, message: "Admin not found" });

    res.status(200).json({ success: true, message: "Admin deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
};

// Export controllers
module.exports = {
  createAdmin,
  createUser,
  getMyUsers,
  getUsers,
  updateAdmin,
  deleteAdmin,
  getAdmins,
  update_user,
};
