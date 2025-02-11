const express = require("express");
const {
  createAdmin,
  createUser,
  getMyUsers,
  getUsers,
  updateAdmin,
  deleteAdmin,
  getAdmins,
  update_user,
} = require("../Controller/userController");
const { protect, checkRole, restrictAdminUpdate } = require("../middleware/authMiddleware");
const validateUser = require("../middleware/validateUser");
const { login } = require("../Controller/login");

const router = express.Router();

// Authentication
router.post("/add-user", protect, checkRole(["admin"]), validateUser, createUser);
router.post("/add-admin", protect, checkRole(["superadmin"]), validateUser, createAdmin);
router.post("/login", login);

// Superadmin Routes
router.put("/update-admin/:id", protect, checkRole(["superadmin"]), updateAdmin);
router.delete("/delete-admin/:id", protect, checkRole(["superadmin"]), deleteAdmin);
router.get("/getAdmins", protect, checkRole(["superadmin"]), getAdmins);

// Admin Routes
router.get("/my-users", protect, checkRole(["admin"]), getMyUsers);
router.get("/getUsers", protect, checkRole(["admin", "superadmin"]), getUsers);
router.put("/update-user/:id", protect, checkRole(["admin"]), restrictAdminUpdate, update_user);

module.exports = router;
