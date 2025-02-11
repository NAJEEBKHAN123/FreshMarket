const validateUser = require('../middleware/validateUser')

router.post("/add-user", protect, checkRole(["admin"]), validateUser, create_user);
router.post("/add-admin", protect, checkRole(["superadmin"]), validateUser, create_admin);
