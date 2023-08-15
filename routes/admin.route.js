const express = require("express");
const router = express.Router();
const userController = require("../controllers/admin.controller");
const { authJwt, validate } = require("../middleware");

// Define routes for the user APIs
router.post("/admin/signup",/* [validate.signUp], */ userController.AdminSignup);
router.post("/login", userController.Adminlogin);
router.get("/", userController.getAdmins);
router.put("/:id", [validate.updateUser], userController.updateAdmins);
router.get("/:id", userController.getAdmin);
router.delete("/:id", userController.deleteAdmins);

module.exports = router;
