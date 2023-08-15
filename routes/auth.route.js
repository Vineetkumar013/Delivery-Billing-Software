const express = require("express");
const router = express.Router();
const userController = require("../controllers/auth.controller");
const { validate } = require("../middleware");
const { verifyToken } = require("../middleware/authJwt");

// Define routes for the user APIs
router.post("/user/signup",[validate.signUp], userController.UserSignup);
// router.post("/login-with-email", userController.login);
router.post("/login", [validate.updateUser], userController.Userlogin);
router.post("/resend-otp/:id", /* verfiyToken, */ userController.resendOtp); 
router.post("/verify-otp/:id", userController.verifyOtp);
router.post("/forget/verify/:id", userController.forgotPasswordOtp);
router.post("/forget", userController.forgotPassword);
router.post("/reset/:id", userController.resetPassword);
router.get("/getuserbyrole", userController.getUsersByRole);
module.exports = router;
