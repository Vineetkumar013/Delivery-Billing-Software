const express = require("express");
const router = express.Router();
const { authJwt } = require("../middleware");
const {
    updateBillingVerifier,
    getAllBillOfVerifier,
    assignBillToPacker,
    Verifysignup,
    Verifylogin,
} = require("../controllers/verifyBill.controller");

// // Get all verifier-bills
router.get("/verifier-bills", getAllBillOfVerifier);
router.post("/signup", Verifysignup);
router.post("/login", Verifylogin);

// // Get product by ID
// router.get("/verifier-bills/:id", getVerifierBill);

// // Create a new product
// router.post("/verifier-bills", [authJwt.isAdmin], createVerifierBill);

// // Update a product by ID
router.put("/verifier-bills/:id", updateBillingVerifier);
router.put("/assign-bill/packer/:id", assignBillToPacker);

// // Delete a product by ID
// router.delete("/verifier-bills/:id", deleteVerifierBill);

// //most selling verifier-bills
// router.put("/verifier-bills/assign-bill/:id", assignBillToPacker);

module.exports = router;
