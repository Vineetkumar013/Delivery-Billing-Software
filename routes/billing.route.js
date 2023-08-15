const express = require("express");
const router = express.Router();
const billingController = require("../controllers/billingController");
const { validate } = require("../middleware");

// const multer = require("multer");
const { isAdmin, verifyToken,/* authMiddleware  */} = require("../middleware/authJwt");


// const storage = multer.diskStorage({
//     destination: (req, file, cb) => {
//         cb(null, 'uploads/');
//     },
//     filename: (req, file, cb) => {
//         cb(null, file.originalname);
//     }
// });

// const upload = multer({ storage });

// GET /api/billings
router.get("/", /* isAdmin, */verifyToken, billingController.getAllBillings);


// POST /api/billings
router.post("/", [validate.billing], /* isAdmin, */ verifyToken, billingController.createBilling);

// GET /api/billings/:id
router.get("/:id", billingController.getBillingById);

// PUT /api/billings/:id
router.put("/:id", isAdmin,billingController.updateBilling);
router.put("/assign-bill/:id", isAdmin, billingController.assignBillToPicker);
// DELETE /api/billings/:id
router.delete("/:id", /* isAdmin, *//* verifyToken, */ billingController.deleteBilling);
router.get("/billing/:id/picker", verifyToken, billingController.getPickerByBilling);

module.exports = router;
