const express = require("express");
const router = express.Router();
const {
    createBillItem,
    getBillItem,
    getAllBillItems,
    updateBillItem,
    deleteBillItem,
} = require("../controllers/billItem.controller");
const { validate } = require("../middleware");
const { verifyToken } = require("../middleware/authJwt");
// CREATE - POST /billitems
router.post("/billitems", [validate.billItemBodies], verifyToken, createBillItem);

// READ - GET /billitems/:id
router.get("/billitems/:id", getBillItem);
router.get("/billitems", getAllBillItems);
// UPDATE - PUT /billitems/:id
router.put("/billitems/:id", updateBillItem);

// DELETE - DELETE /billitems/:id
router.delete("/billitems/:id", deleteBillItem);

module.exports = router;
