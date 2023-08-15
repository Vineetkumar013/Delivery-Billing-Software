const express = require("express");
const {
  excelBill,
  getAllExcelBill,
  getExcelBillById,
  deleteExcelBillById,
  updateExcelBillById,
  assignBillToPicker
} = require("../../controllers/EXCEL CONTROLLER/ExcelCtrl");

const router = express.Router();

const multer = require("multer");
const { isAdmin, verifyToken } = require("../../middleware/authJwt");


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage });

router.post("/excel",isAdmin, upload.single('file'), excelBill);
router.get("/", /* isAdmin */ /* verifyToken, */ getAllExcelBill);
router.get("/bill/:id", /* isAdmin */ /* verifyToken, */ getExcelBillById);
router.delete("/bill/:id", deleteExcelBillById);
router.put("/bill/:id", updateExcelBillById);
router.put("/assign-bill/:id", isAdmin, assignBillToPicker);

module.exports = router;