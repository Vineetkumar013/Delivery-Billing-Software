const express = require("express");
const router = express.Router();
const { authJwt } = require("../middleware");

// Import controllers
const {
    getOrderById,
    createOrder,
    updateOrderToPaid,
    updateOrderToDelivered,
    getOrderSummary,
    getOrders,
    deleteOrder,
    TodayOrder,
    OrderStatus,
    deliveryDetails,
    verifyDeliveryOtp,
    SubmitOrder,
    // deliveryDetailsVerifyOTP
} = require("../controllers/order.controller");

const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
cloudinary.config({ cloud_name: "dbrvq9uxa", api_key: "567113285751718", api_secret: "rjTsz9ksqzlDtsrlOPcTs_-QtW4", });
const storage = new CloudinaryStorage({
        cloudinary: cloudinary, params: { folder: "images/image", allowed_formats: ["jpg", "jpeg", "png", "PNG", "xlsx", "xls", "pdf", "PDF"], },
});
const upload = multer({ storage: storage });

var imageUpload = upload.fields([{ name: "image",maxCount: 1 }]);
router.post("/orders/:orderId", imageUpload, SubmitOrder);


// Routes for handling orders
router.get("/orders/:id", getOrderById);
router.get("/orders-summary", getOrderSummary);
router.get("/orders", getOrders);
router.post("/orders", createOrder);
router.put("/orders/:id", updateOrderToPaid);
router.put("/orders/:id/deliver", updateOrderToDelivered);
router.delete("/orders/", deleteOrder);
router.get("/orders/today", TodayOrder);
router.get("/orders/:orderId/status", OrderStatus)
router.get("/orders/user/:id", deliveryDetails)
router.post("/orders/verify-otp/:orderId", verifyDeliveryOtp)
// router.post("/orders/verify/:orderId",deliveryDetailsVerifyOTP)


module.exports = router;
