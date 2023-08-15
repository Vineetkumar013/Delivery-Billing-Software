const express = require("express");
const {
  Deliverysignup,
  provideDeliveryReason,
  deliverOrder,
  AssignToDelivery
} = require("../controllers/deliveryCtrl");
const router = express.Router();



router.post("/signup", Deliverysignup);
router.post("/reason/:id", provideDeliveryReason);
router.put("/orders/:id", deliverOrder);
router.post('/orders/:orderId/assign', AssignToDelivery)

module.exports = router;