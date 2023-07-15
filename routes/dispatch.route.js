const express = require("express");
const router = express.Router();
const {
    dispatchlogin,
    updateBillingDispatch,
    getAllBillOfDispatch,
    assignBillToDispatch,
    dispatchsignup,
} = require("../controllers/dispatch.controller");
const { authJwt } = require("../middleware");

router.get("/dispatch-bills", getAllBillOfDispatch);
router.post("/login", dispatchlogin);
router.post("/signup", dispatchsignup);
router.put("/assign-bill/dispatch/:id", assignBillToDispatch);
router.put("/dispatch-bills/:id", updateBillingDispatch);

module.exports = router;
