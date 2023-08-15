const express = require("express");
const router = express.Router();
// const upload = require("../uploads");
const {
    getVehicles,
    createVehicle,
    updateVehicle,
    deleteVehicle,
} = require("../controllers/vehicle");
const { authJwt } = require("../middleware");

// const multer = require("multer");
// const { CloudinaryStorage } = require("multer-storage-cloudinary");
// const cloudinary = require("cloudinary").v2;
// cloudinary.config({ cloud_name: "dbrvq9uxa", api_key: "567113285751718", api_secret: "rjTsz9ksqzlDtsrlOPcTs_-QtW4", });
// const storage = new CloudinaryStorage({
//         cloudinary: cloudinary, params: { folder: "images/image", allowed_formats: ["jpg", "jpeg", "png", "PNG", "xlsx", "xls", "pdf", "PDF"], },
// });
// const upload = multer({ storage: storage });


const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
cloudinary.config({ cloud_name: "dbrvq9uxa", api_key: "567113285751718", api_secret: "rjTsz9ksqzlDtsrlOPcTs_-QtW4", });
const storage = new CloudinaryStorage({
        cloudinary: cloudinary, params: { folder: "images/image", allowed_formats: ["jpg", "jpeg", "png", "PNG", "xlsx", "xls", "pdf", "PDF"], },
});
const upload = multer({ storage: storage });
var vehicleUpload = upload.fields([{ name: "image",maxCount: 1 }, { name: "registrationCertificate",maxCount: 1 }]);


router.get("/vehicles", getVehicles);

// router.post("/vehicles", [authJwt.verifyToken], createVehicle);
// const vehicleimages = upload.fields([{ name: "image" }, { name: "registrationCertificate" }]);
router.post("/vehicles", vehicleUpload, createVehicle )
 
router.put("/vehicles/:id", updateVehicle);
router.delete("/vehicles/:id", deleteVehicle);

module.exports = router;
