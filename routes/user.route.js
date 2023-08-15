const express = require("express");
const router = express.Router();
const userController = require("../controllers/user.controller");
// const cloudinary = require("cloudinary").v2;
// const multer = require("multer");
// // const upload = multer({ storage: multer.memoryStorage() });
// cloudinary.config({
//   cloud_name: "dbrvq9uxa",
//   api_key: "567113285751718",
//   api_secret: "rjTsz9ksqzlDtsrlOPcTs_-QtW4",
// });

// const upload = multer({ dest: 'uploads/' });

// router.post("/users/:id/profile", upload.fields([
//   { name: "panCard", maxCount: 1 },
//   { name: "profile", maxCount: 1 },
//   { name: "aadharCard", maxCount: 1 },
//   { name: "drivingLicense", maxCount: 1 }
// ]), userController.updateProfile);


// router.get("/users", userController.getAllUsers);
// router.put("/users/:userId", userController.updateUser);



const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
cloudinary.config({ cloud_name: "dbrvq9uxa", api_key: "567113285751718", api_secret: "rjTsz9ksqzlDtsrlOPcTs_-QtW4", });
const storage = new CloudinaryStorage({
        cloudinary: cloudinary, params: { folder: "images/image", allowed_formats: ["jpg", "jpeg", "png", "PNG", "xlsx", "xls", "pdf", "PDF"], },
});
const upload = multer({ storage: storage });
var cpUpload = upload.fields([ { name: 'aadharCard', maxCount: 1 },{ name: 'drivingLicense', maxCount: 1 },{ name: 'panCard', maxCount: 1 }]);

var ProfileUpload = upload.fields([{ name: 'profile', maxCount: 1 }]);

router.put("/users/profile/:id", cpUpload, userController.UpdateProfile);
router.put("/users/yourprofile/:id", ProfileUpload, userController.YourProfileUpdate);
router.get("/users/:userId", userController.getUser);
router.delete("/users/:userId", userController.deleteUser);
router.put("/users/:userId", userController.updateUser);

module.exports = router;




// const multer = require("multer");
// const { CloudinaryStorage } = require("multer-storage-cloudinary");
// const cloudinary = require("cloudinary").v2;
// cloudinary.config({ cloud_name: "dbrvq9uxa", api_key: "567113285751718", api_secret: "rjTsz9ksqzlDtsrlOPcTs_-QtW4", });
// const storage = new CloudinaryStorage({
//         cloudinary: cloudinary, params: { folder: "images/image", allowed_formats: ["jpg", "jpeg", "png", "PNG", "xlsx", "xls", "pdf", "PDF"], },
// });
// const upload = multer({ storage: storage });