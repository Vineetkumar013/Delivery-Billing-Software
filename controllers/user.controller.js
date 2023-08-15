const User = require("../models/user");
const { createResponse } = require("../utils/response");
// const cloudinary = require("cloudinary").v2;

// const multer = require('multer');

// const uploadToCloudinary = (file) => {
//   return new Promise((resolve, reject) => {
//     cloudinary.uploader.upload(file.tempFilePath, (error, result) => {
//       if (error) {
//         reject(error);
//       } else {
//         resolve(result.secure_url);
//       }
//     });
//   });
// };

// const upload = multer({ dest: 'uploads/' });

// exports.updateProfile = async (req, res) => {
//   const { name, email, password, mobile } = req.body;

//   try {
//     const user = await User.findById(req.params.id);
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     user.name = name || user.name;
//     user.email = email || user.email;
//     user.password = password || user.password;
//     user.mobile = mobile || user.mobile;

//     if (req.files) {
//       // Upload panCard image
//       if (req.files.panCard) {
//         const panCardImage = req.files.panCard;
//         const uploadedPanCard = await uploadToCloudinary(panCardImage);
//         user.panCard = uploadedPanCard;
//       }

//       // Upload profile image
//       if (req.files.profile) {
//         const profileImage = req.files.profile;
//         const uploadedProfile = await uploadToCloudinary(profileImage);
//         user.profile = uploadedProfile;
//       }

//       // Upload aadharCard image
//       if (req.files.aadharCard) {
//         const aadharCardImage = req.files.aadharCard;
//         const uploadedAadharCard = await uploadToCloudinary(aadharCardImage);
//         user.aadharCard = uploadedAadharCard;
//       }

//       // Upload drivingLicense image
//       if (req.files.drivingLicense) {
//         const drivingLicenseImage = req.files.drivingLicense;
//         const uploadedDrivingLicense = await uploadToCloudinary(drivingLicenseImage);
//         user.drivingLicense = uploadedDrivingLicense;
//       }
//     }

//     await user.save();

//     res.json(user);
//   } catch (error) {
//     console.error('Error updating user profile:', error);
//     res.status(500).json({ error: error.message });
//   }
// };

// Helper function to upload a file to Cloudinary


exports.updateUser = async (req, res) => {
  const { userId } = req.params;
  const { email, mobile, name } = req.body;

  try {
    // Check if a user with the given userId exists in the database
    const user = await User.findById(userId);

    if (!user) {
      return createResponse(res, 404, "User not found");
    }

    // Update user details
    user.email = email;
    user.mobile = mobile;
    user.name = name;
    await user.save();

    return createResponse(res, 200, "User updated successfully", user);
  } catch (err) {
    console.error(err);
    return createResponse(res, 500, "Internal server error");
  }
};

// exports.updateUser = async (req, res) => {
//     const { userId } = req.params;
//     const { email, mobile, name } = req.body;
//     try {
//         // Check if a user with the given userId exists in the database
//         const user = await User.findByIdAndUpdate(userId, {email:email,mobile:mobile,name:name}, {
//             new: true,
//         });

//         if (!user) {
//             return createResponse(res, 404, "User not found");
//         }
//         return createResponse(res, 200, "User updated successfully", user);
//     } catch (err) {
//         console.error(err);
//         return createResponse(res, 500, "Internal server error");
//     }
// };
//get all users
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find().lean();
        createResponse(res, 200, "users fetched successfully", users);
    } catch (err) {
        console.error(err);
        createResponse(res, 500, "Internal server error");
    }
};
// Define a get function that retrieves a user document from the database
exports.getUser = async (req, res) => {
    const { userId } = req.params;

    try {
        // Check if a user with the given userId exists in the database
        const user = await User.findById(userId).lean();

        if (!user) {
            return createResponse(res, 404, "User not found");
        }

        // Send a response with the user information
        return createResponse(res, 200, "User retrieved successfully", user);
    } catch (err) {
        console.error(err);
        return createResponse(res, 500, "Internal server error");
    }
};

// Define a delete function that deletes a user document from the database
exports.deleteUser = async (req, res) => {
    const { userId } = req.params;

    try {
        // Check if a user with the given userId exists in the database
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            return createResponse(res, 404, "User not found");
        }

        // Delete the user document from the database

        // Send a response indicating that the user was successfully deleted
        return createResponse(res, 200, "User deleted successfully");
    } catch (err) {
        console.error(err);
        return createResponse(res, 500, "Internal server error");
    }
};

exports.YourProfileUpdate = async (req, res) => {
    try {
        let ProfileUpdate = req.files["profile"];
        req.body.pro = ProfileUpdate[0].path;
        const user = await User.findOneAndUpdate(
            { _id: req.params.id },
            {
                $set: {
                    profile: req.body.pro,
                },
            },
            { new: true }
        );
        // user.save();
        return res
            .status(200)
            .json({ msg: "Your profile updated successfully", user: user });
    } catch (error) {
        console.error(error);
        res
            .status(500)
            .send({ status: 500, message: "Server error" + error.message });
    }
}



exports.UpdateProfile = async (req, res) => {
    try {
        // let profile = req.files["profile"];
        let Aadhar = req.files["aadharCard"];
        let Driver = req.files["drivingLicense"];
        let panCard = req.files["panCard"];
        // req.body.pro = profile[0].path;
        req.body.AadharCard = Aadhar[0].path;
        req.body.drivingLicense = Driver[0].path;
        req.body.uploadPanCard = panCard[0].path;


        const user = await User.findOneAndUpdate(
            { _id: req.params.id },
            {
                $set: {
                    panCard: req.body.uploadPanCard,
                    // profile: req.body.pro,
                    aadharCard: req.body.AadharCard,
                    drivingLicense: req.body.drivingLicense,
                },
            },
            { new: true }
        );
        return res
            .status(200)
            .json({ msg: "profile updated successfully", user: user });
    } catch (error) {
        console.error(error);
        res
            .status(500)
            .send({ status: 500, message: "Server error" + error.message });
    }
};




