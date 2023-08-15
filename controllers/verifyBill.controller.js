const Billing = require("../models/billing");
const { createResponse } = require("../utils/response");
const mongoose = require("mongoose");
const ObjectId = mongoose.Types.ObjectId;
const Notification = require("../models/notification");
const { secret, accessTokenTime } = require("../configs/auth.configs");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");


const Verifysignup = async (req, res) => {
    try {
        const { email, employeeId, password, confirmPassword, name,mobile } = req.body;
        console.log(req.body);
        const emailExists = await User.findOne({ email,role: "VERFIER" });
        if (emailExists) {
            return res.status(401).json({
                message: "Email Number Already Exists",
            });
        }

        if (employeeId) {
            const existingEmployee = await User.findOne({ employeeId });
            if (existingEmployee) {
                errors.push("EmployeeId already in use");
            }
        }

        if (mobile) {
            const existingMobile = await User.findOne({ mobile });
            if (existingMobile) {
                errors.push("Mobile already in use");
            }
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                message: "Passwords do not match",
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const otp = Math.floor(1000 + Math.random() * 9000);
        const user = await User.create({
            email: email,
            employeeId: employeeId,
            password: hashedPassword,
            otp: otp,
            name: name,
            mobile: mobile,
            role: "VERFIER"
        });
        console.log(user);
        res.status(200).json({ message: "OTP is Send ", OTP: otp, data: user });
    } catch (err) {
        console.log(err)
        res.status(400).json({
            message: err.message,
            
        });
    }
};

const Verifylogin = async (req, res) => {
 const { employeeId, password} = req.body;

  try {
    // Check if a user with the given employeeId exists in the database
    const user = await User.findOne({ employeeId, role: "PICKER" });

    if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
    }
      
    const role = "PICKER"
    // Check if the role matches the one stored in the database
    if (role !== user.role) {
      return res.status(401).json({ message: "Role not be Matched" });
    }

    // Check if the password matches the one stored in the database
    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Create a token
    const token = jwt.sign({ id: user._id }, secret, {
      expiresIn: accessTokenTime,
    });

    // Send a response indicating that the user was successfully logged in
    return res.status(200).json({
      message: "User logged in successfully",
      token,
      data: user,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// const getAllBillOfVerifier = async (req, res) => {
//     // const {_id} = req.user
//     try {
//         // const user = User.findById(_id)
//         const query = {};
//         if (req.query.verifierAssignee) {
//             query["verifier.verifierAssignee"] = new ObjectId(
//                 req.query.verifierAssignee
//             );
//         }
//         if (req.query.status) {
//             query["verifier.status"] = req.query.status;
//         }

//         if (req.query.acceptanceStatus) {
//             query["verifier.acceptanceStatus"] = req.query.acceptanceStatus;
//         }
//         if (req.query.assigned && req.query.assigned === "true") {
//             query["verifier.assigned"] = true;
//         }
//         if (req.query.assigned && req.query.assigned === "false") {
//             query["verifier.assigned"] = false;
//         }
//         const pipeline = [
//             {
//                 $match: query,
//             },
//             { $sort: { updatedAt: -1 } },
//             {
//                 $lookup: {
//                     from: "billitems",
//                     localField: "billItems",
//                     foreignField: "_id",
//                     as: "billItems",
//                 },
//             },
//             // {
//             //     $project: {
//             //         _id: 1,
//             //         billingDate: 1,
//             //         totalAmount: 1,
//             //         picker: {
//             //             pickerAssignee: 1,
//             //         },
//             //         billItems: {
//             //             _id: 1,
//             //             itemName: 1,
//             //             itemPrice: 1,
//             //         },
//             //     },
//             // },
//         ];
//         const billings = await Billing.aggregate(pipeline);
//         if (!billings || billings.length === 0) {
//             createResponse(res, 404, "No bills found");
//             return;
//         }
//         createResponse(res, 200, "All bills fetched successfully", billings);
//     } catch (error) {
//         console.log(error);
//         createResponse(res, 500, "Server error");
//     }
// };

const getAllBillOfVerifier = async (req, res) => {
  try {
    const query = {};
    if (req.query.verifierAssignee) {
      query["verifier.verifierAssignee"] = new ObjectId(
        req.query.verifierAssignee
      );
    }
    if (req.query.status) {
      query["verifier.status"] = req.query.status;
    }
    if (req.query.acceptanceStatus) {
      query["verifier.acceptanceStatus"] = req.query.acceptanceStatus;
    }
    if (req.query.assigned && req.query.assigned === "true") {
      query["verifier.assigned"] = true;
    }
    if (req.query.assigned && req.query.assigned === "false") {
      query["verifier.assigned"] = false;
    }

    const pipeline = [
      {
        $match: query,
      },
      { $sort: { updatedAt: -1 } },
      {
        $lookup: {
          from: "billitems",
          localField: "billItems",
          foreignField: "_id",
          as: "billItems",
        },
      },
      {
        $project: {
          "verifier.verifierAssignee": 1,
          "verifier.status": 1,
          "verifier.acceptanceStatus": 1,
          "verifier.assigned": 1,
        },
      },
    ];

    const billings = await Billing.aggregate(pipeline);

    if (!billings || billings.length === 0) {
      return res.status(404).json({ message: "No bills found" });
    }

    res.status(200).json({
      message: "All bills fetched successfully",
      billings,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};
const updateBillingVerifier = async (req, res) => {
    try {
        const { id } = req.params;

        const billing = await Billing.findById(id);

        const { status, acceptanceStatus, packet, reassign,urgencyColor, comment } =
            req.body;
        if (!billing) {
            return res.status(404).json({
                success: false,
                message: "Billing not found",
            });
        }
        const bill = billing.verifier;

        bill.status = status || bill.status;
        bill.acceptanceStatus = acceptanceStatus || bill.acceptanceStatus;
        bill.packet = packet || bill.packet;
        bill.reassign = reassign || bill.reassign;
        bill.comment = comment || bill.comment;
        bill.urgencyColor = urgencyColor || bill.urgencyColor;
        await billing.save();
        if (billing.reassign === "Yes") {
            const notification = await Notification.create({
                userId: billing.picker.pickerAssignee,
                title: "Bill Reassigned",
                message: `Bill has been reassigned`,
            });
            billing.picker.reassigned = true;
            await billing.save();
        }
        return res.status(200).json({
            success: true,
            message: "Billing updated successfully",
            data: billing,
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const assignBillToPacker = async (req, res) => {
    const { id } = req.params;
    const { packerId } = req.body;
    try {
        const billing = await Billing.findById(id);
        if (!billing) {
            createResponse(res, 404, "Bill not found");
            return;
        }
        console.log(packerId, " ", billing.packer.packerAssignee);
        billing.packer.packerAssignee = packerId;
        billing.verifier.assigned = true;
        await billing.save();
        const notification = await Notification.create({
            userId: packerId,
            title: "New Bill Assigned",
            message: `You have been assigned a bill`,
        });
        console.log(notification);
        console.log(billing.packer.packerAssignee);
        createResponse(res, 200, "Bill assigned to packer successfully", billing.packer);
    } catch (error) {
        console.log(error);
        createResponse(res, 500, "Server error");
    }
};

module.exports = {
    Verifysignup,
    Verifylogin,
    updateBillingVerifier,
    getAllBillOfVerifier,
    assignBillToPacker,
};
