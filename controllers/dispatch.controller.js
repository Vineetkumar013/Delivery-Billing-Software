const Billing = require("../models/billing");
const { createResponse } = require("../utils/response");
const mongoose = require("mongoose");
const ObjectId = mongoose.Types.ObjectId;
const { secret, accessTokenTime } = require("../configs/auth.configs");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const dispatchsignup = async (req, res) => {
    try {
        const { email, employeeId, password, confirmPassword, name, mobile } = req.body;
        console.log(req.body);
        const emailExists = await User.findOne({ email, role: "DISPATCH" });
        if (emailExists) {
            return res.status(401).json({
                message: "Email Number Already Exists",
            });
        }

        if (employeeId) {
            const existingEmployee = await User.findOne({ employeeId, mobile });
            if (existingEmployee) {
                return createResponse(res, 409, "EmployeeId already in use");
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
            role: "DISPATCH"
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

// const dispatchlogin = async (req, res) => {
//  const { employeeId, password} = req.body;

//   try {
//     // Check if a user with the given employeeId exists in the database
//     const user = await User.findOne({ employeeId, role: ["DISPATCH-EMPLOYEE"] });

//     if (!user) {
//       return res.status(401).json({ message: "DISPATCH-EMPLOYEE Not Found" });
//     }

//       const role = "DISPATCH-EMPLOYEE"
//     // Check if the role matches the one stored in the database
//     if (role !== user.role) {
//       return res.status(401).json({ message: "Role not be Matched" });
//     }

//     // Check if the password matches the one stored in the database
//     const isPasswordValid = bcrypt.compareSync(password, user.password);

//     if (!isPasswordValid) {
//       return res.status(401).json({ message: "Invalid credentials" });
//     }

//     // Create a token
//     const token = jwt.sign({ id: user._id }, secret, {
//       expiresIn: accessTokenTime,
//     });

//     // Send a response indicating that the user was successfully logged in
//     return res.status(200).json({
//       message: "User logged in successfully",
//       token,
//       data: user,
//     });
//   } catch (err) {
//     console.error(err);
//     return res.status(500).json({ message: "Internal server error" });
//   }
// };

const getAllBillOfDispatch = async (req, res) => {
    // const { _id } = req.user
    try {
        // const user = await User.findById(_id);
        const query = { /* userId: user.id */ };
        if (req.query.mrName) {
            query.mrName = req.query.mrName;
        }
        if (req.query.area) {
            query.area = req.query.area;
        }
        if (req.query.route) {
            query.route = req.query.route;
        }
        if (req.query.dispatchStatus) {
            query.dispatch.status = req.query.dispatchStatus;
        }
        if (req.query.acceptanceStatus) {
            query.dispatch.acceptanceStatus = req.query.acceptanceStatus;
        }
        if (req.query.dispatchAssignee) {
            query["dispatch.dispatchAssignee"] = new ObjectId(
                req.query.dispatchAssignee
            );
        }
        if (req.query.assigned && req.query.assigned === "true") {
            query["dispatch.assigned"] = true;
        }
        if (req.query.assigned && req.query.assigned === "false") {
            query["dispatch.assigned"] = false;
        }

        const pipeline = [
            {
                $match: query,
            },
            {
                $sort: {
                    updatedAt: -1,
                },
            },
            {
                $lookup: {
                    from: "billitems",
                    localField: "billItems",
                    foreignField: "_id",
                    as: "billItems",
                },
            },
            // {
            //     $project: {
            //         _id: 1,
            //         billingDate: 1,
            //         totalAmount: 1,
            //         picker: {
            //             pickerAssignee: 1,
            //         },
            //         billItems: {
            //             _id: 1,
            //             itemName: 1,
            //             itemPrice: 1,
            //         },
            //     },
            // },
        ];
        const billings = await Billing.aggregate(pipeline);
        if (!billings || billings.length === 0) {
            createResponse(res, 404, "No bills found");
            return;
        }
        createResponse(res, 200, "All bills fetched successfully", billings);
    } catch (error) {
        console.log(error);
        createResponse(res, 500, "Server error");
    }
};

const updateBillingDispatch = async (req, res) => {
    // const { _id } = req.user
    try {
        // const user = await User.findById(_id);
        const { id } = req.params;

        const billing = await Billing.findById(id);

        const {
            status,
            acceptanceStatus,
            boxQuantity,
            polyPackQuantity,
            reassign,
            comment,
        } = req.body;
        req.body;
        if (!billing) {
            return res.status(404).json({
                success: false,
                message: "Billing not found",
            });
        }
        const bill = billing.dispatch;

        bill.status = status || bill.status;
        bill.acceptanceStatus = acceptanceStatus || bill.acceptanceStatus;
        bill.boxQuantity = boxQuantity || bill.boxQuantity;
        bill.reassign = reassign || bill.reassign;
        bill.comment = comment || bill.comment;
        bill.polyPackQuantity = polyPackQuantity || bill.polyPackQuantity;
        await billing.save();
        if (billing.reassign === "Yes") {
            const notification = await Notification.create({
                userId: billing.packer.packerAssignee,
                title: "Bill Reassigned",
                message: `Bill has been reassigned`,
            });
            console.log(notification);
            billing.packer.reassign = true;
            await billing.save();
        }
        return res.status(200).json({
            success: true,
            message: "Billing updated successfully",
            data: billing.packer,
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};
const assignBillToDispatch = async (req, res) => {
    const { id } = req.params;
    const { dispatchId } = req.body;
    try {
        const billing = await Billing.findById(id);
        if (!billing) {
            createResponse(res, 404, "Bill not found");
            return;
        }
        console.log(dispatchId, " ", billing.dispatch.dispatchAssignee);
        billing.dispatch.dispatchAssignee = dispatchId;
        await billing.save();
        console.log(billing.dispatch.dispatchAssignee);
        createResponse(res, 200, "Bill assigned to dispatch successfully", billing.dispatch);
    } catch (error) {
        console.log(error);
        createResponse(res, 500, "Server error");
    }
};

module.exports = {
    dispatchsignup,
    // dispatchlogin,
    updateBillingDispatch,
    getAllBillOfDispatch,
    assignBillToDispatch,
};
