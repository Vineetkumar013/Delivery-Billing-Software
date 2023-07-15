const Billing = require("../models/billing");
const { createResponse } = require("../utils/response");
const mongoose = require("mongoose");
const ObjectId = mongoose.Types.ObjectId;
const Notification = require("../models/notification");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { secret, accessTokenTime } = require("../configs/auth.configs");

const Pickersignup = async (req, res) => {
    try {
        const { email, employeeId, password, confirmPassword, name } = req.body;
        console.log(req.body);
        const emailExists = await User.findOne({ email, role: ["PICKER"] });
        console.log(emailExists)
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
        const hashedPassword1 = await bcrypt.hash(confirmPassword, 10);

        const otp = Math.floor(1000 + Math.random() * 9000);
        const user = await User.create({ email: email, employeeId: employeeId, password: hashedPassword, confirmPassword: hashedPassword1, otp: otp, name: name, role: "PICKER" });
        console.log(user);
        res.status(200).json({ message: "OTP is Send ", OTP: otp, data: user });
    } catch (err) {
        console.log(err)
        res.status(400).json({
            message: err.message,

        });
    }
};

const Pickerlogin = async (req, res) => {
    const { employeeId, password } = req.body;

    try {
        // Check if a user with the given employeeId exists in the database
        const user = await User.findOne({ employeeId, role: "PICKER" });

        if (!user) {
            return res.status(401).json({ message: "Picker Not Found" });
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
            message: "PICKER logged in successfully",
            token,
            data: user,
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Internal server error" });
    }
};

const getAllBillOfPicker = async (req, res) => {
    try {
        const query = {};
        if (req.query.pickerAssignee) {
            query["picker.pickerAssignee"] = new ObjectId(
                req.query.pickerAssignee
            );

            // delete query.pickerAssignee;
        }
        if (req.query.assigned && req.query.assigned === "true") {
            query["picker.assigned"] = true;
        }
        if (req.query.assigned && req.query.assigned === "false") {
            query["picker.assigned"] = false;
        }
        if (req.query.status) {
            query["picker.status"] = req.query.status;
            // delete query.status;
        }

        // if (req.query.reassignVerification) {
        //     query["verifier.reassign"] = "Yes";
        //     delete query.reassignVerification;
        // }

        if (req.query.acceptanceStatus) {
            query["picker.acceptanceStatus"] = req.query.acceptanceStatus;
            // delete query.acceptanceStatus;
        }
        console.log(query);
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
        createResponse(res, 200, "All bills fetched successfully", billings);
    } catch (error) {
        console.log(error);
        createResponse(res, 500, "Server error");
    }
};

const updateBillingPicker = async (req, res) => {
    try {
        const { id } = req.params;

        const billing = await Billing.findById(id);

        const {
            status,
            acceptanceStatus,
            numberOfTrays,
            reassign,
            comment,
            urgencyColor,
        } = req.body;
        req.body;
        if (!billing) {
            return res.status(404).json({
                success: false,
                message: "Billing not found",
            });
        }
        const bill = billing.picker;

        bill.status = status || bill.status;
        bill.acceptanceStatus = acceptanceStatus || bill.acceptanceStatus;
        bill.numberOfTrays = numberOfTrays || bill.numberOfTrays;
        bill.reassign = reassign || bill.reassign;
        bill.comment = comment || bill.comment;
        bill.urgencyColor = urgencyColor || bill.urgencyColor;
        await billing.save();

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
const assignBillToVerifier = async (req, res) => {
    const { id } = req.params;
    const { verifierId } = req.body;
    try {
        const billing = await Billing.findById(id);
        if (!billing) {
            createResponse(res, 404, "Bill not found");
            return;
        }
        console.log(verifierId, " ", billing.verifier.verifierAssignee);
        billing.verifier.verifierAssignee = verifierId;
        billing.picker.assigned = true;
        await billing.save();
        await Notification.create({
            userId: verifierId,
            title: "New Bill Assigned",
            message: "You have been assigned a bill for verification",
        });
        console.log(billing.verifier.verifierAssignee);
        createResponse(res, 200, "Bill assigned for verification successfully");
    } catch (error) {
        console.log(error);
        createResponse(res, 500, "Server error");
    }
};

module.exports = {
    Pickersignup,
    Pickerlogin,
    updateBillingPicker,
    getAllBillOfPicker,
    assignBillToVerifier,
};
