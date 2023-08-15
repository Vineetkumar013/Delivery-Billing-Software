const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { secret, accessTokenTime } = require("../configs/auth.configs");
const User = require("../models/user");
const OTP = require("../services/otp")
const { createResponse } = require("../utils/response");

// Define a signup function that creates a new user document in the database

// const signup = async (req, res) => {
//     try {
//         const { email, employeeId, password, confirmPassword, name, mobile } = req.body;
//         console.log(req.body);
//         const emailExists = await User.findOne({ email,role: "USER" });
//         if (emailExists) {
//             return res.status(401).json({
//                 message: "Email Number Already Exists",
//             });
//         }

// if (employeeId) {
//     const existingEmployee = await User.findOne({ employeeId });
//     if (existingEmployee) {
//         errors.push("EmployeeId already in use");
//     }
// }

// if (mobile) {
//     const existingMobile = await User.findOne({ mobile });
//     if (existingMobile) {
//         errors.push("Mobile already in use");
//     }
// }

//         if (password !== confirmPassword) {
//             return res.status(400).json({
//                 message: "Passwords do not match",
//             });
//         }

//         // Hash the password
//         const hashedPassword = await bcrypt.hash(password, 10);
//         const confirmhashedPassword = await bcrypt.hash(password, 10);

//         const otp = Math.floor(1000 + Math.random() * 9000);
//         const user = await User.create({
//             email: email,
//             employeeId: employeeId,
//             password: hashedPassword,
//             confirmhashedPassword: confirmhashedPassword,
//             otp: otp,
//             name: name,
//             role: "USER"
//         });
//         console.log(user);
//         res.status(200).json({
//             status: 200,
//             message: "OTP is Send ",
//             OTP: otp,
//             data: user
//         });
//     } catch (err) {
//         console.log(err)
//         res.status(400).json({
//             message: err.message,

//         });
//     }
// };
const UserSignup = async (req, res) => {
    try {
        const { email, mobile, employeeId, password, confirmPassword, name, location } = req.body;
        const emailExists = await User.findOne({ email: email,});
        if (emailExists) {
            return res.status(401).json({
                message: "Email Number Already Exists",
            });
        }

        if (employeeId) {
            const existingEmployee = await User.findOne({ employeeId });
            if (existingEmployee) {
                return res.json({ message: "Already exists for this employee" })
            }
        }

        if (mobile) {
            const existingMobile = await User.findOne({ mobile });
            if (existingMobile) {
                return createResponse(res, 409, "Mobile already in use");
            }
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                message: "Passwords do not match",
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        const confirmhashedPassword = await bcrypt.hash(password, 10);

        // const otp = Math.floor(1000 + Math.random() * 9000);
        const otp = OTP.generateOTP();
        const user = await User.create({
            email: email,
            password: hashedPassword,
            employeeId: employeeId,
            mobile: mobile,
            confirmhashedPassword: confirmhashedPassword,
            otp: otp,
            name: name,
            location,
            role: "USER"
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


// const verifyOtp = async (req, res) => {
//     try {
//         const { otp } = req.body;
//         const user = await User.findOne({ _id: req.params.id });
//         if (!user) {
//             return createResponse(res, 404, "User not found");
//         }
//         const otpFromDb = user.otp;
//         console.log(otp);
//         if (!otpFromDb || otpFromDb !== otp) {
//             return createResponse(res, 401, "Invalid OTP");
//         }
//         user.otp = null;
//         user.mobileVerified = true;
//         await user.save();
//         return createResponse(res, 200, " verified successfully");
//     } catch (err) {
//         console.error(err);
//         return createResponse(res, 500, "Internal server error");
//     }
// };

const verifyOtp = async (req, res) => {
    try {
        const data = await User.findOne({ otp: req.body.otp });
        if (!data) {
            return res.status(401).json({
                message: "Your Otp is Wrong",
            });
        } else {
            // const accessToken = otpService.generateOTP(data._id.toString());
            res.status(200).json({
                success: true,
                message: "Login Done ",
                // accessToken: accessToken,
                userId: data._id,
            });
        }
    } catch (err) {
        res.status(400).json({
            message: err.message,
        });
    }
};

// Define a login function that checks the user's credentials and sends an OTP for authentication
const Userlogin = async (req, res) => {
    const { employeeId, password, role, email } = req.body;
    // console.log(employeeId, password);
    try {
        if ((employeeId != (null || undefined)) && (role != (null || undefined))) {
            const user = await User.findOne({ employeeId, role });
            if (!user) {
                return res.status(401).json({ message: "User not found" });
            }
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: "Invalid credentials" });
            }
            const token = jwt.sign({ id: user._id }, secret, { expiresIn: accessTokenTime, });
            return res.status(200).json({ message: "User logged in successfully", token, data: user, });
        }
        if ((email != (null || undefined)) && (role != (null || undefined))) {
            const user = await User.findOne({ email, role });
            if (!user) {
                return res.status(401).json({ message: "User not found" });
            }
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: "Invalid credentials" });
            }
            const token = jwt.sign({ id: user._id }, secret, { expiresIn: accessTokenTime, });
            return res.status(200).json({ message: "User logged in successfully", token, data: user, });
        }


        // Create a token

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Internal server error" });
    }
};

require("dotenv").config();
const nodemailer = require("nodemailer");


const forgotPassword = async (req, res) => {
    try {
        // Extract email from request body
        const { email } = req.body;
        console.log(email);
        // Generate a password reset token and save it to the user's document in the database
        const token = Math.floor(Math.random() * 9000) + 999;
        console.log(token);
        const user = await User.findOneAndUpdate(
            { email },
            {
                // resetPasswordToken: token,
                otp: token,
                resetPasswordExpires: Date.now() + 3600000,
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({
                success: true,
                message: "User not found"
            });
        }

        // Create a nodemailer transporter object
        const transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            auth: {
                user: 'jenifer71@ethereal.email',
                pass: 'W9BeAymdFqDnjja33v'
            }
        });
        // Define the email options
        const mailOptions = {
            to: email,
            from: "node1@flyweis.technology",
            subject: "Password reset request",
            text:
                `OTP ${token}\n` +
                `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                `your otp is ${token} ` +
                `for reset password\n\n` +
                `If you did not request this, please ignore this email and your password will remain unchanged.\n`,
        };

        // Send the email with nodemailer
        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                console.error(error);
                return res.status(500).json({
                    message: "Could not send email. Please try again later.",
                });
            }
            res.status(200).json({
                message: "Password Resend Email Sent Successfully",
                otp: token,
                userId: user._id,
            });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "An error occurred. Please try again later.",
        });
    }
};

const forgotPasswordOtp = async (req, res) => {
    try {
        const id1 = req.params.id;
        const otp = req.body.otp;
        const user = await User.findById({ _id: id1 });
        console.log(user);
        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }
        if (user.otp !== otp) {
            return res.status(403).json({
                message: "Wrong otp",
            });
        }

        // user.password = password;
        // user.otp = undefined;
        // user.resetPasswordToken = undefined;
        // user.resetPasswordExpires = undefined;
        // await user.save();
        res.status(200)
            .json({
                status: 200,
                message: "otp verification is successful.",
                data: user
            });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: error.message });
    }
};

// const forgotPasswordOtp = async (req, res) => {
//   try {
//     const { email, otp } = req.body;

//     // Find the user with the given email and OTP
//     const user = await User.findOne({
//       email,
//       otp,
//       resetPasswordExpires: { $gt: Date.now() },
//     });
// console.log(user);
//     if (!user) {
//       return res.status(404).json({ message: "Invalid OTP or email" });
//     }

//     // Update the user's password and remove the OTP
//     user.password = req.body.newPassword;
//     user.otp = undefined;
//     user.resetPasswordToken = undefined;
//     user.resetPasswordExpires = undefined;
//     await user.save();

//     res.status(200).json({ message: "Password reset successfully" });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({
//       message: "An error occurred. Please try again later.",
//     });
//   }
// };

const resetPassword = async (req, res) => {
    try {
        // Extract password and confirm password from request body
        const { password, confirmPassword } = req.body;

        // Verify that passwords match
        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Find user with valid password reset token
        const user = await User.findOne({
            _id: req.params.id,
        });

        if (!user) {
            return res
                .status(400)
                .json({ message: "Invalid or expired token" });
        }

        // Update user's password and clear the reset token
        user.password = bcrypt.hashSync(password, 10);
        user.confirmPassword = bcrypt.hashSync(confirmPassword, 10);

        await user.save();

        res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "An error occurred. Please try again later.",
        });
    }
};


const getUsersByRole = async (req, res) => {
    try {
        const { role } = req.query;
        const query = {};

        if (role) {
            query.role = role;
        }

        const users = await User.find(query);

        res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            data: users,
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            success: false,
            message: "Server error",
        });
    }
};

const resendOtp = async (req, res) => {
    try {
        const otp = Math.floor(1000 + Math.random() * 9000);

        const user = await User.findByIdAndUpdate(
            req.params.id,
            { otp: otp },
            { new: true }
        );
        console.log(user);
        if (!user) {
            return res.status(401).json({
                message: "No User Found ",
            });
        } else {
            // const data = await sendSMS(user.mobile, otp);
            res.status(200).json({
                message: "OTP is Send ",
                otp: otp,
                data: user,
            });
        }
    } catch (err) {
        res.status(400).json({
            message: err.message,
        });
    }
};


module.exports = {
    UserSignup,
    verifyOtp,
    Userlogin,
    forgotPassword,
    forgotPasswordOtp,
    resetPassword,
    getUsersByRole,
    resendOtp
}