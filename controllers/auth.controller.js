const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { secret, accessTokenTime } = require("../configs/auth.configs");
const User = require("../models/user");
const otpService = require("../services/otp");
const { createResponse } = require("../utils/response");

// Define a signup function that creates a new user document in the database

exports.signup = async (req, res) => {
    try {
        const { email, employeeId, password, confirmPassword, name, mobile } = req.body;
        console.log(req.body);
        const emailExists = await User.findOne({ email,role: "USER" });
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
        const user = await User.create({ email: email, employeeId: employeeId, password: hashedPassword, otp:otp ,name:name });
        console.log(user);
        res.status(200).json({ message: "OTP is Send ", OTP: otp, data: user });
    } catch (err) {
        console.log(err)
        res.status(400).json({
            message: err.message,
            
        });
    }
};


exports.verifyOtp = async (req, res) => {
    try {
        const { otp } = req.body;
        const user = await User.findOne({ _id: req.params.id });
        if (!user) {
            return createResponse(res, 404, "User not found");
        }
        const otpFromDb = user.otp;
        console.log(otp);
        if (!otpFromDb || otpFromDb !== otp) {
            return createResponse(res, 401, "Invalid OTP");
        }
        user.otp = null;
        user.mobileVerified = true;
        await user.save();
        return createResponse(res, 200, " verified successfully");
    } catch (err) {
        console.error(err);
        return createResponse(res, 500, "Internal server error");
    }
};


// Define a login function that checks the user's credentials and sends an OTP for authentication
exports.login = async (req, res) => {
 const { employeeId, password } = req.body;
  try {
    // Check if a user with the given employeeId exists in the database
    const user = await User.findOne({ employeeId, role: "USER" });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

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


require("dotenv").config();
const nodemailer = require("nodemailer");


exports.forgotPassword = async (req, res) => {
    try {
        // Extract email from request body
        const { email } = req.body;

        // Generate a password reset token and save it to the user's document in the database
        const token = Math.floor(Math.random() * 9000) + 999;
        console.log(token);
        const user = await User.findOneAndUpdate(
            { email },
            {
                resetPasswordToken: token,
                resetPasswordExpires: Date.now() + 3600000,
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Create a nodemailer transporter object
        const transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            port: 587,
            secure: false,
            auth: {
                user: "node2@flyweis.technology",
                pass: "ayesha@9818#",
            },
        });

        // Define the email options
        const mailOptions = {
            to: email,
            from: "node2@flyweis.technology",
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
                message: "Password reset email sent successfully",
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

exports.forgotPasswordOtp = async (req, res) => {
    try {
        const id = req.params.id;
        const otp = req.body.otp;
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }
        if (user.resetPasswordToken !== otp) {
            return res.status(403).json({
                message: "Wrong otp",
            });
        }
        res.status(200).json({ message: "otp verification is successful" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: error.message });
    }
};

exports.resetPassword = async (req, res) => {
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

        await user.save();

        res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "An error occurred. Please try again later.",
        });
    }
};



// exports.signup = async (req, res) => {
//     try {
//         const data = req.body

//         // Check if a user with the given email already exists in the database
//         const existingUser = await User.findOne({ email: data.email });

//         if (existingUser) {
//             return createResponse(res, 409, "Email address already in use");
//         }

//         // Generate OTP
//         const OTP = otpService.generateOTP();
//         // console.log(OTP)
//         data.otp = OTP
//         // Hash the password
//         console.log(data)
//         data.password = bcrypt.hashSync(req.body.password, 10);
       
//         const b = data

//         const newUser = await User.create(b)

//         // Create a new user document in the database with the given information
// //         const newUser = new User({
// // data// Add the OTP to the user object
// //         });
// //         // console.log(data)
// //         await newUser.save();

//         console.log("User created", newUser);

//         // Send a response indicating that the user was successfully created
//         return createResponse(res, 201, "User created successfully", {
//             user: newUser,
//             otp: OTP,
//         });
//     } catch (err) {
//         console.error(err);
//         return createResponse(res, 500, "Internal server error");
//     }
// };