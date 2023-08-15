const User = require("../models/user"); // Import the User model
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { secret, accessTokenTime } = require("../configs/auth.configs");
const { createResponse } = require("../utils/response");

// Define a signup function that creates a new user document in the database
const AdminSignup = async (req, res) => {
    try {
        const { email, mobile, password, confirmPassword, name } = req.body;
        console.log(req.body);
        const emailExists = await User.findOne({ email, role: "ADMIN" });
        if (emailExists) {
            return res.status(401).json({
                message: "Email Number Already Exists",
            });
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

        const otp = Math.floor(1000 + Math.random() * 9000);
        const user = await User.create({
            email: email,
            password: hashedPassword,
            confirmhashedPassword: confirmhashedPassword,
            otp: otp,
            name: name,
            role: "ADMIN"
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

// Define a login function that checks the user's credentials and logs them in
const Adminlogin = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if a user with the given employeeId exists in the database
        const user = await User.findOne({ email, role: "ADMIN" });

        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        // Check if the role matches the one stored in the database
        const role = "ADMIN"
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
            message: "ADMIN logged in successfully",
            token,
            data: user,
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Internal server error" });
    }
};


const getAdmins = async (req, res) => {
    try {
        let query = { ...req.query };

        const admins = await User.find(query).lean();
        if (!admins.length) {
            return res.status(404).json({ message: "admin not found" });
        }
        createResponse(res, 200, "found successfully", admins);
    } catch (err) {
        console.log(err);
        createResponse(res, 400, "server error ", err.message);
    }
};
const updateAdmins = async (req, res) => {
    try {
        if (req.body.password) {
            req.body.password = bcrypt.hashSync(req.body.password, 10);
        }
        const admins = await User.findByIdAndUpdate(
            { _id: req.params.id },
            req.body,
            { new: true }
        );
        if (!admins) {
            return res.status(404), json({ message: "Admin not found" });
        }
        res.status(200).json({ message: "Admin updated", data: admins });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Internal server error" });
    }
};

const getAdmin = async (req, res) => {
    try {
        const admins = await User.findById(req.params.id).lean();
        if (!admins) {
            return res.status(404).json({ message: "User not found" });
        }
        createResponse(res, 200, " retrieved successfully", admins);
    } catch (err) {
        console.log(err);
        createResponse(res, 400, "server error ", err.message);
    }
};

const deleteAdmins = async (req, res) => {
    try {
        const admins = await User.findByIdAndDelete(req.params.id);
        if (!admins) {
            return res.status(404).json({ message: "User not found" });
        }
        createResponse(res, 200, "admins retrieved successfully", admins);
    } catch (err) {
        console.log(err);
        createResponse(res, 400, "server error ", err.message);
    }
};

module.exports = {
    AdminSignup,
    Adminlogin,
    getAdmin,
    getAdmins,
    deleteAdmins,
    updateAdmins,
};
