const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: "",
    },
    email: {
      type: String,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      // required: true,
    },
    otp: {
      type: String,
    },
    role: {
      type: String,
      enum: ["USER", "PICKER", "ADMIN", "PACKER", "DISPATCH-EMPLOYEE", "VERFICATION-EMPLOYEE","DELIVER"],
      default: "USER",
    },
    employeeId: {
      type: String,
      default:""
    },
    confirmPassword: {
      type: String,
    },

    mobile: {
      type: String,
      default: "",
    },
    mobileVerified: {
      type: Boolean,
      default: false,
    },

    alternateMobile: {
      type: String,
      default: "",
    },
    panCard: {
      type: [],
      default: [],
    },
    profile: {
      type: String,
      default: "",
    },
    aadharCard: {
      type: String,
      default: "",
    },
    drivingLicense: {
      type: String,
      default: "",
    },

    verification: {
      type: String,
      default: "Pending",
      enum: ["Pending", "Approved", "Rejected", "Vineet"],
    },
  },
  { timestamps: true }
);
module.exports = mongoose.model("users", userSchema);
