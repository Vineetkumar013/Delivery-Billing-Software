const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "users",
            required: true,
        },
        uid: {
            type: String,
            required: true,
        },
        bill: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Billing",
            required: true,
        },
        deliveryStatus: {
            type: String,
            default: "pending",
            enum: ["pending", "delivered", "cancelled", "returned"],
        },
        receive: {
            type: String,
            default: "0",
        },
        return: {
            type: String,
            default: "0",
        },
        shortage: {
            type: String,
            default: "0",
        },
        balance: {
            type: String,
            default: "0",
        },
        isDelivered: {
            type: Boolean,
            default: false,
        },
        deliveredAt: {
            type: Date,
            default: () => {
                return new Date();
            },
        },
        description: {
            type: String,
            default: "",
        },
        image: {
            type: Object,
            default: {},
        },
        orderTotal: {
            type: Number,
            // required: true,
            default: ""
        },
        paymentStatus: {
            type: String,
            default: "pending",
            enum: ["pending", "paid", "failed"],
        },
        shippingAddress: {
            type: String,
            // required: true,
            default: ""
        },
        shippingMethod: {
            type: String,
            // required: true,
            default: ""
        },
        trackingNumber: {
            type: String,
        },
        deliveryOTP: {
            type: String,
        }
    },
    { timestamps: true }
);

module.exports = mongoose.model("Order", orderSchema);