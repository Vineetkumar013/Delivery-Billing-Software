const Order = require("../models/order");
const { createResponse } = require("../utils/response");
const Notification = require("../models/notification");
const Bill = require("../models/billing");
const BillItem = require("../models/billItem")
const Admin = require("../models/admin");
const User = require("../models/user")
const mongoose = require("mongoose");
const OTP = require("../services/otp")
const billing = require("../models/billing");
const Payment = require("../models/payment")
const ObjectId = mongoose.Types.ObjectId;

const getOrders = async (req, res) => {
    try {
        const query = {};
        if (req.query.userId) {
            query.userId = new ObjectId(req.query.userId);
        }

        const pipeline = [
            {
                $match: query,
            },
            {
                $lookup: {
                    from: "users",
                    localField: "userId",
                    foreignField: "_id",
                    as: "user",
                },
            },
            {
                $lookup: {
                    from: "billings",
                    localField: "bill",
                    foreignField: "_id",
                    as: "bill",
                },
            },
            {
                $unwind: "$bill",
            },
            {
                $lookup: {
                    from: "billitems",
                    localField: "bill.billItems",
                    foreignField: "_id",
                    as: "billItems",
                },
            },
            {
                $addFields: {
                    billingAddress: "$bill.billingAddress",
                    weight: "$bill.weight",
                    location: "$bill.location",
                },
            },
            {
                $project: {
                    user: { $arrayElemAt: ["$user", 0] }, // Assuming there's only one matching user
                    bill: 1,
                    billItems: 1,
                    billingAddress: 1,
                    weight: 1,
                    location: 1,
                },
            },
            {
                $sort: {
                    _id: -1 // Sort by the order creation date in descending order (latest first)
                },
            },
        ];

        const result = await Order.aggregate(pipeline);

        const orderList = result.map((order) => {
            return {
                orderId: order._id,
                user: order.user,
                bill: order.bill,
                billItems: order.billItems,
            };
        });

        return res.json({
            status: 200,
            message: "Orders found successfully",
            data: orderList,
        });
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Server Error");
    }
};

const deliveryDetails = async (req, res) => {
    try {
        const order = await Order.findOne({ _id: req.params.id });
        if (!order) {
            return res.status(404).json({ message: "Order not found" });
        }
        const bill = await Bill.findById(order.bill);
        if (!bill) {
            return res.status(404).json({ message: "Bill not found" });
        }
        const { customerName, billingAddress, mobile, billAmount, location } = bill;
        const otp = OTP.generateOTP();
        const billItems = await BillItem.find({ billId: bill._id }).select("itemName quantity mrp location");
        res.json({ Order: order, customerName, billingAddress, mobile, billAmount, location, billItems, otp });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server Error" });
    }
};


// const deliveryDetailsVerifyOTP = async (req, res) => {  
//   try {
//     const orderId = req.params.orderId;
//     const { otp } = req.body;

//     const order = await Order.findById(orderId);
//     if (!order) {
//       return res.status(404).json({ message: "Order not found." });
//     }

//     // Check if the order is already delivered
//     if (order.isDelivered) {
//       return res.status(400).json({ message: "Order is already delivered." });
//     }

//     // Compare the provided OTP with the stored OTP
//     if (otp === order.bill.deliveryOTP) {
//       // OTP is correct, mark the order as delivered and update deliveredAt timestamp
//       order.isDelivered = true;
//       order.deliveredAt = new Date();
//       await order.save();

//       return res.status(200).json({ message: "OTP verified. Order delivered successfully." });
//     } else {
//       return res.status(401).json({ message: "Invalid OTP. Delivery verification failed." });
//     }
//   } catch (err) {
//     console.error("Error verifying OTP:", err);
//     return res.status(500).json({ message: "An error occurred while verifying OTP." });
//   }
// };

const getOrderSummary = async (req, res) => {
    try {
        const { startDate, endDate, userId, uid, status } = req.query;

        const query = {};

        if (startDate && endDate) {
            query.deliveredAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
        }

        if (userId) {
            query.userId = userId;
        }

        if (uid) {
            query.uid = uid;
        }

        if (status) {
            query.deliveryStatus = status;
        }

        const orders = await Order.find(query)
            .populate({
                path: "userId",
                model: User,
                select: "-password", // Exclude the password field
            })
            .populate("bill")
            .populate({
                path: "bill",
                populate: {
                    path: "billItems billingAddress location weight",
                    model: billing,
                },
            });

        // Convert orders to list format
        const orderList = orders.map((order) => {
            return {
                orderId: order._id,
                user: order.userId,
                bill: order.bill,
                deliveryStatus: order.deliveryStatus,
                deliveredAt: order.deliveredAt,
            };
        });

        res.json({
            status: 200,
            message: "Success",
            data: orderList
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server Error" });
    }
};

const getOrderById = async (req, res) => {
    try {
        const order = await Order.findById(req.params.id)
            .populate(["userId"])
            .populate({ path: "bill", populate: { path: "billItems" } });
        if (!order) {
            return createResponse(res, 404, "Order not found");
        }

        return createResponse(res, 200, "Order found", order);
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Server Error");
    }
};


const createOrder = async (req, res) => {
    try {
        if (req.body.bill.length === 1) {
            // Create a single order
            const uid = await Order.find().sort({ createdAt: -1 }).limit(1);
            req.body.uid = (!uid || uid.length === 0) ? 1 : uid[0].uid + 1;

            const order = new Order(req.body);
            const createdOrder = await order.save();

            const bill = await Bill.findById(req.body.bill);
            bill.deliveryOrder = createdOrder._id;
            bill.dispatch.status = "dispatched";
            bill.dispatch.assigned = true;
            await bill.save();

            // Generate OTP for single order and store it
            const otp = OTP.generateOTP();
            createdOrder.deliveryOTP = otp;
            await createdOrder.save();

            // Send OTP to the customer
            //   sendOTPViaSMS(req.body.mobile, otp);
            // OTP.sendOTP(req.body.mobile, OTP.generateOTP);

            await Notification.create({
                userId: req.body.userId,
                title: "New Order Assigned",
                message: "You have been assigned 1 new order.",
            });

            return res.status(201).json({ message: "Order created successfully", order: createdOrder });
        } else {
            // Create multiple orders
            const orders = req.body.bill.map((billId) => ({
                userId: req.body.userId,
                uid: req.body.uid + 1,
                bill: billId,
            }));

            const createdOrders = await Order.insertMany(orders);

            // Update bill and generate OTP for each order
            for (let i = 0; i < createdOrders.length; i++) {
                const order = createdOrders[i];
                const bill = await Bill.findById(order.bill);
                bill.deliveryOrder = order._id;
                bill.dispatch.assigned = true;
                await bill.save();

                // Generate OTP for each order and store it
                const otp = OTP.generateOTP();
                order.deliveryOTP = otp;
                await order.save();
                console.log(otp);
                // Send OTP to the customer
                OTP.sendOTP(req.body.mobile, OTP.generateOTP);
            }

            await Notification.create({
                userId: req.body.userId,
                title: "New Order Assigned",
                message: `You have been assigned ${createdOrders.length} new orders.`,
            });

            return res.status(201).json({ message: "Orders created successfully", orders: createdOrders });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server Error" });
    }
};

const updateOrderToPaid = async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return createResponse(res, 404, "Order not found");
        }

        if (req.body.isDelivered === true) {
            req.body.isDelivered = true;
            req.body.deliveredAt = Date.now();
        }

        const orders = await Order.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
        });
        console.log(orders);
        if (req.body.paymentMode) {
            const bill = await Bill.findById(order.bill);
            bill.paymentMode = req.body.paymentMode;
            await bill.save();
        }
        if (orders.isDelivered === true) {
            const admins = await Admin.find({ role: "Admin" });
            let notificationObj = [];
            admins.forEach(async (admin) => {
                notificationObj.push({
                    userId: admin._id,
                    title: "Order Delivered",
                    message: `Order uid ${order.uid} has been delivered.`,
                });
            });
            await Notification.insertMany(notificationObj);
            // msg to customer for delivery on mobile
        }

        // await Notification.create({userId:

        if (!orders) {
            return createResponse(res, 404, "Order not found");
        }

        return createResponse(res, 200, "Order updated", orders);
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Server Error");
    }
};


const updateOrderToDelivered = async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return createResponse(res, 404, "Order not found");
        }

        order.isDelivered = true;
        order.deliveredAt = Date.now();

        const updatedOrder = await order.save();

        return createResponse(res, 200, "Order updated", updatedOrder);
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Server Error");
    }
};


const deleteOrder = async (req, res) => {
    try {
        const order = await Order.deleteMany();
        if (!order) {
            return createResponse(res, 404, "Order not found");
        }
        createResponse(res, 200, "Order deleted successfully", order);
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Server Error");
    }
};


const TodayOrder = async (req, res) => {
    try {
        const { date } = req.query; // Date parameter passed in the query string

        // Create a date range from the provided date to the next day
        const startDate = new Date(date);
        const endDate = new Date(date);
        endDate.setDate(endDate.getDate() + 1);

        // Query the database for orders delivered within the specified date range
        const orders = await Order.find({
            isDelivered: true,
            deliveredAt: { $gte: startDate, $lt: endDate },
        });

        res.json({ orders });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "An error occurred" });
    }
};

const OrderStatus = async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const order = await Order.findById(orderId);

        if (!order) {
            return res.status(404).json({ error: "Order not found" });
        }

        res.json({
            Status: 200,
            OrderStatus: order.deliveryStatus,
            message: `Order Status ${order.deliveryStatus}`
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

const verifyDeliveryOtp = async (req, res) => {
    const orderId = req.params.orderId;
    const { otp } = req.body;

    try {
        // Find the order by ID
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: "Order not found." });
        }
        console.log(order)
        // Check if the order is already delivered
        if (order.isDelivered) {
            return res.status(400).json({ message: "Order is already delivered." });
        }
        
        // Compare the provided OTP with the stored OTP
        if (otp === order.deliveryOTP) {
            // OTP is correct, mark the order as delivered and update deliveredAt timestamp
            order.isDelivered = true;
            order.deliveredAt = new Date();
            await order.save();

            return res.status(200).json({ message: "OTP verified. Order delivered successfully." });
        } else {
            return res.status(401).json({ message: "Invalid OTP. Delivery verification failed." });
        }
    } catch (err) {
        console.error("Error verifying OTP:", err);
        return res.status(500).json({ message: "An error occurred while verifying OTP." });
    }
};

const SubmitOrder = async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: "Order not found" });
        }

        const { paymentStatus, deliveryStatus, description } = req.body;

        if (paymentStatus && ["pending", "paid", "failed"].includes(paymentStatus)) {
            order.paymentStatus = paymentStatus;
        }

        if (deliveryStatus && ["pending", "delivered", "cancelled", "returned"].includes(deliveryStatus)) {
            order.deliveryStatus = deliveryStatus;
        }

        if (description) {
            order.description = description;
        }

        if (req.file) {
            order.image = {
                filename: req.file.filename,
                path: req.file.path,
            };
        }

        await order.save();

        res.status(200).json({
            message: "Order updated successfully",
            data: order
        });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
};


module.exports = {
    getOrderById,
    createOrder,
    updateOrderToPaid,
    updateOrderToDelivered,
    getOrders,
    getOrderSummary,
    deleteOrder,
    TodayOrder,
    OrderStatus,
    deliveryDetails,
    verifyDeliveryOtp,
    SubmitOrder,
    // deliveryDetailsVerifyOTP
};
