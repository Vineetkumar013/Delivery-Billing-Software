const Delivery = require("../models/user");
const Order = require("../models/order");
const bcrypt = require("bcryptjs");

const Deliverysignup = async (req, res) => {
  try {
    const { email, employeeId, password, confirmPassword, name, mobile } = req.body;
    console.log(req.body);
    const emailExists = await Delivery.findOne({ email, role: "PACKER" });
    if (emailExists) {
      return res.status(401).json({
        message: "Email Number Already Exists",
      });
    }


    if (employeeId) {
      const existingEmployee = await Delivery.findOne({ employeeId });
      if (existingEmployee) {
        errors.push("EmployeeId already in use");
      }
    }

    if (mobile) {
      const existingMobile = await Delivery.findOne({ mobile });
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
    const user = await Delivery.create({
      email: email,
      employeeId: employeeId,
      confirmPassword: hashedPassword1,
      password: hashedPassword,
      otp: otp,
      role: "DELIVERY",
      name: name,
      mobile: mobile
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


// const provideDeliveryReason = async (req, res) => {
//   try {
//     const deliveryId = req.params.id;
//     const { description } = req.body;

//     const delivery = await Delivery.findById(deliveryId);

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     // Update the delivery with the provided reason
//     delivery.description = description;
//     await delivery.save();

//     res.status(200).json({ message: "Delivery reason provided successfully" });
//   } catch (error) {
//     console.log(error);
//     res.status(500).json({ message: error.message });
//   }
// };


const provideDeliveryReason = async (req, res) => {
  try {
    const  orderId = req.params.id;
    console.log(orderId);

    const { deliveryStatus, description } = req.body;

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    order.deliveryStatus = deliveryStatus;
    order.description = description;

    if (deliveryStatus === "delivered") {
      order.isDelivered = true;
      order.deliveredAt = new Date();
    }

    await order.save();

    res.json({ message: "Delivery status updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
}

const deliverOrder = async (req, res) => {
  try {
    const orderId = req.params.id;
    const order = await Order.findById(orderId);
    console.log(order)
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    if (order.deliveryStatus !== "pending") {
      return res.status(400).json({ message: "Order cannot be delivered. Delivery status is not pending." });
    }

    // Update the order status to delivered
    order.deliveryStatus = "delivered";
    order.isDelivered = true;
    order.deliveredAt = new Date();
    await order.save();

    res.status(200).json({ message: "Order delivered successfully", order });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to deliver order" });
  }
};



const AssignToDelivery = async (req, res) => {
  const { orderId } = req.params;
  const { deliveryId } = req.body;

  try {
    // Find the order by its ID
    const order = await Order.findById(orderId);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Check if the delivery person exists and has the DELIVERY role
    const deliveryPerson = await Delivery.findOne({
      _id: deliveryId,
      role: 'DELIVERY'
    });

    if (!deliveryPerson) {
      return res.status(404).json({ message: 'Delivery person not found' });
    }

    // Assign the order to the delivery person
    order.deliveryPersonId = deliveryPerson._id;

    // Save the updated order
    await order.save();

    res.status(200).json({ message: 'Order assigned successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = {
  provideDeliveryReason,
  Deliverysignup,
  deliverOrder,
  AssignToDelivery
}