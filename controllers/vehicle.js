const Vehicle = require("../models/vehicle");
const { createResponse } = require("../utils/response");
// Assuming the upload middleware is in a separate file
const Delivery = require("../models/user");
const cloudinary = require("cloudinary").v2;
const getVehicles = async (req, res) => {
    try {
        let queryObj = {};
        if (req.query.userId) {
            queryObj = { userId: req.query.userId };
        }
        const vehicles = await Vehicle.find(queryObj).populate("userId");
        return createResponse(
            res,
            200,
            "Vehicles retrieved successfully",
            vehicles
        );
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Internal server error");
    }
};


const createVehicle = async (req, res) => {
  try {
    const {
      userId,
      vehicleType,
      model,
      pollutionCard,
      insurance,
      vehicleNumber
    } = req.body;

      const vehicleImage = req.files["image"][0].path;
    //   console.log(vehicleImage);
    const registrationCertificate = req.files["registrationCertificate"][0].path;

    const vehicle = new Vehicle({
      userId,
      vehicleType,
      model,
      pollutionCard,
      insurance,
      image:vehicleImage,
      registrationCertificate:registrationCertificate,
      vehicleNumber
    });

    await vehicle.save();

      res.status(201).json({
          status:200,
          message:"Vehicle Add successfully",
          data: vehicle
      });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
};

const updateVehicle = async (req, res) => {
    try {
        const { id } = req.params;

        const vehicle = await Vehicle.findByIdAndUpdate(id, req.body, {
            new: true,
        }).populate("userId");
        return createResponse(
            res,
            200,
            "Vehicle updated successfully",
            vehicle
        );
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Internal server error");
    }
};

const deleteVehicle = async (req, res) => {
    try {
        const { id } = req.params;
        await Vehicle.findByIdAndDelete(id);
        return createResponse(res, 200, "Vehicle deleted successfully");
    } catch (error) {
        console.error(error);
        return createResponse(res, 500, "Internal server error");
    }
};

const provideDeliveryReason = async (req, res) => {
    try {
        const deliveryId = req.params.id;
        const { reason } = req.body;

        const delivery = await Delivery.findById(deliveryId);

        if (!delivery) {
            return res.status(404).json({ message: "Delivery not found" });
        }

        // Update the delivery with the provided reason
        delivery.reason = reason;
        await delivery.save();

        res.status(200).json({ message: "Delivery reason provided successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: error.message });
    }
};


module.exports = {
    getVehicles,
    createVehicle,
    updateVehicle,
    deleteVehicle,
    provideDeliveryReason
};
