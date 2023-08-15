// const mongoose = require("mongoose");

// const dispatchSchema = new mongoose.Schema({
//             urgencyColor: {
//                 type: String,
//                 default: "green",
//             },
//             reassignStatus: {
//                 type: Boolean,
//                 default: false,
//             },
//             status: {
//                 type: String,
//                 enum: [
//                     "cancelled",
//                     "dispatched",
//                     "ready to dispatch",
//                     "return",
//                     "pending",
//                 ],
//                 default: "pending",
//             },
//             assigned: {
//                 type: Boolean,
//                 default: false,
//             },
//             dispatchAssignee: {
//                 type: mongoose.SchemaTypes.ObjectId,
//                 ref: "Admin",
//             },
//             comment: {
//                 type: String,
//                 default: "",
//             },
//             boxQuantity: {
//                 type: Number,
//                 default: 0,
//             },
//             polyPackQuantity: {
//                 type: Number,
//                 default: 0,
//             },
//             acceptanceStatus: {
//                 type: String,
//                 default: "pending",
//                 enum: ["pending", "accepted", "rejected"],
//             },
//             reassign: {
//                 type: String,
//                 default: "No",
//                 enum: ["Yes", "No"],
//             },
//             orderStatus: {
//                 type: String,
//                 default: "pending",
//                 enum: ["pending", "completed", "cancelled"],
//             },
// });

// module.exports = mongoose.model("dispatch", dispatchSchema);