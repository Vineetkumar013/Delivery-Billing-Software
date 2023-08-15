const mongoose = require("mongoose");

const billingSchema = new mongoose.Schema(
    {
        customerName: {
            type: String,
            required: true,
        },
        urgencyColor: {
            type: String,
            default: "green",
        },
        billingDate: {
            type: Date,
            required: true,
        },
        billNumber: {
            type: String,
            unique: true,
            default: "",
            required: true,
        },
        partName: {
            type: String,
        },
        billingAddress: {
            type: String,
            default: "",
            required: true,
        },
        mobile: {
            type: String,
            default: "",
            required: true,
        },
        billAmount: {
            type: Number,
        },
        location: {
            type: Array,
            default: [],
        },
        mrName: {
            type: String,
            default: "",
            required: true,
        },
        area: {
            type: String,
            default: "",
            required: true,
        },
        route: {
            type: String,
            default: "",
            required: true,
        },
        weight: {
            type: String,
            default: "",
            required: true,
        },

        paymentMode: {
            type: String,
            default: "",
        },
        expectedDelivery: {
            type: Date,
        },
        comment: {
            type: String,
            default: "",
        },

        // packing: {
        //     type: String,
        //     default: "",
        // },

        assignedBillitem: {
            type: mongoose.SchemaTypes.ObjectId,
            ref: "user",
        },
        billItems: {
            type: [mongoose.SchemaTypes.ObjectId],
            ref: "BillItems",
            default: [],
        },
        picker: {
            urgencyColor: {
                type: String,
                default: "green",
            },
            status: {
                type: String,
                enum: ["pending", "picked", "reassign", "completed"],
                default: "pending",
            },
            reassignStatus: {
                type: Boolean,
                default: false,
            },

            numberOfTrays: {
                type: Number,
                default: 0,
            },
            pickerAssignee: {
                type: mongoose.SchemaTypes.ObjectId,
                // ref: "Picker",
                ref: "user"
            },
            assigned: {
                type: Boolean,
                default: false,
            },

            comment: {
                type: String,
                default: "",
            },
            acceptanceStatus: {
                type: String,
                default: "pending",
                enum: ["pending", "accepted", "rejected"],
            },
            reassign: {
                type: String,
                default: "No",
                enum: ["Yes", "No"],
            },
        },
        verifier: {
            urgencyColor: {
                type: String,
                default: "green",
            },
            status: {
                type: String,
                enum: ["pending", "verified", "reassign"],
                default: "pending",
            },
            assigned: {
                type: Boolean,
                default: false,
            },
            reassignStatus: {
                type: Boolean,
                default: false,
            },
            verifierAssignee: {
                type: mongoose.SchemaTypes.ObjectId,
                ref: "VerifierBill",
            },

            comment: {
                type: String,
                default: "",
            },
            acceptanceStatus: {
                type: String,
                default: "pending",
                enum: ["pending", "accepted", "rejected"],
            },
            reassign: {
                type: String,
                default: "No",
                enum: ["Yes", "No"],
            },
        },
        packer: {
            urgencyColor: {
                type: String,
                default: "green",
            },
            status: {
                type: String,
                enum: ["pending", "packed", "reassign", "completed"],
                default: "pending",
            },
            assigned: {
                type: Boolean,
                default: false,
            },
            reassignStatus: {
                type: Boolean,
                default: false,
            },
            packerAssignee: {
                type: mongoose.SchemaTypes.ObjectId,
                ref: "user",
            },
            packet: {
                type: String,
                default: "",
            },

            comment: {
                type: String,
                default: "",
            },
            acceptanceStatus: {
                type: String,
                default: "pending",
                enum: ["pending", "accepted", "rejected"],
            },
            reassign: {
                type: String,
                default: "No",
                enum: ["Yes", "No"],
            },
        },
        dispatch: {
            urgencyColor: {
                type: String,
                default: "green",
            },
            reassignStatus: {
                type: Boolean,
                default: false,
            },
            status: {
                type: String,
                enum: [
                    "cancelled",
                    "dispatched",
                    "ready to dispatch",
                    "return",
                    "pending",
                ],
                default: "pending",
            },
            assigned: {
                type: Boolean,
                default: false,
            },
            dispatchAssignee: {
                type: mongoose.SchemaTypes.ObjectId,
                ref: "user",
            },
            comment: {
                type: String,
                default: "",
            },
            boxQuantity: {
                type: Number,
                default: 0,
            },
            polyPackQuantity: {
                type: Number,
                default: 0,
            },
            acceptanceStatus: {
                type: String,
                default: "pending",
                enum: ["pending", "accepted", "rejected"],
            },
            reassign: {
                type: String,
                default: "No",
                enum: ["Yes", "No"],
            },
            orderStatus: {
                type: String,
                default: "pending",
                enum: ["pending", "completed", "cancelled"],
            },
        },
    },
{ timestamps: true }
);

module.exports = mongoose.model("Billing", billingSchema);

// const billingSchema = new mongoose.Schema({
// "Bill Date": String,
// "Bill No.": String,
// "Party Name": String,
// "Address Detail": String,
// "Phone No.": Number,
// "Bill Amount": Number,
// "MR Name": String,
// "Area": String,
// "Rout": String,
// "Wight": Number,
// "Payment Method": String,
// "Expected Del. Date": Number,
// "Item Name": String,
// "MRP": Number,
// "Batch": String,
// "Exp.": String,
// "Quantity": Number,
// "Pillot No.": String
// },
// { timestamps: true }
// );
// module.exports = mongoose.model("Billing", billingSchema);
