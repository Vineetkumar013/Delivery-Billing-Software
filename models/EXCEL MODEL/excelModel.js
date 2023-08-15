const mongoose = require("mongoose");

const ExcelbillSchema = new mongoose.Schema({
"Bill Date": String,
"Bill No.": String,
"Party Name": String,
"Address Detail": String,
"Phone No.": Number,
"Bill Amount": Number,
"MR Name": String,
"Area": String,
"Rout": String,
"Wight": Number,
"Payment Method": String,
"Expected Del. Date": Number,
"Item Name": String,
"MRP": Number,
"Batch": String,
"Exp.": String,
"Quantity": Number,
"Pillot No.": String
},
{ timestamps: true }
);
module.exports = mongoose.model("Excelbill", ExcelbillSchema);