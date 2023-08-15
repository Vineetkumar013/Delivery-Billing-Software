const ExcelBill = require("../../models/EXCEL MODEL/excelModel");
const User = require("../../models/user");
const { createResponse } = require("../../utils/response");
const Notification = require("../../models/notification");
const xlsx = require('xlsx');

const excelBill = async (req, res) => {
    console.log(`Hye from excel side`)
    try {
        const workbook = xlsx.readFile(req.file.path);
        console.log(workbook)
        const sheetName = workbook.SheetNames[0];
        const jsonData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
        console.log(jsonData);
        for (let i = 0; i < jsonData.length; i++) {
            await ExcelBill.create(jsonData[i])
        }
        // const insertedData =  await Billing.insertMany(jsonData);
        // console.log(insertedData);
        console.log(jsonData)
        res.status(200).json({
            Total: jsonData.length,
            msg: "Fetched the excel data successfully",
            data: jsonData
        });
    } catch (error) {
        console.log(error)
        res.status(500).json({ error: error.message });
    }
}

const getAllExcelBill = async (req, res) => {
  try {
    const allBills = await ExcelBill.find();
    res.status(200).json({
      Total: allBills.length,
      msg: "Fetched all bills successfully",
      data: allBills,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

const getExcelBillById = async (req, res) => {
  const { id } = req.params;
  try {
    const bill = await ExcelBill.findById(id);
    if (!bill) {
      return res.status(404).json({ msg: "Bill not found" });
    }
    res.status(200).json({
      msg: "Fetched bill successfully",
      data: bill,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const deleteExcelBillById = async (req, res) => {
  const { id } = req.params;
  try {
    const bill = await ExcelBill.findByIdAndDelete(id);
    if (!bill) {
      return res.status(404).json({ msg: "Bill not found" });
    }
    res.status(200).json({
      msg: "Deleted bill successfully",
      data: bill,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const updateExcelBillById = async (req, res) => {
  const { id } = req.params;
  const updatedData = req.body;
  try {
    const bill = await ExcelBill.findByIdAndUpdate(id, updatedData, {
      new: true,
    });
    if (!bill) {
      return res.status(404).json({ msg: "Bill not found" });
    }
    res.status(200).json({
      msg: "Updated bill successfully",
      data: bill,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const assignBillToPicker = async (req, res) => {
    const { id } = req.params;
    const { pickerId } = req.body;
    try {
        const billing = await ExcelBill.findById(id);
        if (!billing) {
            createResponse(res, 404, "Bill not found");
            return;
        }
        console.log(pickerId, " ", billing.picker.pickerAssignee);
        billing.picker.pickerAssignee = pickerId;
        await billing.save();
        const notification = await Notification.create({
            userId: pickerId,
            title: "New Bill Assigned",
            message: `You have been assigned a bill`,
        });
        console.log(billing.picker.pickerAssignee);
        createResponse(res, 200, "Bill assigned to picker successfully", notification);
    } catch (error) {
        console.log(error);
        createResponse(res, 500, "Server error");
    }
};








module.exports = {
  excelBill,
  getAllExcelBill,
  getExcelBillById,
  deleteExcelBillById,
  updateExcelBillById,
  assignBillToPicker
}