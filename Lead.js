// models/Lead.js
const mongoose = require("mongoose");

const leadSchema = new mongoose.Schema({
    title: String,
    tech: String,
    capacity: String,
    tariff: String,
    distance: String,
    email: String,
    username: String
}, { timestamps: true });

module.exports = mongoose.model("Lead", leadSchema);