// models/Request.js
const mongoose = require("mongoose");

const requestSchema = new mongoose.Schema({
    assetId: String,
    email: String,
    time: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Request", requestSchema);