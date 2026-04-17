// models/Otp.js
const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
    email: String,
    otp: String,
    expires: {
        type: Date,
        index: { expires: 0 }
    },
    verified: { type: Boolean, default: false }
});

module.exports = mongoose.model("Otp", otpSchema);