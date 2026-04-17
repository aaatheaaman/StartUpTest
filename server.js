require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const path = require("path");
const helmet = require("helmet");
const xss = require("xss");
const validator = require("validator");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const app = express();
app.disable("x-powered-by");

const morgan = require("morgan");
app.use(morgan("combined"));
app.use(cookieParser());

/* ================= DB CONNECT ================= */

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connected"))
    .catch(err => console.error("DB Error:", err));

/* ================= MODELS ================= */

const User = require("./models/User");
const Lead = require("./models/Lead");
const Request = require("./models/Request");
const Otp = require("./models/Otp");

/* ================= MIDDLEWARE ================= */

const allowedOrigins = [
    "http://localhost:5000",
    "http://localhost:3000",
    "http://127.0.0.1:5501",   // ✅ ADD THIS
    "http://localhost:5500",   // optional (Live Server alt port)
    "https://your-app.onrender.com",
    "https://energicainfra.com",
    "https://www.energicainfra.com"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true
}));

function validate(req, res, next) {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({
            message: "Validation error",
            errors: errors.array()
        });
    }

    next();
}

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'",
                    "https://cdn.tailwindcss.com",
                    "https://cdnjs.cloudflare.com",
                    "https://unpkg.com"
                ],
                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://fonts.googleapis.com",
                    "https://cdn.tailwindcss.com"
                ],
                fontSrc: [
                    "'self'",
                    "https://fonts.gstatic.com"
                ],
                imgSrc: ["'self'", "data:", "https://images.unsplash.com"],
                connectSrc: [
                    "'self'",
                    "http://localhost:5000",
                    "http://127.0.0.1:5501"
                ],
            }
        }
    })
);

app.use(
    helmet.hsts({
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    })
);


const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

/* ================= EMAIL ================= */

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.set("trust proxy", 1);

app.use((req, res, next) => {
    if (process.env.NODE_ENV === "production") {
        if (req.headers["x-forwarded-proto"] !== "https") {
            return res.redirect(`https://${req.headers.host}${req.url}`);
        }
    }
    next();
});

/* ================= HELPERS ================= */

function isValidEmail(email) {
    return validator.isEmail(email || "");
}

/* ================= AUTH ================= */

function auth(req, res, next) {
    const token = req.cookies.token || req.cookies.adminToken;

    if (!token)
        return res.status(401).json({ message: "No token" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // ✅ Check required fields
        if (!decoded.email || !decoded.role) {
            return res.status(401).json({ message: "Invalid token structure" });
        }

        // ✅ NEW: Validate role
        if (!["user", "admin"].includes(decoded.role)) {
            return res.status(401).json({ message: "Invalid role" });
        }

        req.user = decoded;
        next();

    } catch {
        res.status(401).json({ message: "Invalid/Expired token" });
    }
}


function isAdmin(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Forbidden" });
    }
    next();
}


if (!process.env.JWT_SECRET || !process.env.MONGO_URI) {
    console.error("❌ Missing environment variables");
    process.exit(1);
}


/* ================= ROUTES ================= */

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public/index.html"));
});

app.get("/me", auth, (req, res) => {
    res.json(req.user);
});

/* ================= REGISTER ================= */

app.post(
    "/register",
    [
        body("username").trim().isLength({ min: 3, max: 30 }).escape(),
        body("email").isEmail().normalizeEmail(),
        body("password").isLength({ min: 6 })
    ],
    validate,

    asyncHandler(async (req, res) => {
        const { username, email, password } = req.body;

        const exists = await User.findOne({ email });
        if (exists) {
            const err = new Error("User exists");
            err.status = 400;
            throw err;
        }

        const hashed = await bcrypt.hash(password, 10);

        await User.create({ username, email, password: hashed });

        res.json({ message: "Registered successfully" });
    })
);


/* ================= LOGIN ================= */

app.post(
    "/login",
    [
        body("email").isEmail().normalizeEmail(),
        body("password").notEmpty()
    ],
    validate,

    asyncHandler(async (req, res) => {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            const err = new Error("User not found");
            err.status = 400;
            throw err;
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            const err = new Error("Wrong password");
            err.status = 400;
            throw err;
        }

        const token = jwt.sign(
            {
                email: user.email,
                username: user.username,
                role: "user"
            },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res
            .cookie("token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "Lax",
                maxAge: 60 * 60 * 1000 // 1 hour
            })
            .json({ email, username: user.username });
    })
);


app.post("/logout", (req, res) => {
    res.clearCookie("token");
    res.clearCookie("adminToken");
    res.json({ message: "Logged out" });
});


/* ================= FORGOT PASSWORD (FIXED 🔥) */

app.post(
    "/forgot-password",
    [
        body("email").isEmail().normalizeEmail()
    ],
    validate,

    asyncHandler(async (req, res) => {
        const email = xss(req.body.email).trim().toLowerCase();

        const existing = await Otp.findOne({ email });

        if (existing && existing.expires > Date.now()) {
            const err = new Error("Wait before requesting again");
            err.status = 429;
            throw err;
        }

        const rawOtp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await bcrypt.hash(rawOtp, 10);

        await Otp.findOneAndUpdate(
            { email },
            {
                otp: hashedOtp,
                expires: Date.now() + 5 * 60 * 1000,
                verified: false
            },
            { upsert: true }
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Password Reset OTP",
            text: `Your OTP is: ${rawOtp}`
        });

        res.json({ message: "OTP sent successfully" });
    })
);

/* ================= VERIFY OTP (FIXED 🔥) */

app.post("/verify-otp", asyncHandler(async (req, res) => {
    const email = xss(req.body.email || "").trim().toLowerCase();
    const otp = xss(req.body.otp || "").trim();

    const record = await Otp.findOne({ email });

    if (!record) return res.status(400).json({ message: "No OTP" });
    if (record.verified) return res.status(400).json({ message: "OTP already used" });

    const isMatch = await bcrypt.compare(otp, record.otp);

    if (!isMatch) return res.status(400).json({ message: "Invalid OTP" });
    if (record.expires < Date.now()) return res.status(400).json({ message: "Expired OTP" });

    record.verified = true;
    await record.save();

    res.json({ message: "Verified" });
}));

/* ================= RESET PASSWORD ================= */

app.post(
    "/reset-password",
    [
        body("email").isEmail().normalizeEmail(),
        body("password").isLength({ min: 6 })
    ],
    validate,

    asyncHandler(async (req, res) => {
        const email = xss(req.body.email).trim().toLowerCase();
        const password = req.body.password;

        const record = await Otp.findOne({ email });

        if (!record || !record.verified) {
            const err = new Error("OTP not verified");
            err.status = 400;
            throw err;
        }

        const user = await User.findOne({ email });
        if (!user) {
            const err = new Error("User not found");
            err.status = 400;
            throw err;
        }

        user.password = await bcrypt.hash(password, 10);
        await user.save();

        await Otp.deleteOne({ email });

        res.json({ message: "Password reset successful" });
    })
);

/* ================= ADMIN LOGIN ================= */

app.post("/admin-login", asyncHandler(async (req, res) => {
    const email = xss(req.body.email).trim().toLowerCase();
    const password = xss(req.body.password).trim();

    if (email !== process.env.ADMIN_EMAIL) {
        const err = new Error("Invalid credentials");
        err.status = 400;
        throw err;
    }

    const match = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);

    if (!match) {
        const err = new Error("Invalid credentials");
        err.status = 400;
        throw err;
    }

    const token = jwt.sign(
        { email, role: "admin" },
        process.env.JWT_SECRET,
        { expiresIn: "2h" }
    );

    res
        .cookie("adminToken", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Lax",
            maxAge: 2 * 60 * 60 * 1000
        })
        .json({ message: "Admin login successful" });
}));

/* ================= LEADS ================= */

function anyAuth(req, res, next) {
    const token = req.cookies.adminToken || req.cookies.token;

    if (!token) return res.status(401).json({ message: "No token" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ message: "Invalid token" });
    }
}


app.get("/leads", anyAuth, asyncHandler(async (req, res) => {

    // 👤 USER → only own leads
    if (req.user.role !== "admin") {
        const leads = await Lead.find({ email: req.user.email })
            .sort({ createdAt: -1 })
            .lean();

        return res.json(leads);
    }

    // 👑 ADMIN → all leads
    const leads = await Lead.find()
        .sort({ createdAt: -1 })
        .lean();

    res.json(leads);
}));

app.post(
    "/leads",
    auth,
    asyncHandler(async (req, res) => {
        const lead = new Lead({
            ...req.body,
            username: req.user.username || "User",
            email: req.user.email // 🔥 ADD THIS
        });

        await lead.save();

        res.json({ message: "Saved", lead });
    })
);


app.get("/test-lead", async (req, res) => {
    const lead = new Lead({
        title: "Solar Plant",
        capacity: "100MW",
        username: "Test User",
        email: "test@gmail.com"
    });

    await lead.save();

    res.json({ message: "Test lead added" });
});

app.delete("/leads/:id", auth, isAdmin, async (req, res) => {
    await Lead.deleteOne({ _id: req.params.id });
    res.json({ message: "Deleted" });
});

/* ================= REQUESTS ================= */

app.get("/requests", auth, async (req, res) => {
    const data = await Request.find().sort({ time: -1 });

    res.json(data.map(d => ({
        ...d._doc,
        id: d._id
    })));
});

app.post(
    "/requests",
    auth,
    [
        body("assetId").notEmpty()
    ],
    validate,

    asyncHandler(async (req, res) => {
        const newReq = new Request({
            assetId: req.body.assetId,
            email: req.user.email // ✅ from token
        });

        await newReq.save();

        res.json({ message: "Saved" });
    })
);

app.delete("/requests/:id", auth, isAdmin, async (req, res) => {
    await Request.deleteOne({ _id: req.params.id });
    res.json({ message: "Deleted" });
});


app.use((err, req, res, next) => {
    console.error("🔥 ERROR:", err.message);

    res.status(err.status || 500).json({
        message: err.message || "Internal Server Error"
    });
});

/* ================= START ================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});