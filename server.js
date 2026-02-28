require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors());
app.use(express.json());

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

// Email Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Temporary in-memory store (we'll connect DB next step)
let users = {};

// Signup Route
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  const otp = generateOTP();

  users[email] = {
    password: await bcrypt.hash(password, 10),
    otp: otp,
    verified: false
  };

  await transporter.sendMail({
    to: email,
    subject: "Victris Studios OTP Verification",
    text: `Your OTP is ${otp}`
  });

  res.json({ message: "OTP sent to email" });
});

// Verify Route
app.post("/verify", async (req, res) => {
  const { email, otp } = req.body;

  if (!users[email] || users[email].otp !== otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  users[email].verified = true;

  const token = jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  res.json({ token });
});

app.get("/", (req, res) => {
  res.send("Victris Studios API is running 🚀");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running"));
