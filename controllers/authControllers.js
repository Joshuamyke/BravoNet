const User = require("../models/User");
const Token = require("../models/Token");
const bcrypt = require("bcryptjs");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const generateOTP = () => {
	const otpCode = crypto.randomInt(100000, 999999).toString();

	return otpCode;
};

// Register User
exports.register = async (req, res) => {
	const { name, email, dateOfBirth, password, confirmPassword } = req.body;

	try {
		if (password !== confirmPassword) {
			return res.status(400).json({ message: "Passwords do not match" });
		}

		const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		if (!emailRegex.test(email)) {
			return res.status(400).json({ message: "Invalid email format" });
		}

		let user = await User.findOne({ email });
		if (user) {
			return res.status(400).json({ message: "User  already exists" });
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		user = new User({
			name,
			email,
			dateOfBirth,
			password: hashedPassword,
		});
		await user.save();
		res.status(201).json({ message: "Account Created successfully" });
	} catch (error) {
		console.error(error);
		return res
			.status(500)
			.json({ message: "An error occurred, please try again later." });
	}
};

// Login User
exports.login = async (req, res) => {
	const { email, password } = req.body;

	try {
		const user = await User.findOne({ email });
		if (!user || !(await bcrypt.compare(password, user.password))) {
			return res.status(401).json({ message: "Invalid credentials" });
		}
		const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
			expiresIn: "1h",
		});
		res
			.status(200)
			.json({ message: "Login successful", userId: user._id, token });
	} catch (error) {
		console.error(error);
		return res
			.status(500)
			.json({ message: "An error occurred, please try again later." });
	}
};

// Request Password Reset
exports.forgotPassword = async (req, res) => {
	const { email } = req.body;

	try {
		const user = await User.findOne({ email });
		if (!user) return res.status(404).json({ message: "User  not found" });

		// Generate OTP
		const otp = generateOTP();
		const saltRounds = 10;
		const hashedOtp = await bcrypt.hash(otp, saltRounds);

		user.otp = hashedOtp;
		user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
		await user.save();

		// Send OTP via email
		await sendEmail(email, "Password Reset OTP", `Your OTP is ${otp}`);

		res.status(200).json({ message: "OTP sent to email" });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};

exports.verifyOtp = async (req, res) => {
	const { otp } = req.body;

	if (!otp) {
		return res.status(400).json({ message: "OTP code is required" });
	}

	try {
		// Find the user with the OTP (assuming OTP is unique)
		const user = await User.findOne({ otp });
		if (!user) {
			return res.status(404).json({ message: "User  not found or OTP is invalid" });
		}

		// Check if OTP hasn't expired
		if (Date.now() > user.otpExpires) {
			return res.status(400).json({ message: "OTP is expired" });
		}

		// Compare the hashed OTP with the one entered by the user
		const isOtpValid = await bcrypt.compare(otp, user.otp);
		if (!isOtpValid) {
			return res.status(400).json({ message: "Invalid OTP code" });
		}

		// Clear the OTP and expiration time after successful verification
		user.otp = null; // Clear the OTP
		user.otpExpires = null; // Clear the expiration time

		// Save the user object
		await user.save();

		res.status(200).json({
			message: "OTP verified successfully",
		});
	} catch (error) {
		console.error(error);
		return res.status(500).json({ message: "Server error: " + error.message });
	}
};

// Reset Password
exports.resetPassword = async (req, res) => {
	const { email, newPassword } = req.body;

	try {
		const user = await User.findOne({ email });
		// Check if OTP exists and hasn't expired
		if (!user.otp || Date.now() > user.otpExpires) {
			return res.status(400).json({ message: "OTP is expired or invalid" });
		}

		user.password = await bcrypt.hash(newPassword, 10);
		user.otp = null; // Clear OTP after use
		user.otpExpires = null; // Clear OTP expiration
		await user.save();
		res.status(200).json({ message: "Password reset successfully" });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};
