const User = require("../models/user");
const Token = require("../models/Token");
const bcrypt = require("bcryptjs");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");

// Register User
exports.register = async (req, res) => {
	const { name, email, dateOfBirth, password, confirmPassword } = req.body;

	try {
        let user = await User.findOne({ email });

        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }
        if(user) {
            return res.status(400).json({ message: "User already exists" });
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
        return res.status(500).json({ message: error.message });
    }
};

// Login User
exports.login = async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });
	if (!user || !(await bcrypt.compare(password, user.password))) {
		return res.status(401).json({ message: "Invalid credentials" });
	}
	const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
		expiresIn: "1h",
	});
	res.json({ token });
};

// Request Password Reset
exports.requestPasswordReset = async (req, res) => {
	const { email } = req.body;
	const user = await User.findOne({ email });
	if (!user) return res.status(404).json({ message: "User  not found" });

	// Generate OTP
	const otp = Math.floor(100000 + Math.random() * 900000).toString();
	user.otp = otp;
	user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
	await user.save();

	// Send OTP via email
	const transporter = nodemailer.createTransport({
		service: "gmail",
		auth: {
			user: process.env.EMAIL_USER,
			pass: process.env.EMAIL_PASS,
		},
	});

	await transporter.sendMail({
		to: email,
		subject: "Password Reset OTP",
		text: `Your OTP is ${otp}`,
	});

	res.json({ message: "OTP sent to email" });
};

// Reset Password
exports.resetPassword = async (req, res) => {
	const { email, otp, newPassword } = req.body;
	const user = await User.findOne({ email });

	if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
		return res.status(400).json({ message: "Invalid or expired OTP" });
	}

	user.password = await bcrypt.hash(newPassword, 10);
	user.password = null; // Clear OTP after use
	user.otpExpires = null; // Clear OTP expiration
	await user.save();
	res.json({ message: "Password reset successfully" });
};
