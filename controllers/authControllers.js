const User = require('../models/User');
const Token = require('../models/Token');
const bcrypt = require('bcryptjs');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');

// Register a new user
exports.register = async (req, res) => {
    const { username, password, email } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword, email });
        await user.save();
        res.status(201).json({ message: 'Account Created Succesfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Request password reset
exports.requestPasswordReset = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'Unauthorized Access' });

        // Create a reset token
        const token = crypto.randomBytes(32).toString('hex');
        const resetToken = new Token({ userId: user._id, token });
        await resetToken.save();

        // Send email with reset link
        const resetLink = `http://localhost:5000/api/auth/reset-password/${token}`;
        await sendEmail(user.email, 'Password Reset', `Click this link to reset your password: ${resetLink}`);

        res.status(200).json({ message: 'Password reset link sent to your email' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Reset password
exports.resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const resetToken = await Token.findOne({ token });
        if (!resetToken) return res.status(400).json({ message: 'Invalid or expired token' });

        const user = await User.findById(resetToken.userId);
        if (!user) return res.status(404).json({ message: 'User  not found' });

        // Hash the new password
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        // Delete the token after use
        await Token.deleteOne({ _id: resetToken._id });

        res.status(200).json({ message: 'Password has been reset successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};