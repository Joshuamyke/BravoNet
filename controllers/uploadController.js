const User = require("../models/User");

// Upload profile picture
exports.uploadProfilePicture = async (req, res) => {
	try {
		const user = await User.findById(req.user.id);
		if (!user) return res.status(404).json({ message: "User not found" });

		user.profilePicture = req.file.path;
		await user.save();
		res
			.status(200)
			.json({
				message: "Profile picture updated",
				profilePicture: req.file.path,
			});
	} catch (error) {
		res.status(500).json({ message: "Server error", error });
	}
};