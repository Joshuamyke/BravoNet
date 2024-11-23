const User = require("../models/User");
const path = require("path");

// Update profile information
exports.updateProfile = async (req, res) => {
	try {
		const user = await User.findById(req.user.id);
		if (!user) return res.status(404).json({ message: "User not found" });

		const { bio, location, dateOfBirth, privacy, username, name } = req.body;
		user.bio = bio || user.bio;
		user.location = location || user.location;
		user.dateOfBirth = dateOfBirth || user.dateOfBirth;
		user.privacy = privacy || user.privacy;
		user.name = name;
		user.username = username;

		await user.save();
		res.status(200).json({ message: "Profile updated successfully", user });
	} catch (error) {
		res.status(500).json({ message: "Server error", error });
	}
};



// View user profile based on privacy settings
exports.viewProfile = async (req, res) => {
	try {
		const user = await User.findById(req.params.id).populate(
			"friends",
			"username"
		);
		console.log(user);
		if (!user) return res.status(404).json({ message: "User not found" });

		if (user.privacy === "private" && user.id !== req.user.id) {
			return res.status(403).json({ message: "This profile is private" });
		}

		res.status(200).json({
			name: user.name,
			username: user.username,
			bio: user.bio,
			location: user.location,
			dateOfBirth: user.dateOfBirth,
			friends: user.friends,
			profilePicture: user.profilePicture,
		});
	} catch (error) {
		res.status(500).json({ message: "Server error", error });
	}
};

