const User = require("../models/User");
const path = require("path");



// Update profile information
exports.updateProfile = async (req, res) => {
	try {
		const user = await User.findById(req.user.id);
		if (!user) return res.status(404).json({ message: "User  not found" });

		const { bio, location, dateOfBirth, privacy, username, name } = req.body;

		// Check if the username is already taken
		if (username && username !== user.username) {
			const existingUser  = await User.findOne({ username });
			if (existingUser ) {
				return res.status(400).json({ message: "Username already taken" });
			}
		}

		// Update user fields
		user.bio = bio || user.bio;
		user.location = location || user.location;
		user.dateOfBirth = dateOfBirth || user.dateOfBirth;
		user.privacy = privacy || user.privacy;
		user.name = name || user.name; // Only update if provided
		user.username = username || user.username; // Only update if provided

		await user.save();
		res.status(200).json({ message: "Profile updated successfully", user });
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: "Server error", error: error.message });
	}
};


// View user profile based on privacy settings
const User = require("../models/User");

// View user profile based on privacy settings
exports.viewProfile = async (req, res) => {
	try {
		const user = await User.findById(req.params.id).populate("friends", "username");
		if (!user) return res.status(404).json({ message: "User  not found" });

		// Check privacy settings
		if (user.privacy === "private" && user.id !== req.user.id) {
			return res.status(403).json({ message: "This profile is private" });
		}

		// Return user profile information
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
		console.error(error);
		res.status(500).json({ message: "Server error", error: error.message });
	}
};