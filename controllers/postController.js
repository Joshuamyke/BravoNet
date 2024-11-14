const User = require("../models/user");
const Post = require("../models/post");


// Create post
exports.createPost = async (req, res) => {
	const { content } = req.body;

	const media = req.files ? req.files.map((file) => file.path) : [];

	try {
		const post = await Post.create({ userId: req.user.id, content, media });
		res.status(200).json({message: "Post created successfully", post });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

// Get news feed
// exports.getNewsFeed = async (req, res) => {
// 	try {
// 		const posts = await Post.find()
// 			.sort({ createdAt: -1 })
// 			.limit(50)
// 			.populate("userId", "username profilePicture")
// 			.populate("comments.userId", "username profilePicture")
// 			.populate("likes", "username profilePicture");
//         console.log(posts)
// 		res.status(200).json(posts);
// 	} catch (error) {
// 		res.status(500).json({ error: error.message });
// 	}
// };

exports.getNewsFeed = async (req, res) => {
	try {
		const posts = await Post.find()
			.sort({ createdAt: -1 })
			.limit(50)
        console.log(posts)
		res.status(200).json(posts);
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};
