const Post = require('../models/post');

// Create a new post
exports.createPost = async (req, res) => {
	try {
		const { content } = req.body;
		const media = req.file ? `/uploads/media/${req.file.filename}` : null;
		const mediaType = req.file ? req.file.mimetype.split('/')[0] : 'none';

		const newPost = new Post({
			userId: req.user._id,
			content,
			media,
			mediaType,
		});

		await newPost.save();
		res.status(201).json({ success: true, post: newPost });
	} catch (error) {
		res.status(500).json({ success: false, message: error.message });
	}
};

// Fetch the user's news feed
exports.fetchNewsFeed = async (req, res) => {
	try {
		const posts = await Post.find({ userId: { $in: req.user.connections } })
			.populate('userId', 'name profilePicture')
			.sort({ createdAt: -1 }); // Sort by the latest posts first

		res.status(200).json({ success: true, posts });
	} catch (error) {
		res.status(500).json({ success: false, message: error.message });
	}
};

// Like or unlike a post
exports.likePost = async (req, res) => {
	try {
		const post = await Post.findById(req.params.postId);
		if (!post) return res.status(404).json({ success: false, message: 'Post not found' });

		const isLiked = post.likes.includes(req.user._id);
		if (isLiked) post.likes.pull(req.user._id);
		else post.likes.push(req.user._id);

		await post.save();
		res.status(200).json({ success: true, likes: post.likes.length });
	} catch (error) {
		res.status(500).json({ success: false, message: error.message });
	}
};

// Add a comment to a post
exports.addComment = async (req, res) => {
	try {
		const { postId } = req.params;
		const { text } = req.body;

		const post = await Post.findById(postId);
		if (!post) return res.status(404).json({ success: false, message: 'Post not found' });

		const newComment = { userId: req.user._id, text };
		post.comments.push(newComment);
		await post.save();

		res.status(200).json({ success: true, comment: newComment });
	} catch (error) {
		res.status(500).json({ success: false, message: error.message });
	}
};

// Share a post
exports.sharePost = async (req, res) => {
	try {
		const { postId } = req.params;

		const post = await Post.findById(postId);
		if (!post) return res.status(404).json({ success: false, message: 'Post not found' });

		const newShare = { userId: req.user._id };
		post.shares.push(newShare);
		await post.save();

		res.status(200).json({ success: true, shares: post.shares.length });
	} catch (error) {
		res.status(500).json({ success: false, message: error.message });
	}
};