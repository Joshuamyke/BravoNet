const Post = require('../models/Post');
const path = require('path');

// Create a new post
exports.createPost = async (req, res) => {
  try {
    const { id } = req.user;
    const { content } = req.body;

    const files = req.files || [];

    files.forEach((file) => {
      console.log(`Fieldname: ${file.fieldname}, Originalname: ${file.originalname}`);
    });

    let media = [];
    if (req.files && req.files.length > 0) {
      media = req.files.map((file) => path.join(__dirname, '../uploads/media', file.filename));
    }

    const mediaType = req.file ? req.file.mimetype.split('/')[0] : 'none';

    const newPost = new Post({
      userId: id,
      content,
      media,
      mediaType,
    });

    await newPost.save();
    res.status(201).json({ success: true, post: newPost });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Get Posts Feed
exports.getPostsFeed = async (req, res) => {
  try {
    const posts = await Post.find({ user: { $in: req.user.friends } }).populate('user', 'name');
    res.status(200).json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
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

// Update Post
exports.updatePost = async (req, res) => {
  const { postId, content, media } = req.body;

  try {
    const post = await Post.findById(postId);
    if (!post || post.user.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    post.content = content || post.content;
    post.media = media || post.media;
    await post.save();
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete Post
exports.deletePost = async (req, res) => {
  const { postId } = req.body;

  try {
    const post = await Post.findById(postId);
    if (!post || post.user.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    await post.remove();
    res.json({ message: 'Post deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Add Post Validation
exports.validatePost = async (req, res, next) => {
  try {
    const { content } = req.body;
    if (!content) {
      return res.status(400).json({ message: 'Content is required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Add Post Authorization
exports.authorizePost = async (req, res, next) => {
  try {
    const { postId } = req.params;
    const post = await Post.findById(postId);
    if (!post || post.user.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Add Post Error Handling
exports.errorHandler = (error, req, res, next) => {
  res.status(500).json({ error: error.message });
};

// Add Post Logging
exports.logPost = async (req, res, next) => {
  try {
    const { postId } = req.params;
    const post = await Post.findById(postId);
    console.log(`Post ${postId} accessed by user ${req.user.id}`);
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};