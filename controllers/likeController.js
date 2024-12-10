const Like = require('../models/Like');
const Post = require('../models/Post');

// Like a Post
exports.likePost = async (req, res) => {
   const { postId } = req.body;

   try {
      const existingLike = await Like.findOne({ user: req.user.id, post: postId });
      if (existingLike) {
         return res.status(400).json({ message: 'Post already liked' });
      }
      const newLike = new Like({ user: req.user.id, post: postId });
      const savedLike = await newLike.save();
      await Post.findByIdAndUpdate(postId, { $push: { likes: savedLike._id } });
      res.status(201).json(savedLike);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Unlike a Post
exports.unlikePost = async (req, res) => {
   const { postId } = req.body;

   try {
      const like = await Like.findOneAndDelete({ user: req.user.id, post: postId });
      if (!like) {
         return res.status(404).json({ message: 'Like not found' });
      }
      await Post.findByIdAndUpdate(postId, { $pull: { likes: like._id } });
      res.json({ message: 'Post unliked' });
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Get all likes for a post
exports.getPostLikes = async (req, res) => {
   const { postId } = req.params;

   try {
      const likes = await Like.find({ post: postId }).populate('user');
      res.json(likes);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Get all likes for a user
exports.getUserLikes = async (req, res) => {
   const { userId } = req.params;

   try {
      const likes = await Like.find({ user: userId }).populate('post');
      res.json(likes);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
}; 