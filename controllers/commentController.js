const Comment = require('../models/Comment');
const Post = require('../models/Post');

// Create Comment
exports.createComment = async (req, res) => {
   const { postId, content } = req.body;

   if (!postId || !content) {
      return res.status(400).json({ error: 'Post ID and content are required' });
   }

   try {
      const newComment = new Comment({ user: req.user.id, post: postId, content });
      await newComment.save();
      await Post.findByIdAndUpdate(postId, { $push: { comments: newComment._id } });
      res.status(201).json(newComment);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Get Comments for a Post
exports.getComments = async (req, res) => {
   const { postId } = req.params;

   if (!postId) {
      return res.status(400).json({ error: 'Post ID is required' });
   }

   try {
      const comments = await Comment.find({ post: postId }).populate('user', 'name');
      res.json(comments);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Update Comment
exports.updateComment = async (req, res) => {
   const { commentId, content } = req.body;

   if (!commentId || !content) {
      return res.status(400).json({ error: 'Comment ID and content are required' });
   }

   try {
      const comment = await Comment.findById(commentId);
      if (!comment || comment.user.toString() !== req.user.id) {
         return res.status(403).json({ message: 'Not authorized' });
      }
      comment.content = content;
      await comment.save();
      res.json(comment);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Delete Comment
exports.deleteComment = async (req, res) => {
   const { commentId } = req.body;

   if (!commentId) {
      return res.status(400).json({ error: 'Comment ID is required' });
   }

   try {
      const comment = await Comment.findById(commentId);
      if (!comment || comment.user.toString() !== req.user.id) {
         return res.status(403).json({ message: 'Not authorized' });
      }
      await comment.remove();
      await Post.findByIdAndUpdate(comment.post, { $pull: { comments: commentId } });
      res.json({ message: 'Comment deleted' });
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};