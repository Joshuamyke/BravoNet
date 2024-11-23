const Comment = require('../models/Comment');
const Post = require('../models/Post');

// Create Comment
exports.createComment = async (req, res) => {
   const { postId, content } = req.body;

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

   try {
      const comment = await Comment.findById(commentId);
      if (!comment || comment.user.toString() !== req.user.id) {
         return res.status(403).json({ message: 'Not authorized' });
      }
      comment.content = content || comment.content;
      await comment.save();
      res.json(comment);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Delete Comment
exports.deleteComment = async (req, res) => {
   const { commentId } = req.body;

   try {
      const comment = await Comment.findById(commentId);
      if (!comment || comment.user.toString() !== req.user.id) {
         return res.status(403).json({ message: 'Not authorized' });
      }
      await comment.remove();
      res.json({ message: 'Comment deleted' });
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};
