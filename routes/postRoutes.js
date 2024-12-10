const express = require('express');
const multer = require('multer');
const authMiddleware = require("../middleware/authMiddleware");
const {
  createPost,
  getPostsFeed,
  sharePost,
  updatePost,
  deletePost,
  validatePost,
  authorizePost,
  errorHandler,
  logPost
} = require('../controllers/postController');
const path = require('path');

const router = express.Router();

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../uploads/media')); // Adjust the path as needed
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});
const upload = multer({ storage });

// Routes for post functionality

// Create post
router.post('/create', authMiddleware, upload.array('media'), validatePost, createPost);

// Fetch news feed
router.get('/feeds', authMiddleware, getPostsFeed);

// Share post
router.post('/:postId/share', authMiddleware, authorizePost, sharePost);

// Update post
router.put('/update', authMiddleware, authorizePost, updatePost);

// Delete post
router.delete('/delete', authMiddleware, authorizePost, deletePost);

// Error handling middleware
router.use(errorHandler);

// Logging middleware
router.use(logPost);

module.exports = router;
