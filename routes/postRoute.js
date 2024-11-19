const express = require('express');
const multer = require('multer');
const { authenticateUser } = require('../middleware/authenticateUser');
const { createPost, fetchNewsFeed, likePost, addComment, sharePost } = require('../controllers/postController');

const router = express.Router();

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/media');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});
const upload = multer({ storage });

// Routes for post functionality
router.post('/', authenticateUser, upload.single('media'), createPost);  // Create post
router.get('/feed', authenticateUser, fetchNewsFeed);                    // Fetch news feed
router.patch('/:postId/like', authenticateUser, likePost);              // Like/unlike post
router.post('/:postId/comment', authenticateUser, addComment);          // Comment on a post
router.patch('/:postId/share', authenticateUser, sharePost);            // Share post

module.exports = router;