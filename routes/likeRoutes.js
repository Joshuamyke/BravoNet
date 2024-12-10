const express = require('express');
const { likePost, unlikePost, getPostLikes, getUserLikes } = require('../controllers/likeController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/like', authMiddleware, likePost);
router.post('/unlike', authMiddleware, unlikePost);
router.get('/post/:postId/likes', authMiddleware, getPostLikes);
router.get('/user/:userId/likes', authMiddleware, getUserLikes);

module.exports = router;
