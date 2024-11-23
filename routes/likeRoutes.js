const express = require('express');
const { likePost, unlikePost } = require('../controllers/likeController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/like', authMiddleware, likePost);
router.post('/unlike', authMiddleware, unlikePost);

module.exports = router;