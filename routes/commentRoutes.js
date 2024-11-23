const express = require('express');
const { createComment, getComments, updateComment, deleteComment } = require('../controllers/commentController');
const authMiddleware  = require('../middleware/authMiddleware');

const router = express.Router();


router.post('/create-comment', authMiddleware, createComment);
router.get('/:postId/get-comments', authMiddleware, getComments);
router.put('/update-comment', authMiddleware, updateComment);
router.delete('/delete-comment',authMiddleware, deleteComment);

module.exports = router;