const express = require('express');
const { sendFriendRequest, acceptFriendRequest, getFriendsList } = require('../controllers/connectionController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();


router.post('/send-request', authMiddleware, sendFriendRequest);
router.post('/accept-request', authMiddleware, acceptFriendRequest);
router.get('/friends', authMiddleware, getFriendsList);

module.exports = router;