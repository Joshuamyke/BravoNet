const express = require('express');
const { createPost, getNewsFeed } = require('../controllers/postController');
const authMiddleware = require('../middleware/authMiddleware');

const {uploadPostMedia} = require("../config/multerUpload");


const router = express.Router();

router.post('/create', authMiddleware, uploadPostMedia.array('media',10), createPost);

router.get('/feeds',authMiddleware, getNewsFeed);

module.exports = router;