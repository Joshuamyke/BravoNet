const express = require('express');
const {upload} = require('../config/multerUpload');
const uploadController = require('../controllers/uploadController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Apply authMiddleware to the upload route
router.post('/upload-profile-picture', authMiddleware, upload.single('profilePicture'), uploadController.uploadProfilePicture);

module.exports = router;