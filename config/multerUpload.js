const multer = require('multer');
const path = require('path');
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const dotenv = require('dotenv');

dotenv.config();

cloudinary.config({
	cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
	api_key: process.env.CLOUDINARY_API_KEY,
	api_secret: process.env.CLOUDINARY_API_SECRET,
});

const profilePictureStorage = new CloudinaryStorage({
	cloudinary: cloudinary,
	params: {
		folder: "bravoNet-uploads/profile_pictures", // optional: specify the folder in Cloudinary
		allowed_formats: ["jpg", "jpeg", "png", "gif", "pdf", "docx"], // allowed formats
	},
});

// Storage for post media
const postMediaStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: "bravoNet-uploads/post_media",
        allowed_formats: ["jpg", "jpeg", "png", "gif", "pdf", "docx"],
    },
});

const uploadProfilePhoto = multer({ storage: profilePictureStorage });

const uploadPostMedia = multer({ storage: postMediaStorage });

module.exports = {uploadProfilePhoto, uploadPostMedia}
