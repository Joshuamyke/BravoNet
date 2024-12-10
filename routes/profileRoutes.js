const express = require("express");
const { uploadProfilePhoto } = require("../config/multerUpload");
const profileController = require("../controllers/profileController");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

router.put("/update-profile", authMiddleware, profileController.updateProfile);

router.post("/upload-profile-picture", authMiddleware, uploadProfilePhoto.single("profilePicture"), profileController.uploadProfilePicture);

router.get("/view-profile/:id", authMiddleware, profileController.viewProfile);

router.post("/add-friend/:friendId", authMiddleware, profileController.addFriend);

module.exports = router;
