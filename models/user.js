const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    dateOfBirth: {
        month: {
            type: String,
            required: [true, "Month of birth is required"],
        },
        day: {
            type: Number,
            required: true,
            min: 1,
            max: 31,
        },
        year: {
            type: Number,
            required: true,
            min: 1900,
            max: new Date().getFullYear(),
        },
    },

    password: {
        type: String,
        required: true,
    },
    username: {
        type: String
    },
    bio: { type: String },

    location: { type: String },

    otp: { type: String},

    friends: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    profilePicture: { type: String }, // Path to profile picture
    privacySettings: { type: String, enum: ['public', 'private'], default: 'public' },
    
    otpExpires: { type: Date }
}, {
    timestamps: true,
});

const User = mongoose.model('User', userSchema); // This line registers the model
module.exports = User;