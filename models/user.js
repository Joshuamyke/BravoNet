const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name is required"],
        trim: true,
        minlength: 3,
        maxlength: 50,
    },
    username: {
        type: String,
        required: [true, "Username is required"],
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 50,
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Please enter a valid email address'],
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: 8,
        maxlength: 128,
    },
    bio: {
        type: String,
        trim: true,
        maxlength: 500,
    },
    location: {
        type: String,
        trim: true,
        maxlength: 100,
    },
    dateOfBirth: {
        month: {
            type: String,
            required: [true, "Month of birth is required"],
            enum: ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'],
        },
        day: {
            type: Number,
            required: [true, "Day of birth is required"],
            min: 1,
            max: 31,
        },
        year: {
            type: Number,
            required: [true, "Year of birth is required"],
            min: 1900,
            max: new Date().getFullYear(),
        },
    },
    privacy: {
        type: String,
        enum: ['public', 'private'],
        default: 'public',
    },
    profilePicture: {
        type: String,
        default: 'default_profile_picture_url', // Replace with a default image URL
    },
    friends: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    }],
    otp: {
        type: String,
        // This field can be used for OTP verification
    },
    otpExpires: {
        type: Date,
    },
}, {
    timestamps: true,
    versionKey: false,
});

// Create the User model
const User = mongoose.model('User', userSchema);

module.exports = User;