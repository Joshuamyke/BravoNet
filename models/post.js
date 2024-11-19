
const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
	userId: {
		type: mongoose.Schema.Types.ObjectId,
		ref: 'User',
		required: true,
	},
	content: {
		type: String,
		required: true,
	},
	media: {
		type: String,
		default: null,
	},
	mediaType: {
		type: String,
		enum: ['image', 'video', 'none'],
		default: 'none',
	},
	likes: [{
		type: mongoose.Schema.Types.ObjectId,
		ref: 'User',
	}],
	comments: [{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: 'User',
		},
		text: String,
	}],
	shares: [{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: 'User',
		},
	}],
}, { timestamps: true });

module.exports = mongoose.model('Post', postSchema);