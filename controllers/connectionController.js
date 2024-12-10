const Connection = require('../models/Connection');
const User = require('../models/User');
const { celebrate, Joi } = require('celebrate');
const winston = require('winston');

// Create a logger
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Send Friend Request
exports.sendFriendRequest = [
    celebrate({
        body: Joi.object({
            friendId: Joi.string().required()
        })
    }),
    async (req, res) => {
        const { friendId } = req.body;

        try {
            const existingConnection = await Connection.findOne({ $or: [{ user: req.user.id, friend: friendId }, { user: friendId, friend: req.user.id }] });
            if (existingConnection) {
                logger.error(`Friend request already sent or already friends with user ${friendId}`);
                return res.status(400).json({ message: 'Friend request already sent or already friends' });
            }
            const newConnection = new Connection({ user: req.user.id, friend: friendId, status: 'pending' });
            await newConnection.save();
            logger.info(`Friend request sent to user ${friendId}`);
            res.status(201).json(newConnection);
        } catch (error) {
            logger.error(`Error sending friend request: ${error.message}`);
            res.status(500).json({ error: error.message });
        }
    }
];

// Accept Friend Request
exports.acceptFriendRequest = [
    celebrate({
        body: Joi.object({
            requestId: Joi.string().required()
        })
    }),
    async (req, res) => {
        const { requestId } = req.body;

        try {
            const connection = await Connection.findById(requestId);
            if (!connection) {
                logger.error(`Connection request not found for id ${requestId}`);
                return res.status(404).json({ message: 'Connection request not found' });
            }
            if (connection.user.toString() !== req.user.id && connection.friend.toString() !== req.user.id) {
                logger.error(`User ${req.user.id} is not authorized to accept request ${requestId}`);
                return res.status(403).json({ message: 'You are not authorized to accept this request' });
            }
            connection.status = 'accepted';
            await connection.save();
            logger.info(`Friend request accepted for id ${requestId}`);
            res.json(connection);
        } catch (error) {
            logger.error(`Error accepting friend request: ${error.message}`);
            res.status(500).json({ error: error.message });
        }
    }
];

// Get Friends List
exports.getFriendsList = async (req, res) => {
    try {
        const connections = await Connection.find({ $or: [{ user: req.user.id, status: 'accepted' }, { friend: req.user.id, status: 'accepted' }] }).populate('friend', 'name email').populate('user', 'name email');
        logger.info(`Friends list retrieved for user ${req.user.id}`);
        res.json(connections);
    } catch (error) {
        logger.error(`Error retrieving friends list: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
};
