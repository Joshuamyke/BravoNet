const Connection = require('../models/Connection');
const User = require('../models/User');

// Send Friend Request
exports.sendFriendRequest = async (req, res) => {
   const { friendId } = req.body;

   try {
      const existingConnection = await Connection.findOne({ user: req.user.id, friend: friendId });
      if (existingConnection) {
         return res.status(400).json({ message: 'Friend request already sent' });
      }
      const newConnection = new Connection({ user: req.user.id, friend: friendId });
      await newConnection.save();
      res.status(201).json(newConnection);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Accept Friend Request
exports.acceptFriendRequest = async (req, res) => {
   const { requestId } = req.body;

   try {
      const connection = await Connection.findById(requestId);
      if (!connection) {
         return res.status(404).json({ message: 'Connection request not found' });
      }
      connection.status = 'accepted'; // You can add a status field to manage requests
      await connection.save();
      res.json(connection);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};

// Get Friends List
exports.getFriendsList = async (req, res) => {
   try {
      const connections = await Connection.find({ user: req.user.id }).populate('friend', 'name email');
      res.json(connections);
   } catch (error) {
      res.status(500).json({ error: error.message });
   }
};