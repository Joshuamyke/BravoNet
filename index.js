const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');
const { authenticateSocket } = require('./middleware/authenticateUser');


const upload = require("./config/multerUpload");
const cookieParser = require(`cookie-parser`);
const profileRoute = require('./routes/profileRoute')
const postRoute = require('./routes/postRoute')
//const { adminLogin, viewStatistics, manageUser, reviewReports, resolveReport } = require('../controllers/adminController');
//const { authenticateAdmin } = require('./routes/adminRoutes')
const app = express();
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' },
});

dotenv.config();


app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use('/uploads/media', express.static('uploads/media'));

connectDB();

app.use('/api/auth', authRoutes);

// Static folder for profile picture uploads
app.get('/', (req, res) => {
    res.send("WELCOME TO BRAVONET SOCIAL MEDIA APP")
})
app.use('/uploads/profile_pictures', express.static(path.join(__dirname, 'uploads/profile_pictures')))
app.use(`/api/profile`, profileRoute);
app.use(`/api/posts`, postRoute);
//app.use('/api/admin', adminRoutes);



// Socket.IO integration
io.use(authenticateSocket); // Authenticate user sockets
io.on('connection', (socket) => {
    console.log('User connected');

    socket.on('likePost', (data) => {
        socket.broadcast.emit('postLiked', data);
    });

    socket.on('commentPost', (data) => {
        socket.broadcast.emit('postCommented', data);
    });

    socket.on('sharePost', (data) => {
        socket.broadcast.emit('postShared', data);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));