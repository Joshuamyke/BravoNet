const express = require("express");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const dotenv = require("dotenv");
const http = require("http");
const { Server } = require("socket.io");
const { authenticateSocket } = require("./middleware/authenticateUser");
const swaggerUI = require("swagger-ui-express");
const swaggerDocs = require("./docs/swaggerOptions");

const upload = require("./config/multerUpload");
const cookieParser = require(`cookie-parser`);
const profileRoutes = require("./routes/profileRoutes");
const postRoutes = require("./routes/postRoutes");

const commentRoutes = require("./routes/commentRoutes");
const likeRoutes = require("./routes/likeRoutes");
const connectionRoutes = require("./routes/connectionRoutes");
const uploadRoutes = require("./routes/uploadRoutes");

//const { adminLogin, viewStatistics, manageUser, reviewReports, resolveReport } = require('../controllers/adminController');
//const { authenticateAdmin } = require('./routes/adminRoutes')
const app = express();
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const server = http.createServer(app);
const io = new Server(server, {
	cors: { origin: "*" },
});

dotenv.config();

app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use("/uploads/media", express.static("uploads/media"));

connectDB();

app.use("/api/auth", authRoutes);

// Static folder for profile picture uploads
app.get("/", (req, res) => {
	res.send("WELCOME TO BRAVONET SOCIAL MEDIA APP");
});
app.use(
	"/uploads/profile_pictures",
	express.static(path.join(__dirname, "uploads/profile_pictures"))
);
app.use("/api/profile", profileRoutes, uploadRoutes);
app.use(`/api/posts`, postRoutes);
app.use("/api/comments", commentRoutes);
app.use("/api/likes", likeRoutes);
app.use("/api/connections", connectionRoutes);


//app.use('/api/admin', adminRoutes);

// Socket.IO integration
io.use(authenticateSocket); // Authenticate user sockets
io.on("connection", (socket) => {
	console.log("New User connected");

	socket.on("disconnect", () => {
		console.log("User disconnected");
	});

	io.on("connection", (socket) => {
		console.log("New User connected");

		socket.on("send-friend-request", (data) => {
			socket.broadcast.emit("friend-request", data);
		});
		socket.on("likePost", (data) => {
			socket.broadcast.emit("postLiked", data);
		});

		socket.on("commentPost", (data) => {
			socket.broadcast.emit("postCommented", data);
		});

		socket.on("sharePost", (data) => {
			socket.broadcast.emit("postShared", data);
		});

		socket.on("disconnect", () => {
			console.log("User disconnected");
		});
	});
});

// Swagger documentation
app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(swaggerDocs));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
