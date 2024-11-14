const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const dotenv = require('dotenv');


const upload = require("./config/multerUpload");
const cookieParser = require(`cookie-parser`);
const profileRoute = require('./routes/profileRoute')
const postRoute = require('./routes/postRoute')

const cors = require('cors');
const fs = require('fs');
const path = require('path');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

connectDB();

app.use('/api/auth', authRoutes);

// Static folder for profile picture uploads
app.use('/uploads/profile_pictures', express.static(path.join(__dirname, 'uploads/profile_pictures')))
app.use(`/api/profile`, profileRoute);
app.use(`/api/posts`, postRoute);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));