require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').MongoStore;
const path = require('path');
const bcrypt = require('bcryptjs');

const User = require('./models/User');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log('MongoDB Connection Error:', err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session Configuration
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 30, // Stay logged in for 30 days
        secure: false, // Set to true if using HTTPS
        httpOnly: true
    }
});

app.use(sessionMiddleware);

app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// Share session with Socket.io
io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

// Create Admin Users if not exists
async function createAdmin() {
    // Remove old admin account for security
    await User.deleteOne({ username: 'admin' });

    const admins = [
        { username: 'sasi', password: 'sasi123' }
    ];

    for (const adminData of admins) {
        try {
            const admin = await User.findOne({ username: adminData.username });
            if (!admin) {
                const hashedPassword = await bcrypt.hash(adminData.password, 10);
                await User.create({
                    username: adminData.username,
                    password: hashedPassword,
                    role: 'admin'
                });
                console.log(`Admin user created: ${adminData.username}`);
            } else {
                // Ensure existing user has admin role
                if (admin.role !== 'admin') {
                    admin.role = 'admin';
                    await admin.save();
                    console.log(`Updated ${adminData.username} to admin role`);
                }
            }
        } catch (err) {
            if (err.code !== 11000) {
                console.error(`Error creating admin ${adminData.username}:`, err);
            }
        }
    }
}
createAdmin();

// Routes
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'User does not exist. Please contact admin.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        req.session.userId = user._id;
        req.session.role = user.role;
        req.session.username = user.username;

        res.json({ success: true, role: user.role, userId: user._id });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    res.json({ userId: req.session.userId, role: req.session.role, username: req.session.username });
});

app.get('/api/users', async (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const users = await User.find({ role: 'user' }).select('-password');
    res.json(users);
});

app.post('/api/users/add', async (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ error: 'Username already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, password: hashedPassword, role: 'user' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/users/:userId', async (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { userId } = req.params;
    try {
        await User.findByIdAndDelete(userId);
        await Message.deleteMany({
            $or: [{ senderId: userId }, { receiverId: userId }]
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/messages/:otherUserId', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

    const { otherUserId } = req.params;
    const currentUserId = req.session.userId;

    // Check permissions: Admin can chat with anyone, User can ONLY chat with Admin
    if (req.session.role === 'user') {
        const admin = await User.findOne({ role: 'admin' });
        if (otherUserId !== admin._id.toString()) {
            return res.status(403).json({ error: 'Users can only chat with Admin' });
        }
    }

    const messages = await Message.find({
        $or: [
            { senderId: currentUserId, receiverId: otherUserId },
            { senderId: otherUserId, receiverId: currentUserId }
        ]
    }).sort({ timestamp: -1 }).limit(50);

    res.json(messages.reverse());
});

app.get('/api/admin-id', async (req, res) => {
    const admin = await User.findOne({ role: 'admin' }).select('_id isOnline lastSeen');
    res.json({
        adminId: admin ? admin._id : null,
        isOnline: admin ? admin.isOnline : false,
        lastSeen: admin ? admin.lastSeen : null
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Socket.io Logic
io.on('connection', async (socket) => {
    const userId = socket.request.session.userId;
    if (!userId) return socket.disconnect();

    // Set online status and update lastSeen
    const updatedUser = await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() }, { new: true });
    io.emit('status_change', { userId, isOnline: true, lastSeen: updatedUser.lastSeen });

    // Join private room
    socket.join(userId.toString());
    console.log(`User ${userId} connected and joined room ${userId}`);

    socket.on('send_message', async (data) => {
        const { receiverId, messageText } = data;

        const newMessage = new Message({
            senderId: userId,
            receiverId,
            messageText,
            status: 'sent' // Default status
        });
        const savedMsg = await newMessage.save();

        // Emit to receiver's room
        io.to(receiverId).emit('new_message', savedMsg);
        // Emit back to sender for confirmation/sync
        io.to(userId.toString()).emit('new_message', savedMsg);
    });

    socket.on('mark_seen', async (data) => {
        const { senderId } = data; // The user who sent the messages being marked as seen
        await Message.updateMany(
            { senderId: senderId, receiverId: userId, status: { $ne: 'seen' } },
            { $set: { status: 'seen' } }
        );
        io.to(senderId).emit('messages_seen', { viewerId: userId });
    });

    socket.on('disconnect', async () => {
        const now = new Date();
        await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: now });
        io.emit('status_change', { userId, isOnline: false, lastSeen: now });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
