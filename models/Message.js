const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    messageText: { type: String, required: true },
    timestamp: { type: Date, default: Date.now, index: { expires: 2592000 } }, // Auto-delete after 30 days
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' }
});

module.exports = mongoose.model('Message', MessageSchema);
