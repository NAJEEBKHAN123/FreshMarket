const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['superadmin', 'admin', 'user'], required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Reference to the creator
}, { timestamps: true });

// Ensure uniqueness of email per admin
userSchema.index({ email: 1, createdBy: 1 }, { unique: true });

module.exports = mongoose.model('User', userSchema);
