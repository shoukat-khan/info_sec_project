const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema(
  {
    user1: {
      type: String,
      required: true
    },
    user2: {
      type: String,
      required: true
    },
    lastSequenceUser1: {
      type: Number,
      default: 0
    },
    lastSequenceUser2: {
      type: Number,
      default: 0
    },
    recentNonces: [
      {
        nonce: String,
        timestamp: Number
      }
    ]
  },
  {
    timestamps: true
  }
);

conversationSchema.index({ user1: 1, user2: 1 }, { unique: true });

const Conversation = mongoose.model('Conversation', conversationSchema);

module.exports = Conversation;

