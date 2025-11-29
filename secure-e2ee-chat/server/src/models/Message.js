const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema(
  {
    sender: {
      type: String,
      required: true
    },
    receiver: {
      type: String,
      required: true
    },
    ciphertext: {
      type: String,
      required: true
    },
    iv: {
      type: String,
      required: true
    },
    nonce: {
      type: String,
      required: true
    },
    sequence: {
      type: Number,
      required: true
    },
    timestamp: {
      type: Number,
      required: true
    }
  },
  {
    timestamps: true
  }
);

messageSchema.index({ sender: 1, receiver: 1, nonce: 1 }, { unique: true });
messageSchema.index({ sender: 1, receiver: 1, sequence: 1 });

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;

