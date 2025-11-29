const mongoose = require('mongoose');

const fileMessageSchema = new mongoose.Schema(
  {
    sender: {
      type: String,
      required: true
    },
    receiver: {
      type: String,
      required: true
    },
    filename: {
      type: String,
      required: true
    },
    mimeType: {
      type: String,
      required: true
    },
    filesize: {
      type: Number,
      required: true
    },
    ciphertext: {
      type: Buffer,
      required: true
    },
    fileIv: {
      type: String,
      required: true
    },
    wrappedFileKey: {
      type: String,
      required: true
    },
    keyIv: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

fileMessageSchema.index({ sender: 1, receiver: 1, timestamp: -1 });

const FileMessage = mongoose.model('FileMessage', fileMessageSchema);

module.exports = FileMessage;

