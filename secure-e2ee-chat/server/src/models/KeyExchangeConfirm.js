const mongoose = require('mongoose');

const keyExchangeConfirmSchema = new mongoose.Schema(
  {
    senderUsername: {
      type: String,
      required: true
    },
    targetUsername: {
      type: String,
      required: true
    },
    confirmMessage: {
      type: String,
      required: true
    }
  },
  {
    timestamps: true
  }
);

const KeyExchangeConfirm = mongoose.model('KeyExchangeConfirm', keyExchangeConfirmSchema);

module.exports = KeyExchangeConfirm;

