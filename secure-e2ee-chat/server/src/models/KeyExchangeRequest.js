const mongoose = require('mongoose');

const keyExchangeRequestSchema = new mongoose.Schema(
  {
    requesterUsername: {
      type: String,
      required: true
    },
    targetUsername: {
      type: String,
      required: true
    },
    ecdhPublicKey: {
      type: String,
      required: true
    },
    signature: {
      type: String,
      required: true
    }
  },
  {
    timestamps: true
  }
);

keyExchangeRequestSchema.index({ requesterUsername: 1, targetUsername: 1 });

const KeyExchangeRequest = mongoose.model('KeyExchangeRequest', keyExchangeRequestSchema);

module.exports = KeyExchangeRequest;

