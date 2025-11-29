const mongoose = require('mongoose');

const keyExchangeResponseSchema = new mongoose.Schema(
  {
    responderUsername: {
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

const KeyExchangeResponse = mongoose.model('KeyExchangeResponse', keyExchangeResponseSchema);

module.exports = KeyExchangeResponse;

