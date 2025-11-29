const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    password: {
      type: String,
      required: true
    },
    publicKey: {
      type: String,
      default: ''
    },
    keyAlgorithm: {
      type: String,
      default: ''
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model('User', userSchema);

const dropOldEmailIndex = async () => {
  try {
    if (mongoose.connection.readyState === 1) {
      await User.collection.dropIndex('email_1');
      console.log('Dropped old email_1 index');
    }
  } catch (error) {
    if (error.code !== 27) {
      console.log('Old email index does not exist or already dropped');
    }
  }
};

if (mongoose.connection.readyState === 1) {
  dropOldEmailIndex();
} else {
  mongoose.connection.once('connected', dropOldEmailIndex);
}

module.exports = User;


