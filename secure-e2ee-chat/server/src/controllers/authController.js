const bcrypt = require('bcrypt');
const User = require('../models/User');
const { validateRegisterInput, validateLoginInput } = require('../utils/validateInput');

const register = async (req, res, next) => {
  try {
    const { valid, message } = validateRegisterInput(req.body);
    if (!valid) {
      res.status(400);
      throw new Error(message);
    }

    const { username, password, publicKey, keyAlgorithm } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      res.status(400);
      throw new Error('Username already taken');
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const user = await User.create({
      username,
      password: hashedPassword,
      publicKey: publicKey || '',
      keyAlgorithm: keyAlgorithm || ''
    });

    const userResponse = {
      id: user._id,
      username: user.username,
      publicKey: user.publicKey,
      keyAlgorithm: user.keyAlgorithm
    };

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: userResponse
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { valid, message } = validateLoginInput(req.body);
    if (!valid) {
      res.status(400);
      throw new Error(message);
    }

    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      res.status(400);
      throw new Error('Invalid username or password');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.status(400);
      throw new Error('Invalid username or password');
    }

    const userResponse = {
      id: user._id,
      username: user.username,
      publicKey: user.publicKey,
      keyAlgorithm: user.keyAlgorithm
    };

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      user: userResponse
    });
  } catch (error) {
    next(error);
  }
};

const getUserByUsername = async (req, res, next) => {
  try {
    const { username } = req.params;
    const user = await User.findOne({ username });
    if (!user) {
      res.status(404);
      throw new Error('User not found');
    }
    const userResponse = {
      id: user._id,
      username: user.username,
      publicKey: user.publicKey,
      keyAlgorithm: user.keyAlgorithm
    };
    return res.status(200).json({
      success: true,
      user: userResponse
    });
  } catch (error) {
    next(error);
  }
};

const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find({}, 'username').sort({ username: 1 });
    const usernames = users.map((user) => user.username);
    return res.status(200).json({
      success: true,
      users: usernames
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  getUserByUsername,
  getAllUsers
};

