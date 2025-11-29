const Message = require('../models/Message');
const Conversation = require('../models/Conversation');

const TIMESTAMP_TOLERANCE_MS = 30000;

const getConversationKey = (user1, user2) => {
  return [user1, user2].sort().join('|');
};

const getOrCreateConversation = async (sender, receiver) => {
  const [user1, user2] = [sender, receiver].sort();
  let conversation = await Conversation.findOne({ user1, user2 });

  if (!conversation) {
    conversation = await Conversation.create({
      user1,
      user2,
      lastSequenceUser1: 0,
      lastSequenceUser2: 0,
      recentNonces: []
    });
  }

  return conversation;
};

const cleanupOldNonces = (conversation) => {
  const now = Date.now();
  const maxAge = 5 * 60 * 1000;
  conversation.recentNonces = conversation.recentNonces.filter(
    (n) => now - n.timestamp < maxAge
  );
};

const sendMessage = async (req, res, next) => {
  try {
    const { sender, receiver, ciphertext, iv, nonce, sequence, timestamp } = req.body;

    if (!sender || !receiver || !ciphertext || !iv || !nonce || sequence === undefined || !timestamp) {
      res.status(400);
      throw new Error('All fields are required');
    }

    const conversation = await getOrCreateConversation(sender, receiver);
    cleanupOldNonces(conversation);

    const now = Date.now();
    const timeDiff = Math.abs(now - timestamp);

    if (timeDiff > TIMESTAMP_TOLERANCE_MS) {
      res.status(400);
      throw new Error('Replay attack detected: timestamp out of tolerance window');
    }

    const isSenderUser1 = conversation.user1 === sender;
    const lastSeq = isSenderUser1 ? conversation.lastSequenceUser1 : conversation.lastSequenceUser2;

    if (sequence <= lastSeq) {
      res.status(400);
      throw new Error('Replay attack detected: sequence number not increasing');
    }

    const nonceExists = conversation.recentNonces.some((n) => n.nonce === nonce);
    if (nonceExists) {
      res.status(400);
      throw new Error('Replay attack detected: nonce already used');
    }

    const message = await Message.create({
      sender,
      receiver,
      ciphertext,
      iv,
      nonce,
      sequence,
      timestamp
    });

    if (isSenderUser1) {
      conversation.lastSequenceUser1 = sequence;
    } else {
      conversation.lastSequenceUser2 = sequence;
    }
    conversation.recentNonces.push({
      nonce,
      timestamp: now
    });
    await conversation.save();

    return res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      messageId: message._id
    });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400);
      return res.json({
        success: false,
        error: 'Replay attack detected: duplicate nonce'
      });
    }
    next(error);
  }
};

const getMessages = async (req, res, next) => {
  try {
    const { username, otherUser } = req.query;

    if (!username || !otherUser) {
      res.status(400);
      throw new Error('Username and otherUser are required');
    }

    const messages = await Message.find({
      $or: [
        { sender: username, receiver: otherUser },
        { sender: otherUser, receiver: username }
      ]
    })
      .sort({ sequence: 1 })
      .select('sender receiver ciphertext iv nonce sequence timestamp createdAt');

    return res.status(200).json({
      success: true,
      messages
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  sendMessage,
  getMessages
};

