const FileMessage = require('../models/FileMessage');

const uploadEncryptedFile = async (req, res, next) => {
  try {
    const { sender, receiver, filename, mimeType, filesize, ciphertext, fileIv, wrappedFileKey, keyIv } = req.body;

    if (!sender || !receiver || !filename || !mimeType || filesize === undefined || !ciphertext || !fileIv || !wrappedFileKey || !keyIv) {
      res.status(400);
      throw new Error('All fields are required');
    }

    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');

    const fileMessage = await FileMessage.create({
      sender,
      receiver,
      filename,
      mimeType,
      filesize,
      ciphertext: ciphertextBuffer,
      fileIv,
      wrappedFileKey,
      keyIv
    });

    return res.status(201).json({
      success: true,
      fileId: fileMessage._id,
      message: 'Encrypted file uploaded successfully'
    });
  } catch (error) {
    next(error);
  }
};

const listFiles = async (req, res, next) => {
  try {
    const { user, peer } = req.query;

    if (!user || !peer) {
      res.status(400);
      throw new Error('User and peer are required');
    }

    const files = await FileMessage.find({
      $or: [
        { sender: user, receiver: peer },
        { sender: peer, receiver: user }
      ]
    })
      .sort({ timestamp: -1 })
      .select('_id sender receiver filename mimeType filesize timestamp createdAt');

    return res.status(200).json({
      success: true,
      files
    });
  } catch (error) {
    next(error);
  }
};

const downloadEncryptedFile = async (req, res, next) => {
  try {
    const { id } = req.params;

    const fileMessage = await FileMessage.findById(id);

    if (!fileMessage) {
      res.status(404);
      throw new Error('File not found');
    }

    return res.status(200).json({
      success: true,
      file: {
        filename: fileMessage.filename,
        mimeType: fileMessage.mimeType,
        filesize: fileMessage.filesize,
        ciphertext: fileMessage.ciphertext.toString('base64'),
        fileIv: fileMessage.fileIv,
        wrappedFileKey: fileMessage.wrappedFileKey,
        keyIv: fileMessage.keyIv,
        sender: fileMessage.sender,
        receiver: fileMessage.receiver,
        timestamp: fileMessage.timestamp
      }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  uploadEncryptedFile,
  listFiles,
  downloadEncryptedFile
};

