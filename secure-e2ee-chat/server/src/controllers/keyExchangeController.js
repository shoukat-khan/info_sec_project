const KeyExchangeRequest = require('../models/KeyExchangeRequest');
const KeyExchangeResponse = require('../models/KeyExchangeResponse');
const KeyExchangeConfirm = require('../models/KeyExchangeConfirm');

const createRequest = async (req, res, next) => {
  try {
    const { requesterUsername, targetUsername, ecdhPublicKey, signature } = req.body;

    if (!requesterUsername || !targetUsername || !ecdhPublicKey || !signature) {
      res.status(400);
      throw new Error('All fields are required');
    }

    const existingRequest = await KeyExchangeRequest.findOne({
      requesterUsername,
      targetUsername
    });

    if (existingRequest) {
      return res.status(400).json({
        success: false,
        error: 'Key exchange already in progress'
      });
    }

    const request = await KeyExchangeRequest.create({
      requesterUsername,
      targetUsername,
      ecdhPublicKey,
      signature
    });

    return res.status(201).json({
      success: true,
      message: 'Key exchange request created',
      request
    });
  } catch (error) {
    next(error);
  }
};

const getPendingRequests = async (req, res, next) => {
  try {
    const { username } = req.params;
    const requests = await KeyExchangeRequest.find({ targetUsername: username }).sort({ createdAt: -1 });
    return res.status(200).json({
      success: true,
      requests
    });
  } catch (error) {
    next(error);
  }
};

const createResponse = async (req, res, next) => {
  try {
    const { responderUsername, targetUsername, ecdhPublicKey, signature } = req.body;

    if (!responderUsername || !targetUsername || !ecdhPublicKey || !signature) {
      res.status(400);
      throw new Error('All fields are required');
    }

    const response = await KeyExchangeResponse.create({
      responderUsername,
      targetUsername,
      ecdhPublicKey,
      signature
    });

    return res.status(201).json({
      success: true,
      message: 'Key exchange response created',
      response
    });
  } catch (error) {
    next(error);
  }
};

const getResponse = async (req, res, next) => {
  try {
    const { username } = req.params;
    const response = await KeyExchangeResponse.findOne({ targetUsername: username }).sort({ createdAt: -1 });
    return res.status(200).json({
      success: true,
      response
    });
  } catch (error) {
    next(error);
  }
};

const createConfirm = async (req, res, next) => {
  try {
    const { senderUsername, targetUsername, confirmMessage } = req.body;

    if (!senderUsername || !targetUsername || !confirmMessage) {
      res.status(400);
      throw new Error('All fields are required');
    }

    const confirm = await KeyExchangeConfirm.create({
      senderUsername,
      targetUsername,
      confirmMessage
    });

    return res.status(201).json({
      success: true,
      message: 'Key exchange confirmation created',
      confirm
    });
  } catch (error) {
    next(error);
  }
};

const getConfirm = async (req, res, next) => {
  try {
    const { username } = req.params;
    const confirm = await KeyExchangeConfirm.findOne({ targetUsername: username }).sort({ createdAt: -1 });
    return res.status(200).json({
      success: true,
      confirm
    });
  } catch (error) {
    next(error);
  }
};

const deleteRequest = async (req, res, next) => {
  try {
    const { requesterUsername, targetUsername } = req.body;

    if (!requesterUsername || !targetUsername) {
      res.status(400);
      throw new Error('Requester and target usernames are required');
    }

    const deleted = await KeyExchangeRequest.deleteOne({
      requesterUsername,
      targetUsername
    });

    return res.status(200).json({
      success: true,
      message: 'Request deleted',
      deleted: deleted.deletedCount > 0
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createRequest,
  getPendingRequests,
  createResponse,
  getResponse,
  createConfirm,
  getConfirm,
  deleteRequest
};

