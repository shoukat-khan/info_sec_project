const AuditLog = require('../models/AuditLog');

const logEvent = async (req, res, next) => {
  try {
    const { username, eventType, details } = req.body;

    if (!username || !eventType) {
      res.status(400);
      throw new Error('Username and eventType are required');
    }

    const auditLog = await AuditLog.create({
      username,
      eventType,
      details: details || {},
      timestamp: new Date()
    });

    return res.status(201).json({
      success: true,
      message: 'Audit log created successfully',
      logId: auditLog._id
    });
  } catch (error) {
    next(error);
  }
};

const getUserLogs = async (req, res, next) => {
  try {
    const { username } = req.params;
    const { limit = 50 } = req.query;

    if (!username) {
      res.status(400);
      throw new Error('Username is required');
    }

    const logs = await AuditLog.find({ username })
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .select('eventType details timestamp')
      .lean();

    return res.status(200).json({
      success: true,
      logs
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  logEvent,
  getUserLogs
};

