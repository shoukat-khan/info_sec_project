const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      index: true
    },
    eventType: {
      type: String,
      required: true
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    }
  },
  {
    timestamps: false
  }
);

auditLogSchema.index({ username: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;

