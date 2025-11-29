const express = require('express');
const router = express.Router();
const { logEvent, getUserLogs } = require('../controllers/auditController');

router.post('/log', logEvent);
router.get('/:username', getUserLogs);

module.exports = router;

