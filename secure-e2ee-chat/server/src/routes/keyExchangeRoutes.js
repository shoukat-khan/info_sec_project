const express = require('express');
const {
  createRequest,
  getPendingRequests,
  createResponse,
  getResponse,
  createConfirm,
  getConfirm,
  deleteRequest
} = require('../controllers/keyExchangeController');

const router = express.Router();

router.post('/request', createRequest);
router.get('/pending/:username', getPendingRequests);
router.post('/response', createResponse);
router.get('/response/:username', getResponse);
router.post('/confirm', createConfirm);
router.get('/confirm/:username', getConfirm);
router.delete('/request', deleteRequest);

module.exports = router;

