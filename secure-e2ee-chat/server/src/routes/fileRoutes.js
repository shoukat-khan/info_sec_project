const express = require('express');
const router = express.Router();
const { uploadEncryptedFile, listFiles, downloadEncryptedFile } = require('../controllers/fileController');

router.post('/upload', uploadEncryptedFile);
router.get('/', listFiles);
router.get('/:id', downloadEncryptedFile);

module.exports = router;

