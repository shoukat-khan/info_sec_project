const express = require('express');
const { register, login, getUserByUsername, getAllUsers } = require('../controllers/authController');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/user/:username', getUserByUsername);
router.get('/users', getAllUsers);

module.exports = router;


