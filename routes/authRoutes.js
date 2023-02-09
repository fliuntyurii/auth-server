const express = require('express');
const router = express.Router();

const authenticateUser = require('../middleware/authentication');
const { signup, signin, logout, info } = require('../controllers/authController');

router.post('/signup', signup);
router.post('/signin', signin);
router.get('/logout/:all', authenticateUser, logout);
router.get('/info', authenticateUser, info);

module.exports = router;
