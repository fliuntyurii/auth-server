const express = require('express');
const router = express.Router();

const { signup, signin, logout, info } = require('../controllers/authController');
const authenticateUser = require('../middleware/authentication');

router.post('/signup', signup);
router.post('/signin', signin);
router.get('/logout/:all', authenticateUser, logout);
router.get('/info', authenticateUser, info);

module.exports = router;
