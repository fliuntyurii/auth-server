const jwt = require('jsonwebtoken');
const { StatusCodes } = require('http-status-codes');

const User = require('../models/User');

const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'No token provided' })
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decoded.email });
    if (user.tokens.find(t => t.token == token)) {
      req.user = user;
      next();
    }
    else {
      res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid Credentials' })
    }
  }
  catch(err) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid Credentials' })
  }
};

module.exports = authenticateUser;