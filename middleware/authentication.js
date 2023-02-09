const jwt = require('jsonwebtoken');

const User = require('../models/User');
const CustomError = require('../errors');

const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new CustomError.UnauthenticatedError('No token provided');
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
      throw new CustomError.UnauthenticatedError('Authentication Invalid');
    }
  }
  catch(err) {
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  }
};

module.exports = authenticateUser;