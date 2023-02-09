const { StatusCodes } = require('http-status-codes');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const crypto = require("crypto");

const User = require('../models/User');
const refreshToken = require('../utils/refreshToken');
const removeToken = require('../utils/removeToken');

const signup = async (req, res) => {
  const { email, password } = req.body;
  const id = crypto.randomBytes(16).toString("hex");

  const idAlreadyExists = await User.findOne({ email });
  if (idAlreadyExists) {
    res.status(StatusCodes.BAD_REQUEST).json({ message: 'Email already exists' })
  }
  if (!validator.isEmail(email) && !validator.isMobilePhone(email)) {
    res.status(StatusCodes.BAD_REQUEST).json({ message: 'Please provide valid email' })
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_LIFETIME });  
  const email_type = validator.isMobilePhone(email) ? 'Phone' : 'Email' ;

  await User.create({ id, email_type, email, password, tokens: [ { token, signedAt: Date.now().toString() } ] });

  res.status(StatusCodes.OK).json({ token });
};

const signin = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(StatusCodes.BAD_REQUEST).json({ message: 'Please provide email and password' })
  }

  const user = await User.findOne({ email });
  if (!user) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid Credentials' })
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid Credentials' })
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_LIFETIME });

  refreshToken(user, token, 0);
  res.status(200).json({ email: user.email, token });
};

const logout = async (req, res) => {
  const isAll = req.params.all;
  const authHeader = req.headers.authorization;
  const token = authHeader.split(' ')[1];
  const user = req.user;

  removeToken(isAll, user, token);
  res.status(StatusCodes.OK).json({ message: 'Logout successfully' });
};

const info = async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.split(' ')[1];
  const user = req.user;
  
  refreshToken(user, token, 600);
  res.status(StatusCodes.OK).json({ email: user.email, email_type: user.email_type });
}

module.exports = {
  signup,
  signin,
  logout,
  info
};