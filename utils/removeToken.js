const User = require('../models/User');

const removeToken = async (isAll, user, token) => {
  let tokens = user.tokens;
  if(isAll) {
    tokens = [];
  } 
  else {
    tokens.filter(t => t.token != token);
  }
  await User.findByIdAndUpdate(user._id, { tokens });
}

module.exports = removeToken;