const User = require('../models/User');

const refreshToken = async (user, token, time) => {
  let oldTokens = user.tokens || [];
  if (oldTokens.length) {
    oldTokens = oldTokens.filter(t => {
      const timeDiff = (Date.now() - parseInt(t.signedAt)) / 1000;
      if (timeDiff < time) {
        return t;
      }
    })
  }
  await User.findByIdAndUpdate(user._id, 
    { 
      tokens: [ 
        ...oldTokens, { token, signedAt: Date.now().toString() } 
      ] 
    }
  );
}

module.exports = refreshToken;