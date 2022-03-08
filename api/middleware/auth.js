const jwt = require('jsonwebtoken');

const jwtSecret = process.env.SECRET || 'devsecret';

function auth(req, res, next) {
  try {
    const token = req.header('x-auth-token');
    if (!token) {
      console.error('No Authorization token in the request');
      return res
        .status(401)
        .json({ msg: 'Authorization denied, token missing' });
    }

    const verified = jwt.verify(token, jwtSecret);

    req.user = verified;
    next();
  } catch (e) {
    console.error(e);
    res.status(400).json({ msg: 'Invalid Token' });
  }
}

module.exports = auth;
