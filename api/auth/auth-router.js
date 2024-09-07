const router = require('express').Router();
const User = require('../users/users-model');
const bcrypt = require('bcryptjs');
const {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
} = require('./auth-middleware');

router.post(
  '/register',
  checkPasswordLength,
  checkUsernameFree,
  (req, res, next) => {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8); // 2 ^ 8

    User.add({ username, password: hash })
      .then((saved) => {
        res.status(201).json(saved);
      })
      .catch(next);
  }
);

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, req.user.password)) {
    // cookie is set on the client
    // server stores a session with a session id
    req.session.user = req.user;
    res.json({ message: `Welcome ${req.user.username}` });
  } else {
    next({ status: 401, message: 'Invalid credentials' });
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res, next) => {
  res.json('logout');
});

module.exports = router;
