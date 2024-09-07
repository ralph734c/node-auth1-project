const User = require('../users/users-model');

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  // if (req.session && req.session.userId) {
  //   next()
  // }
  console.log('restricted');
  next();
}

async function checkUsernameFree(req, res, next) {
  try {
    const users = await User.findBy({ username: req.body.username });
    if (!users.length) {
      next();
    } else {
      next({ message: 'Username taken', status: 422 });
    }
  } catch (error) {
    next(error);
  }
}

async function checkUsernameExists(req, res, next) {
  try {
    const users = await User.findBy({ username: req.body.username });
    if (users.length) {
      next();
    } else {
      next({ message: 'Invalid credentials', status: 401 });
    }
  } catch (error) {
    next(error);
  }
}

function checkPasswordLength(req, res, next) {
  if (!req.body.password || req.body.password.length < 3) {
    next({ message: 'Password must be longer than 3 chars', status: 422 });
  } else {
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
};
