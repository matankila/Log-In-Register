var {User} = require('./../models/user');
var express = require('express'),
    app = express();
var cookieParser = require('cookie-parser');

app.use(cookieParser());
var authenticate = (req, res, next) => {
  var token = req.cookies['x-auth'];
  console.log("this is token  "+ token);
    User.findByToken(token).then((user) => {
        console.log(user);
        if (!user) 
        {
          return Promise.reject();
        }
        req.user = user;
        req.token = token;
        next();
      }).catch((e) => {
        res.status(401).send();
      });
    };

module.exports = {authenticate};
