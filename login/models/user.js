const mongoose = require('mongoose'),
    validator = require('validator'),
    jwt = require('jsonwebtoken'),
    _ = require('lodash'),
    bcrypt = require('bcryptjs');
// set user Schema
var userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        minlength: 1,
        unique: true,
        validate: {
            validator: validator.isEmail,
            message: '{value} is not valid email'
        }
    },
    password: {
        type: String,
        require: true,
        trim: true,
        minlength: 6
    },
    tokens: [{
        access: {
            type: String,
            require: true
        },
        token: {
            type: String,
            require: true
        }
    }]
});
//override toJSON function so password will not return to client side
userSchema.methods.toJSON = function () {
    var user = this;
    var userObject = user.toObject();

    return _.pick(userObject, ['_id', 'email']);
};
//generate a token for user
userSchema.methods.generateAuthToken = function () {
    var user = this;
    var access = 'auth';
    if(!user.tokens.length)
    {
        var token = jwt.sign({_id: user._id.toHexString(), access}, 'abc123').toString();
  
        user.tokens.push({access, token});
      
        return user.save().then(() => {
          return token;
        });
    }
    else{
        var t =  user.tokens[0].token;
        return user.save().then(() => {
            return t;
        });
    }

};

//find user by token
userSchema.statics.findByToken = function (token) {
    var user = this;
    var decoded;
    try {
      decoded = jwt.verify(token, 'abc123');
      console.log(decoded);
    } catch (e) {
      return Promise.reject();
    }
    return user.findById(decoded._id);
  };
  
//check if user password is correct
userSchema.methods.checkPassword = function (password) {
    var user = this;
            if(bcrypt.compareSync(password,user.password))
            {
                return true;
            }else{
                return false;
            }
};

//logout method
userSchema.methods.removeToken = function (token) {
    var user = this;
  
    return user.update({
      $pull: {
        tokens: {token}
      }
    });
  };

  //swap user password to password+hash+salt before saving to the DB
userSchema.pre('validate', function (next) {
    var user = this;
    if (user.isModified('password')) {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(user.password, salt, (err, hash) => {
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
});

//set user model
var User = mongoose.model('User', userSchema);
//return user model with all the functions
module.exports = {User};