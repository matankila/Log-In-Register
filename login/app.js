var express          = require('express'),
    app              = express(),
    ejs              = require('ejs'),
    body             = require('body-parser'),
    mongoose         = require('mongoose'),
    request          = require('request'),
    {User}           = require('./models/user'),
    bcrypt           = require('bcryptjs'),
    {authenticate}   = require('./middleware/authenticate');
const methodOverride = require('method-override')

const jwt            = require('jsonwebtoken'); 
var cookieParser     = require('cookie-parser');

// ==========================  MIDDLEWARE  ======================================
//use method override to use delete/put/etc..
app.use(methodOverride('_method'));
//use cookie parser to set and get cookie value (used for passing the token)
app.use(cookieParser("secret"));
//use the body parser to return values from post requests
app.use(body.urlencoded({ extended: true }));
//connect to UsersDB
mongoose.connect('mongodb://localhost:27017/usersDB', { useNewUrlParser: true });
//use for the css to use the public folder
app.use(express.static("public"));

// ============================  ROUTES  ========================================
//root route
app.get('/', function (req, res) {
    var token = req.cookies['x-auth'];
    res.render('home.ejs',{token:token});
});

//register route
app.get('/register', function (req, res) {
    var msg = "", eMsg = "";
    res.clearCookie('x-auth');
    res.render("regiester.ejs", { msg: msg, eMsg: eMsg });
});

//ADD ROUTE FOR REGISTER - add new user to DB able to log in
app.post('/register', function (req, res) {
    console.log(req.body.reg);
    if (req.body.reg.password.length < 6) {
        var eMsg = "password is less then 6 charcters", msg = "";
        res.render('regiester.ejs', { msg: msg, eMsg: eMsg });
    }
    else {
        User.create(req.body.reg, function (err, user) {
            if (err) {
                if (err.code == 11000) {
                    var eMsg = "mail exist", msg = "";
                    res.render('regiester.ejs', { msg: msg, eMsg: eMsg });
                }
            }
            else {
                user.generateAuthToken().then((token) => {
                    //show message to user of success!
                    res.cookie('x-auth',token);
                    res.redirect('/secret');
                });
                console.log("created!");
            }
        });
    }
});

//login route
app.get('/login', function (req, res) {
    res.clearCookie('x-auth');
    var msg="",eMsg="";
    res.render('login.ejs',{msg:msg,eMsg:eMsg});
});

//Validation route - check if the email exist and the password is correct
app.post('/login',function(req,res){
    User.findOne({email:req.body.reg.email},function(err,user){
        if(user == null)
        {
            var msg="",eMsg="email not exsit!";
            res.render('login.ejs',{msg:msg,eMsg:eMsg});
        }
        else{
            if(user.checkPassword(req.body.reg.password)){
                return user.generateAuthToken().then((token) => {
                    res.cookie('x-auth',token);
                    res.redirect('/secret');
                }).catch((e) => {
                  res.status(400).send();
                });
            }
            else{
                var msg="",eMsg="password incorrect!";
                res.render('login.ejs',{msg:msg,eMsg:eMsg});
            }
        }
    });
});

//log out SECURE route
app.delete('/logout' ,authenticate, function(req,res){
    res.clearCookie('x-auth');
    res.redirect('/');
});

//secret SECURE route
app.get('/secret',authenticate,function(req,res){
    res.render('secret.ejs');
});

//listen to local host on port 3000
app.listen(3000, function () {
    console.log("server is up on port 3000");
});
