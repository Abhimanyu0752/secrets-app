//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));


app.use(session({
  secret: 'Our little secret',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);      //passport local mongoose package will create hash and salt automatically
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({    //in this section we provide our app's information to third party server.
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRETS,
    callbackURL: "http://localhost:3000/auth/google/secrets",    //this is the link where third party server sent us back the users data/information

  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));  //here scope is the value which we wants to get as user data/information.
                                                       //initiate authentication on google's server.



  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }), //this is where we authenticate the user locally and save the session and cookies.
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});



app.get("/secrets",function(req,res){
User.find({secret:{$ne:null}},function(err,foundusers){
  if(err){
    console.log(err);
  }else{
    if(foundusers){
      res.render("secrets",{usersWithSecrets:foundusers});
    }
  }
});
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/");
  }
});

app.post("/submit",function(req,res){
  const userSecret = req.body.secret;
  User.findById(req.user.id,function(err,founduser){
    if(err){
      console.log(err);
    }else{
      if(founduser){
        founduser.secret=userSecret;
        founduser.save(function(){
        res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register", function(req, res) {

User.register({username:req.body.username},req.body.password,function(err,user){
  if(err){
    console.log(err);
    res.redirect("/register");
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }
});
});


app.post("/login", function(req, res) {
const user = new User({
  username:req.body.username,
  password:req.body.password
});

req.login(user,function(err){
  if(err){
    console.log(err);
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }
});
});


app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
