/*
file: server.js
description: WEB API for movie API
 */

var express = require('express');
var http = require('http');
var bodyParser = require('body-parser');
var passport = require('passport');
var authController = require('./auth');
var authjwtController = require('./auth_jwt');
db = require('./db')(); //hack
var jwt = require('jsonwebtoken');
var cors = require('cors');

var app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(passport.initialize());

var router = express.Router();

function getJSONObjectForMovieRequirement(req) {
    var json = {
        headers: "No headers",
        key: process.env.UNIQUE_KEY,
        body: "No body"
    };
    if (req.headers != null) {
        json.headers =req.headers;
    }
    return json;
}
router.post('/signup', function(req,res){
    if (!req.body.username || !req.body.password) {
        res.json({success: false, msg: 'please include both username and password to signup.'})
    } else {
        var newUser = {
            username: req.body.username,
            password: req.body.password
        };
        db.save(newUser); //no dublicate check
        res.json({success: true, msg: 'successfully created new user.'})
    }
});
router.post('/signin', function (req,res){
    var user = db.findOne(req.body.username);
    if(!user){
        res.status(401).send({success: false, msg: 'Authentication failed. user not found.'});
    } else {
        if (req.body.password == user.password){
            var userToken = { id: user.id, username: user.username};
            var token = jwt.sign(userToken, process.env.SECRET_KEY);
            res.json({success: true, token: 'jwt' + token});
        }
        else {
            res.status(401).send({success: false, msg: 'Austhentication failed.'});
        }
    }
});
router.route('/movie')
    .delete(authController.isAuthenticated, function(req, res) {
        console.log(req.body);
        res = res.status(200);
        if(req.get('content-Type')) {
            res = res.type(req.get('content-Type'));
        }
        var o = getJSONObjectForMovieRequirement(req);
        res.json(o);
    }
    )
    .put(authjwtController.isAuthenticated, function(req, res) {
            console.log(req.body);
            res = res.status(200);
            if(req.get('content-Type')) {
                res = res.type(req.get('content-Type'));
            }
            var o = getJSONObjectForMovieRequirement(req);
            res.json(o);
        }
    );

app.use('/', router);
app.listen(process.env.PORT || 3000);
module.exports = app; // for testing only