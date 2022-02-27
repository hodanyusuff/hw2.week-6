var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;

passport.use(new BasicStrategy(
    function(username, password, done){
        var user = { name: "Hodan_Yusuf"};
        if (username === user.name && password === "Hodan_Y") // tripple === means type and value and double == means just equal
        {
            return done(null, user);
        }
        else
        {
            return done(null, false);
        }
    }
));
exports.isAuthenticated = passport.authenticate('basic', {session: false});