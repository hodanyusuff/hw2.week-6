var passport = require('passport');
var jwtStrategy = require('passport-jwt').Strategy;
var Extractjwt = require('passport-jwt').Extractjwt;

var opts = {};
opts.jwtFromRequest = Extractjwt.fromAuthHeaderWithScheme("jwt");
opts.secretOrkey = process.env.SECRET_KEY;

passport.use(new jwtStrategy(opts,
    function(jwt_payload, done){
        var user = db.find(jwt_payload.id);
        if (user)
        {
            return done(null, user);
        }
        else
        {
            return done(null, false);
        }
    }
));
exports.isAuthenticated = passport.authenticate('jwt', {session: false});
exports.secret = opts.secretOrkey;