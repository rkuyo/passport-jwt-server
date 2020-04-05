const passport = require("passport");
const User = require("../models/user");
const config = require("../config");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");

// Create local strategy
const localOptions = { usernameField: "email" }; // Says to look at email property to find username
const localLogin = new LocalStrategy(localOptions, function(
  email,
  password,
  done
) {
  // Verify this email and password
  User.findOne({ email: email }, function(err, user) {
    if (err) {
      return done(err);
    }
    // User not found
    if (!user) {
      return done(null, false);
    }

    // Compare passwords
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return done(err);
      }
      // Password does not match
      if (!isMatch) {
        return done(null, false);
      }
      // User found and password matching
      return done(null, user);
    });
  });
});

// Set up options for JWT Strategy
const jwtOptions = {
  // Attempt to get token from a header called 'authorisation'
  jwtFromRequest: ExtractJwt.fromHeader("authorisation"),
  secretOrKey: config.secret
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if the user ID in the payload exists in our db
  User.findById(payload.sub, function(err, user) {
    if (err) {
      return done(err, false);
    }
    if (user) {
      // If user exists, call 'done' with that user - authenticated
      done(null, user);
    } else {
      // Else, call 'done' without a user object - not authenticated
      done(null, false);
    }
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
