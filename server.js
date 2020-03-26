//ASCII arts from http://patorjk.com/software/taag/#p=display&f=Banner3
const express = require('express');
const passport = require('passport');
const db = require('./db');
const assert = require('assert');
const path = require('path');

const { custom } = require('openid-client');

require('custom-env').env(true);

console.log('Configuration mode:', process.env.APP_ENV);

// Assert env variables
assert(process.env.APP_URL, 'process.env.APP_URL missing');
console.log('Public URL of the service', process.env.APP_URL);

// For self signed certificates
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;

// Configure OIDC client
const defaultHttpOptions = {
  timeout: 10000,
  retries: 1,
  hooks: {
    beforeRequest: [
      (options) => {
        console.log('--> %s %s', options.method.toUpperCase(), options.href);
        console.log('--> HEADERS %o', options.headers);
        if (options.body) {
          console.log('--> BODY %s', options.body);
        }
      },
    ],
    afterResponse: [
      (response) => {
        console.log(
          '<-- %i FROM %s %s',
          response.statusCode,
          response.request.gotOptions.method.toUpperCase(),
          response.request.gotOptions.href,
        );
        console.log('<-- HEADERS %o', response.headers);
        if (response.body) {
          console.log('<-- BODY %s', response.body);
        }
        return response;
      },
    ],
  },
};
custom.setHttpOptionsDefaults(defaultHttpOptions);
console.log('OIDC client HTTP configuration %O', defaultHttpOptions);

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.
passport.serializeUser(function(req, user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(req, id, cb) {
  db.users.findById(id, "pl103", function(err, user) {
    if (err) {
      return cb(err);
    }
    cb(null, user);
  });
});


function renderHome(req, res, renderMode) {
  let mode = {
    social:
      renderMode && renderMode.social
        ? renderMode.social
        : req.session.mode && req.session.social
        ? req.session.social
        : false,
    sli: renderMode && renderMode.sli ? renderMode.sli : req.session.mode && req.session.sli ? req.session.sli : true,
    emailpwd:
      renderMode && renderMode.emailpwd
        ? renderMode.emailpwd
        : req.session.mode && req.session.emailpwd
        ? req.session.emailpwd
        : false,
    deepLink: renderMode && renderMode.deepLink,
  };
  req.session.mode = mode;
  req.session.casPassphraseRedirectURI = REDIRECT_LOGIN_URI;

  res.render('home', {
    user: req.user,
    casPassphraseRedirectURI: REDIRECT_LOGIN_URI,
    platform: { name: 'Platform103', mode: "p103"},
    mode,
    explorerUrl: process.env.UNS_EXPLORER_URL,
  });
}

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(__dirname + '/public'));

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));

let expressSession = require('express-session');
let store = new expressSession.MemoryStore();
app.use(
  expressSession({
    store,
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
  }),
);

app.use(function(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

if (process.env.APP_ENFORCE_TLS) {
  console.log('Enforce TLS, all HTTP requests will be redirected to HTTPS');
  const enforce = require('express-sslify');
  app.use(enforce.HTTPS({ trustProtoHeader: true }));
}



let REDIRECT_LOGIN_URI = '/login';
let REDIRECT_LOGIN_URI_CB = `${REDIRECT_LOGIN_URI}/cb`;

var StrategyAuth0  = require('passport-auth0-openidconnect').Strategy;

passport.use(new StrategyAuth0({
  domain: process.env.AUTH0_APP_DOMAIN,
  clientID: process.env.AUTH0_APP_CLIENT_ID,
  clientSecret: process.env.AUTH0_APP_CLIENT_SECRET,
  callbackURL: `${process.env.AUTH0_APP_CB_URL}`,
},
function(issuer, audience, profile, done) {
  if (profile) {
    user = {
      id: profile.id,
      username: profile.id,
      displayName: '',
    };
    db.users.createUserIfNeeded(user, "pl103", () => {
      done(null, user);
    });
  }
}));


// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

// Define routes.
app.get('/', function(req, res) {
  renderHome(req, res);
});


app.get('/login', passport.authenticate('auth0-oidc'));

app.get('/signout', function(req, res) {
  req.logout(req);
  res.redirect('/');
});

app.post('/saveMessage', require('connect-ensure-login').ensureLoggedIn(), function(req, res) {
  let customMessage = req.body.customMessage;
  if (customMessage) {
    customMessage = customMessage.trim();
    let user = req.user;
    user.customMessage = customMessage;
    db.users.updateUser(user, "pl103", () => {
      res.redirect('/');
    });
  } else {
    res.send();
  }
});

let interface = process.env.SERVER_LISTEN_INTERFACE;
let port = process.env.DEV_PORT ? process.env.DEV_PORT : process.env.PORT ? process.env.PORT : 3003;

// authentication callback
app.get(REDIRECT_LOGIN_URI_CB, passport.authenticate('auth0-oidc'), function(req, res) {
  db.users.updateSignIn(req.user, 'pl103', () => {
    res.redirect('/');
  });
});

app.listen(port, interface);
console.log('Server started on', `http://${interface}:${port}`);
