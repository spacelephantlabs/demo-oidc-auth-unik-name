//ASCII arts from http://patorjk.com/software/taag/#p=display&f=Banner3
const express = require("express");
const passport = require("passport");
const db = require("./db");
const assert = require("assert");
const path = require('path');


const Strategy = require("passport-local").Strategy;
const OIDC = require("openid-client");

require("custom-env").env(true);

console.log("Configuration mode:", process.env.APP_ENV);

// Assert env variables
assert(process.env.APP_URL, "process.env.APP_URL missing");
console.log("Public URL of the service", process.env.APP_URL);

// For self signed certificates
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

// Configure OIDC client
OIDC.Issuer.defaultHttpOptions = { timeout: 10000, retries: 1 };
console.log(
  "OIDC client HTTP configuration %O",
  OIDC.Issuer.defaultHttpOptions
);

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.
passport.serializeUser(function(user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  db.users.findById(id, function(err, user) {
    if (err) {
      return cb(err);
    }
    console.log("USER FROM DB !!!!!!!!!!!!!!", user);
    cb(null, user);
  });
});

function getQueryParameters(mode) {
  let queryParams = "";
  if (mode && Object.keys(mode).length > 0) {
    let reducer = (acc, currentValue, index) =>  `${acc}${currentValue}=${mode[currentValue]}${(index === (Object.keys(mode).length - 1)) ? '' : '&'}`;
    queryParams = Object.keys(mode).reduce(reducer, "?");
  }
  return queryParams;
}

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(__dirname + "/public"));

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require("morgan")("combined"));
app.use(require("cookie-parser")());
app.use(require("body-parser").urlencoded({ extended: true }));
app.use(
  require("express-session")({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false
  })
);

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

if (process.env.APP_ENFORCE_TLS) {
  console.log("Enforce TLS, all HTTP requests will be redirected to HTTPS");
  const enforce = require("express-sslify");
  app.use(enforce.HTTPS({ trustProtoHeader: true }));
}

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

let casPassphraseRedirectURI = "/login/unikname";

// Define routes.
app.get("/", function(req, res) {
  mode = {
    social: (req.query.social === undefined) ? false : (req.query.social === 'true'),
    sli: (req.query.sli === undefined) ? true : (req.query.sli === 'true'),
    emailpwd: (req.query.emailpwd === undefined) ? false : (req.query.emailpwd === 'true'),
  }
  let redirect = `${(mode.sli) ? '/sli' : ''}${casPassphraseRedirectURI}`
  req.session.mode = mode;
  req.session.casPassphraseRedirectURI = redirect;
  res.render("home", {
    user: req.user,
    casPassphraseRedirectURI: redirect
  });
});

app.get("/login", function(req, res) {
  let redirect = `${(req.session.mode && req.session.mode.sli) ? '/sli' : ''}${casPassphraseRedirectURI}`
  if (req.session.mode && !req.session.mode.social && !req.session.mode.emailpwd) {
    res.redirect(redirect);
  }
});

app.get("/connectSocialAuthent", function(req, res) {
  res.redirect('/?social=true&emailpwd=true&sli=false');
});

app.get("/connectEmail", function(req, res) {
  res.redirect('/?emailpwd=true&sli=false');
});

app.get("/signout", function(req, res) {
  let mode = req.session.mode;
  req.logout();
  res.redirect('/' + getQueryParameters(mode));
});


app.get("/profile", require("connect-ensure-login").ensureLoggedIn(), function(
  req,
  res
) {
  res.render("profile", {
    user: req.user,
    casPassphraseRedirectURI: req.session.casPassphraseRedirectURI
  });
});

let interface = process.env.SERVER_LISTEN_INTERFACE;
let port = process.env.PORT ? process.env.PORT : 3003;

function isAuthModeEnabled(authMode) {
  let enabled = process.env[authMode + "_ENABLED"] === "true";
  console.log(`Authentication mode ${authMode} is enabled: ${enabled}`);
  return enabled;
}

app.get("/reset", function(req, res) {
  // Logout
  req.logout();
  // Destroy session & Reset cookies
  req.session.destroy(a => {
    Object.keys(req.cookies).forEach((cookieName) => {
      res.clearCookie(cookieName);
    });
    res.redirect('/');
  });
});

// ##        #######   ######     ###    ##          ########     ###     ######   ######  ##      ##  #######  ########  ########
// ##       ##     ## ##    ##   ## ##   ##          ##     ##   ## ##   ##    ## ##    ## ##  ##  ## ##     ## ##     ## ##     ##
// ##       ##     ## ##        ##   ##  ##          ##     ##  ##   ##  ##       ##       ##  ##  ## ##     ## ##     ## ##     ##
// ##       ##     ## ##       ##     ## ##          ########  ##     ##  ######   ######  ##  ##  ## ##     ## ########  ##     ##
// ##       ##     ## ##       ######### ##          ##        #########       ##       ## ##  ##  ## ##     ## ##   ##   ##     ##
// ##       ##     ## ##    ## ##     ## ##          ##        ##     ## ##    ## ##    ## ##  ##  ## ##     ## ##    ##  ##     ##
// ########  #######   ######  ##     ## ########    ##        ##     ##  ######   ######   ###  ###   #######  ##     ## ########

if (isAuthModeEnabled("LOCAL_PWD")) {
  // Configure the local strategy for use by Passport.
  //
  // The local strategy require a `verify` function which receives the credentials
  // (`username` and `password`) submitted by the user.  The function must verify
  // that the password is correct and then invoke `cb` with a user object, which
  // will be set at `req.user` in route handlers after authentication.
  passport.use(
    new Strategy(function(username, password, cb) {
      db.users.findById(username, function(err, user) {
        if (err) {
          return cb(err);
        }
        if (!user) {
          return cb(null, false);
        }
        if (user.password != password) {
          return cb(null, false);
        }
        return cb(null, user);
      });
    })
  );
}

//  #######  #### ########   ######     ########  ######## ##     ##  #######  ######## ########    ##      ##    ###    ##       ##       ######## ########
// ##     ##  ##  ##     ## ##    ##    ##     ## ##       ###   ### ##     ##    ##    ##          ##  ##  ##   ## ##   ##       ##       ##          ##
// ##     ##  ##  ##     ## ##          ##     ## ##       #### #### ##     ##    ##    ##          ##  ##  ##  ##   ##  ##       ##       ##          ##
// ##     ##  ##  ##     ## ##          ########  ######   ## ### ## ##     ##    ##    ######      ##  ##  ## ##     ## ##       ##       ######      ##
// ##     ##  ##  ##     ## ##          ##   ##   ##       ##     ## ##     ##    ##    ##          ##  ##  ## ######### ##       ##       ##          ##
// ##     ##  ##  ##     ## ##    ##    ##    ##  ##       ##     ## ##     ##    ##    ##          ##  ##  ## ##     ## ##       ##       ##          ##
//  #######  #### ########   ######     ##     ## ######## ##     ##  #######     ##    ########     ###  ###  ##     ## ######## ######## ########    ##

if (isAuthModeEnabled("CAS_PASSPHRASE")) {
  createPassphraseInstance();
  createPassphraseInstance('sli');
}

function createPassphraseInstance(subRoute = '') {
  let CAS_PASSPHRASE_REDIRECT_URI = `${subRoute ? '/' + subRoute : ''}${casPassphraseRedirectURI}`;
  let CAS_PASSPHRASE_REDIRECT_URI_CB = `${CAS_PASSPHRASE_REDIRECT_URI}/cb`;
  let oidcName = `oidc-wallet${subRoute ? '-' + subRoute : ''}`;

  const varEnvSuffix = subRoute ? `_${subRoute.toUpperCase()}` : '';

  console.log("Auth server uri:", process.env.CAS_PASSPHRASE_DISCOVERY_URI);
  console.log("Local redirect URI:", CAS_PASSPHRASE_REDIRECT_URI);
  console.log("Local callback redirect URI:", CAS_PASSPHRASE_REDIRECT_URI_CB);
  console.log("OIDC client id:", process.env[`CAS_PASSPHRASE_CLIENT_ID${varEnvSuffix}`]);
  console.log("OIDC client pass:", process.env[`CAS_PASSPHRASE_CLIENT_SECRET${varEnvSuffix}`]);

  (async function addOIDC_PassphraseStrategy() {
    let unAuthIssuer = await OIDC.Issuer.discover(
      process.env.CAS_PASSPHRASE_DISCOVERY_URI
    ); // => Promise

    console.log(
      "Discovered Unik-Name Auth\n Issuer: %s\n Metadata:\n%O",
      unAuthIssuer.issuer,
      unAuthIssuer.metadata
    );

    const client = new unAuthIssuer.Client({
      client_id: process.env[`CAS_PASSPHRASE_CLIENT_ID${varEnvSuffix}`],
      client_secret: process.env[`CAS_PASSPHRASE_CLIENT_SECRET${varEnvSuffix}`],
      redirect_uris: [
        `${process.env.APP_URL}${CAS_PASSPHRASE_REDIRECT_URI_CB}`
      ],
      response_types: ["code"]
    });

    const params = {
      scope: "openid email"
    };

    passport.use(
      oidcName,
      new OIDC.Strategy(
        { client: client, params: params },
        (tokenset, userinfo, done) => {
          console.log("userinfo", userinfo);
          if (userinfo) {
            user = {
              id: userinfo.sub,
              username: userinfo.sub,
              displayName: ""
            };
            db.users.createUserIfNeeded(user, () => {
              done(null, user);
            });
          }
        }
      )
    );
  })();

  app.get(CAS_PASSPHRASE_REDIRECT_URI, passport.authenticate(oidcName));

  // authentication callback
  app.get(
    CAS_PASSPHRASE_REDIRECT_URI_CB,
    passport.authenticate(oidcName),
    function(
      //{ successRedirect: '/', failureRedirect: '/login' }));
      req,
      res
    ) {
      res.redirect("/profile");
    }
  );
}

// ######  ######## ########  ##     ## ######## ########
// ##    ## ##       ##     ## ##     ## ##       ##     ##
// ##       ##       ##     ## ##     ## ##       ##     ##
//  ######  ######   ########  ##     ## ######   ########
//       ## ##       ##   ##    ##   ##  ##       ##   ##
// ##    ## ##       ##    ##    ## ##   ##       ##    ##
//  ######  ######## ##     ##    ###    ######## ##     ##

app.listen(port, interface);
console.log("Server started on", `http://${interface}:${port}`);
