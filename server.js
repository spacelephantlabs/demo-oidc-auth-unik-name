//ASCII arts from http://patorjk.com/software/taag/#p=display&f=Banner3
const express = require("express");
const passport = require("passport");
const db = require("./db");
const assert = require("assert");
const path = require('path');

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
passport.serializeUser(function(req, user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(req, id, cb) {
  db.users.findById(id, getTenantFromRequest(req), function(err, user) {
    if (err) {
      return cb(err);
    }
    console.log("USER FROM DB !!!!!!!!!!!!!!", user);
    cb(null, user);
  });
});

function getTenantFromRequest(request) {
  return isDevMode() ? request.headers.host : request.hostname;
}

function isDevMode() {
  return process.env.APP_ENV === 'dev';
}

function getPlatform(request) {
  let p102ModeActivated =  isDevMode() ? (request.headers.host === process.env.P102_HOST_URL) : (request.hostname === process.env.P102_HOST_URL);

  console.log("P102_HOST_URL : ", process.env.P102_HOST_URL);
  let platformMode = p102ModeActivated ? 'p102' : 'p101';

  console.log("HOST TO STORE : ", isDevMode() ? request.headers.host : request.hostname);
  let platformName = p102ModeActivated ? 'Platform102' : 'Platform101';

  return {
    mode: platformMode,
    name: platformName
  };
}

function getAppUrlPort() {
  return process.env.DEV_PORT ? `:${process.env.DEV_PORT}` : '';
}

function logout(req) {
  req.logout();
  req.user = undefined;
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

app.set('trust proxy', isDevMode());

let expressSession = require("express-session");
let store = new expressSession.MemoryStore();
app.use(
  expressSession({
    store,
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
    social: (req.query.social === undefined) ? (req.session.mode && req.session.social ? req.session.social : false) : (req.query.social === 'true'),
    sli: (req.query.sli === undefined) ? (req.session.mode && req.session.sli ? req.session.sli : true) : (req.query.sli === 'true'),
    emailpwd: (req.query.emailpwd === undefined) ? (req.session.mode && req.session.emailpwd ? req.session.emailpwd : false) : (req.query.emailpwd === 'true'),
  }
  let redirect = `${(mode.sli) ? '/sli' : ''}${casPassphraseRedirectURI}`
  let deepLink = req.query.deepLink;
  req.session.mode = mode;
  req.session.casPassphraseRedirectURI = redirect;
  req.session.platform = getPlatform(req);

  res.render("home", {
    user: req.user,
    casPassphraseRedirectURI: redirect,
    platform: req.session.platform,
    deepLink
  });
});

app.get("/login", function(req, res) {
  let redirect = `${(req.session.mode && req.session.mode.sli) ? '/sli' : ''}${casPassphraseRedirectURI}`
  if (req.session.mode && !req.session.mode.social && !req.session.mode.emailpwd) {
    res.redirect(redirect);
  }
});
app.get("/connectSocialAuthent", function(req, res) {
  res.redirect('/?social=true&emailpwd=true&sli=false&deepLink=true');
});

app.get("/connectEmail", function(req, res) {
  res.redirect('/?emailpwd=true&sli=false&deepLink=true');
});

app.get("/signout", function(req, res) {
  logout(req);
  res.redirect('/');
});

app.post("/saveMessage", require("connect-ensure-login").ensureLoggedIn(), function(req, res) {
  let customMessage = req.body.customMessage;
  if (customMessage) {
    customMessage = customMessage.trim();
    let user = req.user;
    user.customMessage = customMessage;
    db.users.updateUser(user, getTenantFromRequest(req), () => {res.redirect("/")});
  } else {
    res.send();
  }
});

let interface = process.env.SERVER_LISTEN_INTERFACE;
let port = process.env.DEV_PORT
  ? process.env.DEV_PORT
  : (process.env.PORT ? process.env.PORT : 3003);

function isAuthModeEnabled(authMode) {
  let enabled = process.env[authMode + "_ENABLED"] === "true";
  console.log(`Authentication mode ${authMode} is enabled: ${enabled}`);
  return enabled;
}

app.get("/reset", function(req, res) {
  let mode = req.session.mode;
  req.session.cookie.httpOnly = false;

  // Logout
  logout(req);

  // Reset cookies
  Object.keys(req.cookies).forEach((cookieName) => {
    //res.clearCookie(cookieName, { path: '/', httpOnly: false });
    res.cookie(cookieName, '', { path: '/', httpOnly: false, expires: new Date("Thu, 25 Dec 2000 12:00:00 UTC") });
    store.destroy(req.cookies[cookieName]);
  });

  req.session.mode = mode;
  res.redirect('/');
});

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
        `${process.env.APP_URL}${getAppUrlPort()}${CAS_PASSPHRASE_REDIRECT_URI_CB}`
      ],
      response_types: ["code"]
    });

    const params = {
      scope: "openid email"
    };

    passport.use(
      oidcName,
      new OIDC.Strategy(
        { client: client, params: params, passReqToCallback: true },
        (req, tokenset, userinfo, done) => {
          console.log("userinfo", userinfo);
          if (userinfo) {
            user = {
              id: userinfo.sub,
              username: userinfo.sub,
              displayName: ""
            };
            db.users.createUserIfNeeded(user, getTenantFromRequest(req), () => {
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
    function(req, res) {
      db.users.updateSignIn(req.user, getTenantFromRequest(req), () => {
        res.redirect("/");
      });
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
