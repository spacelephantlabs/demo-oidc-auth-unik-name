//ASCII arts from http://patorjk.com/software/taag/#p=display&f=Banner3
const express = require('express');
const passport = require('passport');
const db = require('./db');
const assert = require('assert');
const path = require('path');
const helmet = require('helmet');

const { custom, Issuer, Strategy } = require('openid-client');

const P101_MODE = 'p101';
const P102_MODE = 'p102';

const P101_NAME = 'Platform101';
const P102_NAME = 'Platform102';

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
passport.serializeUser(function (req, user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function (req, id, cb) {
  db.users.findById(id, req.session.tenant, function (err, user) {
    if (err) {
      return cb(err);
    }
    console.log('USER FROM DB !!!!!!!!!!!!!!', user);
    cb(null, user);
  });
});

function isDevMode() {
  return process.env.APP_ENV === 'dev';
}

function loadPlatformAndTenant(request) {
  let tenant = isDevMode() ? request.headers.host : request.hostname;
  request.session.tenant = tenant;

  console.log('GET PLATFORM FOR TENANT: ', tenant);

  let p102ModeActivated = tenant === process.env.P102_HOST_URL;

  console.log('P102_HOST_URL : ', process.env.P102_HOST_URL);
  let platformMode = p102ModeActivated ? P102_MODE : P101_MODE;

  console.log('HOST TO STORE : ', tenant);
  let platformName = p102ModeActivated ? P102_NAME : P101_NAME;

  request.session.platform = {
    mode: platformMode,
    name: platformName,
  };
}

function logout(req) {
  req.logout();
  req.user = undefined;
}

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
  req.session.casPassphraseRedirectURI = CAS_PASSPHRASE_REDIRECT_URI;

  if (!req.session.tenant) {
    loadPlatformAndTenant(req);
  }

  res.render('home', {
    user: req.user,
    casPassphraseRedirectURI: CAS_PASSPHRASE_REDIRECT_URI,
    platform: req.session.platform,
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

app.set('trust proxy', !isDevMode());

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

app.use(function (req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// Enforce Helmet, especially for the Referrer policy
// All options https://www.npmjs.com/package/helmet#how-it-works
app.use(helmet());

if (process.env.APP_ENFORCE_TLS) {
  console.log('Enforce TLS, all HTTP requests will be redirected to HTTPS');
  const enforce = require('express-sslify');
  app.use(enforce.HTTPS({ trustProtoHeader: true }));
}

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

let CAS_PASSPHRASE_REDIRECT_URI = '/login/unikname';
let CAS_PASSPHRASE_REDIRECT_URI_CB = `${CAS_PASSPHRASE_REDIRECT_URI}/cb`;

// Define routes.
app.get('/', function (req, res) {
  renderHome(req, res);
});

app.get('/login', function (req, res) {
  let redirect = `${req.session.mode && req.session.mode.sli ? '/sli' : ''}${CAS_PASSPHRASE_REDIRECT_URI}`;
  if (req.session.mode && !req.session.mode.social && !req.session.mode.emailpwd) {
    res.redirect(redirect);
  }
});
app.get('/connectSocialAuthent', function (req, res) {
  let mode = {
    social: true,
    emailpwd: true,
    sli: false,
    deepLink: true,
  };
  renderHome(req, res, mode);
  //res.redirect('/?social=true&emailpwd=true&sli=false&deepLink=true');
});

app.get('/connectEmail', function (req, res) {
  let mode = {
    social: false,
    emailpwd: true,
    sli: false,
    deepLink: true,
  };
  renderHome(req, res, mode);
  //res.redirect('/?emailpwd=true&sli=false&deepLink=true');
});

app.get('/signout', function (req, res) {
  logout(req);
  res.redirect('/');
});

app.post('/saveMessage', require('connect-ensure-login').ensureLoggedIn(), function (req, res) {
  let customMessage = req.body.customMessage;
  if (customMessage) {
    customMessage = customMessage.trim();
    let user = req.user;
    user.customMessage = customMessage;
    db.users.updateUser(user, req.session.tenant, () => {
      res.redirect('/');
    });
  } else {
    res.send();
  }
});

let interface = process.env.SERVER_LISTEN_INTERFACE;
let port = process.env.DEV_PORT ? process.env.DEV_PORT : process.env.PORT ? process.env.PORT : 3003;

function isAuthModeEnabled(authMode) {
  let enabled = process.env[authMode + '_ENABLED'] === 'true';
  console.log(`Authentication mode ${authMode} is enabled: ${enabled}`);
  return enabled;
}

app.get('/reset', function (req, res) {
  let mode = req.session.mode;
  req.session.cookie.httpOnly = false;

  // Logout
  logout(req);

  // Reset cookies
  Object.keys(req.cookies).forEach((cookieName) => {
    //res.clearCookie(cookieName, { path: '/', httpOnly: false });
    res.cookie(cookieName, '', { path: '/', httpOnly: false, expires: new Date('Thu, 25 Dec 2000 12:00:00 UTC') });
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

const params101 = {
  scope: 'openid',
  prompt: 'login',
};

const params102 = {
  scope: 'openid',
};

// Custom strategies
const P101_STRATEGY_NAME = 'p101Strategy';
createPassphraseInstance(
  process.env.P101_HOST_URL,
  process.env.CAS_PASSPHRASE_CLIENT_ID_P101,
  process.env.CAS_PASSPHRASE_CLIENT_SECRET_P101,
  P101_STRATEGY_NAME,
  params101,
);

const STAGING_P101_STRATEGY_NAME = 'stagingP101Strategy';
createPassphraseInstance(
  process.env.STAGING_P101_HOST_URL,
  process.env.CAS_PASSPHRASE_CLIENT_ID_STAGING_P101,
  process.env.CAS_PASSPHRASE_CLIENT_SECRET_STAGING_P101,
  STAGING_P101_STRATEGY_NAME,
  params101,
);

const P102_STRATEGY_NAME = 'p102Strategy';
createPassphraseInstance(
  process.env.P102_HOST_URL,
  process.env.CAS_PASSPHRASE_CLIENT_ID_P102,
  process.env.CAS_PASSPHRASE_CLIENT_SECRET_P102,
  P102_STRATEGY_NAME,
  params102,
);

function doAuthenticate(req, res, next) {
  if (!req.session.tenant) {
    loadPlatformAndTenant(req);
  }
  let strategy2Use =
    req.session.platform && req.session.platform.mode === P102_MODE ? P102_STRATEGY_NAME : P101_STRATEGY_NAME;
  passport.authenticate(strategy2Use)(req, res, next);
}

// Common routes
app.get(CAS_PASSPHRASE_REDIRECT_URI, doAuthenticate);

// authentication callback
app.get(CAS_PASSPHRASE_REDIRECT_URI_CB, doAuthenticate, function (req, res) {
  db.users.updateSignIn(req.user, req.session.tenant, () => {
    res.redirect('/');
  });
});

function createPassphraseInstance(hostname, clientId, clientSecret, strategyName, strategyParams) {
  console.log('Auth server uri:', process.env.CAS_PASSPHRASE_DISCOVERY_URI);
  console.log('Local redirect URI:', CAS_PASSPHRASE_REDIRECT_URI);
  console.log('Local callback redirect URI:', CAS_PASSPHRASE_REDIRECT_URI_CB);
  console.log('OIDC client id:', clientId);
  console.log('OIDC client pass:', clientSecret);

  (async function addOIDC_PassphraseStrategy() {
    let unAuthIssuer = await Issuer.discover(process.env.CAS_PASSPHRASE_DISCOVERY_URI); // => Promise

    console.log('Discovered Unik-Name Auth\n Issuer: %s\n Metadata:\n%O', unAuthIssuer.issuer, unAuthIssuer.metadata);

    const client = new unAuthIssuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [`http${isDevMode() ? '' : 's'}://${hostname}${CAS_PASSPHRASE_REDIRECT_URI_CB}`],
      response_types: ['code'],
    });

    passport.use(
      strategyName,
      new Strategy(
        { client: client, params: strategyParams, passReqToCallback: true },
        (req, tokenset, userinfo, done) => {
          console.log('userinfo', userinfo);
          if (userinfo) {
            user = {
              id: userinfo.sub,
              username: userinfo.sub,
              displayName: '',
            };
            db.users.createUserIfNeeded(user, req.session.tenant, () => {
              done(null, user);
            });
          }
        },
      ),
    );
  })();
}

// ######  ######## ########  ##     ## ######## ########
// ##    ## ##       ##     ## ##     ## ##       ##     ##
// ##       ##       ##     ## ##     ## ##       ##     ##
//  ######  ######   ########  ##     ## ######   ########
//       ## ##       ##   ##    ##   ##  ##       ##   ##
// ##    ## ##       ##    ##    ## ##   ##       ##    ##
//  ######  ######## ##     ##    ###    ######## ##     ##

app.listen(port, interface);
console.log('Server started on', `http://${interface}:${port}`);
