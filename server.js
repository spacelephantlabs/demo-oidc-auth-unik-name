//ASCII arts from http://patorjk.com/software/taag/#p=display&f=Banner3
const express = require("express");
const passport = require("passport");
const db = require("./db");
const assert = require("assert");

const OIDC = require("openid-client");

require("custom-env").env(true);

console.log("Configuration mode:", process.env.APP_ENV);

// Assert env variables
assert(process.env.APP_URL, "process.env.APP_URL missing");
console.log("Public URL of the service", process.env.APP_URL);

// For self signed certificates
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

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
    cb(null, user);
  });
});

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set("views", __dirname + "/views");
app.set("view engine", "ejs");
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

// Define routes.
app.get("/", function(req, res) {
  res.render("home", { user: req.user });
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/");
  }
);

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/profile", require("connect-ensure-login").ensureLoggedIn(), function(
  req,
  res
) {
  res.render("profile", { user: req.user });
});

let interface = process.env.SERVER_LISTEN_INTERFACE;
let port = process.env.PORT ? process.env.PORT : 3003;

function isAuthModeEnabled(authMode) {
  let enabled = process.env[authMode + "_ENABLED"] === "true";
  console.log(`Authentication mode ${authMode} is enabled: ${enabled}`);
  return enabled;
}

// #######  #### ########   ######     ########     ###     ######   ######  ########  ##     ## ########     ###     ######  ########
// ##     ##  ##  ##     ## ##    ##    ##     ##   ## ##   ##    ## ##    ## ##     ## ##     ## ##     ##   ## ##   ##    ## ##
// ##     ##  ##  ##     ## ##          ##     ##  ##   ##  ##       ##       ##     ## ##     ## ##     ##  ##   ##  ##       ##
// ##     ##  ##  ##     ## ##          ########  ##     ##  ######   ######  ########  ######### ########  ##     ##  ######  ######
// ##     ##  ##  ##     ## ##          ##        #########       ##       ## ##        ##     ## ##   ##   #########       ## ##
// ##     ##  ##  ##     ## ##    ##    ##        ##     ## ##    ## ##    ## ##        ##     ## ##    ##  ##     ## ##    ## ##
//  #######  #### ########   ######     ##        ##     ##  ######   ######  ##        ##     ## ##     ## ##     ##  ######  ########

if (isAuthModeEnabled("CAS_PASSPHRASE")) {
  (async function addOIDC_PassphraseStrategy() {
    let casIssuer = await OIDC.Issuer.discover(
      process.env.CAS_PASSPHRASE_DISCOVERY_URI
    ); // => Promise

    const client = new casIssuer.Client({
      client_id: process.env.CAS_PASSPHRASE_CLIENT_ID,
      client_secret: process.env.CAS_PASSPHRASE_CLIENT_SECRET,
      redirect_uris: [
        `${process.env.APP_URL}/login/unikname-cas-passphrase/cb`
      ],
      response_types: ["code"]
    });

    const params = {
      scope: ""
    };

    passport.use(
      "oidc-passphrase",
      new OIDC.Strategy(
        { client: client, params: params },
        (tokenset, userinfo, done) => {
          console.log("userinfo", userinfo);
          if (userinfo) {
            user = {
              id: userinfo.id,
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

  app.get(
    "/login/unikname-cas-passphrase",
    passport.authenticate("oidc-passphrase")
  );

  // authentication callback
  app.get(
    "/login/unikname-cas-passphrase/cb",
    passport.authenticate("oidc-passphrase"),
    function(
      //{ successRedirect: '/', failureRedirect: '/login' }));
      req,
      res
    ) {
      res.redirect("/");
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
