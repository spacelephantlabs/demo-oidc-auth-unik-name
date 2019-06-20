var DEFAULT_RECORDS = {
  default: {
    jack: {
      id: "jack",
      username: "jack",
      password: "secret",
      displayName: "Jack",
      emails: [{ value: "jack@example.com" }],
      customMessage: "My custom message"
    },
    jill: {
      id: "jill",
      username: "jill",
      password: "birthday",
      displayName: "Jill",
      emails: [{ value: "jill@example.com" }]
    }
  }
};

var records = DEFAULT_RECORDS;

exports.findById = function(id, tenant, cb) {
  process.nextTick(function() {
    if (records[tenant] && records[tenant][id]) {
      cb(null, records[tenant][id]);
    } else {
      cb(new Error(`User ${id} does not exist for tenant ${tenant}`));
    }
  });
};

exports.findByUsername = function(username, theTenant, cb) {
  process.nextTick(function() {
    for (var i = 0, len = records.length; i < len; i++) {
      var tenant = records[i];
      if (tenant[username] === username) {
        return cb(null, tenant[username]);
      }
    }
    return cb(null, null);
  });
};

exports.createUserIfNeeded = function(user, tenant, cb) {
  process.nextTick(function() {
    if (user && user.id && !(records[tenant] && records[tenant][user.id])) {
      user.signInCount = 0;
      if (!records[tenant]) {
        records[tenant] = {};
      }
      records[tenant][user.id] = user;
    }
    cb(null, user);
  });
};

exports.updateUser = (user, tenant, cb) => {
  process.nextTick(_ => {
    if (user && user.id && records[tenant] && records[tenant][user.id]) {
      records[tenant][user.id] = user;
    }
    cb();
  });
};


exports.updateSignIn = (user, tenant, cb) => {
  if (user && user.id && records[tenant] && records[tenant][user.id]) {
    let signInDate = new Date().getTime();
    user = records[tenant][user.id];
    if (!user.signupDate) {
      user.signupDate = signInDate;
    }
    user.lastSignInDate = signInDate;
    user.signInCount++;
    records[tenant][user.id] = user;
  }
  cb();
};