var DEFAULT_RECORDS = {
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
};

var records = DEFAULT_RECORDS;

exports.findById = function(id, cb) {
  process.nextTick(function() {
    if (records[id]) {
      cb(null, records[id]);
    } else {
      cb(new Error("User " + id + " does not exist"));
    }
  });
};

exports.findByUsername = function(username, cb) {
  process.nextTick(function() {
    for (var i = 0, len = records.length; i < len; i++) {
      var record = records[i];
      if (record.username === username) {
        return cb(null, record);
      }
    }
    return cb(null, null);
  });
};

exports.createUserIfNeeded = function(user, cb) {
  process.nextTick(function() {
    if (user && user.id && !records[user.id]) {
      records[user.id] = user;
    }
    cb(null, user);
  });
};

exports.updateUser = (user, cb) => {
  process.nextTick(_ => {
    if (user && user.id && records[user.id]) {
      records[user.id] = user;
    }
    cb();
  });
};
