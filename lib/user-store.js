'use strict';

// a simple minimal file based database, use it only in a demo

const _BOM = /^\uFEFF/;

let _ = require('lodash'),
    path = require('path'),
    fs = require('fs'),
    B = require('bluebird'),
    config = require(path.join(__dirname, '../config/config'));

/// start persist the following into site database
let db_path = path.join(__dirname, '../data/database.json');
let local_db = undefined;
/// end

let load_db = function () {
    return new B((resolve, reject) => {
        fs.readFile(db_path, 'utf8', (err, content) => {
            if (err)
                return reject(err);
            if (_BOM.test(content)) {
                content = content.replace(_BOM, '');
            }
            local_db = JSON.parse(content);
            resolve();
        });
    });
};

let startWatch = () => {
    fs.watch(db_path, (evt, filename) => {
        if (global.__local_write__ || evt !== 'change')
            return;
        console.log(' external change of data file ...');
        load_db();
    });
};


fs.access(db_path, (err) => {
    if (err) {
        local_db = {
            users: [],
            user_roles: {},
            access_controls: {},
            user_auth_table: {}
        };
        fs.writeFile(db_path, JSON.stringify(local_db, null, 4), (err) => {
            if (!err) {
                console.log(' initial data file created ...');
                startWatch();
            }
        });
    } else {
        startWatch();
    }
});

class userStore {
    constructor() { }
    static mapUser(req, authInfo) {
        return new B((resolve, reject) => {
            let action = () => {
                let local_u = _.find(local_db.users, u => { return u.id === authInfo.user.userId });
                if (!local_u) {
                    local_u = {
                        id: authInfo.user.userId
                    }
                    local_db.users.push(local_u);
                }
                let rec = local_db.user_auth_table[local_u.id];
                if (rec) {
                    rec.user_details = authInfo.user;
                    rec.auth_tokens[authInfo.auth.access_token.endpointId] = authInfo.auth;
                } else {
                    rec = {
                        user_details: authInfo.user,
                        auth_tokens: {}
                    };
                    rec.auth_tokens[authInfo.auth.access_token.endpointId] = authInfo.auth;
                    local_db.user_auth_table[local_u.id] = rec;
                }
                req.session.user.roles = local_db.user_roles[local_u.id];
                global.__local_write__ = true;
                fs.writeFile(db_path, JSON.stringify(local_db, null, 4), () => {
                    resolve();
                    setTimeout(() => {
                        global.__local_write__ = false;
                    }, 300);
                });
            };
            if (!local_db) {
                return load_db().then(() => {
                    action();
                });
            } else {
                action();
            }
        });
    }

    static updateToken(req, token) {
        return new B((resolve, reject) => {
            let action = () => {
                if (local_db.user_auth_table[req.user.id]) {
                    local_db.user_auth_table[req.user.id].auth_tokens[token.access_token.endpointId] = token;
                    global.__local_write__ = true;
                    fs.writeFile(db_path, JSON.stringify(local_db, null, 4), () => {
                        resolve();
                        setTimeout(() => {
                            global.__local_write__ = false;
                        }, 300);
                    });
                } else {
                    reject();
                }
            };
            if (!local_db) {
                return load_db().then(() => {
                    action();
                });
            } else {
                action();
            }
        });
    }

    static unmapUser(user) {
        return new B((resolve, reject) => {
            let action = () => {
                if (!user)
                    return resolve();
                let rec = local_db.user_auth_table[user.id];
                if (rec) {
                    rec.auth_tokens[user.eid] = undefined;
                    let cnt = 0;
                    for (let k in rec.auth_tokens) {
                        if (rec.auth_tokens[k]) {
                            cnt++;
                        }
                    }
                    if (cnt === 0) {
                        local_db.user_auth_table[user.id] = undefined;
                    }
                }
                global.__local_write__ = true;
                fs.writeFile(db_path, JSON.stringify(local_db, null, 4), () => {
                    resolve();
                    setTimeout(() => {
                        global.__local_write__ = false;
                    }, 300);
                });
            };
            if (!local_db) {
                return load_db().then(() => {
                    action();
                });
            } else {
                action();
            }
        });
    }

    static accessControlList(configId) {
        return new B((resolve, reject) => {
            if (!configId) {
                resolve();
            } else {
                let action = () => {
                    let acl = local_db.access_controls[configId] || {};
                    resolve(acl);
                };
                if (!local_db) {
                    return load_db().then(() => {
                        action();
                    });
                } else {
                    action();
                }
            }
        });
    }
};

module.exports = userStore;
