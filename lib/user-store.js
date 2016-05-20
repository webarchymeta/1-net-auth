'use strict';

// a simple minimal file base database, use it only in a demo

let _ = require('lodash'),
    path = require('path'),
    fs = require('fs'),
    B = require('bluebird'),
    config = require(path.join(__dirname, '../config/config'));

/// start persist the following into site database
let db_path = path.join(__dirname, '../data/database.json');
let local_db = undefined;
/// end

fs.watch(db_path, (evt, filename) => {
    if (global.__local_write__)
        return;
    console.log(' external change of data file ...');
    fs.readFile(db_path, (content) => {
        local_db = JSON.parse(content);
    });
});

class userStore {
    constructor() { }
    static mapUser(req, authInfo) {
        return new B((resolve, reject) => {
            let action = () => {
                let local_u = _.find(users, u => { return u.id === authInfo.user.userId });
                if (!local_u) {
                    local_u = {
                        id: authInfo.user.userId
                    }
                    local_db.users.push(local_u);
                }
                local_db.user_auth_table[local_u.id] = {
                    user_details: authInfo.user,
                    auth_info: authInfo.auth
                };
                req.session.user.roles = user_roles[local_u.id];
                global.__local_write__ = true;
                fs.writeFile(db_path, JSON.stringify(local_db, null, 4), () => {
                    resolve();
                    setTimeout(() => {
                        global.__local_write__ = false;
                    }, 300);
                });
            };
            if (!local_db) {
                fs.readFile(db_path, (content) => {
                    local_db = JSON.parse(content);
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
                if (local_db.user_auth_table[userId]) {
                    local_db.user_auth_table[req.user.id].auth_info = token;
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
                fs.readFile(db_path, (content) => {
                    local_db = JSON.parse(content);
                    action();
                });
            } else {
                action();
            }
        });
    }

    static unmapUser(userId) {
        return new B((resolve, reject) => {
            let action = () => {
                local_db.user_auth_table[userId] = undefined;
                global.__local_write__ = true;
                fs.writeFile(db_path, JSON.stringify(local_db, null, 4), () => {
                    resolve();
                    setTimeout(() => {
                        global.__local_write__ = false;
                    }, 300);
                });
            };
            if (!local_db) {
                fs.readFile(db_path, (content) => {
                    local_db = JSON.parse(content);
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
                    fs.readFile(db_path, (content) => {
                        local_db = JSON.parse(content);
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