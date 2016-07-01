'use strict';

let _ = require('lodash'),
    path = require('path'),
    B = require('bluebird'),
    https = require('https'),
    http_req = require('request'),
    uuid = require('node-uuid'),
    crypto = require('crypto');

let Authenticator = function () {
    let self = this;
    let config = Authenticator.config;
    let userStore = Authenticator.userStore;

    let authHost = config.vnet.endponts.baseUrl.substr('https://'.length);
    let authPort = 443;

    if (authHost.indexOf(':') !== -1) {
        authPort = parseInt(authHost.substr(authHost.indexOf(':') + 1));
        authHost = authHost.substr(0, authHost.indexOf(':'));
    }

    let agentOptions = {
        host: authHost,
        port: authPort,
        path: config.vnet.endponts.token.apiPath,
        rejectUnauthorized: !config.debugMode
    };

    let authAgent = new https.Agent(agentOptions);

    let isInRole = (req, roles) => {
        return req.user && (!roles || roles && req.user.roles && _.intersection([_.map(req.user.roles, r => { return r.toLowerCase(); }), _.map(roles, r => { return r.toLowerCase(); })]).length > 0);
    };

    let isEndpointAllowed = (req, endpoints) => {
        if (!endpoints) {
            return true;
        } else if (endpoints.blacklist && _.find(endpoints.blacklist, ep => { return ep === req.session.endpoint; })) {
            return false;
        }
        if (!endpoints.blacklist) {
            return endpoints.whitelist && _.find(endpoints.whitelist, ep => { return ep === req.session.endpoint; });
        } else {
            return !endpoints.whitelist || endpoints.whitelist && _.find(endpoints.whitelist, ep => { return ep === req.session.endpoint; });
        }
    };

    let encodeState = state => {
        let aes = crypto.createCipher('aes-256-cbc', config.authKey);
        return aes.update(JSON.stringify(state), 'utf8', 'base64') + aes.final('base64');
    };

    let decodeState = state => {
        let aes = crypto.createDecipher('aes-256-cbc', config.authKey);
        let json = aes.update(state, 'base64', 'utf8') + aes.final('utf8');
        return JSON.parse(json);
    };

    let domainUrl = (req) => {
        return config.accessProtocol + '://' + req.headers['host'] + (config.accessPort ? ':' + config.accessPort : '');
    };

    self.check = (policyId) => {
        return (req, res, next) => {
            userStore.getAccessControl(policyId).then((policy) => {
                if (!req.isAuthenticated()) {
                    let transId = uuid.v4();
                    let state = {
                        tid: transId,
                        returnTo: domainUrl(req) + req.originalUrl
                    };
                    req.session['oauth-login-state'] = state;
                    let cstate = encodeState(state);
                    let authUrl = _.trimEnd(config.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.vnet.endponts.authorize.apiPathFmt.replace(/\{0\}/, config.viewType), '/');
                    authUrl += '?response_type=code';
                    authUrl += '&client_id=' + encodeURIComponent(config.vnet.clientId);
                    authUrl += '&redirect_uri=' + encodeURIComponent(domainUrl(req) + config.returnPath);
                    authUrl += '&scope=' + encodeURIComponent(_.join(config.vnet.scope, ' '));
                    authUrl += '&state=' + encodeURIComponent(cstate);
                    res.redirect(authUrl);
                } else if (policy && !isInRole(req, policy.roles)) {
                    next({ auth_failed: true, fail_type: 'do_not_has_proper_role' });
                } else if (policy && !isEndpointAllowed(req, policy.endpoints)) {
                    next({ auth_failed: true, fail_type: 'end_point_access_not_allowed' });
                } else {
                    let refreshAt = new Date(req.user.refresh);
                    let now = new Date();
                    if (now > refreshAt) {
                        self.refresh(req.session.user.refId).then((aToken) => {
                            aToken.access_token = JSON.parse(new Buffer(aToken.access_token, 'base64').toString('utf8'));
                            return userStore.updateToken(req, aToken).then(() => {
                                let expires = new Date((new Date(aToken.access_token.content.date)).getTime() + 1000 * aToken.access_token.content.expires_in);
                                req.session.user.refresh = expires.getTime();
                                req.user = req.session.user;
                                next();
                            });
                        }).catch((err) => {
                            console.log('token refresh error:');
                            console.log(err);
                            self.logout(req, res);
                        }).done();
                    } else {
                        next();
                    }
                }
            });
        };
    };

    self.login = (req, authInfo) => {
        let expires = new Date((new Date(authInfo.auth.access_token.content.date)).getTime() + 1000 * authInfo.auth.access_token.content.expires_in);
        req.user = {
            id: authInfo.user.userId,
            name: authInfo.user.displayName,
            eid: authInfo.auth.access_token.endpointId,
            refId: authInfo.auth.refresh_token,
            refresh: expires.getTime()
        };
        req.session.user = req.user;
        req.session.endpoint = authInfo.auth.access_token.endpointId;
        req.session.scope = authInfo.auth.access_token.content.scope;
        return userStore.mapUser(req, authInfo);
    };

    self.logout = (req, res) => {
        return userStore.unmapUser(req.user).then(() => {
            req.session.user = undefined;
            req.session.endpoint = undefined;
            req.session.scope = undefined;
            req.user = undefined;
            let logoutUrl = _.trimEnd(config.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.vnet.endponts.user.apiPath, '/') + '/logout';
            logoutUrl += '?returnUrl=' + encodeURIComponent(domainUrl(req));
            res.redirect(logoutUrl);
        });
    };

    self.refresh = (refreshToken) => {
        return new B((resolve, reject) => {
            let callOpts = {
                url: _.trimEnd(config.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.vnet.endponts.token.apiPath, '/'),
                method: 'POST',
                agent: authAgent,
                json: {
                    grant_type: 'refresh_token',
                    refresh_token: refreshToken,
                    client_id: config.vnet.clientId,
                    client_secret: config.vnet.clientSecret
                }
            };
            http_req(callOpts, (error, response, body) => {
                if (!error && response.statusCode === 200) {
                    resolve(body);
                } else {
                    if (response)
                        reject({ err: error, httpCode: response.statusCode, msg: body });
                    else
                        reject({ err: error, httpCode: -1 });
                }
            });
        });
    };

    self.callback = (req) => {
        let state = decodeState(req.query.state);
        let promise = new B((resolve, reject) => {
            let code = req.query.code;
            let old_state = req.session['oauth-login-state'];
            req.session['oauth-login-state'] = undefined;
            if (!old_state || old_state.tid !== state.tid) {
                reject(new Error('state mismatch'));
            } else {
                let callOpts = {
                    url: _.trimEnd(config.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.vnet.endponts.token.apiPath, '/'),
                    method: 'POST',
                    agent: authAgent,
                    json: {
                        grant_type: 'authorization_code',
                        code: req.query.code,
                        redirect_uri: domainUrl(req) + config.returnPath,
                        client_id: config.vnet.clientId,
                        client_secret: config.vnet.clientSecret
                    }
                };
                http_req(callOpts, (error, response, body) => {
                    if (!error && response.statusCode === 200) {
                        resolve(body);
                    } else {
                        if (response)
                            reject({ err: error, httpCode: response.statusCode, msg: body });
                        else
                            reject({ err: error, httpCode: -1 });
                    }
                });
            }
        }).then((oauth2Token) => {
            return new B((resolve, reject) => {
                let accToken = JSON.parse(new Buffer(oauth2Token.access_token, 'base64').toString('utf8'));
                oauth2Token.access_token = accToken;
                let callOpts = {
                    url: _.trimEnd(config.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.vnet.endponts.user.apiPath, '/'),
                    method: 'POST',
                    agent: authAgent,
                    headers: {
                        'Accept-Language': req.headers['accept-language']
                    },
                    json: {
                        uid: accToken.userId,
                        eid: accToken.endpointId,
                        client_id: config.vnet.clientId,
                        client_secret: config.vnet.clientSecret
                    }
                };
                http_req(callOpts, (error, response, userDetails) => {
                    if (!error && response.statusCode === 200) {
                        resolve({
                            ok: true,
                            auth: oauth2Token,
                            user: userDetails,
                            returnTo: state.returnTo
                        });
                    } else {
                        if (response)
                            reject({ err: error, httpCode: response.statusCode, msg: userDetails });
                        else
                            reject({ err: error, httpCode: -1 });
                    }
                });
            });
        });
        return promise;
    };
};

Authenticator.initialize = (app, config, userStore) => {
    Authenticator.config = config;
    Authenticator.userStore = userStore;
    app.use(function (req, res, next) {
        req.isAuthenticated = () => {
            if (!req.user && req.session && req.session.user) {
                req.user = req.session.user;
            }
            return req.user ? true : false;
        };
        next();
    });
};

module.exports = Authenticator;
