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

    let authHost = config.oauth.vnet.endponts.baseUrl.substr('https://'.length);
    let authPort = 443;

    if (authHost.indexOf(':') !== -1) {
        authPort = parseInt(authHost.substr(authHost.indexOf(':') + 1));
        authHost = authHost.substr(0, authHost.indexOf(':'));
    }

    let agentOptions = {
        host: authHost,
        port: authPort,
        path: config.oauth.vnet.endponts.token.apiPath,
        rejectUnauthorized: !config.debugMode
    };

    let authAgent = new https.Agent(agentOptions);

    let isInRole = (req, roles) => {
        return req.user && (!roles && !req.user.roles
            || roles && req.user.roles && _.intersection([_.map(req.user.roles, r => { return r.toLowerCase(); }), _.map(roles, r => { return r.toLowerCase(); })]).length > 0);
    };

    let isEndpointAllowed = (req, endpoints) => {
        return !endpoints || _.find(endpoints, ep => { return ep === req.session.endpoint; });
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

    self.check = (configId) => {
        return (req, res, next) => {
            if (req.session.user) {
                req.user = req.session.user;
            }
            userStore.accessControlList(configId).then((opts) => {
                if (!req.user) {
                    let schema = config.accessProtocol + '://';
                    let transId = uuid.v4();
                    let state = {
                        tid: transId,
                        returnTo: schema + req.headers['host'] + req.originalUrl
                    };
                    req.session['oauth-login-state'] = state;
                    let cstate = encodeState(state);
                    let authUrl = _.trimEnd(config.oauth.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.oauth.vnet.endponts.authorize.apiPathFmt.replace(/\{0\}/, config.oauth.viewType), '/');
                    authUrl += '?response_type=code';
                    authUrl += '&client_id=' + encodeURIComponent(config.oauth.vnet.clientId);
                    authUrl += '&redirect_uri=' + encodeURIComponent(schema + req.headers['host'] + config.oauth.returnPath);
                    authUrl += '&scope=' + encodeURIComponent(_.join(config.oauth.vnet.scope, ' '));
                    authUrl += '&state=' + encodeURIComponent(cstate);
                    res.redirect(authUrl);
                } else if (opts && !isInRole(req, opts.roles)) {
                    next({ auth_failed: true, fail_type: 'do_not_has_proper_role' });
                } else if (opts && !isEndpointAllowed(req, opts.endpoints)) {
                    next({ auth_failed: true, fail_type: 'end_point_access_not_allowed' });
                } else {
                    let refreshAt = new Date(req.user.refresh);
                    let now = new Date();
                    if (now > refreshAt) {
                        self.refresh(req.session.user.refId).then((aToken) => {
                            aToken.access_token = JSON.parse(new Buffer(aToken.access_token, 'base64').toString('utf8'));
                            return userStore.updateToken(req, aToken).then(() => {
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
        req.session.user = {
            id: authInfo.user.userId,
            name: authInfo.user.displayName,
            eid: authInfo.auth.access_token.endpointId,
            refId: authInfo.auth.refresh_token,
            refresh: expires.getTime()
        };
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
            let logoutUrl = _.trimEnd(config.oauth.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.oauth.vnet.endponts.user.apiPath, '/') + '/logout';
            logoutUrl += '?returnUrl=' + encodeURIComponent(config.accessProtocol + '://' + req.headers['host']);
            res.redirect(logoutUrl);
        });
    };

    self.refresh = (refreshToken) => {
        return new B((resolve, reject) => {
            let callOpts = {
                url: _.trimEnd(config.oauth.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.oauth.vnet.endponts.token.apiPath, '/'),
                method: 'POST',
                agent: authAgent,
                json: {
                    grant_type: 'refresh_token',
                    refresh_token: refreshToken,
                    client_id: config.oauth.vnet.clientId,
                    client_secret: config.oauth.vnet.clientSecret
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
            let schema = config.accessProtocol + '://';
            let code = req.query.code;
            let old_state = req.session['oauth-login-state'];
            req.session['oauth-login-state'] = undefined;
            if (!old_state || old_state.tid !== state.tid) {
                reject();
            } else {
                let callOpts = {
                    url: _.trimEnd(config.oauth.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.oauth.vnet.endponts.token.apiPath, '/'),
                    method: 'POST',
                    agent: authAgent,
                    json: {
                        grant_type: 'authorization_code',
                        code: req.query.code,
                        redirect_uri: schema + req.headers['host'] + config.oauth.returnPath,
                        client_id: config.oauth.vnet.clientId,
                        client_secret: config.oauth.vnet.clientSecret
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
        }).then((tokenPackage) => {
            return new B((resolve, reject) => {
                let accToken = JSON.parse(new Buffer(tokenPackage.access_token, 'base64').toString('utf8'));
                tokenPackage.access_token = accToken;
                let callOpts = {
                    url: _.trimEnd(config.oauth.vnet.endponts.baseUrl, '/') + '/' + _.trimStart(config.oauth.vnet.endponts.user.apiPath, '/'),
                    method: 'POST',
                    agent: authAgent,
                    headers: {
                        'Accept-Language': req.headers['accept-language']
                    },
                    json: {
                        uid: accToken.userId,
                        eid: accToken.endpointId,
                        client_id: config.oauth.vnet.clientId,
                        client_secret: config.oauth.vnet.clientSecret
                    }
                };
                http_req(callOpts, (error, response, body) => {
                    if (!error && response.statusCode === 200) {
                        resolve({
                            ok: true,
                            auth: tokenPackage,
                            user: body,
                            returnTo: state.returnTo
                        });
                    } else {
                        if (response)
                            reject({ err: error, httpCode: response.statusCode, msg: body });
                        else
                            reject({ err: error, httpCode: -1 });
                    }
                });
            });
        });
        return promise;
    };
};

Authenticator.initialize = (config, userStore) => {
    Authenticator.config = config;
    Authenticator.userStore = userStore;
};

module.exports = Authenticator;