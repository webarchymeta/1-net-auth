'use strict';

let localAccessIP;
let localAccessPort;
let args = process.argv.slice(2);

args.forEach((v, i, arr) => {
    if (/^--ip=/.test(v)) {
        localAccessIP = v.substr(v.indexOf('=') + 1);
    } else if (/^-port=/.test(v)) {
        localAccessPort = parseInt(v.substr(v.indexOf('=') + 1));
    }
});

localAccessIP = localAccessIP || process.env.IP || 'localhost';
localAccessPort = localAccessPort || parseInt(process.env.PORT) || 7730;

module.exports = {
    ip: localAccessIP,
    port: localAccessPort,
    cookieSessionKeys: ['092EC17EF84F54EEEA', '390271DDBD0ABEB72A9D00104C'],
    oauth: {
        debugMode: true,
        accessProtocol: 'http',
        authKey: '--- create your random security key ---',
        viewType: 'browser',
        returnPath: '/external_signin',
        vnet: {
            clientId: '--- your client id ---',
            clientSecret: '--- your client secret ---',
            scope: ['user', 'duration:3600'],
            endponts: {
                baseUrl: 'https://www.yiwg.net:8787',
                authorize: {
                    apiPathFmt: '/api/signin/{0}/authorize'
                },
                token: {
                    apiPath: '/api/signin/token'
                },
                user: {
                    apiPath: 'api/signin/user'
                }
            }
        }
    }
};
