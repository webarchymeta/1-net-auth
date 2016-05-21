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
    debugMode: true,
    accessProtocol: 'http',
    authKey: '37CE30EC2697C7666ABBDAC3E41A1FAE',
    oauth: {
        viewType: 'browser',
        returnPath: '/external_signin',
        vnet: {
            clientId: '88cbb41e-3d64-430a-a13c-944a6ffcbc7a',
            clientSecret: 'm|coqedg:(*/9/CaGJA~SqZu~p1)lf5c',
            scope: ['user', 'duration:3600'],
            endponts: {
                baseUrl: 'https://192.168.1.200:3232',
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