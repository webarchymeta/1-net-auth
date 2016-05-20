'use strict';

const stackTrace = require('stack-trace');

let cachers = function (app) {
    // will print stacktrace
    if (app.get('env') === 'development') {
        app.use((err, req, res, next) => {
            if (err.httpCode && err.httpCode !== 500) {
                let _err = err.message || err.msg || JSON.stringify(err);
                //winston.log('info', _err);
                res.statusCode = err.httpCode;
                res.send(_err);
                res.end();
            } else if (err.auth_failed) {
                res.render('access-denied.html', { msg: err.fail_type });
            } else {
                let _err = err.message || err.msg || JSON.stringify(err);
                let trace = stackTrace.parse(err);
                let traceList = _.map(trace, (t) => { return JSON.stringify(t); });
                let traceMsg = _.reduce(traceList, (str, ts) => { return str + ts + '\n'; }, '');
                console.log('error', _err);
                console.log('error', traceMsg);
                res.statusCode = 500;
                res.send(_err);
                res.end();
            }
        });
    } else {
        // production error handler
        // no stacktraces leaked to user
        app.use((err, req, res, next) => {
            if (err.httpCode && err.httpCode !== 500) {
                let _err = err.message || err.msg || JSON.stringify(err);
                //winston.log('info', _err);
                res.statusCode = err.httpCode;
                res.send(_err);
                res.end();
            } else if (err.auth_failed) {
                res.statusCode = 403;
                res.send('access denied: ' + err.fail_type);
                res.end();
            } else {
                let _err = err.message || err.msg || JSON.stringify(err);
                console.log('error', _err);
                res.statusCode = 500;
                res.send(_err);
                res.end();
            }
        });
    }
};

module.exports = cachers;