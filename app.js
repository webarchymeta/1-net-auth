'use strict';

const _ = require('lodash'),
    express = require('express'),
    path = require('path'),
    favicon = require('serve-favicon'),
    ejs = require('ejs'),
    logger = require('morgan'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    session = require('cookie-session'),
    config = require('./config/config'),
    userStore = require(path.join(__dirname, 'lib/user-store')),
    oauth = require(path.join(__dirname, 'lib/1-net-oauth2'));

oauth.initialize(config, userStore);

const app = express();
const routes = require('./routes/index');

if (process.cwd() !== __dirname) {
    process.chdir(__dirname);
}

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.engine('.html', ejs.__express);
app.set('view options', { layout: false });
app.set('view engine', 'ejs');

app.use(session({
    keys: config.cookieSessionKeys
}));

// uncomment after placing your favicon in /public
// app.use(favicon(__dirname + '/public/favicon.ico'));

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);

require('./lib/error-catchers')(app);

let server = app.listen(config.port, config.ip, undefined,  () => {
    console.log('Express server listening on port ' + config.port + ' at ' + config.ip);
});
