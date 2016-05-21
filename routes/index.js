'use strict';

let fs = require('fs'),
    express = require('express'),
    marked = require('marked'),
    router = express.Router(),
    path = require('path'),
    config = require(path.join(__dirname, '../config/config')),
    oauth = require(path.join(__dirname, '../lib/1-net-oauth2')),
    userStore = require(path.join(__dirname, '../lib/user-store'));

let auth =  new oauth();

router.get(config.oauth.returnPath, (req, res, next) => {
    auth.callback(req).then(result => {
        if (!result.ok) {
            next('login failed');
        }
        return auth.login(req, result).then(() => {
            res.redirect(result.returnTo);
        });
    }).catch(() => {
        next('login failed');
    }).done();
});

router.get('/logout', auth.check(), auth.logout);

router.get('/login', auth.check(), (req, res) => {
    res.redirect('/');
});

router.get('/admin', auth.check('admin_page_acl'), (req, res) => {
    userStore.accessControlList('admin_page_acl').then((acl) => {
        res.render('admin.html', { title: 'Administration page', acl: acl, login: req.user });
    });
});

router.get('/work', auth.check(), (req, res) => {
    res.render('work.html', { title: 'Work page', login: req.user });
});

router.get('/readme', (req, res, next) => {
    fs.readFile(path.join(__dirname, '../README.md'), 'utf8', (err, mkd) => {
        if (err) {
            return next(err);
        } else {
            res.render('readme.html', { title: 'Info', login: req.user, content: marked(mkd) });
        }
    });
});

router.get('/', (req, res) => {
    res.render('index.html', { title: '1-NET sign in demo', login: req.session.user });
});

module.exports = router;