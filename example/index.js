'use strict';


// Load modules

const Boom = require('boom');
const Bcrypt = require('bcryptjs');
const Hapi = require('hapi');
const Joi = require('joi');
const Path = require('path');


const users = {
    'nicolasrotta@gmail.com': {
        password: '$2a$08$.sI.S6l9lL0crviIOn/EUuAc/0oTlBA9R0b6rGEJYRD2p2h76bKK.', // 'secret'
        secret: null
    }
};


const server = new Hapi.Server();
server.connection({
    port: 8080
});


server.register([require('vision'), require('hapi-auth-cookie'), require('../lib')], (err) => {

    if (err) {
        throw err;
    }

    server.views({
        engines: {
            hbs: require('handlebars')
        },
        path: Path.join(__dirname, 'templates'),
        layout: true
    });

    server.auth.strategy('session', 'cookie', {
        password: 'MyCookiePasswordMustBeReallyLong',
        redirectTo: '/login',
        isSecure: false
    });

    server.auth.strategy('hapi-auth-2fa', 'hapi-auth-2fa', {
        cookieOptions: {
            password: 'MyCookiePasswordMustBeReallyLong'
        }
    });

    server.route([{
        method: 'GET',
        path: '/',
        config: {
            auth: 'session',
            handler: {
                view: 'index'
            }
        }
    }, {
        method: 'GET',
        path: '/login',
        handler: {
            view: 'login'
        }
    }, {
        method: 'POST',
        path: '/login',
        config: {
            validate: {
                payload: {
                    email: Joi.string().email().required(),
                    password: Joi.string().required()
                }
            }
        },
        handler: (request, reply) => {

            const email = request.payload.email;
            const user = users[email];

            if (!user) {
                return reply(Boom.unauthorized());
            }

            Bcrypt.compare(request.payload.password, user.password, (err, valid) => {

                if (err || !valid) {
                    return reply(Boom.unauthorized());
                }

                return reply.redirect('/two-factor').state('hapi-auth-2fa', {
                    email: email,
                    secret: user.secret
                });
            });
        }
    }, {
        method: ['GET', 'POST'],
        path: '/two-factor',
        config: {
            auth: {
                strategies: ['hapi-auth-2fa'],
                payload: true
            },
            handler: (request, reply) => {

                const credentials = request.auth.credentials;
                const user = users[credentials.email];
                user.secret = credentials.secret;

                request.cookieAuth.set(user);
                return reply.redirect('/');
            }
        }
    }]);

    server.start(() => {

        console.log('Started server');
    });
});
