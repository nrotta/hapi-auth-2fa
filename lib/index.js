'use strict';


// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const Authenticator = require('otplib/lib/authenticator');


// Declare internals

const internals = {};


exports.register = (server, options, next) => {

    server.auth.scheme('hapi-auth-2fa', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.schema = Joi.object({
    appName: Joi.string().default('hapi-auth-2fa'),
    cookieName: Joi.string().default('hapi-auth-2fa'),
    cookieOptions: Joi.object({
        password: Joi.string().min(32),
        encoding: Joi.string().valid('iron').default('iron')
    })
}).required();


internals.implementation =  (server, options) => {

    const results = Joi.validate(options, internals.schema);
    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    server.state(settings.cookieName, settings.cookieOptions);

    const scheme = {
        authenticate: (request, reply) => {

            const cookie = request.state[settings.cookieName];

            if (!cookie) {
                return reply(Boom.unauthorized('Missing two-factor cookie'));
            }

            if (request.method === 'get') {

                if (!cookie.secret) {
                    const secret = Authenticator.generateSecret();
                    cookie.secret = secret;

                    const qr = Authenticator.qrcode(cookie.email, settings.appName, secret);
                    return reply.view('pair', { qr: qr }).state(settings.cookieName, cookie);
                }

                if (!cookie.verified) {
                    return reply.view('verify');
                }
            }

            reply.continue({ credentials: cookie });
        },
        payload: (request, reply) => {

            const cookie = request.state[settings.cookieName];
            const payload = request.payload;

            const schema = {
                token: Joi.number().required()
            };

            const result = Joi.validate(payload, schema);

            if (result.error) {
                return reply(Boom.unauthorized('Token format is invalid'));
            }

            const valid = Authenticator.check(payload.token, cookie.secret);

            if (valid) {
                cookie.verified = true;
                return reply.redirect('/two-factor').state(settings.cookieName, cookie);
            }

            return reply(Boom.unauthorized('Token is invalid'));
        }
    };

    return scheme;
};
