'use strict';


// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');
const Iron = require('iron');
const Path = require('path');
const Authenticator = require('otplib/lib/authenticator');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;
const before = lab.before;


internals.password = 'MyCookiePasswordMustBeReallyLong';

internals.genCookie = (obj, next) => {

    Iron.seal(obj, internals.password, Iron.defaults, (err, sealed) => {

        if (err) {
            throw err;
        }

        next(sealed);
    });
};


describe('hapi-auth-2af', () => {

    let server;

    before((done) => {

        server = new Hapi.Server();
        server.connection({ port: 8080 });

        server.register([require('vision'), require('../lib')], (err) => {

            if (err) {
                throw err;
            }

            server.auth.strategy('hapi-auth-2fa', 'hapi-auth-2fa', {
                cookieOptions: {
                    password: 'MyCookiePasswordMustBeReallyLong'
                }
            });

            server.views({
                engines: {
                    hbs: require('handlebars')
                },
                path: Path.join(__dirname, 'templates')
            });

            server.route({
                method: ['GET', 'POST'],
                path: '/two-factor',
                config: {
                    auth: {
                        strategies: ['hapi-auth-2fa'],
                        payload: true
                    },
                    handler: function (request, reply) {

                        reply('OK');
                    }
                }
            });

            done();
        });
    });

    it('expects a cookie to be set', (done) => {

        server.inject('/two-factor', (res) => {

            expect(res.statusCode).to.equal(401);
            expect(res.result.message).to.equal('Missing two-factor cookie');
            done();
        });
    });

    it('prompts for device pairing when required', (done) => {

        const obj = {
            email: 'john.doe@gmail.com',
            secret: null
        };

        internals.genCookie(obj, (cookie) => {

            server.inject({ method: 'GET', url: '/two-factor', headers: { cookie: 'hapi-auth-2fa=' + cookie } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('pair');
                done();
            });
        });
    });

    it('prompts for the token', (done) => {

        const obj = {
            email: 'john.doe@gmail.com',
            secret: 'J5VEO5BYJMZHA2LV'
        };

        internals.genCookie(obj, (cookie) => {

            server.inject({ method: 'GET', url: '/two-factor', headers: { cookie: 'hapi-auth-2fa=' + cookie } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('verify');
                done();
            });
        });
    });

    it('verifies the token successfully', (done) => {

        const obj = {
            email: 'john.doe@gmail.com',
            secret: 'J5VEO5BYJMZHA2LV'
        };

        const token = Authenticator.generate(obj.secret);

        internals.genCookie(obj, (cookie) => {

            server.inject({ method: 'POST', url: '/two-factor', headers: { cookie: 'hapi-auth-2fa=' + cookie }, payload: { token: token } }, (res) => {

                expect(res.statusCode).to.equal(302);
                done();
            });
        });
    });

    it('fails verification on incorrect token', (done) => {

        const obj = {
            email: 'john.doe@gmail.com',
            secret: 'J5VEO5BYJMZHA2LV'
        };

        internals.genCookie(obj, (cookie) => {

            server.inject({ method: 'POST', url: '/two-factor', headers: { cookie: 'hapi-auth-2fa=' + cookie }, payload: { token: '123456' } }, (res) => {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Token is invalid');
                done();
            });
        });
    });

    it('fails verification on incorrect format token', (done) => {

        const obj = {
            email: 'john.doe@gmail.com',
            secret: 'J5VEO5BYJMZHA2LV'
        };

        internals.genCookie(obj, (cookie) => {

            server.inject({ method: 'POST', url: '/two-factor', headers: { cookie: 'hapi-auth-2fa=' + cookie }, payload: { token: 'abcdef' } }, (res) => {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Token format is invalid');
                done();
            });
        });
    });

    it('passes through when cookie is verified', (done) => {

        const obj = {
            email: 'john.doe@gmail.com',
            secret: 'J5VEO5BYJMZHA2LV',
            verified: true
        };

        internals.genCookie(obj, (cookie) => {

            server.inject({ method: 'GET', url: '/two-factor', headers: { cookie: 'hapi-auth-2fa=' + cookie } }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('OK');
                done();
            });
        });
    });

});
