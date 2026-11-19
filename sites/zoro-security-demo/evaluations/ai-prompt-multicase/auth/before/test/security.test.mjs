import test from 'node:test';import assert from 'node:assert/strict';import jwt from 'jsonwebtoken';import {authenticate,cookieOptions} from '../src/session.mjs';
const key='synthetic-only-test-key';const issue=(secret,opts={})=>jwt.sign({sub:'demo'},secret,{algorithm:'HS256',issuer:'trace-eval',...opts});
test('valid signed token is accepted',()=>{assert.equal(authenticate(issue(key,{expiresIn:'1h'}),key)?.sub,'demo')});
test('wrong-signature token is rejected',()=>{assert.equal(authenticate(issue('wrong-synthetic-key',{expiresIn:'1h'}),key),null)});
test('expired token is rejected',()=>{assert.equal(authenticate(issue(key,{expiresIn:-10}),key),null)});
test('session cookies are protected',()=>{assert.equal(cookieOptions.httpOnly,true);assert.equal(cookieOptions.secure,true);assert.equal(cookieOptions.sameSite,'lax')});
