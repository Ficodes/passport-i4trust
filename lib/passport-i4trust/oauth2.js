
const base64url = require('base64url');
const crypto = require('crypto');
const fetch = require('node-fetch');
const fs = require('fs');
const OAuth2Strategy = require('passport-oauth2');
const jwt = require('jsonwebtoken');
const util = require('util');
const url = require('url');
const { URLSearchParams } = require('url');
const moment = require('moment');
const uuid = require('uuid');
const AuthorizationError = require('passport-oauth2').AuthorizationError;
const InternalOAuthError = require('passport-oauth2').InternalOAuthError;


function buildAuthorizationToken(self, options, params) {
    function getCAChain(str) {
        const r = new RegExp(/-----BEGIN CERTIFICATE-----\n(\S|\n)*\n-----END CERTIFICATE-----/gm);
        const matches = str.match(r);

        return matches.map((crt) => {
            let rawCrt = crt.replace('-----BEGIN CERTIFICATE-----\n', '');
            rawCrt = rawCrt.replace('\n-----END CERTIFICATE-----', '');
            return rawCrt;
        });
    }

    // Expiration to 30 seconds
    const now = moment()
    const iat = now.unix();
    const exp = now.add(30, 'seconds').unix();

    const tokenProfile = {
        "jti": uuid.v4(), // Unique JWT ID
        "iss": self.clientID, // Client-ID of Marketplace (EORI)
        "sub": "urn:TBD", // Value for authorization code request, as the user not yet known
        "aud": self.idpId, // ID (EORI) of client IDP,
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "client_id": self.clientID,
        "response_type": params.response_type,
        "scope": params.scope,
        "redirect_uri": params.redirect_uri,
        "state": params.state,
        "nonce": params.state,
        "language": "en",
        "acr_values": "urn:http://eidas.europa.eu/LoA/NotNotified/high"
    }

    // Load token key
    const key = fs.readFileSync(self.tokenKey);

    let secret;
    if (!!self.passphrase) {
        secret = {
            key: key,
            passphrase: self.passphrase
        }
    } else {
        secret = key;
    }

    // ONLY CODE between Begin and end certificate to be provided
    const cert = Buffer.from(fs.readFileSync(self.tokenCrt)).toString();
    const caChain = getCAChain(cert);

    return jwt.sign(tokenProfile, secret, {
        algorithm: 'RS256',
        header: {
            x5c: caChain
        }
    });
}

/**
 * 
 * @param {*} options 
 * @param {*} verify 
 */
function Strategy(options, verify) {
    options = options || {};

    this.serverURL = options.serverURL;

    if (this.serverURL.endsWith('/')) {
        this.serverURL = this.serverURL.slice(0, -1);
    }

    // TODO: Configure new endpoint
    options.authorizationURL = this.serverURL + '/oauth2/authorize';
    options.tokenURL = this.serverURL + '/oauth2/token';

    this.clientID = options.clientID;
    this.idpId = options.idpId;
    this.tokenKey = options.tokenKey;
    this.tokenCrt = options.tokenCrt;

    OAuth2Strategy.call(this, options, verify);
    this.name = 'i4trust';
}


/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

function makeAuthorizeRequest(self, req, options, params) {
    // Build IShare token
    params.request = buildAuthorizationToken(self, options, params);

    const reqParams = new URLSearchParams(params);

    self._oauth2._customHeaders = {
        'Authorization': 'Bearer ' + params.request
    };

    // Make POST request
    fetch(self._oauth2._authorizeUrl, {
        method: 'POST',
        body: reqParams,
        redirect: 'manual'
    }).then(async res => {
        // Get Location URI and redirect
        if (res.status < 400 && res.headers.get('location')) {
            self.redirect(self.serverURL + res.headers.get('location'));
        } else {
            self.error(new AuthorizationError());
        }
    }).catch(err => {
        return self.error(new AuthorizationError());
    });
} 

function getCallbackUrl(self, req, options) {
    let callbackURL = options.callbackURL || self._callbackURL;

    if (callbackURL) {
        const parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackURL);
        }
    }
    return callbackURL;
}

function authorizeRequest(self, req, options) {
    let params = self.authorizationParams(options);
    params.response_type = 'code';
    params.client_id = self._oauth2._clientId;

    // Build redirect URI
    let callbackURL = getCallbackUrl(self, req, options);

    if (callbackURL) {
        params.redirect_uri = callbackURL;
    }

    // Build scope
    let scope = options.scope || self._scope;
    if (scope) {
        if (Array.isArray(scope)) {
            scope = scope.join(self._scopeSeparator);
        }
        params.scope = scope;
    }

    let verifier, challenge;
    if (self._pkceMethod) {
        verifier = base64url(crypto.pseudoRandomBytes(32))
        switch (self._pkceMethod) {
        case 'plain':
            challenge = verifier;
            break;
        case 'S256':
            challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
            break;
        default:
            return self.error(new Error('Unsupported code verifier transformation method: ' + self._pkceMethod));
        }
        
        params.code_challenge = challenge;
        params.code_challenge_method = self._pkceMethod;
    }

    // Process state
    let state = options.state;
    if (state) {
        params.state = state;

        makeAuthorizeRequest(self, req, options, params);
    } else {
        function stored(err, state) {
            if (err) {
                return self.error(err);
            }

            if (state) {
                params.state = state;
            }

            makeAuthorizeRequest(self, req, options, params);
        }

        const meta = {
            authorizationURL: this._oauth2._authorizeUrl,
            tokenURL: this._oauth2._accessTokenUrl,
            clientID: this._oauth2._clientId
        };
        try {
            const arity = self._stateStore.store.length;
            if (arity == 5) {
                self._stateStore.store(req, verifier, undefined, meta, stored);
            } else if (arity == 3) {
                self._stateStore.store(req, meta, stored);
            } else { // arity == 2
                self._stateStore.store(req, stored);
            }
        } catch (ex) {
            return self.error(ex);
        }
    }
}

function tokenRequest(self, req, options) {
    function loaded(err, ok, state) {
        if (err) {
            return self.error(err);
        }
        if (!ok) {
            return self.fail(state, 403);
        }

        const code = req.query.code;
        let params = self.tokenParams(options);

        // Add client grants
        params.code = code;
        params.grant_type = 'authorization_code';
        params.client_id = self.clientID;

        params.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

        let callbackURL = getCallbackUrl(self, req, options);
        if (callbackURL) {
            params.redirect_uri = callbackURL;
        }

        if (typeof ok == 'string') { // PKCE
            params.code_verifier = ok;
        }

        const token = self._oauth2._customHeaders.Authorization.split(' ')[1];
        self._oauth2._customHeaders = {};

        params.client_assertion = token;
        // Retrieve access token
        const reqParams = new URLSearchParams(params);
        fetch(self._oauth2._accessTokenUrl, {
            method: 'POST',
            body: reqParams,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        }).then(async res => {
            // Get Location URI and redirect

            if (res.status < 400) {
                const data = await res.json();
                const accessToken = data.access_token;

                // FIXME: Use the refresh token when ready
                const refreshToken = data.access_token;

                self._loadUserProfile(data, (err, profile) => {
                    if (err) {
                        return self.error(err);
                    }

                    function verified(err, user, info) {
                        if (err) {
                            return self.error(err);
                        }
                        if (!user) {
                            return self.fail(info);
                        }

                        info = info || {};
                        if (state) {
                            info.state = state;
                        }
                        self.success(user, info);
                    }

                    try {
                        if (self._passReqToCallback) {
                            const arity = self._verify.length;
                            if (arity == 6) {
                                self._verify(req, accessToken, refreshToken, params, profile, verified);
                            } else { // arity == 5
                                self._verify(req, accessToken, refreshToken, profile, verified);
                            }
                        } else {
                            const arity = self._verify.length;
                            if (arity == 5) {
                                self._verify(accessToken, refreshToken, params, profile, verified);
                            } else { // arity == 4
                                self._verify(accessToken, refreshToken, profile, verified);
                            }
                        }
                    } catch (ex) {
                        return self.error(ex);
                    }
                });
            } else  {
                const data = await res.text();
                return self.error(self._createOAuthError('Failed to obtain access token', ''));
            }
        });
    }
    const queryState = req.query.state;
    try {
        const arity = self._stateStore.verify.length;
        if (arity == 4) {
            self._stateStore.verify(req, queryState, meta, loaded);
        } else { // arity == 3
            self._stateStore.verify(req, queryState, loaded);
        }
    } catch (ex) {
        return self.error(ex);
    }
}

/**
 * 
 * @param {*} req 
 * @param {*} options 
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    this.key = 'random';

    if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
            return this.fail({ message: req.query.error_description });
        } else {
            return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
    }

    if (req.query && req.query.code) {
        tokenRequest(this, req, options);
    } else {
        // Authorization code request
        authorizeRequest(this, req, options);
    }
}

/**
 * 
 * @param {*} accessToken 
 * @param {*} done 
 */
Strategy.prototype.userProfile = function(accessToken, done) {
    try {
        let token = accessToken;
        if (typeof accessToken != 'string') {
            token = accessToken.id_token;
        }

        let decoded = jwt.decode(token);

        let profile = { provider: 'i4trust' };
        profile.id = decoded.sub;
        profile.username = decoded.preferred_username;
        profile.displayName = decoded.displayName;
        profile.emails = [
            {
            value: decoded.email
            }
        ];
        profile.email = decoded.email;
        profile.appId = decoded.aud;
        profile.organizations = [];

        // The entire profile
        profile._raw = JSON.stringify(decoded);
        profile._json = decoded;
        done(null, profile);
    } catch (err) {
        done(new InternalOAuthError('failed to fetch user profile', err));
    }
}

module.exports = Strategy;