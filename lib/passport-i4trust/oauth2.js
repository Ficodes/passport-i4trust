
const base64url = require('base64url');
const crypto = require('crypto');
const fs = require('fs');
const OAuth2Strategy = require('passport-oauth2').OAuth2Strategy;
const jwt = require('jsonwebtoken');
const util = require('util');
const url = require('url');
const { URLSearchParams } = require('url');
const moment = require('moment');
const uuid = require('uuid');
const AuthorizationError = require('passport-oauth2').AuthorizationError;


function buildAuthorizationToken(options, params) {
    function getCAChain(str) {
        const r = new RegExp(/-----BEGIN CERTIFICATE-----\n(\S|\n)*\n-----END CERTIFICATE-----/gm);
        const matches = str.match(r);

        return matches.map((crt) => {
            let rawCrt = crt.replace('-----BEGIN CERTIFICATE-----\n', '');
            rawCrt = rawCrt.replace('\n-----END CERTIFICATE-----', '');
            return rawCrt;
        });
    }

    // Expiration to 5 min
    const iat = moment().unix();
    const exp = moment().add(30, 'seconds').unix();

    const tokenProfile = {
        "jti": uuid.v4(), // Unique JWT ID
        "iss": options.clientId, // Client-ID of Marketplace (EORI)
        "sub": options.clientId, // Client-ID of Marketplace (EORI)
        "aud": options.idpId, // ID (EORI) of client IDP,
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "response_type": params.response_type,
        "scope": params.scope,
        "redirect_uri": params.redirect_uri,
        "state": params.state,
        "nonce": params.state, // FIXME
        "acr_values": "urn:http://eidas.europa.eu/LoA/NotNotified/high"
    }

    // Load token key
    const key = fs.readFileSync(options.tokenKey);

    let secret;
    if (!!options.passphrase) {
        secret = {
            key: key,
            passphrase: options.passphrase
        }
    } else {
        secret = key;
    }

    // ONLY CODE between Begin and end certificate to be provided
    const cert = Buffer.from(fs.readFileSync(options.tokenCrt)).toString();
    const caChain = getCAChain(cert);

    console.log(caChain);
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

    this.key = options.key;

    OAuth2Strategy.call(this, options, verify);
    this.name = 'i4trust';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

function makeAuthorizeRequest(self, req, options, params) {
    // Build IShare token
    params.request = buildAuthorizationToken(options, params);

    const reqParams = new URLSearchParams(params);

    // Make POST request
    fetch(self._oauth2._authorizeUrl, {
        method: 'POST',
        body: reqParams
    }).then(res => {
        // Get Location URI and redirect
        if (res.status == '302') {
            self.redirect(res.headers.get('location'));
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

        params.grant_type = 'authorization_code';

        let callbackURL = getCallbackUrl(self, req, options);
        if (callbackURL) {
            params.redirect_uri = callbackURL;
        }

        if (typeof ok == 'string') { // PKCE
            params.code_verifier = ok;
        }

        // Retrieve access token
        self._oauth2.getOAuthAccessToken(code, params,
            (err, accessToken, refreshToken, params) => {
                if (err) {
                    return self.error(self._createOAuthError('Failed to obtain access token', err));
                }

                // Load user profile
                self._loadUserProfile(accessToken, (err, profile) => {
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
        });

        const state = req.query.state;
        try {
            const arity = self._stateStore.verify.length;
            if (arity == 4) {
                self._stateStore.verify(req, state, meta, loaded);
            } else { // arity == 3
                self._stateStore.verify(req, state, loaded);
            }
        } catch (ex) {
            return self.error(ex);
        }
    }
}

/**
 * 
 * @param {*} req 
 * @param {*} options 
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};

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
        let decoded = jwt.verify(accessToken, this.key);
  
        let profile = { provider: 'i4trust' };

        profile.id = decoded.id;
        profile.displayName = decoded.displayName;
        profile.emails = [
          {
            value: decoded.email
          }
        ];
        profile.email = decoded.email;
        profile.appId = decoded.app_id;
  
        profile.roles = decoded.roles;
        profile.organizations = decoded.organizations;
  
        // The entire profile
        profile._raw = JSON.stringify(decoded);
        profile._json = decoded;
        done(null, profile);
    } catch (e) {
        done(e);
    }
}
