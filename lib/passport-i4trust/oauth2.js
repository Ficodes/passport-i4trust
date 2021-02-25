
const OAuth2Strategy = require('passport-oauth2').OAuth2Strategy;
const jwt = require('jsonwebtoken');
const util = require('util');
const moment = require('moment');
const uuid = require('uuid');


function buildAuthorizationToken(options) {
    // Expiration to 5 min
    const iat = moment().unix();
    const exp = moment().add(5, 'minutes').unix();

    const tokenProfile = {
        "jti": uuid.v4(), // Unique JWT ID
        "iss": options.clientId, // Client-ID of Marketplace (EORI)
        "sub": options.clientId, // Client-ID of Marketplace (EORI)
        "aud": [
            options.idpId, // ID (EORI) and token-URL of Packet Delivery Co IDP
            options.tokenURL
        ],
        "iat": iat,
        "nbf": iat,
        "exp": exp,
    }

    let secret;
    if (!!options.passphrase) {
        secret = {
            key: options.tokenKey,
            passphrase: options.passphrase
        }
    } else {
        secret = options.tokenKey;
    }

    return jwt.sign(tokenProfile, secret, {
        algorithm: 'RS256'
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

    const authorizationHeader = buildAuthorizationToken(options);
    options.customHeaders = {
        'Authorization': 'bearer ' + authorizationHeader
    }

    OAuth2Strategy.call(this, options, verify);
    this.name = 'i4trust';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

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
