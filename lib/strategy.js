/**
 * IMPORTS
 */

var util = require('util')
var OAuth2Strategy = require('passport-oauth2')
var InternalOAuthError = require('passport-oauth2').InternalOAuthError

/**
 * `Strategy` constructor.
 *
 * The Sketchfab authentication strategy authenticates requests by delegating to
 * Sketchfab using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientId`      	your Sketchfab application's client id. This identifies client to service provider
 *   - `clientSecret`  	your Sketchfab application's client secret. This secret used to establish ownership of the client identifer
 *   - `callbackURL`   	URL to which Sketchfab will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     var SketchfabStrategy = require('passport-sketchfab').Strategy;
 *
 *     passport.use(new SketchfabStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/sketchfab/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function Strategy(options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://sketchfab.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://sketchfab.com/oauth2/token/';
  options.customHeaders = options.customHeaders || {};

  OAuth2Strategy.call(this, options, verify)
  this.name = 'sketchfab'
}

/**
 * Inherit from `OAuth2Strategy`.
 */

util.inherits(Strategy, OAuth2Strategy)

/**
 * Return extra Skechfab-specific parameters to be included in the authorization request.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return {};
};


/**
 * Retrieve user profile from Sketchfab.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `sketchfab`
 *   - `id`
 *   - etc..
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.useAuthorizationHeaderforGET(true);
  this._oauth2.get(
    'https://api.sketchfab.com/v3/me',
    accessToken,
    function (err, body, res) {
      if (err) {
        return done(new InternalOAuthError('failed to fetch user profile', err))
      }
      try {
        var json = JSON.parse(body)

        var profile = {
          provider: 'sketchfab',
          name: {}
        }
        profile.id = json.uid
        profile.accessToken = accessToken
        profile.account = json.account
        profile.facebookUsername =  json.facebookUsername
        profile.linkedinUsername = json.linkedinUsername
        profile.twitterUsername = json.twitterUsername
        profile.profileUrl = json.profileUrl
        profile.displayName = json.displayName
        profile.username = json.username
        profile.email = json.email
        profile.profilePicture = json.avatar?.images[3].url
        profile._raw = body
        profile._json = json

        done(null, profile)
      }
      catch (e) {
        done(e)
      }
    }
  )
  return done(null, {});
}

/**
 * Expose `Strategy`.
 */

module.exports = Strategy
