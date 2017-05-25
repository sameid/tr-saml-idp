/**
 * server.js
 *
 * Handles all incoming IDP SAML requests from the web and any necessary call made from Saleforce
 *
 * Created by sameid on May 25th, 2017.
 */
'use strict';

/**
 * @imports
 */
var async = require("async");
var _ = require("underscore");
var samlp = require("samlp");
var fs = require("fs");
var express = require("express");
var path = require("path");

var app = express();

/**
 * Build the Auth route for SAML
 *
 * @param issuer {String}
 * @param cert {Blob}
 * @param key {Blob}
 * @param postUrl {String}
 */
function _buildAuthRoute(issuer, cert, key, postUrl) {

	app.get('/auth', samlp.auth({
		issuer: issuer,
		cert: cert,
		key: key,
		getPostURL: function (audience, samlRequestDom, req, cb){
			return cb(null, postUrl);
		},
		getUserFromRequest: function(req) {
			return {
				userName: "kebadi@rhhonda.com",
				nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
			};
		},
		audience: postUrl,
		recipient: postUrl,
		destination: postUrl,
		allowRequestAcsUrl: true
	}));
}

async.series({

	/**
	 * Retrieves the ISSUER name
	 *
	 * @param next {function(Error|Object)}
	 */
	issuer: function(next) {
		// should get the issuer name from system configs
		next(null, "tr-saml-idp");
	},

	/**
	 * Retrieves the certificate for all SAML requests
	 *
	 * @param next {function(Error|Object)}
	 */
	cert: function(next) {
		// should get certificate name from system configs
		// then should pull certificate from S3
		next(null, fs.readFileSync(path.join(__dirname, 'idp-public-cert.pem')));
	},

	/**
	 * Retrieves the private key for all SAML requests
	 *
	 * @param next {function(Error|Object)}
	 */
	key: function(next) {
		// should get private key name from system configs
		// then should pull private key from S3
		next(null, fs.readFileSync(path.join(__dirname, 'idp-private-key.pem')));
	},

	/**
	 * Retrieves the post url 
	 *
	 * @param next {function(Error|Object)}
	 */
	postUrl: function(next) {
		// should get the sso postUrl from system configs
		next(null, "https://rc-traderev.cs54.force.com/login?so=00D0S0000000Wyo");
	}


}, function(err, results) {
	if (err) {
		console.log("An error occured.");
	}

	//Start server
	_buildAuthRoute(results.issuer, results.cert, results.key, results.postUrl);
	app.listen(7000);

});
