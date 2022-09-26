/** @type {Object} */
var DKIM = module.exports

/** @type {string} */
DKIM.NONE = 'NONE'
/** @type {string} */
DKIM.OK = 'OK'
/** @type {string} */
DKIM.TEMPFAIL = 'TEMPFAIL'
/** @type {string} */
DKIM.PERMFAIL = 'PERMFAIL'

/**
 * DKIM Signature
 * @constructor
 * @see [dkim-signature](https://github.com/jhermsmeier/node-dkim-signature)
 */
DKIM.Signature = require( 'dkim-signature' )

/**
 * DKIM Key
 * @constructor
 * @see [dkim-key](https://github.com/jhermsmeier/node-dkim-key)
 */
DKIM.Key = require( 'dkim-key' )

DKIM.getKey = require( './get-key' )
DKIM.processHeader = require( './process-header' )
DKIM.processBody = require( './process-body' )
DKIM.verifySignature = require( './verify-signature' )
DKIM.verify = require( './verify' )
