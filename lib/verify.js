var DKIM = require( './dkim' )

const isDKIM = v => /^(DKIM-Signature|X-Google-DKIM-Signature)/.test(v);

/**
 * Verify a message's signatures
 * @memberOf DKIM
 * @param {Buffer} message
 * @param {function(error: Error, result?: VerifyResult[])} callback
 * @throws {Error} If input is not a buffer
 */
function verify( message, callback ) {

  if( !Buffer.isBuffer( message ) ) {
    throw new Error( 'Message must be a Buffer' )
  }

  var boundary = message.indexOf( '\r\n\r\n' )
  if( boundary === -1 ) {
    return callback( new Error( 'No header boundary found' ) )
  }

  var header = message.toString( 'utf8', 0, boundary )
  var body = message.slice( boundary + 4 )

  var results = []
  var signatures = []

  header.split(/\r\n(?=[^\x20\x09]|$)/g).forEach(function(h, i, headers) {
    // ISSUE: executing line below, may result in including a different 'DKIM-Signature' header
    // signatures.push( headers.slice( i ) )
    // FIX: after slicing, remove any included 'DKIM-Signature' header that differ from "oneHeader"
    if (isDKIM(h)) {
      // remove DKIM headers
      const sigHeaders = headers.filter(v => !isDKIM(v));
      // add one DKIM header
      sigHeaders.unshift(h);

      signatures.push(sigHeaders);
    }
  });

  function verifyNextSignature() {

    var headers = signatures.pop()
    if( headers == null ) {
      return callback( null, results )
    }

    DKIM.verifySignature( body, headers, function( error, result ) {
      if( error ) return callback( error, results )
      results.push( result )
      verifyNextSignature()
    })

  }

  verifyNextSignature()

}

/**
 * Filter out signature headers other than the specified `signatureHeader`
 * @param {string[]} headers - list of headers to filter
 * @param {string} signatureHeader - signature header to keep
 * @return {string[]} filtered headers
 */
verify.filterSignatureHeaders = function filterSignatureHeaders(headers, signatureHeader) {
  return headers.filter( function( header ) {
    return header === signatureHeader ||
      !/^(DKIM-Signature|X-Google-DKIM-Signature)/i.test( header )
  })
}

module.exports = verify
