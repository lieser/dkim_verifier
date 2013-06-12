var EXPORTED_SYMBOLS = ["DKIM_STRINGS"];
var DKIM_STRINGS = {};

// DKIM_STRINGS
DKIM_STRINGS.loading = "Validating...";
DKIM_STRINGS.SUCCESS = function(domain) {return "Valid (Signed by "+domain+")";};
DKIM_STRINGS.PERMFAIL = "Invalid";
DKIM_STRINGS.TEMPFAIL = function(domain) {
	return "Temporary validation error (For Signature by "+domain+")";
};
DKIM_STRINGS.NOSIG = "No Signature";
DKIM_STRINGS.NOT_EMAIL = "Message is not an e-mail";

// DKIM_INTERNALERROR
DKIM_STRINGS.DKIM_INTERNALERROR					= "DKIM verifier internal error";
DKIM_STRINGS.DKIM_INTERNALERROR_DEFAULT			= "error";

// DKIM_SIGERROR
DKIM_STRINGS.DKIM_SIGERROR					= "DKIM Signature Error";
DKIM_STRINGS.DKIM_SIGERROR_DEFAULT			= "error";
// DKIM_SIGERROR - DKIM-Signature Header
DKIM_STRINGS.DKIM_SIGERROR_VERSION			= "Unsupported version";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_V		= "DKIM version missing";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_A		= "Missing signature algorithm";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_A		= "Unsupported Signature algorithm";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_B		= "Missing signature";
// DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_B		= "Signature wrong";
DKIM_STRINGS.DKIM_SIGERROR_BADSIG			= "Signature wrong";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_BH		= "Missing body hash";
DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_BH		= "Wrong body hash";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_H		= "Unsupported canonicalization algorithm for header";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_B		= "Unsupported canonicalization algorithm for body";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_D		= "Missing Signing Domain Identifier (SDID)";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_H		= "Missing signed header fields";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_FROM		= "From header is not signed";
DKIM_STRINGS.DKIM_SIGERROR_SUBDOMAIN_I		= "AUID is not in a subdomain of SDID";
DKIM_STRINGS.DKIM_SIGERROR_DOMAIN_I			= "AUID must be in the same domain as SDID (s-flag set in key record)";
DKIM_STRINGS.DKIM_SIGERROR_TOOLARGE_L		= "Value of the body lenght tag exceeds body size";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_Q		= "Unsupported query methods for public key retrieval";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_S		= "Missing selector tag";
DKIM_STRINGS.DKIM_SIGERROR_TIMESTAMPS		= "Signature Expiration before Signature Timestamp";
// DKIM_SIGERROR - key query
DKIM_STRINGS.DKIM_SIGERROR_KEYFAIL			= "DNS query for key failed";
// DKIM_SIGERROR - Key record
DKIM_STRINGS.DKIM_SIGERROR_KEY_INVALID_V	= "Invalid Version of the DKIM key record";
DKIM_STRINGS.DKIM_SIGERROR_KEY_UNKNOWN_K	= "Unsupported key type";
DKIM_STRINGS.DKIM_SIGERROR_KEY_MISSING_P	= "Missing key";
DKIM_STRINGS.DKIM_SIGERROR_KEY_REVOKED		= "Key revoked";
DKIM_STRINGS.DKIM_SIGERROR_KEY_NOTEMAILKEY	= "Key is not an e-mail key";
DKIM_STRINGS.DKIM_SIGERROR_KEY_TESTMODE		= "The domain is only testing DKIM";
// DKIM_SIGERROR - key decode
DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE		= "Key couldn't be decoded";

// DKIM_SIGWARNING
DKIM_STRINGS.DKIM_SIGWARNING_SMALL_L		= "Not the entire body is singned";
DKIM_STRINGS.DKIM_SIGWARNING_EXPIRED		= "Signature is expired";
DKIM_STRINGS.DKIM_SIGWARNING_FUTURE			= "Signature is in the future";
DKIM_STRINGS.DKIM_SIGWARNING_KEYSMALL		= "Signature key size is small";
DKIM_STRINGS.DKIM_SIGWARNING_FROM_NOT_IN_SDID	= "From is not in Signing Domain";
DKIM_STRINGS.DKIM_SIGWARNING_FROM_NOT_IN_AUID	= "From does not match User Identifier";
