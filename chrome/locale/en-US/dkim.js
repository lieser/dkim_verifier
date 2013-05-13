var DKIM_STRINGS = {};

// DKIM_STRINGS
DKIM_STRINGS.loading = "Validating...";
DKIM_STRINGS.SUCCESS = function(domain) {return "Valid (Signed by "+domain+")";};
DKIM_STRINGS.PERMFAIL = "Invalid";
DKIM_STRINGS.TEMPFAIL = function(domain) {
	return "Temporary validating error (For Signature by "+domain+")";};

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
DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_B		= "Signature wrong";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_BH		= "Missing body hash";
DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_BH		= "Wrong body hash";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_H		= "Unsupported canonicalization algorithm for header";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_B		= "Unsupported canonicalization algorithm for body";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_D		= "Missing Signing Domain Identifier (SDID)";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_H		= "Missing signed header fields";
DKIM_STRINGS.DKIM_SIGERROR_DOMAIN_I			= "AUID is not in a subdomain of SDID";
DKIM_STRINGS.DKIM_SIGERROR_TOOLARGE_L		= "Value of the body lenght tag exceeds body size";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_Q		= "Unsupported query methods for public key retrievel";
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
// DKIM_SIGERROR - key decode
DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE		= "Key couldn't be decoded";

// DKIM_SIGWARNING
DKIM_STRINGS.DKIM_SIGWARNING_SMALL_L		= "Not the entire body is singned";


// #define DKIM_SIGERROR_UNKNOWN		(-1)	/* unknown error */
// #define DKIM_SIGERROR_OK		0	/* no error */
// #define DKIM_SIGERROR_EXPIRED		3	/* signature expired */
// #define DKIM_SIGERROR_FUTURE		4	/* signature in the future */
	// #define DKIM_SIGERROR_INVALID_HC	7	/* c= invalid (header) */
	// #define DKIM_SIGERROR_INVALID_BC	8	/* c= invalid (body) */
// #define DKIM_SIGERROR_INVALID_L		12	/* l= invalid */
	// #define DKIM_SIGERROR_INVALID_Q		13	/* q= invalid */
	// #define DKIM_SIGERROR_INVALID_QO	14	/* q= option invalid */
// #define DKIM_SIGERROR_EMPTY_D		16	/* d= empty */
// #define DKIM_SIGERROR_EMPTY_S		18	/* s= empty */
// #define DKIM_SIGERROR_EMPTY_B		20	/* b= empty */
// #define DKIM_SIGERROR_NOKEY		22	/* no key found in DNS */
// #define DKIM_SIGERROR_DNSSYNTAX		23	/* DNS reply corrupt */
// #define DKIM_SIGERROR_EMPTY_BH		26	/* bh= empty */
// #define DKIM_SIGERROR_BADSIG		28	/* signature mismatch */
// #define DKIM_SIGERROR_MULTIREPLY	30	/* multiple records returned */
// #define DKIM_SIGERROR_EMPTY_H		31	/* h= empty */
// #define DKIM_SIGERROR_INVALID_H		32	/* h= missing req'd entries */
// #define DKIM_SIGERROR_MBSFAILED		34	/* "must be signed" failure */
	// #define DKIM_SIGERROR_KEYVERSION	35	/* unknown key version */
// #define DKIM_SIGERROR_KEYUNKNOWNHASH	36	/* unknown key hash */
// #define DKIM_SIGERROR_KEYHASHMISMATCH	37	/* sig-key hash mismatch */
// #define DKIM_SIGERROR_KEYTYPEMISSING	40	/* key type missing */
// #define DKIM_SIGERROR_EMPTY_V		45	/* v= tag empty */
// #define DKIM_SIGERROR_KEYTOOSMALL	46	/* too few key bits */

