var EXPORTED_SYMBOLS = ["DKIM_STRINGS"];
var DKIM_STRINGS = {};

// DKIM_STRINGS
DKIM_STRINGS.loading = "ÃœberprÃ¼fe...";
DKIM_STRINGS.SUCCESS = function(domain) {return "GÃ¼ltig (Signiert durch "+domain+")";};
DKIM_STRINGS.PERMFAIL = "UngÃ¼ltig";
DKIM_STRINGS.TEMPFAIL = function(domain) {
  return "TemporÃ¤rer ÃœberprÃ¼fungsfehler (FÃ¼r Signatur durch "+domain+")";};

// DKIM_INTERNALERROR
DKIM_STRINGS.DKIM_INTERNALERROR					= "DKIM verifier Interner Fehler";
DKIM_STRINGS.DKIM_INTERNALERROR_DEFAULT			= "Fehler";

// DKIM_SIGERROR
DKIM_STRINGS.DKIM_SIGERROR					= "DKIM Signatur Fehler";
DKIM_STRINGS.DKIM_SIGERROR_DEFAULT			= "Fehler";
// DKIM_SIGERROR - DKIM-Signature Header
DKIM_STRINGS.DKIM_SIGERROR_VERSION			= "Nicht unterstÃ¼tzte Version";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_V		= "DKIM Version fehlt";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_A		= "Fehlender Signatur-Algorithmus";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_A		= "Nicht unterstÃ¼tzter Signatur-Algorithmus";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_B		= "Fehlende Signatur";
DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_B		= "Signatur falsch";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_BH		= "Fehlende Mailtext PrÃ¼fsumme";
DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_BH		= "Falsche Mailtext PrÃ¼fsumme";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_H		= "Nicht unterstÃ¼tzte Kanonisierungmethode fÃ¼r Kopfzeile";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_B		= "Nicht unterstÃ¼tzte Kanonisierungmethode fÃ¼r Mailtext";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_D		= "Fehlender 'Signing Domain Identifier' (SDID)";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_H		= "Fehlende signierte Kopfzeilenfelder";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_FROM		= "From-Kopfzeile ist nicht signiert";
DKIM_STRINGS.DKIM_SIGERROR_SUBDOMAIN_I		= "AUID ist keine Subdomain der SDID";
DKIM_STRINGS.DKIM_SIGERROR_DOMAIN_I			= "AUID muss in der gleichen Domain wie SDID sein (Gesetztes S-Flag)";
DKIM_STRINGS.DKIM_SIGERROR_TOOLARGE_L		= "LÃ¤nge des Mailtext Ã¼berschreitet die maximale LÃ¤nge";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_Q		= "Nicht unterstÃ¼tzte Abfragemethode fÃ¼r Empfang des Ã¶ffentlichen SchlÃ¼ssels";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_S		= "Fehlender Selector-Tag";
DKIM_STRINGS.DKIM_SIGERROR_TIMESTAMPS		= "Signatur abgelaufen";
// DKIM_SIGERROR - key query
DKIM_STRINGS.DKIM_SIGERROR_KEYFAIL			= "DNS Abfrage fÃ¼r SchlÃ¼ssel fehlgeschlagen";
// DKIM_SIGERROR - Key record
DKIM_STRINGS.DKIM_SIGERROR_KEY_INVALID_V	= "Invalid Version of the DKIM SchlÃ¼ssel record";
DKIM_STRINGS.DKIM_SIGERROR_KEY_UNKNOWN_K	= "Nicht unterstÃ¼tzte SchlÃ¼sseltyp";
DKIM_STRINGS.DKIM_SIGERROR_KEY_MISSING_P	= "Fehlender SchlÃ¼ssel";
DKIM_STRINGS.DKIM_SIGERROR_KEY_REVOKED		= "SchÃ¼ssel zurÃ¼ckgezogen";
DKIM_STRINGS.DKIM_SIGERROR_KEY_NOTEMAILKEY	= "SchlÃ¼ssel ist kein Mail-SchlÃ¼ssel";
DKIM_STRINGS.DKIM_SIGERROR_KEY_TESTMODE		= "Die Domain ist im DKIM-Testmodus";
// DKIM_SIGERROR - key decode
DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE		= "SchlÃ¼ssel konnte nicht dekodiert werden";

// DKIM_SIGWARNING
DKIM_STRINGS.DKIM_SIGWARNING_SMALL_L		= "Der Mailtext ist nicht vollstÃ¤ndig signiert";
