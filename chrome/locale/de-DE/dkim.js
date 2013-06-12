var EXPORTED_SYMBOLS = ["DKIM_STRINGS"];
var DKIM_STRINGS = {};

// DKIM_STRINGS
DKIM_STRINGS.loading = "Überprüfe...";
DKIM_STRINGS.SUCCESS = function(domain) {return "Gültig (Signiert durch "+domain+")";};
DKIM_STRINGS.PERMFAIL = "Ungültig";
DKIM_STRINGS.TEMPFAIL = function(domain) {
	return "Temporärer Überprüfungsfehler (Für Signatur durch "+domain+")";
};
DKIM_STRINGS.NOSIG = "Keine Signatur";
DKIM_STRINGS.NOT_EMAIL = "Keine E-Mail";

// DKIM_INTERNALERROR
DKIM_STRINGS.DKIM_INTERNALERROR					= "DKIM Verifier Interner Fehler";
DKIM_STRINGS.DKIM_INTERNALERROR_DEFAULT			= "Fehler";

// DKIM_SIGERROR
DKIM_STRINGS.DKIM_SIGERROR					= "DKIM Signatur Fehler";
DKIM_STRINGS.DKIM_SIGERROR_DEFAULT			= "Fehler";
// DKIM_SIGERROR - DKIM-Signature Header
DKIM_STRINGS.DKIM_SIGERROR_VERSION			= "Nicht unterstützte Version";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_V		= "DKIM Version fehlt";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_A		= "Fehlender Signatur-Algorithmus";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_A		= "Nicht unterstützter Signatur-Algorithmus";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_B		= "Fehlende Signatur";
//DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_B		= "Signatur falsch";
DKIM_STRINGS.DKIM_SIGERROR_BADSIG			= "Signatur falsch";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_BH		= "Fehlende Mailtext Prüfsumme";
DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_BH		= "Falsche Mailtext Prüfsumme";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_H		= "Nicht unterstützte Kanonisierungmethode für Kopfzeile";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_B		= "Nicht unterstützte Kanonisierungmethode für Mailtext";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_D		= "Fehlender 'Signing Domain Identifier' (SDID)";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_H		= "Fehlende signierte Kopfzeilenfelder";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_FROM		= "Absenderadresse ist nicht signiert";
DKIM_STRINGS.DKIM_SIGERROR_SUBDOMAIN_I		= "AUID ist keine Subdomain der SDID";
DKIM_STRINGS.DKIM_SIGERROR_DOMAIN_I			= "AUID muss in der gleichen Domain wie SDID sein (Gesetztes S-Flag)";
DKIM_STRINGS.DKIM_SIGERROR_TOOLARGE_L		= "In der Signatur angegebene Länge des Mailtextes ist größer als die Länge des Mailtextes";
DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_Q		= "Nicht unterstützte Abfragemethode für Empfang des öffentlichen Schlüssels";
DKIM_STRINGS.DKIM_SIGERROR_MISSING_S		= "Fehlender Selector-Tag";
DKIM_STRINGS.DKIM_SIGERROR_TIMESTAMPS		= "Signatur abgelaufen";
// DKIM_SIGERROR - key query
DKIM_STRINGS.DKIM_SIGERROR_KEYFAIL			= "DNS Abfrage für Schlüssel fehlgeschlagen";
// DKIM_SIGERROR - Key record
DKIM_STRINGS.DKIM_SIGERROR_KEY_INVALID_V	= "Ungültige DKIM Schlüssel Record Version";
DKIM_STRINGS.DKIM_SIGERROR_KEY_UNKNOWN_K	= "Nicht unterstützter Schlüsseltyp";
DKIM_STRINGS.DKIM_SIGERROR_KEY_MISSING_P	= "Fehlender Schlüssel";
DKIM_STRINGS.DKIM_SIGERROR_KEY_REVOKED		= "Schüssel zurückgezogen";
DKIM_STRINGS.DKIM_SIGERROR_KEY_NOTEMAILKEY	= "Schlüssel ist kein Mail-Schlüssel";
DKIM_STRINGS.DKIM_SIGERROR_KEY_TESTMODE		= "Die Domain ist im DKIM-Testmodus";
// DKIM_SIGERROR - key decode
DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE		= "Schlüssel konnte nicht dekodiert werden";

// DKIM_SIGWARNING
DKIM_STRINGS.DKIM_SIGWARNING_SMALL_L		= "Der Mailtext ist nicht vollständig signiert";
DKIM_STRINGS.DKIM_SIGWARNING_EXPIRED		= "Signatur ist abgelaufen";
DKIM_STRINGS.DKIM_SIGWARNING_FUTURE			= "Signatur Erstellungszeit liegt in der Zukunft";
DKIM_STRINGS.DKIM_SIGWARNING_KEYSMALL		= "Signatur-Schlüssellänge ist zu klein";
DKIM_STRINGS.DKIM_SIGWARNING_FROM_NOT_IN_SDID	= "Absender gehört nicht zur Domain";
DKIM_STRINGS.DKIM_SIGWARNING_FROM_NOT_IN_AUID	= "Absender passt nicht zur Benutzeridentität";
