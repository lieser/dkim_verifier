var EXPORTED_SYMBOLS = ["DNS_STRINGS"];
var DNS_STRINGS = new Object();
DNS_STRINGS.TOO_MANY_HOPS = "Zu viele Server-SprÃ¼nge.";
DNS_STRINGS.CONNECTION_REFUSED = function(server) { return "DNS server " + server + " verweigert eine TCP Verbindung."; };
DNS_STRINGS.TIMED_OUT = function(server) { return "DNS server " + server + " hat Zeitlimit fÃ¼r ein TCP connection Ã¼berschritten."; };
DNS_STRINGS.SERVER_ERROR = function(server) { return "Fehler bei der Verbindung zum DNS-Server " + server + "."; };
DNS_STRINGS.INCOMPLETE_RESPONSE = function(server) { return "UnvollstÃ¤ndige Antwort from " + server + "."; };

