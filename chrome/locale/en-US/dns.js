var DNS_STRINGS = new Object();
DNS_STRINGS.TOO_MANY_HOPS = "Too many hops.";
DNS_STRINGS.CONNECTION_REFUSED = function(server) { return "DNS server " + server + " refused a TCP connection."; };
DNS_STRINGS.TIMED_OUT = function(server) { return "DNS server " + server + " timed out on a TCP connection."; };
DNS_STRINGS.SERVER_ERROR = function(server) { return "Error connecting to DNS server " + server + "."; };
DNS_STRINGS.INCOMPLETE_RESPONSE = function(server) { return "Incomplete response from " + server + "."; };

