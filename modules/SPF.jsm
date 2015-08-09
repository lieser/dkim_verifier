/*
 * SPF.jsm
 * 
 * SPF verifier as specified in RFC 7208.
 *
 * Version: 0.1.0 (24 Mai 2015)
 * 
 * Copyright (c) 2015 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/*
 * Violations against RFC 7208:
 * ============================
 *  - no IPv6 support
 *  - no support for mechanism "mx"
 *  - no support for mechanism "ptr"
 *  - no support for macro expansion
 *  - no support for explanation string
 *  - ...
 */

// options for JSHint
/* jshint strict:true, globalstrict:true, moz:true, smarttabs:true, unused:true, bitwise:true */
/* global Components, Task */
/* global Logging, DNS, exceptionToStr */
/* exported EXPORTED_SYMBOLS, SPF */

"use strict";

const module_version = "0.1.0";

var EXPORTED_SYMBOLS = [
	"SPF"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Task.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/DNSWrapper.jsm");


let log = Logging.getLogger("SPF");


let SPF = {
	get version() { return module_version; },

};

function SPFContext() {
}
SPFContext.prototype = Object.create(null, {
	/**
	 * The check_host() function fetches SPF records, parses them, and
	 * evaluates them to determine whether a particular host is or is not
	 * permitted to send mail with a given identity.
	 * 
	 * Generator function.
	 * 
	 * @param {String} ip
	 * @param {String} domain
	 * @param {String} sender
	 * @return {Promise<String>}
	 *   none|neutral|pass|fail|softfail|temperror|permerror
	 */
	check_host: {
		value: function SPFContext_check_host(ip, domain, sender) {
			// Record lookup
			let record = yield DNS.resolve(domain, "TXT");
			if (record.rcode === 3) {
				log.warn("SPF DNS lookup for " + domain + " returns NXDOMAIN");
				throw new Task.Result("permerror");
			}
			if (record.bogus || record.rcode !== 0) {
				log.warn("SPF DNS lookup for " + domain + " returns bogus or error");
				throw new Task.Result("temperror");
			}

			try {
				// Record selection
				// Parse all records
				record.data = record.data || [];
				record = record.data.map(parseRecord);
				// Filter non "v=spf1" records
				record.filter(function(e){ return e !== null;});

				if (record.length === 0) {
					log.warn("Found no spf1 record.");
					throw new Task.Result("none");
				}
				if (record.length > 1) {
					log.warn("Found more than one spf1 record.");
					throw new Task.Result("permerror");
				}
				record = record[0];

				// Mechanism evaluation
				for (let i = 0; i < record.mechanism.length; i++) {
					if (yield this.matchMechanism(record.mechanism[i], ip, domain, sender)) {
						switch (record.mechanism[i].qualifier) {
							case "+":
								throw new Task.Result("pass");
							case "-":
								// TODO: explanation string (section 6.2)
								throw new Task.Result("fail");
							case "~":
								throw new Task.Result("softfail");
							case "?":
								throw new Task.Result("neutral");
							default:
								throw new Error("invalid qualifier: " +
									record.mechanism[i].qualifier);
						}
					}
				}
			} catch (e) {
				if (e instanceof Task.Result) {
					throw e;
				} else if (e.message === "SPF_TEMPERROR") {
					log.warn(exceptionToStr(e));
					throw new Task.Result("temperror");
				} else if (e.message === "SPF_PERMERROR") {
					log.warn(exceptionToStr(e));
					throw new Task.Result("permerror");
				} else {
					// TODO: propagate non SPF errors
					log.error(exceptionToStr(e));
					throw new Task.Result("permerror");
				}
			}

			// TODO: redirect modifier (and increaseDNSLookupCount();)

			// default result
			throw new Task.Result("neutral");
		}
	},

	/**
	 * Checks if a mechanism matches.
	 * 
	 * Generator function.
	 * 
	 * @param {SPFTerm} mechanism
	 * @param {String} ip
	 * @param {String} domain
	 * @param {String} sender
	 * @return {Promise<Boolean>}
	 * @throws {Error}
	 */
	matchMechanism: {
		value: function SPFContext_matchMechanism(mechanism, ip, domain, sender) {
			/**
			 * Performs a DNS queries to fetch information for a mechanism.
			 * Specified in section 5 of RFC 7208.
			 * 
			 * Generator function.
			 * 
			 * @param {String} name
			 * @param {String} rrtype
			 * @return {Promise<Object[]>}
			 */
			function queryDNS(name, rrtype) {
				let record = yield DNS.resolve(name, "A");
				if (record.bogus || (record.rcode !== 0 && record.rcode !== 3)) {
					log.warn(rrtype + " DNS lookup for " + name +
						" returns bogus or error other than NXDOMAIN");
					throw new Error("SPF_TEMPERROR");
				}
				if (record.rcode === 3) {
					log.warn(rrtype + " DNS lookup for " +	name +
						" returns NXDOMAIN");
				}
				if (record.data === null) {
					record.data = [];
				}
				throw new Task.Result(record.data);
			}

			let target;
			let records;
			switch (mechanism.mechanism) {
				case "all":
					throw new Task.Result(true);
				case "include":
					this.increaseDNSLookupCount();
					let check_host_res = this.check_host(
						ip, this.expandDomainSpec(mechanism.domain_spec), sender);
					switch (check_host_res) {
						case "pass":
							throw new Task.Result(true);
						case "fail":
						case "softfail":
						case "neutral":
							throw new Task.Result(false);
						case "temperror":
							throw new Error("SPF_TEMPERROR");
						case "permerror":
						case "none":
							throw new Error("SPF_PERMERROR");
					}
					throw new Error("invalid check_host result: " + check_host_res);
				case "a":
					this.increaseDNSLookupCount();
					target = this.expandDomainSpec(mechanism.domain_spec) || domain;
					let ip_ = new IP(ip);
					records = yield queryDNS(target,
						(ip_.type === "IPv4")? "A" : "AAA");
					throw new Task.Result(
						records.some(function (element/*, index, array*/) {
							return ip_.isInNetwork(new IP(element), (ip_.type === "IPv4")?
									mechanism.ip4_cidr_length : mechanism.ip6_cidr_length);
						}));
				case "mx":
					this.increaseDNSLookupCount();
					target = this.expandDomainSpec(mechanism.domain_spec) || domain;
					// let records = yield queryDNS(target, "MX");
					// TODO: address lookup on each MX name returned and comp. of addresses
					throw new Error("TODO: mx");
				case "ptr":
					this.increaseDNSLookupCount();
					throw new Error("TODO: ptr");
				case "ip4":
					throw new Task.Result(new IP(ip).isInNetwork(
						new IP(mechanism.ip4), mechanism.ip4_cidr_length));
				case "ip6":
					throw new Task.Result(new IP(ip).isInNetwork(
						new IP(mechanism.ip6), mechanism.ip6_cidr_length));
				case "exists":
					this.increaseDNSLookupCount();
					target = this.expandDomainSpec(mechanism.domain_spec);
					records = yield queryDNS(target, "A");
					if (records.length > 0) {
						throw new Task.Result(true);
					}
					throw new Task.Result(false);
				default:
					throw new Error("invalid mechanism: " +
						mechanism.mechanism);
			}
		}
	},

	/**
	 * Increases the DNS Lookup count and checks if it is still in the limit.
	 * Specified in section 4.6.4. of RFC 7208.
	 * 
	 * @throws {Error} If DNS Lookup Limits is reached
	 */
	increaseDNSLookupCount: {
		value: function SPFContext_increaseDNSLookupCount() {
			if (this._DNSLookupCount === undefined) {
				this._DNSLookupCount = 0;
			}
			this._DNSLookupCount++;
			if (this._DNSLookupCount > 10) {
				// DNS Lookup Limits reached
				throw new Error("SPF_PERMERROR: DNS Lookup Limits reached");
			}
		}
	},

	/**
	 * Performs a macro expansion.
	 * Specified in section 7 of RFC 7208.
	 * 
	 * @param {String} str
	 * @param {String} rrtype
	 * @return {Promise<Object[]>}
	 */
	expandDomainSpec: {
		value: function SPFContext_expandDomainSpec(str) {
			// TODO: expandDomainSpec
			return str;
		}
	},
});

/**
 * @typedef {Object} SPFRecord
 * @property {String} version "spf1"
 * @property {SPFTerm[]} mechanism
 * @property {SPFTerm[]} modifier
 */

/**
 * @typedef {Object} SPFTerm
 * @property {String} type "mechanism" / "modifier"
 * 
 * @property {String} [qualifier]
 *   "+" | "-" | "~" | "?"
 * @property {String} [mechanism]
 * @property {String} [domain_spec]
 * @property {String} [ip4]
 * @property {String} [ip6]
 * @property {Number} [ip4_cidr_length]
 * @property {Number} [ip6_cidr_length]
 * 
 * @property {String} [modifier]
 * @property {String} [modifier_value]
 */

/**
 * Parses a single SPF record.
 *
 * @param {String} str SPF record
 * @return {SPFRecord|Null} parsed SPF record
 *   Null if record does not begin with version section of exactly "v=spf1"
 */
function parseRecord(str) {
	log.trace("parseRecord str: " + str.toSource());

	str = new RefString(str);

	// match version
	if (match_o(str, "v=spf1(?= |$)") === null) {
		return null;
	}
	let record = {};
	record.version = "spf1";

	// get the terms
	record.mechanism = [];
	record.modifier = [];
	while (true) {
		match(str, " +|$");
		if (str.value === "") {
			break;
		}
		let term = parseTerm(str);
		record[term.type].push(term);
	}

	// The "redirect" and "exp" modifier MUST NOT appear in a record more than
	// once each.
	if (record.modifier.filter(function(e){ return e.modifier === "redirect";}).
			length > 0) {
		throw new Error("SPF_PERMERROR: more than one 'redirect' record");
	}
	if (record.modifier.filter(function(e){ return e.modifier === "exp";}).
			length > 0) {
		throw new Error("SPF_PERMERROR: more than one 'exp' record");
	}

	log.debug("Parsed SPF record: " + record.toSource());
	return record;
}

/**
 * Parses the next term in str. The parsed part of str is removed from str.
 *
 * @param {RefString} str
 * @return {SPFTerm} Parsed term
 */
function parseTerm(str) {
	log.trace("parseTerm str: " + str.toSource());

	let reg_match;
	let term = {};

	let macro_literal_p = "[!-$&-~]";
	let macro_expand_p = "(?:%{[slodiphcrtv][0-9]*r?[.+,/_=-]*}|%%|%_|%-)";
	let macro_string_p = "(?:" + macro_expand_p + "|" + macro_literal_p + ")*";
	let explain_string_p = "(?:" + macro_string_p + "| )*";
	let toplabel_p = "(?:[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9])|(?:[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*)";
	let domain_end_p = "(?:(?:\\." + toplabel_p + "\\.?)|" + macro_expand_p + ")";
	let domain_spec_cp = "(" + macro_string_p + domain_end_p + ")";

	// try to match a directive
	let directive_p = "([+?~-])?(all|include|a|mx|ptr|ip4|ip6|exists)";
	reg_match = match_o(str, directive_p);
	if (reg_match !== null) {
		// term is a mechanism
		term.type = "mechanism";

		// "+" is the default qualifier
		term.qualifier = reg_match[1] || "+";
		term.mechanism = reg_match[2].toLowerCase();

		let ip4_cidr_length_ocp = "(?:/(0|[1-9][0-9]{0,1}))?";
		let ip6_cidr_length_cp  = "(?:/(0|[1-9][0-9]{0,2}))";
		let ip6_cidr_length_ocp = "(?:/(0|[1-9][0-9]{0,2}))?";
		let dual_cidr_length_ocp = "(?:" + ip4_cidr_length_ocp + "(?:/" +
			ip6_cidr_length_cp + ")?)?";
		let qnum_p = "(?:1[0-9]{2}|2[0-4][0-9]|25[0-5]|[1-9][0-9]|[0-9])";
		let ip4_network_cp = "(" + qnum_p + "\\." + qnum_p + "\\." + qnum_p +
			"\\." + qnum_p + ")";
		// does also match invalid addresses
		let ip6_network_cp = "([0-9a-zA-Z:.]+)";

		// match mechanism
		switch (term.mechanism) {
			case "all":
				break;
			case "include":
			case "exists":
				reg_match = match(str, ":" + domain_spec_cp);
				term.domain_spec = reg_match[1];
				break;
			case "a":
			case "mx":
				reg_match = match(str, "(?::" + domain_spec_cp + ")?" + dual_cidr_length_ocp);
				term.domain_spec = reg_match[1];
				term.ip4_cidr_length = parseInt(reg_match[2], 10) || 32;
				term.ip6_cidr_length = parseInt(reg_match[3], 10) || 128;
				break;
			case "ptr":
				reg_match = match(str, "(?::" + domain_spec_cp + ")?");
				term.domain_spec = reg_match[1];
				break;
			case "ip4":
				reg_match = match(str, ":" + ip4_network_cp + ip4_cidr_length_ocp);
				term.ip4 = reg_match[1];
				term.ip4_cidr_length = parseInt(reg_match[2], 10) || 32;
				break;
			case "ip6":
				reg_match = match(str, ":" + ip6_network_cp + ip6_cidr_length_ocp);
				term.ip6 = reg_match[1];
				term.ip6_cidr_length = parseInt(reg_match[2], 10) || 128;
				break;
			default:
				throw new Error("invalid mechanism: " + term.mechanism);
		}

		// ensure cidr-length has a valid value
		if (term.ip4_cidr_length && term.ip4_cidr_length > 32) {
			throw new Error("SPF_PERMERROR: ip4_cidr_length is bigger than 32 ");
		}
		if (term.ip6_cidr_length && term.ip6_cidr_length > 128) {
			throw new Error("SPF_PERMERROR: ip6_cidr_length is bigger than 128 ");
		}
	} else {
		// term is a modifier
		term.type = "modifier";

		// match modifier
		let modifier_cp = "(?:(redirect|explanation)=" + domain_spec_cp +	")|" +
			"([a-zA-Z][a-zA-Z0-9_.-]*)=(" + macro_string_p + ")";
		reg_match = match(str, modifier_cp);
		term.modifier = reg_match[1].toLowerCase() || reg_match[3].toLowerCase();
		term.modifier_value = reg_match[2] || reg_match[4];
	}

	return term;
}

/**
 * Object wrapper around a string.
 */
function RefString(s) {
    this.value = s;
}
RefString.prototype.match = function() {
	return this.value.match.apply(this.value, arguments);
};
RefString.prototype.substr = function() {
	return this.value.substr.apply(this.value, arguments);
};
RefString.prototype.toSource = function() {
	return this.value.toSource.apply(this.value, arguments);
};

/**
 * Matches a pattern case-insensitive to the beginning of str.
 * Removes the found match from str.
 *
 * @param {RefString} str
 * @param {String} pattern
 * @return {String[]} An Array, containing the matches
 * @throws if match no match found
 */
function match(str, pattern) {
	let reg_match = match_o(str, pattern);
	if (reg_match === null) {
		log.debug("str failed to match " + pattern.toSource() + " against:" +
			str.toSource());
		throw new Error("SPF_PERMERROR: Parsing error");
	}
	return reg_match;
}

/**
 * Tries to matches a pattern case-insensitive to the beginning of str.
 * If match is found, removes it from str.
 *
 * @param {RefString} str
 * @param {String} pattern
 * @return {String[]|Null} Null if no match for the pattern is found, else
 *                        an Array, containing the matches
 */
function match_o(str, pattern) {
	let regexp = new RegExp("^(?:" + pattern + ")", "i");
	let reg_match = str.match(regexp);
	if (reg_match === null) {
		return null;
	}
	log.trace("matched: " + reg_match[0].toSource());
	str.value = str.substr(reg_match[0].length);
	return reg_match;
}


/**
 * Constructs a IPv4 or IPv6 address from a string.
 * Stored as s byte array.
 * 
 * @typedef {Object} IP
 * @property {String} type "IPv4" / "IPv6"
 */
function IP(s){
	if (s.indexOf(".") !== -1) {
		this._buffer = s.split(".").map(function(e) {return parseInt(e, 10);});
		this.type = "IPv4";
	} else {
		this.type = "IPv6";
		// split in right and left part
		let parts = s.split("::");
		// split right and left part into groups
		parts = parts.map(function(e) {return e.split(":");});
		// add omitted groups
		parts.push([]);
		let groups = parts[0];
		let omitted_length = 8 - parts[0].length - parts[1].length;
		for (let i = 0; i < omitted_length; i++) {
			groups.push("0");
		}
		groups = groups.concat(parts[1]);
		// convert groups to byte array
		this._buffer = [];
		for (let i = 0; i < 8; i++) {
			// add leading zeroes
			let e = "0".repeat(4 - groups[i].length) + groups[i];
			// convert
			this._buffer.push(parseInt(e.substr(0, 2), 16));
			this._buffer.push(parseInt(e.substr(2, 4), 16));
		}
	}
}

/**
 * Compares the IP address to the given network.
 * If CIDR prefix length high-order bits match, true is returned.
 *
 * @param {IP} network
 * @param {Number} cidr_length
 * @return {Boolean}
 */
IP.prototype.isInNetwork = function(network, cidr_length) {
	/* jshint bitwise:false */
	if (this._buffer.length !==network._buffer.length) {
		return false;
	}

	let i;
	for (i = 0; i < ((cidr_length / 8) >> 0); i++) {
		if (this._buffer[i] !== network._buffer[i]) {
			return false;
		}
	}
	let rem = cidr_length % 8;
	if (rem !== 0) {
		return ((this._buffer[i] | network._buffer[i]) >>> (8 - rem)) === 0;
	} else {
		return true;
	}
	/* jshint bitwise:true */
};

// expose internal components for testing
SPF._SPFContext = SPFContext;
SPF._parseRecord = parseRecord;
SPF._IP = IP;
