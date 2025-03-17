/*
 * dkimDMARC.jsm.js
 *
 * Implements a very small part of DMARC to determined if an e-mail should
 * have a DKIM signature.
 *
 * This module is NOT conform to DMARC.
 *
 * Version: 1.1.1 (13 January 2019)
 *
 * Copyright (c) 2014-2019 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* eslint strict: ["warn", "function"] */
/* global Components, Services */
/* global Logging, DNS, rfcParser */
/* global getBaseDomainFromAddr, getDomainFromAddr, toType, DKIM_Error */
/* exported EXPORTED_SYMBOLS, DMARC */

// @ts-expect-error
const module_version = "1.1.1";

var EXPORTED_SYMBOLS = [
	"DMARC"
];

// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/dnsWrapper.jsm.js");
Cu.import("resource://dkim_verifier/rfcParser.jsm.js");

/**
 * @public
 */
// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.policy.DMARC.";


// @ts-expect-error
let prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-expect-error
let log = Logging.getLogger("DMARC");

var DMARC = {
	get version() { "use strict"; return module_version; },

	/**
	 * Tries to determinate with DMARC if an e-mail should be signed.
	 *
	 * @param {String} fromAddress
	 *
	 * @returns {Promise<Object>}
	 *         .shouldBeSigned true if fromAddress should be signed
	 *         .sdid {String[]} Signing Domain Identifier
	 */
	shouldBeSigned: async function Policy_shouldBeSigned(fromAddress) {
		"use strict";

		log.trace("shouldBeSigned Task begin");

		// default result
		let res = {};
		res.shouldBeSigned = false;
		res.sdid = [];

		// return false if DMARC shouldBeSigned check is disabled
		if (!prefs.getBoolPref("shouldBeSigned.enable")) {
			log.trace("shouldBeSigned Task end");
			return res;
		}

		let DMARCPolicy;
		try {
			DMARCPolicy = await getDMARCPolicy(fromAddress);
		} catch (e) {
			// ignore errors on getting the DMARC policy
			log.error("Ignored error on getting the DMARC policy", e);
			return res;
		}
		let neededPolicy = prefs.getCharPref("shouldBeSigned.neededPolicy");
		if (DMARCPolicy &&
			(neededPolicy === "none" ||
				(neededPolicy === "quarantine" && DMARCPolicy.p !== "none") ||
				(neededPolicy === "reject" && DMARCPolicy.p === "reject"))) {
			res.shouldBeSigned = true;

			if (DMARCPolicy.source === DMARCPolicy.domain) {
				res.sdid = [DMARCPolicy.domain];
			} else {
				res.sdid = [DMARCPolicy.domain, DMARCPolicy.source];
			}
		}

		log.trace("shouldBeSigned Task end");
		return res;
	}
};

/**
 * A DMARC Record.
 *
 * @typedef {Object} DMARCRecord
 * @property {String} adkim
 *   DKIM identifier alignment mode
 *   Possible values: "r" (relaxed), "s" (strict)
 * @property {String} p
 *   Requested Mail Receiver policy
 *   Possible values: "none", "quarantine", "reject"
 * @property {Number} pct
 *   Percentage of messages from the Domain Owner's mail stream to which the
 *   DMARC mechanism is to be applied
 * @property {String?} sp
 *   Requested Mail Receiver policy for all subdomains
 *   Possible values: "none", "quarantine", "reject"
 * @property {String} v
 *   Version
 *   Possible values: "DMARC1"
 */

/**
 * A DMARC Policy.
 *
 * @typedef {Object} DMARCPolicy
 * @property {String} adkim
 *   DKIM identifier alignment mode
 *   Possible values: "r" (relaxed), "s" (strict)
 * @property {String} p
 *   Requested Mail Receiver policy
 *   Possible values: "none", "quarantine", "reject"
 * @property {Number} pct
 *   Percentage of messages from the Domain Owner's mail stream to which the
 *   DMARC mechanism is to be applied
 * @property {String} domain
 *   Full domain of the e-mail address.
 * @property {String} source
 *   Domain in which the DMARC Policy was found.
 */

/**
 * Get the DMARC Policy.
 *
 * @param {String} fromAddress
 *
 * @returns {Promise<DMARCPolicy|Null>}
 *
 * @throws {DKIM_TempError}
 */
async function getDMARCPolicy(fromAddress) {
	"use strict";

	log.trace("getDMARCPolicy Task begin");

	let dmarcRecord;
	let domain = getDomainFromAddr(fromAddress);
	let baseDomain;

	// 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
	//     DNS domain matching the one found in the RFC5322.From domain in
	//     the message.  A possibly empty set of records is returned

	// get the DMARC Record
	dmarcRecord = await getDMARCRecord(domain);

	// 2.  Records that do not start with a "v=" tag that identifies the
	// current version of DMARC are discarded.

	// NOTE: record with "v=" tag not "DMARC1" are not parsed

	// 3.  If the set is now empty, the Mail Receiver MUST query the DNS for
	//     a DMARC TXT record at the DNS domain matching the Organizational
	//     Domain in place of the RFC5322.From domain in the message (if
	//     different).  This record can contain policy to be asserted for
	//     subdomains of the Organizational Domain.  A possibly empty set of
	//     records is returned.

	if (!dmarcRecord) {
		// get the DMARC Record of the base domain
		baseDomain = getBaseDomainFromAddr(fromAddress);
		if (domain !== baseDomain) {
			dmarcRecord = await getDMARCRecord(baseDomain);

			if (dmarcRecord) {
				// overrides Receiver policy if one for subdomains was specified
				dmarcRecord.p = dmarcRecord.sp || dmarcRecord.p;
			}
		}
	}

	// 4.  Records that do not start with a "v=" tag that identifies the
	// current version of DMARC are discarded.

	// NOTE: record with "v=" tag not "DMARC1" are not parsed

	// 5.  If the remaining set contains multiple records or no records,
	//     processing terminates and the Mail Receiver takes no action.

	// NOTE: no test for multiple records in DNS

	// 6.  If a retrieved policy record does not contain a valid "p" tag, or
	//     contains an "sp" tag that is not valid, then:
	//
	//     1.  if an "rua" tag is present and contains at least one
	//         syntactically valid reporting URI, the Mail Receiver SHOULD
	//         act as if a record containing a valid "v" tag and "p=none"
	//         was retrieved, and continue processing;
	//
	//     2.  otherwise, the Mail Receiver SHOULD take no action.

	// NOTE: records with invalid "p" or "sp" tag are not parsed

	if (!dmarcRecord) {
		log.trace("getDMARCPolicy Task end");
		return null;
	}
	let dmarcPolicy = {
		adkim: dmarcRecord.adkim,
		pct: dmarcRecord.pct,
		p: dmarcRecord.p,
		domain: domain,
		source: baseDomain || domain,
	};
	log.debug("DMARCPolicy: "+dmarcPolicy.toSource());

	log.trace("getDMARCPolicy Task end");
	return dmarcPolicy;
}

/**
 * Get the DMARC Record.
 *
 * @param {String} domain
 *
 * @returns {Promise<DMARCRecord|Null>}
 *
 * @throws {DKIM_TempError}
 */
async function getDMARCRecord(domain) {
	"use strict";

	log.trace("getDMARCRecord Task begin");

	let dmarcRecord = null;

	// get the DMARC Record
	let result = await DNS.resolve("_dmarc."+domain, "TXT");

	DNS.checkForErrors(result);

	// try to parse DMARC Record if record was found in DNS Server
	if (result.data !== null && result.data[0]) {
		try {
			dmarcRecord = parseDMARCRecord(result.data[0]);
		} catch (e) {
			log.error("Ignored error in parsing of DMARC record", e);
		}
	}

	log.trace("getDMARCRecord Task end");
	return dmarcRecord;
}

/**
 * Parse the DMARC Policy Record.
 *
 * @param {String} DMARCRecordStr
 *
 * @returns {DMARCRecord}
 *
 * @throws {DKIM_Error}
 */
function parseDMARCRecord(DMARCRecordStr) {
	"use strict";

	log.trace("parseDMARCRecord begin");

	/** @type {DMARCRecord} */
	let dmarcRecord = {
		adkim : "", // DKIM identifier alignment mode
		// aspf : null, // SPF identifier alignment mode
		// fo : null, // Failure reporting options
		p : "", // Requested Mail Receiver policy
		pct : NaN, // Percentage of messages from the Domain Owner's
			// mail stream to which the DMARC mechanism is to be applied
		// rf : null, // Format to be used for message-specific failure reports
		// ri : null, // Interval requested between aggregate reports
		// rua : null, // Addresses to which aggregate feedback is to be sent
		// ruf : null, // Addresses to which message-specific failure information is to
			// be reported
		sp : null, // Requested Mail Receiver policy for all subdomains
		v : "" // Version
	};

	// parse tag-value list
	let parsedTagMap = rfcParser.parseTagValueList(DMARCRecordStr);
	if (parsedTagMap === -1) {
		throw new DKIM_Error("DKIM_DMARCERROR_ILLFORMED_TAGSPEC");
	} else if (parsedTagMap === -2) {
		throw new DKIM_Error("DKIM_DMARCERROR_DUPLICATE_TAG");
	}
	if (!(toType(parsedTagMap) === "Map")) {
		throw new DKIM_Error(`unexpected return value from rfcParser.parseTagValueList: ${parsedTagMap}`);
	}
	/** @type {Map} */
	// @ts-expect-error
	let tagMap = parsedTagMap;

	// v: Version (plain-text; REQUIRED). Identifies the record retrieved
	// as a DMARC record.  It MUST have the value of "DMARC1".  The value
	// of this tag MUST match precisely; if it does not or it is absent,
	// the entire retrieved record MUST be ignored.  It MUST be the first
	// tag in the list.
	let versionTag = rfcParser.parseTagValue(tagMap, "v", "DMARC1", 3);
	if (versionTag === null) {
		throw new DKIM_Error("DKIM_DMARCERROR_MISSING_V");
	} else {
		dmarcRecord.v = "DMARC1";
	}

	// adkim:  (plain-text; OPTIONAL, default is "r".)  Indicates whether
	// strict or relaxed DKIM identifier alignment mode is required by
	// the Domain Owner.
	let adkimTag = rfcParser.parseTagValue(tagMap, "adkim", "[rs]", 3);
	if (adkimTag === null || versionTag[0] === "DMARC1") {
		dmarcRecord.adkim = "r";
	} else {
		dmarcRecord.adkim = adkimTag[0];
	}

	// p: Requested Mail Receiver policy (plain-text; REQUIRED for policy
	// records).  Indicates the policy to be enacted by the Receiver at
	// the request of the Domain Owner.  Policy applies to the domain
	// queried and to sub-domains unless sub-domain policy is explicitly
	// described using the "sp" tag.  This tag is mandatory for policy
	// records only, but not for third-party reporting records (see
	// Section 7.1).  Possible values are as follows:
	// none:  The Domain Owner requests no specific action be taken
	//    regarding delivery of messages.
	// quarantine:  The Domain Owner wishes to have email that fails the
	//    DMARC mechanism check to be treated by Mail Receivers as
	//    suspicious.  Depending on the capabilities of the Mail
	//    Receiver, this can mean "place into spam folder", "scrutinize
	//    with additional intensity", and/or "flag as suspicious".
	// reject:  The Domain Owner wishes for Mail Receivers to reject
	//    email that fails the DMARC mechanism check.  Rejection SHOULD
	//    occur during the SMTP transaction.  See Section 15.4 for some
	//    discussion of SMTP rejection methods and their implications.
	let pTag = rfcParser.parseTagValue(tagMap, "p", "(?:none|quarantine|reject)", 3);
	if (pTag === null) {
		throw new DKIM_Error("DKIM_DMARCERROR_MISSING_P");
	} else {
		dmarcRecord.p = pTag[0];
	}

	// pct:  (plain-text integer between 0 and 100, inclusive; OPTIONAL;
	// default is 100).  Percentage of messages from the Domain Owner's
	// mail stream to which the DMARC mechanism is to be applied.
	// However, this MUST NOT be applied to the DMARC-generated reports,
	// all of which must be sent and received unhindered.  The purpose of
	// the "pct" tag is to allow Domain Owners to enact a slow rollout
	// enforcement of the DMARC mechanism.  The prospect of "all or
	// nothing" is recognized as preventing many organizations from
	// experimenting with strong authentication-based mechanisms.  See
	// Section 6.1 for details.  Note that random selection based on this
	// percentage, such as the following pseudocode, is adequate:
	//
	//  if (random mod 100) < pct then
	//    selected = true
	//  else
	//    selected = false
	let pctTag = rfcParser.parseTagValue(tagMap, "pct", "[0-9]{1,3}", 3);
	if (pctTag === null) {
		dmarcRecord.pct = 100;
	} else {
		dmarcRecord.pct = parseInt(pctTag[0], 10);
		if (dmarcRecord.pct < 0 || dmarcRecord.pct > 100) {
			throw new DKIM_Error("DKIM_DMARCERROR_INVALID_PCT");
		}
	}

	// sp:  Requested Mail Receiver policy for all subdomains (plain-text;
	// OPTIONAL).  Indicates the policy to be enacted by the Receiver at
	// the request of the Domain Owner.  It applies only to subdomains of
	// the domain queried and not to the domain itself.  Its syntax is
	// identical to that of the "p" tag defined above.  If absent, the
	// policy specified by the "p" tag MUST be applied for subdomains.
	// Note that "sp" will be ignored for DMARC records published on sub-
	// domains of Organizational Domains due to the effect of the DMARC
	// Policy Discovery mechanism described in Section 8.
	let spTag = rfcParser.parseTagValue(tagMap, "sp", "(?:none|quarantine|reject)", 3);
	if (spTag !== null) {
		dmarcRecord.sp = spTag[0];
	}

	log.trace("parseDMARCRecord end");
	return dmarcRecord;
}
