/*
 * Implements a very small part of DMARC to determined if an e-mail should
 * have a DKIM signature.
 *
 * This module is NOT conform to DMARC.
 *
 * Copyright (c) 2014-2019;2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../experiments/mailUtils.d.ts" />
/* eslint-env webextensions */
/* eslint-disable no-magic-numbers */
/* eslint-disable no-use-before-define */

import { DKIM_InternalError } from "../error.mjs.js";
import DNS from "../dns.mjs.js";
import Logging from "../logging.mjs.js";
import RfcParser from "../rfcParser.mjs.js";
import { getDomainFromAddr } from "../utils.mjs.js";
import prefs from "../preferences.mjs.js";

const log = Logging.getLogger("DMARC");

/**
 * @typedef { typeof DNS.txt } queryDnsTxtCallback
 */

export default class DMARC {
	/**
	 * @param {queryDnsTxtCallback} [queryDnsTxt]
	 */
	constructor(queryDnsTxt) {
		/** @private */
		this._queryDnsTxt = queryDnsTxt ?? DNS.txt;
	}

	/**
	 * Tries to determinate with DMARC if an e-mail should be signed.
	 *
	 * @param {string} fromAddress
	 * @return {Promise<{shouldBeSigned: boolean, sdid: string[]}>}
	 *         .shouldBeSigned true if fromAddress should be signed
	 *         .sdid Signing Domain Identifier
	 */
	async shouldBeSigned(fromAddress) {
		// default result
		const res = {
			shouldBeSigned: false,
			/** @type {string[]} */
			sdid: [],
		};

		let DMARCPolicy;
		try {
			DMARCPolicy = await getDMARCPolicy(fromAddress, this._queryDnsTxt);
		} catch (e) {
			// ignore errors on getting the DMARC policy
			log.error("Ignored error on getting the DMARC policy", e);
			return res;
		}
		const neededPolicy = prefs["policy.DMARC.shouldBeSigned.neededPolicy"];
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

		return res;
	}
}

/**
 * A DMARC Record.
 *
 * @typedef {Object} DMARCRecord
 * @property {string} adkim
 *   DKIM identifier alignment mode
 *   Possible values: "r" (relaxed), "s" (strict)
 * @property {string} p
 *   Requested Mail Receiver policy
 *   Possible values: "none", "quarantine", "reject"
 * @property {number} pct
 *   Percentage of messages from the Domain Owner's mail stream to which the
 *   DMARC mechanism is to be applied
 * @property {string?} sp
 *   Requested Mail Receiver policy for all subdomains
 *   Possible values: "none", "quarantine", "reject"
 * @property {string} v
 *   Version
 *   Possible values: "DMARC1"
 */

/**
 * A DMARC Policy.
 *
 * @typedef {Object} DMARCPolicy
 * @property {string} adkim
 *   DKIM identifier alignment mode
 *   Possible values: "r" (relaxed), "s" (strict)
 * @property {string} p
 *   Requested Mail Receiver policy
 *   Possible values: "none", "quarantine", "reject"
 * @property {number} pct
 *   Percentage of messages from the Domain Owner's mail stream to which the
 *   DMARC mechanism is to be applied
 * @property {string} domain
 *   Full domain of the e-mail address.
 * @property {string} source
 *   Domain in which the DMARC Policy was found.
 */

/**
 * Get the DMARC Policy.
 *
 * @param {string} fromAddress
 * @param {queryDnsTxtCallback} queryDnsTxt
 * @return {Promise<DMARCPolicy|null>}
 * @throws {DKIM_InternalError}
 */
async function getDMARCPolicy(fromAddress, queryDnsTxt) {
	let dmarcRecord;
	const domain = getDomainFromAddr(fromAddress);
	let baseDomain;

	// 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
	//     DNS domain matching the one found in the RFC5322.From domain in
	//     the message.  A possibly empty set of records is returned

	// get the DMARC Record
	dmarcRecord = await getDMARCRecord(domain, queryDnsTxt);

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
		baseDomain = await browser.mailUtils.getBaseDomainFromAddr(fromAddress);
		if (domain !== baseDomain) {
			dmarcRecord = await getDMARCRecord(baseDomain, queryDnsTxt);

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
		return null;
	}
	const dmarcPolicy = {
		adkim: dmarcRecord.adkim,
		pct: dmarcRecord.pct,
		p: dmarcRecord.p,
		domain: domain,
		source: baseDomain || domain,
	};
	log.debug("DMARCPolicy:", dmarcPolicy);

	return dmarcPolicy;
}

/**
 * Get the DMARC Record.
 *
 * @param {string} domain
 * @param {queryDnsTxtCallback} queryDnsTxt
 * @return {Promise<DMARCRecord|null>}
 * @throws {DKIM_InternalError}
 */
async function getDMARCRecord(domain, queryDnsTxt) {
	let dmarcRecord = null;

	// get the DMARC Record
	const result = await queryDnsTxt(`_dmarc.${domain}`);

	// throw error on bogus result or DNS error
	if (result.bogus) {
		throw new DKIM_InternalError(null, "DKIM_DNSERROR_DNSSEC_BOGUS");
	}
	if (result.rcode !== DNS.RCODE.NoError && result.rcode !== DNS.RCODE.NXDomain) {
		throw new DKIM_InternalError(`rcode: ${result.rcode}`, "DKIM_DNSERROR_SERVER_ERROR");
	}

	// try to parse DMARC Record if record was found in DNS Server
	if (result.data !== null) {
		try {
			dmarcRecord = parseDMARCRecord(result.data[0]);
		} catch (e) {
			log.error("Ignored error in parsing of DMARC record", e);
		}
	}

	return dmarcRecord;
}

/**
 * Parse the DMARC Policy Record.
 *
 * @param {string} DMARCRecordStr
 * @return {DMARCRecord}
 * @throws {DKIM_InternalError}
 */
function parseDMARCRecord(DMARCRecordStr) {
	/** @type {DMARCRecord} */
	const dmarcRecord = {
		adkim: "", // DKIM identifier alignment mode
		// aspf : null, // SPF identifier alignment mode
		// fo : null, // Failure reporting options
		p: "", // Requested Mail Receiver policy
		pct: NaN, // Percentage of messages from the Domain Owner's
		// mail stream to which the DMARC mechanism is to be applied
		// rf : null, // Format to be used for message-specific failure reports
		// ri : null, // Interval requested between aggregate reports
		// rua : null, // Addresses to which aggregate feedback is to be sent
		// ruf : null, // Addresses to which message-specific failure information is to
		// be reported
		sp: null, // Requested Mail Receiver policy for all subdomains
		v: "" // Version
	};

	// parse tag-value list
	const tagMap = RfcParser.parseTagValueList(DMARCRecordStr);
	if (tagMap === -1) {
		throw new DKIM_InternalError("DKIM_DMARCERROR_ILLFORMED_TAGSPEC");
	} else if (tagMap === -2) {
		throw new DKIM_InternalError("DKIM_DMARCERROR_DUPLICATE_TAG");
	}
	if (!(tagMap instanceof Map)) {
		throw new DKIM_InternalError(`unexpected return value from RfcParser.parseTagValueList: ${tagMap}`);
	}

	// v: Version (plain-text; REQUIRED).  Identifies the record retrieved
	// as a DMARC record.  It MUST have the value of "DMARC1".  The value
	// of this tag MUST match precisely; if it does not or it is absent,
	// the entire retrieved record MUST be ignored.  It MUST be the first
	// tag in the list.
	const versionTag = RfcParser.parseTagValue(tagMap, "v", "DMARC1", 3);
	if (versionTag === null) {
		throw new DKIM_InternalError("DKIM_DMARCERROR_MISSING_V");
	} else {
		dmarcRecord.v = "DMARC1";
	}

	// adkim:  (plain-text; OPTIONAL, default is "r".)  Indicates whether
	// strict or relaxed DKIM identifier alignment mode is required by
	// the Domain Owner.
	const adkimTag = RfcParser.parseTagValue(tagMap, "adkim", "[rs]", 3);
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
	const pTag = RfcParser.parseTagValue(tagMap, "p", "(?:none|quarantine|reject)", 3);
	if (pTag === null) {
		throw new DKIM_InternalError("DKIM_DMARCERROR_MISSING_P");
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
	const pctTag = RfcParser.parseTagValue(tagMap, "pct", "[0-9]{1,3}", 3);
	if (pctTag === null) {
		dmarcRecord.pct = 100;
	} else {
		dmarcRecord.pct = parseInt(pctTag[0], 10);
		if (dmarcRecord.pct < 0 || dmarcRecord.pct > 100) {
			throw new DKIM_InternalError("DKIM_DMARCERROR_INVALID_PCT");
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
	const spTag = RfcParser.parseTagValue(tagMap, "sp", "(?:none|quarantine|reject)", 3);
	if (spTag !== null) {
		dmarcRecord.sp = spTag[0];
	}

	return dmarcRecord;
}
