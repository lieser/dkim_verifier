/**
 * Copyright (c) 2020-2022 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "VerifierModule" }]*/

import "../helpers/initWebExtensions.mjs.js";
import Verifier, * as VerifierModule from "../../modules/dkim/verifier.mjs.js";
import prefs, { BasePreferences } from "../../modules/preferences.mjs.js";
import KeyStore from "../../modules/dkim/keyStore.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { queryDnsTxt } from "../helpers/dnsStub.mjs.js";
import { readTestFile } from "../helpers/testUtils.mjs.js";

/**
 * Verify DKIM for the given eml file.
 *
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<VerifierModule.dkimResultV2>}
 */
async function verifyEmlFile(file) {
	const msgPlain = await readTestFile(file);
	const msgParsed = MsgParser.parseMsg(msgPlain);
	const from = msgParsed.headers.get("from");
	if (!from || !from[0]) {
		throw new Error("eml file does not contain a From header");
	}
	const msg = {
		headerFields: msgParsed.headers,
		bodyPlain: msgParsed.body,
		from: MsgParser.parseFromHeader(from[0]),
	};
	const verifier = new Verifier(new KeyStore(queryDnsTxt));
	return verifier.verify(msg);
}

describe("DKIM Verifier [unittest]", function () {
	before(async function () {
		await prefs.init();
	});

	beforeEach(async function () {
		await prefs.clear();
	});

	describe("Valid examples", function () {
		it("RFC 6376 Appendix A Example", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
			expect(res.signatures[0]?.sdid).to.be.equal("example.com");
			expect(res.signatures[0]?.auid).to.be.equal("joe@football.example.com");
			expect(res.signatures[0]?.selector).to.be.equal("brisbane");
		});
		it("RFC 8463 Appendix A Example", async function () {
			const res = await verifyEmlFile("rfc8463-A.3.eml");
			expect(res.signatures.length).to.be.equal(2);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
			expect(res.signatures[0]?.sdid).to.be.equal("football.example.com");
			expect(res.signatures[0]?.auid).to.be.equal("@football.example.com");
			expect(res.signatures[0]?.selector).to.be.equal("test");
			expect(res.signatures[1]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[1]?.warnings).to.be.empty;
			expect(res.signatures[1]?.sdid).to.be.equal("football.example.com");
			expect(res.signatures[1]?.auid).to.be.equal("@football.example.com");
			expect(res.signatures[1]?.selector).to.be.equal("brisbane");
		});
	});
	describe("Syntax errors", function () {
		it("Missing v-tag in signature", async function () {
			const res = await verifyEmlFile("rfc6376-A.2-ill_formed-missing_v.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_MISSING_V");
			expect(res.signatures[0]?.sdid).to.be.undefined;
		});
	});
	describe("Mismatches between signature and key", function () {
		it("Wrong key signature algorithm", async function () {
			const res = await verifyEmlFile("rfc8463-A.3-key_algo_mismatch.eml");
			expect(res.signatures.length).to.be.equal(2);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_MISMATCHED_K");
			expect(res.signatures[1]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[1]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_MISMATCHED_K");
		});
	});
	describe("Modifications", function () {
		describe("Simple body canonicalization", function () {
			describe("Disallowed modifications", function () {
				it("Body modified", async function () {
					const res = await verifyEmlFile("rfc6376-A.2-body_modified.eml");
					expect(res.signatures.length).to.be.equal(1);
					expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
					expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_CORRUPT_BH");
					expect(res.signatures[0]?.sdid).to.be.equal("example.com");
				});
			});
		});
		describe("Simple header canonicalization", function () {
			describe("Disallowed modifications", function () {
				it("Signed header subject modified", async function () {
					const res = await verifyEmlFile("rfc6376-A.2-header_subject_modified.eml");
					expect(res.signatures.length).to.be.equal(1);
					expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
					expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_BADSIG");
					expect(res.signatures[0]?.sdid).to.be.equal("example.com");
				});
			});

		});
	});
	describe("Signature warnings", function () {
		it("From address is not in the SDID ", async function () {
			// TODO: instead of artificial test, add test mail there this is the case
			const msgPlain = await readTestFile("rfc6376-A.2.eml");
			const msgParsed = MsgParser.parseMsg(msgPlain);
			const msg = {
				headerFields: msgParsed.headers,
				bodyPlain: msgParsed.body,
				from: "foo@bar.com",
			};
			const verifier = new Verifier(new KeyStore(queryDnsTxt));
			const res = await verifier.verify(msg);
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.an('array').
				that.deep.includes({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });
		});
	});
	describe("Detect and prevent possible attacks", function () {
		describe("Additional unsigned header was added", function () {
			// Thunderbirds uses the top most, unsigned header.

			it("Added From header", async function () {
				const res = await verifyEmlFile("dkim/added_header-from.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
				expect(res.signatures[0]?.errorType).to.be.equal("DKIM_POLICYERROR_UNSIGNED_HEADER_ADDED");
				expect(res.signatures[0]?.errorStrParams).to.be.deep.equal(["From"]);
			});
			it("Added Subject header", async function () {
				const res = await verifyEmlFile("dkim/added_header-subject.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
				expect(res.signatures[0]?.errorType).to.be.equal("DKIM_POLICYERROR_UNSIGNED_HEADER_ADDED");
				expect(res.signatures[0]?.errorStrParams).to.be.deep.equal(["Subject"]);
			});
			it("Added Date header", async function () {
				const res = await verifyEmlFile("dkim/added_header-date.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
				expect(res.signatures[0]?.errorType).to.be.equal("DKIM_POLICYERROR_UNSIGNED_HEADER_ADDED");
				expect(res.signatures[0]?.errorStrParams).to.be.deep.equal(["Date"]);
			});
			it("Added To header", async function () {
				// Thunderbirds shows both the unsigned and signed header.
				const res = await verifyEmlFile("dkim/added_header-to.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
				expect(res.signatures[0]?.errorType).to.be.equal("DKIM_POLICYERROR_UNSIGNED_HEADER_ADDED");
				expect(res.signatures[0]?.errorStrParams).to.be.deep.equal(["To"]);
			});
		});
		describe("Recommended or advised header is not signed", function () {
			// All headers that are directly shown, affect the displaying of the body
			// or affect how Thunderbird behaves should be signed.

			it("Unsigned Content-Type header", async function () {
				prefs.setValue("policy.dkim.unsignedHeadersWarning.mode", BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.STRICT);
				const res = await verifyEmlFile("dkim/unsigned_header-content-type.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
				expect(res.signatures[0]?.warnings).to.be.an('array').
					that.deep.includes({ name: "DKIM_SIGWARNING_UNSIGNED_HEADER", params: ["Content-Type"] });
			});
			it("Unsigned Reply-To header that is in the signing domain", async function () {
				prefs.setValue("policy.dkim.unsignedHeadersWarning.mode", BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.RECOMMENDED);
				let res = await verifyEmlFile("dkim/unsigned_header-reply_to-in_domain.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
				expect(res.signatures[0]?.warnings).to.be.empty;

				prefs.setValue("policy.dkim.unsignedHeadersWarning.mode", BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.STRICT);
				res = await verifyEmlFile("dkim/unsigned_header-reply_to-in_domain.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
				expect(res.signatures[0]?.warnings).to.be.an('array').
					that.deep.includes({ name: "DKIM_SIGWARNING_UNSIGNED_HEADER", params: ["Reply-To"] });
			});
			it("Unsigned Reply-To header that is not in the signing domain", async function () {
				prefs.setValue("policy.dkim.unsignedHeadersWarning.mode", BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.RECOMMENDED);
				const res = await verifyEmlFile("dkim/unsigned_header-reply_to-not_in_domain.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
				expect(res.signatures[0]?.warnings).to.be.an('array').
					that.deep.includes({ name: "DKIM_SIGWARNING_UNSIGNED_HEADER", params: ["Reply-To"] });
			});
			it("Unsigned Reply-To header that is invalid", async function () {
				const res = await verifyEmlFile("dkim/unsigned_header-reply_to-invalid.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
				expect(res.signatures[0]?.warnings).to.be.empty;
			});
		});
	});
});
