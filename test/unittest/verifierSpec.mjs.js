/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import "../helpers/initWebExtensions.mjs.js";
import { createTxtQueryCallback, queryDnsTxt } from "../helpers/dnsStub.mjs.js";
import prefs, { BasePreferences } from "../../modules/preferences.mjs.js";
import KeyStore from "../../modules/dkim/keyStore.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import Verifier from "../../modules/dkim/verifier.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { readTestFile } from "../helpers/testUtils.mjs.js";

/**
 * Verify DKIM for the given eml file.
 *
 * @param {string} file - path to file relative to test data directory
 * @param {Map<string, string>} [dnsEntries]
 * @returns {Promise<import("../../modules/dkim/verifier.mjs.js").dkimResultV2>}
 */
async function verifyEmlFile(file, dnsEntries) {
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
	const queryFunktion = dnsEntries ? createTxtQueryCallback(dnsEntries) : queryDnsTxt;
	const verifier = new Verifier(new KeyStore(queryFunktion));
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
		it("DKIM key with empty notes tag", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;n=;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
		});
		it("DKIM key with list of allowed hash algorithms", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;h=sha1:sha256;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
		});
		it("DKIM key with wildcard service tag", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;s=*;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
		});
		it("DKIM key with email service tag", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;s=email;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
		});
		it("DKIM key with unknown tag", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;g=*;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
		});
		it("Received time is after Signature Timestamp", async function () {
			const res = await verifyEmlFile("dkim/time-received_after_creation.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
		});
		it("Received time is briefly before Signature Timestamp", async function () {
			// I.e. a small clock difference between sender and receiver should not result in an error
			const res = await verifyEmlFile("dkim/time-received_briefly_before_creation.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.empty;
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
	describe("General errors", function () {
		it("Revoked key", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com", "v=DKIM1; p="]
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_REVOKED");
		});
		it("Hash algorithm is not in the allowed list of the DKIM key", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;h=sha1;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_HASHNOTINCLUDED");
		});
		it("Wrong key signature algorithm", async function () {
			const res = await verifyEmlFile("rfc8463-A.3-key_algo_mismatch.eml");
			expect(res.signatures.length).to.be.equal(2);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_MISMATCHED_K");
			expect(res.signatures[1]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[1]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_MISMATCHED_K");
		});
		it("DKIM key with other service tag", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;s=other;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_KEY_NOTEMAILKEY");
		});
		it("DKIM key does not allow AUID to be a subdomain", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml", new Map([
				["brisbane._domainkey.example.com",
					"v=DKIM1;t=s;p=" +
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
					"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
					"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
					"MmPSPDdQPNUYckcQ2QIDAQAB"],
			]));
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("PERMFAIL");
			expect(res.signatures[0]?.errorType).to.be.equal("DKIM_SIGERROR_DOMAIN_I");
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
			expect(res.signatures[0]?.warnings).to.be.an("array").
				that.deep.includes({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });
		});
		it("Received time is before Signature Timestamp", async function () {
			const res = await verifyEmlFile("dkim/time-received_long_before_creation.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
			expect(res.signatures[0]?.warnings).to.be.an("array").
				that.deep.includes({ name: "DKIM_SIGWARNING_FUTURE" });
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
				expect(res.signatures[0]?.warnings).to.be.an("array").
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
				expect(res.signatures[0]?.warnings).to.be.an("array").
					that.deep.includes({ name: "DKIM_SIGWARNING_UNSIGNED_HEADER", params: ["Reply-To"] });
			});
			it("Unsigned Reply-To header that is not in the signing domain", async function () {
				prefs.setValue("policy.dkim.unsignedHeadersWarning.mode", BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.RECOMMENDED);
				const res = await verifyEmlFile("dkim/unsigned_header-reply_to-not_in_domain.eml");
				expect(res.signatures.length).to.be.equal(1);
				expect(res.signatures[0]?.result).to.be.equal("SUCCESS");
				expect(res.signatures[0]?.warnings).to.be.an("array").
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
